import base64
import hashlib
from urllib.parse import parse_qs
from urllib.parse import urlsplit

import httpx2
import pytest

from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.idp import IdpClient
from netbox_mcp.oauth.idp import IdpRejected
from netbox_mcp.oauth.idp import IdpUnavailable
from tests.oauth.fakes import FakeIdP

REDIRECT = "https://mcp.example.com/oauth/callback"
VERIFIER = "v" * 64


@pytest.fixture(autouse=True)
def _aligned(fake_idp: FakeIdP, clock) -> None:
    fake_idp.now = clock


async def _client(config: OAuthConfig, idp: FakeIdP) -> IdpClient:
    client = IdpClient(config, transport=idp.transport)
    await client.discover()
    return client


async def _login_code(idp: FakeIdP, client: IdpClient, nonce: str = "n-1") -> str:
    """Drive the fake's authorize endpoint with the client's own URL."""
    url = client.authorization_url("st-1", nonce, VERIFIER, REDIRECT)
    async with httpx2.AsyncClient(
        transport=idp.transport, follow_redirects=False
    ) as http:
        resp = await http.get(url)
    assert resp.status_code == 302
    return parse_qs(urlsplit(resp.headers["location"]).query)["code"][0]


async def _logged_in(config, idp, nonce="n-1"):
    client = await _client(config, idp)
    code = await _login_code(idp, client, nonce)
    return client, code


# -- discovery


async def test_discovery_ok(oauth_config, fake_idp) -> None:
    await _client(oauth_config, fake_idp)
    assert fake_idp.calls["discovery"] == 1


async def test_discovery_issuer_exact_trailing_slash(oauth_config, fake_idp) -> None:
    config = oauth_config.model_copy(
        update={"issuer_url": oauth_config.issuer_url.rstrip("/")}
    )
    client = IdpClient(config, transport=fake_idp.transport)
    with pytest.raises(IdpUnavailable):
        await client.discover()


@pytest.mark.parametrize(
    "issuer",
    [
        "https://idp.example.com",
        "https://idp.example.com/",
        "https://idp.example.com/realms/main",
        "https://idp.example.com/realms/main/",
    ],
)
async def test_discovery_with_and_without_trailing_slash(
    oauth_config, issuer, clock
) -> None:
    idp = FakeIdP(issuer=issuer, now=clock)
    config = oauth_config.model_copy(update={"issuer_url": issuer})
    client = IdpClient(config, transport=idp.transport)
    await client.discover()
    (request,) = idp.requests_to("discovery")
    root = issuer.rstrip("/")
    assert request.path == urlsplit(f"{root}/.well-known/openid-configuration").path
    # The issuer is compared exactly, so the login still validates the ID token.
    code = await _login_code(idp, client)
    assert (await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")).sub


async def test_discovery_rejects_http_endpoint(oauth_config) -> None:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        i = oauth_config.issuer_url
        return httpx2.Response(
            200,
            json={
                "issuer": i,
                "authorization_endpoint": f"{i}authorize/",
                "token_endpoint": "http://idp.example.com/token/",
                "userinfo_endpoint": f"{i}userinfo/",
                "jwks_uri": f"{i}jwks/",
            },
        )

    client = IdpClient(oauth_config, transport=httpx2.MockTransport(handler))
    with pytest.raises(IdpUnavailable):
        await client.discover()


@pytest.mark.parametrize("outcome", [503, 403, "timeout", "html", "malformed"])
async def test_discovery_failure_is_unavailable(
    oauth_config, fake_idp, outcome
) -> None:
    fake_idp.discovery_outcome = outcome
    client = IdpClient(oauth_config, transport=fake_idp.transport)
    with pytest.raises(IdpUnavailable):
        await client.discover()


# -- authorization URL


async def test_authorization_url(oauth_config, fake_idp) -> None:
    client = await _client(oauth_config, fake_idp)
    config = oauth_config.model_copy(update={"extra_scopes": ["groups"]})
    client.config = config
    url = client.authorization_url("st", "no", VERIFIER, REDIRECT)
    parts = urlsplit(url)
    q = parse_qs(parts.query)
    assert url.startswith(f"{fake_idp.issuer}authorize/?")
    assert q["response_type"] == ["code"]
    assert q["client_id"] == ["netbox-mcp"]
    assert q["redirect_uri"] == [REDIRECT]
    assert q["scope"] == ["openid profile email offline_access groups"]
    assert q["state"] == ["st"]
    assert q["nonce"] == ["no"]
    assert q["code_challenge_method"] == ["S256"]
    digest = hashlib.sha256(VERIFIER.encode()).digest()
    assert q["code_challenge"] == [
        base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    ]


# -- code exchange


async def test_exchange_code_happy(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    login = await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    assert login.sub == "sub-alice"
    assert login.username == "alice"
    assert login.groups == ["netbox-users"]
    assert login.refresh_token in fake_idp.refresh_tokens
    form = fake_idp.requests_to("token")[0].form
    assert form["code_verifier"] == VERIFIER


async def test_exchange_requires_refresh_token(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    fake_idp.code_outcome = "no_refresh_token"
    with pytest.raises(IdpRejected):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


async def test_exchange_requires_access_token(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    fake_idp.code_outcome = "no_access_token"
    with pytest.raises(IdpRejected):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


async def test_id_token_wrong_nonce_rejected(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp, nonce="n-1")
    with pytest.raises(IdpRejected):
        await client.exchange_code(code, VERIFIER, REDIRECT, "other")


async def test_id_token_expired_rejected(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    fake_idp.access_ttl = -120  # expired beyond the 60 s leeway
    with pytest.raises(IdpRejected):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


async def test_id_token_within_leeway_accepted(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    fake_idp.access_ttl = -30
    login = await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    assert login.sub == "sub-alice"


async def test_id_token_wrong_audience_rejected(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    original = fake_idp._id_token

    def foreign(username, nonce):
        fake_idp.client_id = "someone-else"
        try:
            return original(username, nonce)
        finally:
            fake_idp.client_id = "netbox-mcp"

    fake_idp._id_token = foreign
    with pytest.raises(IdpRejected):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


async def test_id_token_tampered_signature_rejected(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    original = fake_idp._id_token

    def tampered(username, nonce):
        token = original(username, nonce)
        head, body, sig = token.split(".")
        flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
        return ".".join([head, body, flipped])

    fake_idp._id_token = tampered
    with pytest.raises(IdpRejected):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


async def test_userinfo_sub_mismatch_rejected(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    fake_idp.userinfo_sub = "sub-mallory"
    with pytest.raises(IdpRejected):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


async def test_exchange_requires_groups_list(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    fake_idp.userinfo_omit_groups = True
    with pytest.raises(IdpRejected):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


async def test_exchange_bad_code_rejected(oauth_config, fake_idp) -> None:
    client = await _client(oauth_config, fake_idp)
    with pytest.raises(IdpRejected):
        await client.exchange_code("nope", VERIFIER, REDIRECT, "n-1")


@pytest.mark.parametrize("outcome", [503, 429, 403, "timeout", "html", "malformed"])
async def test_exchange_unavailable(oauth_config, fake_idp, outcome) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    fake_idp.code_outcome = outcome
    with pytest.raises(IdpUnavailable):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


async def test_jwks_failure_is_unavailable(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    fake_idp.jwks_outcome = 503
    with pytest.raises(IdpUnavailable):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


async def test_jwks_cached_for_300_seconds(oauth_config, fake_idp, clock) -> None:
    client = await _client(oauth_config, fake_idp)
    for _ in range(2):
        code = await _login_code(fake_idp, client)
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    assert fake_idp.calls["jwks"] == 1
    clock.advance(301)
    code = await _login_code(fake_idp, client)
    await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    assert fake_idp.calls["jwks"] == 2


async def test_jwks_refetched_once_on_unknown_kid(oauth_config, fake_idp) -> None:
    client = await _client(oauth_config, fake_idp)
    client._jwks = {"stale": {"kid": "stale"}}
    client._jwks_fetched = fake_idp.now()
    code = await _login_code(fake_idp, client)
    login = await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    assert login.sub == "sub-alice"
    assert fake_idp.calls["jwks"] == 1


# -- refresh


async def test_refresh_rotates(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    login = await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    result = await client.refresh(login.refresh_token)
    assert result.access_token
    assert result.refresh_token
    assert result.refresh_token != login.refresh_token


async def test_refresh_returns_none_when_not_rotated(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    login = await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    fake_idp.refresh_outcome = "no_refresh_token"
    result = await client.refresh(login.refresh_token)
    assert result.access_token
    assert result.refresh_token is None


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (400, IdpRejected),
        (401, IdpRejected),
        ("no_access_token", IdpRejected),
        (403, IdpUnavailable),
        (429, IdpUnavailable),
        (503, IdpUnavailable),
        (500, IdpUnavailable),
        ("redirect", IdpUnavailable),
        ("timeout", IdpUnavailable),
        ("html", IdpUnavailable),
        ("malformed", IdpUnavailable),
    ],
)
async def test_refresh_classification(
    oauth_config, fake_idp, outcome, expected
) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    login = await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    fake_idp.refresh_outcome = outcome
    with pytest.raises(expected):
        await client.refresh(login.refresh_token)


async def test_refresh_with_revoked_token_rejected(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    login = await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    fake_idp.revoke_refresh_tokens()
    with pytest.raises(IdpRejected):
        await client.refresh(login.refresh_token)


# -- userinfo


async def _access_token(config, idp):
    client, code = await _logged_in(config, idp)
    login = await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    return client, (await client.refresh(login.refresh_token)).access_token


async def test_userinfo_returns_groups(oauth_config, fake_idp) -> None:
    client, access = await _access_token(oauth_config, fake_idp)
    assert await client.userinfo(access, "sub-alice") == ["netbox-users"]


async def test_userinfo_uses_configured_groups_claim(oauth_config, fake_idp) -> None:
    client, access = await _access_token(oauth_config, fake_idp)
    client.config = oauth_config.model_copy(update={"groups_claim": "roles"})
    with pytest.raises(IdpRejected):
        await client.userinfo(access, "sub-alice")


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (401, IdpRejected),
        (403, IdpUnavailable),
        (429, IdpUnavailable),
        (503, IdpUnavailable),
        ("redirect", IdpUnavailable),
        ("timeout", IdpUnavailable),
        ("html", IdpUnavailable),
        ("malformed", IdpUnavailable),
    ],
)
async def test_userinfo_classification(
    oauth_config, fake_idp, outcome, expected
) -> None:
    client, access = await _access_token(oauth_config, fake_idp)
    fake_idp.userinfo_outcome = outcome
    with pytest.raises(expected):
        await client.userinfo(access, "sub-alice")


async def test_userinfo_revoked_access_token_rejected(oauth_config, fake_idp) -> None:
    client, access = await _access_token(oauth_config, fake_idp)
    fake_idp.revoke_access_tokens()
    with pytest.raises(IdpRejected):
        await client.userinfo(access, "sub-alice")


async def test_userinfo_sub_mismatch_with_expected(oauth_config, fake_idp) -> None:
    client, access = await _access_token(oauth_config, fake_idp)
    with pytest.raises(IdpRejected):
        await client.userinfo(access, "sub-other")


@pytest.mark.parametrize("groups", [None, "netbox-users", [1, 2]])
async def test_userinfo_non_list_groups_rejected(
    oauth_config, fake_idp, groups
) -> None:
    client, access = await _access_token(oauth_config, fake_idp)
    if groups is None:
        fake_idp.userinfo_omit_groups = True
    else:
        fake_idp.userinfo_groups = groups
    with pytest.raises(IdpRejected):
        await client.userinfo(access, "sub-alice")


# -- redirects


async def test_no_redirect_following(oauth_config, fake_idp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    fake_idp.code_outcome = "redirect"
    with pytest.raises(IdpUnavailable):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    assert [r.path for r in fake_idp.requests_to("token")] == [
        "/application/o/test/token/"
    ]


# -- hardening (review fix round 1)


def _set_jwks(monkeypatch, doc):
    monkeypatch.setattr(FakeIdP, "jwks", property(lambda _self: doc))


def _custom_token(idp: FakeIdP, nonce: str = "n-1", **overrides):
    from joserfc import jwt as jose_jwt

    from tests.oauth.fakes import _rsa_key

    fixed_nonce = nonce

    def build(username: str, nonce: str | None) -> str:  # noqa: ARG001
        now = int(idp.now())
        claims = {
            "iss": idp.issuer,
            "aud": idp.client_id,
            "sub": idp.users[username]["sub"],
            "preferred_username": username,
            "iat": now,
            "exp": now + 3600,
            "nonce": fixed_nonce,
            **overrides,
        }
        claims = {k: v for k, v in claims.items() if v is not ...}
        return jose_jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, _rsa_key())

    idp._id_token = build


@pytest.mark.parametrize(
    ("overrides", "ok"),
    [
        ({"aud": ["netbox-mcp", "other"]}, False),
        ({"aud": ["netbox-mcp", "other"], "azp": "netbox-mcp"}, True),
        ({"aud": ["netbox-mcp", "other"], "azp": "other"}, False),
        ({"azp": "other"}, False),
        ({"azp": "netbox-mcp"}, True),
        ({"azp": None}, False),
        ({"iat": "yesterday"}, False),
        ({"iat": None}, False),
        ({"iat": ...}, True),
    ],
)
async def test_id_token_azp_and_iat(oauth_config, fake_idp, overrides, ok) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    _custom_token(fake_idp, **overrides)
    if ok:
        assert (await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")).sub
    else:
        with pytest.raises(IdpRejected):
            await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


@pytest.mark.parametrize("exp", ["soon", None, float("inf"), True])
async def test_id_token_bad_exp_rejected(oauth_config, fake_idp, exp) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    _custom_token(fake_idp, exp=exp)
    with pytest.raises(IdpRejected):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


async def test_unknown_kid_after_refetch_is_unavailable(
    oauth_config, fake_idp, monkeypatch
):
    client, code = await _logged_in(oauth_config, fake_idp)
    _set_jwks(monkeypatch, {"keys": []})
    with pytest.raises(IdpUnavailable):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


@pytest.mark.parametrize("extra", [{"alg": "RS512"}, {"use": "enc"}])
async def test_unusable_jwk_is_unavailable(
    oauth_config, fake_idp, extra, monkeypatch
) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    keys = fake_idp.jwks
    _set_jwks(monkeypatch, {"keys": [{**keys["keys"][0], **extra}]})
    with pytest.raises(IdpUnavailable):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")


async def test_jwk_with_matching_alg_and_use_accepted(
    oauth_config, fake_idp, monkeypatch
) -> None:
    client, code = await _logged_in(oauth_config, fake_idp)
    keys = fake_idp.jwks
    _set_jwks(
        monkeypatch, {"keys": [{**keys["keys"][0], "alg": "RS256", "use": "sig"}]}
    )
    assert (await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")).sub


@pytest.mark.parametrize(
    "bad",
    ["https://", "https://[bad", "not a url", "", "https://idp.example.com:bad/t/"],
)
async def test_discovery_malformed_url_is_unavailable(oauth_config, bad) -> None:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        i = oauth_config.issuer_url
        return httpx2.Response(
            200,
            json={
                "issuer": i,
                "authorization_endpoint": f"{i}authorize/",
                "token_endpoint": bad,
                "userinfo_endpoint": f"{i}userinfo/",
                "jwks_uri": f"{i}jwks/",
            },
        )

    client = IdpClient(oauth_config, transport=httpx2.MockTransport(handler))
    with pytest.raises(IdpUnavailable):
        await client.discover()


async def test_unknown_kid_refetch_rate_limited(
    oauth_config, fake_idp, clock, monkeypatch
):
    client, code = await _logged_in(oauth_config, fake_idp)
    keys = fake_idp.jwks
    _set_jwks(monkeypatch, {"keys": []})
    client._jwks = {"x": {"kid": "x"}}
    client._jwks_fetched = fake_idp.now()
    with pytest.raises(IdpUnavailable):
        await client.exchange_code(code, VERIFIER, REDIRECT, "n-1")
    assert fake_idp.calls["jwks"] == 1
    # Within 60 s: no further fetch.
    code2 = await _login_code(fake_idp, client)
    with pytest.raises(IdpUnavailable):
        await client.exchange_code(code2, VERIFIER, REDIRECT, "n-1")
    assert fake_idp.calls["jwks"] == 1
    # After the window a forced refetch is allowed again and finds the key.
    clock.advance(61)
    _set_jwks(monkeypatch, keys)
    code3 = await _login_code(fake_idp, client)
    assert (await client.exchange_code(code3, VERIFIER, REDIRECT, "n-1")).sub
    assert fake_idp.calls["jwks"] == 2
