"""Registration, authorization, IdP callback and consent (spec 5.2, 5.3)."""

import asyncio
import logging
import re
from collections.abc import AsyncIterator
from urllib.parse import parse_qs
from urllib.parse import urlsplit

import httpx2
import pytest
from starlette.applications import Starlette

from netbox_mcp.models import NetBoxConfig
from netbox_mcp.oauth import routes
from netbox_mcp.oauth.broker import NetBoxBroker
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.idp import IdpClient
from netbox_mcp.oauth.idp import pkce_challenge
from netbox_mcp.oauth.routes import oauth_routes
from netbox_mcp.oauth.sessions import SessionManager
from netbox_mcp.oauth.state import Client
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import _decrypt
from netbox_mcp.oauth.tokens import AccessTokens
from netbox_mcp.oauth.tokens import hash_secret
from tests.oauth.fakes import FakeIdP
from tests.oauth.fakes import FakeNetBoxTokens

PUBLIC = "https://mcp.example.com/mcp"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
LOOPBACK = "http://127.0.0.1:33418/callback"
VERIFIER = "verifier-" + "x" * 50
CHALLENGE = pkce_challenge(VERIFIER)
COOKIE = routes.FLOW_COOKIE


@pytest.fixture
async def manager(
    oauth_config: OAuthConfig,
    store: StateStore,
    fake_idp: FakeIdP,
    fake_netbox_tokens: FakeNetBoxTokens,
    clock,
) -> SessionManager:
    fake_idp.now = clock
    fake_netbox_tokens.now = clock
    config = NetBoxConfig(netbox_url=fake_netbox_tokens.base_url, token="nbt_o.o")
    broker = NetBoxBroker(
        config, "nbt_broker.secret", transport=fake_netbox_tokens.transport
    )
    idp = IdpClient(oauth_config, transport=fake_idp.transport)
    await idp.discover()
    return SessionManager(oauth_config, store, broker, idp, AccessTokens(oauth_config))


@pytest.fixture
async def http(
    oauth_config: OAuthConfig, manager: SessionManager
) -> AsyncIterator[httpx2.AsyncClient]:
    app = Starlette(routes=oauth_routes(oauth_config, manager))
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="https://mcp.example.com",
    ) as client:
        yield client


# ----------------------------------------------------------------- helpers


def qs(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


async def register(http, uris=(REDIRECT,), path="/mcp/oauth/register", **extra):
    resp = await http.post(path, json={"redirect_uris": list(uris), **extra})
    assert resp.status_code == 201, resp.text
    return resp.json()["client_id"]


def auth_params(client_id: str, **over) -> dict[str, str]:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "state": "client-state-1",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "scope": "netbox whatever",
    }
    params.update(over)
    return {k: v for k, v in params.items() if v is not None}


async def authorize(http, client_id, path="/mcp/oauth/authorize", **over):
    return await http.get(path, params=auth_params(client_id, **over))


async def idp_round_trip(fake_idp: FakeIdP, idp_url: str) -> str:
    async with httpx2.AsyncClient(
        transport=fake_idp.transport, follow_redirects=False
    ) as idp_http:
        resp = await idp_http.get(idp_url)
    assert resp.status_code == 302
    return resp.headers["location"]


async def callback_url(http, fake_idp, client_id, **over) -> str:
    resp = await authorize(http, client_id, **over)
    assert resp.status_code == 302, resp.text
    return await idp_round_trip(fake_idp, resp.headers["location"])


def csrf_of(html: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match
    return match.group(1)


async def consent_form(http, consent_location: str):
    page = await http.get(consent_location)
    assert page.status_code == 200, page.text
    return page, csrf_of(page.text)


async def approve(http, consent_location: str, decision: str = "approve"):
    _page, csrf = await consent_form(http, consent_location)
    return await http.post(
        "/mcp/oauth/consent", data={"csrf": csrf, "decision": decision}
    )


async def login_with_consent(http, fake_idp, client_id):
    resp = await http.get(await callback_url(http, fake_idp, client_id))
    assert resp.status_code == 303, resp.text
    return await approve(http, resp.headers["location"])


def flow_cookie_header(http, store) -> dict[str, str]:
    """The current flow cookie as an explicit header; empties the jar."""
    (flow_id,) = [k for k, f in store.snapshot().flows.items() if not f.claimed]
    http.cookies.clear()
    return {"cookie": f"{COOKIE}={flow_id}"}


def created_tokens(fake: FakeNetBoxTokens) -> int:
    return len(fake.sent("POST", "tokens.create"))


# ------------------------------------------------------------ registration


async def test_dcr_echoes_none_for_client_secret_post(http, store) -> None:
    resp = await http.post(
        "/mcp/oauth/register",
        json={
            "redirect_uris": [REDIRECT],
            "client_name": "Example",
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["client_credentials"],
            "response_types": ["token"],
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["token_endpoint_auth_method"] == "none"
    assert body["grant_types"] == ["authorization_code", "refresh_token"]
    assert body["response_types"] == ["code"]
    assert body["redirect_uris"] == [REDIRECT]
    assert "client_secret" not in body
    assert resp.headers["cache-control"] == "no-store"
    assert body["client_id"] in store.snapshot().clients


@pytest.mark.parametrize("param", ["iss", "code"])
async def test_dcr_rejects_reserved_params(http, store, param) -> None:
    resp = await http.post(
        "/mcp/oauth/register",
        json={"redirect_uris": [f"http://localhost:8080/cb?{param}=x"]},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"
    assert store.snapshot().clients == {}


@pytest.mark.parametrize(
    "body",
    [
        {"redirect_uris": []},
        {"redirect_uris": "https://claude.ai/api/mcp/auth_callback"},
        {"redirect_uris": [1]},
        {"redirect_uris": ["https://evil.example/cb"]},
        {"redirect_uris": [f"http://localhost:{8000 + i}/cb" for i in range(21)]},
    ],
)
async def test_dcr_invalid_redirect_uris(http, store, body) -> None:
    resp = await http.post("/mcp/oauth/register", json=body)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"
    assert store.snapshot().clients == {}


async def test_dcr_twenty_redirect_uris_accepted(http) -> None:
    await register(http, uris=[f"http://localhost:{8000 + i}/cb" for i in range(20)])


@pytest.mark.parametrize("content", [b"{not json", b"[]", b"\xff\xfe"])
async def test_dcr_malformed_json(http, content) -> None:
    resp = await http.post(
        "/mcp/oauth/register",
        content=content,
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


async def test_dcr_client_name_sanitised(http, store) -> None:
    client_id = await register(http, client_name="Evil\x00\n\tName   " + "x" * 500)
    name = store.snapshot().clients[client_id].client_name
    assert name.startswith("Evil Name x")
    assert len(name) == routes.CLIENT_NAME_MAX
    assert name.isprintable()


async def test_dcr_rate_limit_per_ip(http) -> None:
    for _ in range(10):
        await register(http)
    resp = await http.post("/mcp/oauth/register", json={"redirect_uris": [REDIRECT]})
    assert resp.status_code == 429
    assert resp.json()["error"] == "invalid_client_metadata"


async def test_dcr_rate_limit_window_expires(http, clock) -> None:
    for _ in range(10):
        await register(http)
    clock.advance(61)
    await register(http)


async def test_dcr_registration_cap(http, store, clock) -> None:
    async with store.mutate() as state:
        for i in range(routes.MAX_CLIENTS):
            state.clients[f"c{i}"] = Client(
                client_id=f"c{i}",
                client_name="x",
                redirect_uris=[REDIRECT],
                created_at=clock(),
                last_used_at=clock(),
            )
    resp = await http.post("/mcp/oauth/register", json={"redirect_uris": [REDIRECT]})
    assert resp.status_code == 429
    assert resp.json()["error"] == "invalid_client_metadata"
    assert len(store.snapshot().clients) == routes.MAX_CLIENTS


async def test_dcr_store_failure_is_503(http, store, monkeypatch) -> None:
    def boom(_data: bytes) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(store, "_write_file", boom)
    resp = await http.post("/mcp/oauth/register", json={"redirect_uris": [REDIRECT]})
    assert resp.status_code == 503
    assert store.snapshot().clients == {}


async def test_root_aliases_share_handlers(oauth_config, manager, http) -> None:
    by_path = {r.path: r.endpoint for r in oauth_routes(oauth_config, manager)}
    assert by_path["/register"] is by_path["/mcp/oauth/register"]
    assert by_path["/authorize"] is by_path["/mcp/oauth/authorize"]
    client_id = await register(http, path="/register")
    resp = await authorize(http, client_id, path="/authorize")
    assert resp.status_code == 302


# --------------------------------------------------------------- authorize


@pytest.mark.parametrize(
    "over",
    [
        {"state": None},
        {"state": ""},
        {"code_challenge_method": "plain"},
        {"code_challenge_method": None},
        {"code_challenge": None},
        {"code_challenge": "short"},
        {"response_type": "token"},
    ],
)
async def test_authorize_requires_state_and_s256(http, store, over) -> None:
    client_id = await register(http)
    resp = await authorize(http, client_id, **over)
    assert resp.status_code == 400
    assert "location" not in resp.headers
    assert resp.headers["content-type"].startswith("text/html")
    assert store.snapshot().flows == {}


@pytest.mark.parametrize(
    ("resource", "ok"),
    [
        (None, True),
        (PUBLIC, True),
        (PUBLIC + "/", True),
        (PUBLIC + "//", False),
        ("https://other.example/mcp", False),
    ],
)
async def test_authorize_resource_optional_trailing_slash(http, resource, ok) -> None:
    client_id = await register(http)
    resp = await authorize(http, client_id, resource=resource)
    if ok:
        assert resp.status_code == 302
    else:
        assert resp.status_code == 400
        assert "invalid_target" in resp.text
        assert "location" not in resp.headers


async def test_authorize_redirect_must_match_client_registration(http) -> None:
    client_id = await register(http)
    # Allowed globally but not registered by this client.
    other = "https://claude.com/api/mcp/auth_callback"
    resp = await authorize(http, client_id, redirect_uri=other)
    assert resp.status_code == 400
    assert "location" not in resp.headers
    unknown = await authorize(http, "no-such-client")
    assert unknown.status_code == 400


async def test_authorize_loopback_port_may_differ(http) -> None:
    client_id = await register(http, uris=[LOOPBACK])
    other_port = "http://127.0.0.1:50000/callback"
    resp = await authorize(http, client_id, redirect_uri=other_port)
    assert resp.status_code == 302


async def test_authorize_redirects_to_idp_with_pkce(http, store, fake_idp) -> None:
    client_id = await register(http)
    resp = await authorize(http, client_id)
    location = resp.headers["location"]
    assert location.startswith(f"{fake_idp.issuer}authorize/?")
    params = qs(location)
    (flow,) = store.snapshot().flows.values()
    assert params["redirect_uri"] == f"{PUBLIC}/oauth/callback"
    assert params["state"] == flow.idp_state
    assert params["nonce"] == flow.idp_nonce
    assert params["code_challenge"] == pkce_challenge(flow.idp_verifier)
    assert params["code_challenge_method"] == "S256"
    assert flow.state == "client-state-1"
    assert flow.code_challenge == CHALLENGE
    assert flow.created_at > 0


async def test_flow_cookie_attributes(http, store) -> None:
    client_id = await register(http)
    resp = await authorize(http, client_id)
    cookie = resp.headers["set-cookie"]
    (flow_id,) = store.snapshot().flows
    parts = [p.strip() for p in cookie.split(";")]
    assert parts[0] == f"{COOKIE}={flow_id}"
    assert "HttpOnly" in parts
    assert "Secure" in parts
    assert "SameSite=Lax" in parts
    assert "Path=/mcp/oauth" in parts
    assert "Max-Age=600" in parts
    assert "SameSite=Strict" not in cookie


async def test_authorize_store_failure_is_503(http, store, monkeypatch) -> None:
    client_id = await register(http)

    def boom(_data: bytes) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(store, "_write_file", boom)
    resp = await authorize(http, client_id)
    assert resp.status_code == 503
    assert "location" not in resp.headers
    assert "set-cookie" not in resp.headers


# ------------------------------------------------------------ full flow


async def test_full_login_success_redirect_has_code_state_iss(
    http, store, fake_idp, fake_netbox_tokens
) -> None:
    client_id = await register(http)
    resp = await login_with_consent(http, fake_idp, client_id)
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert location.startswith(REDIRECT + "?")
    params = qs(location)
    assert params["state"] == "client-state-1"
    assert params["iss"] == PUBLIC
    (session,) = store.snapshot().sessions.values()
    assert session.code_hash == hash_secret(params["code"])
    assert session.client_id == client_id
    assert session.netbox_user_id == fake_netbox_tokens.user_id("alice")
    assert session.idp_refresh_token
    assert created_tokens(fake_netbox_tokens) == 1
    assert store.snapshot().flows == {}
    assert f"{COOKIE}=;" in resp.headers["set-cookie"]


async def test_redirect_uri_with_query_keeps_it(http, fake_idp) -> None:
    uri = "http://localhost:8080/cb?x=1"
    client_id = await register(http, uris=[uri])
    resp = await http.get(
        await callback_url(http, fake_idp, client_id, redirect_uri=uri)
    )
    final = await approve(http, resp.headers["location"])
    location = final.headers["location"]
    assert location.startswith("http://localhost:8080/cb?x=1&code=")
    assert qs(location)["iss"] == PUBLIC


async def test_flow_pages_security_headers(http, fake_idp) -> None:
    client_id = await register(http)
    responses = [await authorize(http, client_id, state=None)]  # error page
    auth = await authorize(http, client_id)
    responses.append(auth)
    cb = await http.get(await idp_round_trip(fake_idp, auth.headers["location"]))
    responses.append(cb)
    page, csrf = await consent_form(http, cb.headers["location"])
    responses.append(page)
    responses.append(
        await http.post(
            "/mcp/oauth/consent", data={"csrf": csrf, "decision": "approve"}
        )
    )
    responses.append(await http.get("/mcp/oauth/callback?code=x&state=y"))
    for resp in responses:
        assert resp.headers["cache-control"] == "no-store"
        assert resp.headers["referrer-policy"] == "no-referrer"
        assert resp.headers["x-frame-options"] == "DENY"
        csp = resp.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in csp
        assert "script-src" not in csp or "'none'" in csp
        assert "unsafe-inline" not in csp
    assert "<script" not in page.text


# ------------------------------------------------------------- denials


async def _assert_denied(resp, store, fake_netbox_tokens) -> None:
    assert resp.status_code == 302
    params = qs(resp.headers["location"])
    assert resp.headers["location"].startswith(REDIRECT + "?")
    assert params["error"] == "access_denied"
    assert params["state"] == "client-state-1"
    assert params["iss"] == PUBLIC
    assert "code" not in params
    snap = store.snapshot()
    assert snap.sessions == {}
    assert snap.flows == {}
    assert created_tokens(fake_netbox_tokens) == 0


async def test_bob_without_group_access_denied_redirect(
    http, store, fake_idp, fake_netbox_tokens
) -> None:
    fake_idp.login_user = "bob"
    client_id = await register(http)
    resp = await http.get(await callback_url(http, fake_idp, client_id))
    await _assert_denied(resp, store, fake_netbox_tokens)
    assert store.snapshot().links == {}


async def test_carol_without_account_access_denied_redirect(
    http, store, fake_idp, fake_netbox_tokens
) -> None:
    fake_idp.login_user = "carol"
    client_id = await register(http)
    resp = await http.get(await callback_url(http, fake_idp, client_id))
    await _assert_denied(resp, store, fake_netbox_tokens)
    assert store.snapshot().links == {}


async def test_denied_user_refresh_token_never_persisted(
    http, store, fake_idp, monkeypatch
) -> None:
    fake_idp.login_user = "bob"
    client_id = await register(http)
    url = await callback_url(http, fake_idp, client_id)
    writes = []
    original = store._write_file

    def spy(data: bytes) -> None:
        writes.append(_decrypt(data, store._key))
        original(data)

    monkeypatch.setattr(store, "_write_file", spy)
    resp = await http.get(url)
    assert resp.status_code == 302
    assert writes
    issued = set(fake_idp.refresh_tokens)
    assert issued
    for state in writes:
        dumped = state.model_dump_json()
        assert not any(token in dumped for token in issued)


async def test_idp_error_maps_to_access_denied(
    http, store, fake_idp, fake_netbox_tokens
) -> None:
    client_id = await register(http)
    auth = await authorize(http, client_id)
    idp_state = qs(auth.headers["location"])["state"]
    resp = await http.get(
        "/mcp/oauth/callback",
        params={"error": "access_denied", "state": idp_state},
    )
    await _assert_denied(resp, store, fake_netbox_tokens)
    assert fake_idp.calls["token"] == 0


async def test_idp_rejects_code_maps_to_access_denied(
    http, store, fake_idp, fake_netbox_tokens
) -> None:
    fake_idp.code_outcome = "no_refresh_token"
    client_id = await register(http)
    resp = await http.get(await callback_url(http, fake_idp, client_id))
    await _assert_denied(resp, store, fake_netbox_tokens)


async def test_callback_state_mismatch_rejected(http, fake_idp) -> None:
    client_id = await register(http)
    url = await callback_url(http, fake_idp, client_id)
    code = qs(url)["code"]
    resp = await http.get(
        "/mcp/oauth/callback", params={"code": code, "state": "forged"}
    )
    assert resp.status_code == 400
    assert "location" not in resp.headers
    assert fake_idp.calls["token"] == 0
    # The genuine callback still works afterwards.
    assert (await http.get(url)).status_code == 303


async def test_callback_without_cookie_rejected(http, fake_idp) -> None:
    client_id = await register(http)
    url = await callback_url(http, fake_idp, client_id)
    http.cookies.clear()
    resp = await http.get(url)
    assert resp.status_code == 400
    assert fake_idp.calls["token"] == 0


async def test_expired_flow_rejected(http, store, fake_idp, clock) -> None:
    client_id = await register(http)
    url = await callback_url(http, fake_idp, client_id)
    clock.advance(routes.FLOW_TTL + 1)
    resp = await http.get(url)
    assert resp.status_code == 400
    assert fake_idp.calls["token"] == 0
    assert store.snapshot().sessions == {}


async def test_expired_flow_rejected_at_consent(http, store, fake_idp, clock) -> None:
    client_id = await register(http)
    cb = await http.get(await callback_url(http, fake_idp, client_id))
    _page, csrf = await consent_form(http, cb.headers["location"])
    clock.advance(routes.FLOW_TTL + 1)
    resp = await http.post(
        "/mcp/oauth/consent", data={"csrf": csrf, "decision": "approve"}
    )
    assert resp.status_code == 400
    assert store.snapshot().sessions == {}


@pytest.mark.parametrize("outage", ["idp_token", "idp_userinfo", "netbox"])
async def test_login_outage_error_page_creates_nothing(
    http, store, fake_idp, fake_netbox_tokens, outage
) -> None:
    client_id = await register(http)
    url = await callback_url(http, fake_idp, client_id)
    if outage == "idp_token":
        fake_idp.fail_next("token", 503)
    elif outage == "idp_userinfo":
        fake_idp.fail_next("userinfo", "timeout")
    else:
        fake_netbox_tokens.fail("users.list", 503, times=1)
    resp = await http.get(url)
    assert resp.status_code == 503
    assert resp.headers["content-type"].startswith("text/html")
    assert "location" not in resp.headers
    snap = store.snapshot()
    assert snap.sessions == {}
    assert snap.links == {}
    assert snap.flows == {}
    assert created_tokens(fake_netbox_tokens) == 0
    # A fresh authorization is not blocked by the failed one.
    final = await login_with_consent(http, fake_idp, client_id)
    assert final.status_code == 303
    assert "code" in qs(final.headers["location"])
    assert len(store.snapshot().sessions) == 1


async def test_netbox_token_failure_error_page(
    http, store, fake_idp, fake_netbox_tokens
) -> None:
    client_id = await register(http)
    cb = await http.get(await callback_url(http, fake_idp, client_id))
    fake_netbox_tokens.fail("tokens.create", 400, times=1)
    resp = await approve(http, cb.headers["location"])
    assert resp.status_code == 502
    assert "location" not in resp.headers
    snap = store.snapshot()
    assert snap.sessions == {}
    assert snap.flows == {}


# -------------------------------------------------------------- consent


async def test_consent_shown_once_per_user_and_client(http, store, fake_idp) -> None:
    client_id = await register(http, client_name="My Client")
    first = await http.get(await callback_url(http, fake_idp, client_id))
    assert first.status_code == 303
    assert first.headers["location"] == f"{PUBLIC}/oauth/consent"
    page, _ = await consent_form(http, first.headers["location"])
    assert "My Client" in page.text
    assert "unverified" in page.text.lower()
    assert "claude.ai" in page.text
    done = await approve(http, first.headers["location"])
    assert done.status_code == 303
    assert len(store.snapshot().grants) == 1

    # Second authorization of the same user and client: no consent page.
    second = await http.get(
        await callback_url(http, fake_idp, client_id, state="client-state-2")
    )
    assert second.status_code == 302
    params = qs(second.headers["location"])
    assert params["state"] == "client-state-2"
    assert params["iss"] == PUBLIC
    assert "code" in params
    assert len(store.snapshot().sessions) == 2

    # Another client of the same user needs its own consent.
    other = await register(http, uris=[LOOPBACK])
    third = await http.get(
        await callback_url(http, fake_idp, other, redirect_uri=LOOPBACK)
    )
    assert third.status_code == 303


async def test_consent_csrf_mismatch_rejected(http, store, fake_idp) -> None:
    client_id = await register(http)
    cb = await http.get(await callback_url(http, fake_idp, client_id))
    _page, csrf = await consent_form(http, cb.headers["location"])
    for bad in ("", "0" * len(csrf), csrf[:-1]):
        resp = await http.post(
            "/mcp/oauth/consent", data={"csrf": bad, "decision": "approve"}
        )
        assert resp.status_code == 403
    no_field = await http.post("/mcp/oauth/consent", data={"decision": "approve"})
    assert no_field.status_code == 403
    assert store.snapshot().sessions == {}
    assert store.snapshot().grants == {}
    # The genuine form still works.
    ok = await http.post(
        "/mcp/oauth/consent", data={"csrf": csrf, "decision": "approve"}
    )
    assert ok.status_code == 303


async def test_consent_csrf_is_hmac_of_flow_id(
    http, store, fake_idp, oauth_config
) -> None:
    client_id = await register(http)
    cb = await http.get(await callback_url(http, fake_idp, client_id))
    _page, csrf = await consent_form(http, cb.headers["location"])
    (flow_id,) = store.snapshot().flows
    assert csrf == routes.consent_csrf(oauth_config, flow_id)


async def test_consent_requires_flow_cookie(http, store, fake_idp) -> None:
    client_id = await register(http)
    cb = await http.get(await callback_url(http, fake_idp, client_id))
    _page, csrf = await consent_form(http, cb.headers["location"])
    http.cookies.clear()
    resp = await http.post(
        "/mcp/oauth/consent", data={"csrf": csrf, "decision": "approve"}
    )
    assert resp.status_code in (400, 403)
    assert store.snapshot().sessions == {}


async def test_consent_deny_redirects_access_denied(
    http, store, fake_idp, fake_netbox_tokens
) -> None:
    client_id = await register(http)
    cb = await http.get(await callback_url(http, fake_idp, client_id))
    resp = await approve(http, cb.headers["location"], decision="deny")
    assert resp.status_code == 303
    params = qs(resp.headers["location"])
    assert params["error"] == "access_denied"
    assert params["state"] == "client-state-1"
    assert params["iss"] == PUBLIC
    snap = store.snapshot()
    assert snap.sessions == {}
    assert snap.grants == {}
    assert snap.flows == {}
    assert created_tokens(fake_netbox_tokens) == 0


async def test_consent_page_escapes_client_name(http, fake_idp) -> None:
    client_id = await register(http, client_name='<img src=x onerror="alert(1)">')
    cb = await http.get(await callback_url(http, fake_idp, client_id))
    page, _ = await consent_form(http, cb.headers["location"])
    assert "<img" not in page.text
    assert "&lt;img" in page.text


async def test_callback_replay_after_consent_handoff_rejected(http, fake_idp) -> None:
    client_id = await register(http)
    url = await callback_url(http, fake_idp, client_id)
    assert (await http.get(url)).status_code == 303
    again = await http.get(url)
    assert again.status_code == 400
    assert fake_idp.calls["token"] == 1


# ----------------------------------------------------------- concurrency


def slow(monkeypatch, obj, name: str) -> None:
    """Make ``obj.name`` yield to the loop first, so concurrent requests overlap."""
    original = getattr(obj, name)

    async def wrapper(*args, **kwargs):
        await asyncio.sleep(0.05)
        return await original(*args, **kwargs)

    monkeypatch.setattr(obj, name, wrapper)


async def test_concurrent_callbacks_create_one_session(
    http, store, fake_idp, fake_netbox_tokens, manager, monkeypatch
) -> None:
    client_id = await register(http)
    await login_with_consent(http, fake_idp, client_id)  # grant exists now
    slow(monkeypatch, manager.idp, "exchange_code")
    before = created_tokens(fake_netbox_tokens)
    url = await callback_url(http, fake_idp, client_id)
    # Send the cookie explicitly: the winner's response clears it in the jar.
    headers = flow_cookie_header(http, store)
    a, b = await asyncio.gather(
        http.get(url, headers=headers), http.get(url, headers=headers)
    )
    winner, loser = sorted([a, b], key=lambda r: r.status_code)
    assert winner.status_code == 302
    assert "code" in qs(winner.headers["location"])
    assert loser.status_code == 400
    assert "already been completed" in loser.text
    assert len(store.snapshot().sessions) == 2
    assert created_tokens(fake_netbox_tokens) == before + 1
    assert fake_idp.calls["token"] == 2  # one per login, none for the loser


async def test_concurrent_consents_create_one_session(
    http, store, fake_idp, fake_netbox_tokens, manager, monkeypatch
) -> None:
    client_id = await register(http)
    cb = await http.get(await callback_url(http, fake_idp, client_id))
    _page, csrf = await consent_form(http, cb.headers["location"])
    slow(monkeypatch, manager, "create_session")
    form = {"csrf": csrf, "decision": "approve"}
    headers = flow_cookie_header(http, store)
    a, b = await asyncio.gather(
        http.post("/mcp/oauth/consent", data=form, headers=headers),
        http.post("/mcp/oauth/consent", data=form, headers=headers),
    )
    winner, loser = sorted([a, b], key=lambda r: r.status_code)
    assert winner.status_code == 303
    assert "code" in qs(winner.headers["location"])
    assert loser.status_code == 400
    assert "already been completed" in loser.text
    assert len(store.snapshot().sessions) == 1
    assert created_tokens(fake_netbox_tokens) == 1


# --------------------------------------------------------------- logging


async def test_no_secrets_in_logs(http, store, fake_idp, caplog) -> None:
    caplog.set_level(logging.DEBUG, logger="netbox_mcp")
    client_id = await register(http, client_name="Logged Client")
    url = await callback_url(http, fake_idp, client_id)
    cb = await http.get(url)
    (flow_id,) = store.snapshot().flows
    final = await approve(http, cb.headers["location"])
    code = qs(final.headers["location"])["code"]
    text = "\n".join(
        r.getMessage() for r in caplog.records if r.name.startswith("netbox_mcp")
    )
    secrets = [
        code,
        flow_id,
        qs(url)["code"],
        qs(url)["state"],
        *fake_idp.refresh_tokens,
    ]
    assert text
    for secret in secrets:
        assert secret not in text
    assert "?" not in text
