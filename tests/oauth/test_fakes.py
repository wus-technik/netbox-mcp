import json
import time

import httpx2
import pytest
from joserfc import jwt
from joserfc.jwk import KeySet

from tests.oauth.fakes import FakeIdP
from tests.oauth.fakes import FakeNetBoxTokens

REDIRECT = "https://mcp.example.com/oauth/callback"
NB = "https://netbox.example.com"


def _client(transport) -> httpx2.Client:
    return httpx2.Client(transport=transport, follow_redirects=False)


def _login(idp: FakeIdP, http: httpx2.Client, nonce: str = "n-1") -> str:
    resp = http.get(
        f"{idp.issuer}authorize",
        params={
            "client_id": idp.client_id,
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "scope": "openid profile groups offline_access",
            "state": "st-1",
            "nonce": nonce,
        },
    )
    assert resp.status_code == 302
    location = httpx2.URL(resp.headers["location"])
    assert str(location).startswith(REDIRECT)
    assert location.params["state"] == "st-1"
    return location.params["code"]


def _token(idp: FakeIdP, http: httpx2.Client, **form) -> httpx2.Response:
    form.setdefault("client_id", idp.client_id)
    form.setdefault("client_secret", idp.client_secret)
    return http.post(f"{idp.issuer}token", data=form)


def _code_grant(idp: FakeIdP, http: httpx2.Client) -> dict:
    code = _login(idp, http)
    resp = _token(
        idp, http, grant_type="authorization_code", code=code, redirect_uri=REDIRECT
    )
    assert resp.status_code == 200
    return resp.json()


def test_fake_idp_code_and_refresh_rotation(fake_idp: FakeIdP):
    http = _client(fake_idp.transport)
    disco = http.get(f"{fake_idp.issuer}.well-known/openid-configuration").json()
    assert disco["issuer"] == "https://idp.example.com/application/o/test/"

    code = _login(fake_idp, http)
    resp = _token(
        fake_idp,
        http,
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["refresh_token"]

    jwks = http.get(disco["jwks_uri"]).json()
    claims = jwt.decode(body["id_token"], KeySet.import_key_set(jwks)).claims
    assert claims["aud"] == "netbox-mcp"
    assert claims["nonce"] == "n-1"
    assert claims["iss"] == fake_idp.issuer
    assert claims["preferred_username"] == "alice"
    assert claims["exp"] > time.time()

    info = http.get(
        f"{fake_idp.issuer}userinfo",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    ).json()
    assert info["sub"] == claims["sub"]
    assert info["groups"] == ["netbox-users"]

    # A code works once.
    reuse = _token(
        fake_idp,
        http,
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT,
    )
    assert reuse.status_code == 400

    first = body["refresh_token"]
    rotated = _token(fake_idp, http, grant_type="refresh_token", refresh_token=first)
    assert rotated.status_code == 200
    second = rotated.json()["refresh_token"]
    assert second != first
    old = _token(fake_idp, http, grant_type="refresh_token", refresh_token=first)
    assert old.status_code == 400
    assert old.json()["error"] == "invalid_grant"
    assert fake_idp.calls["token"] == 4


def test_fake_netbox_token_crud(fake_netbox_tokens: FakeNetBoxTokens):
    nb = fake_netbox_tokens
    http = _client(nb.transport)
    service = {"Authorization": f"Bearer {nb.service_token}"}

    users = http.get(
        f"{NB}/api/users/users/", params={"username": "alice"}, headers=service
    ).json()
    assert users["count"] == 1
    uid = users["results"][0]["id"]

    created = http.post(
        f"{NB}/api/users/tokens/",
        json={"user": uid, "description": "NetBox MCP abc", "write_enabled": True},
        headers=service,
    )
    assert created.status_code == 201
    made = created.json()
    bearer = {"Authorization": f"Bearer nbt_{made['key']}.{made['token']}"}

    # The issued token authenticates as its user.
    http.get(f"{NB}/api/status/", headers=bearer)
    assert nb.requests[-1].authenticated_as == "alice"

    listed = http.get(
        f"{NB}/api/users/tokens/",
        params={"user_id": uid, "description__ic": "mcp"},
        headers=service,
    ).json()
    assert [t["id"] for t in listed["results"]] == [made["id"]]
    assert "token" not in listed["results"][0]

    url = f"{NB}/api/users/tokens/{made['id']}/"
    assert http.delete(url, headers=service).status_code == 204
    assert http.delete(url, headers=service).status_code == 404
    rejected = http.get(f"{NB}/api/status/", headers=bearer)
    assert rejected.status_code in (401, 403)


@pytest.mark.parametrize(
    ("mode", "check"),
    [
        (400, lambda r: r.status_code == 400),
        (401, lambda r: r.status_code == 401),
        (403, lambda r: r.status_code == 403),
        (429, lambda r: r.status_code == 429 and "retry-after" in r.headers),
        (503, lambda r: r.status_code == 503),
        ("redirect", lambda r: r.status_code == 302),
        (
            "html",
            lambda r: r.status_code == 200 and "text/html" in r.headers["content-type"],
        ),
        ("malformed", lambda r: r.status_code == 200 and r.content.startswith(b"{")),
    ],
)
def test_idp_status_outcomes(fake_idp: FakeIdP, mode, check):
    http = _client(fake_idp.transport)
    fake_idp.userinfo_outcome = mode
    resp = http.get(f"{fake_idp.issuer}userinfo", headers={"Authorization": "Bearer x"})
    assert check(resp)
    if mode in ("html", "malformed"):
        with pytest.raises(json.JSONDecodeError):
            resp.json()


def test_idp_timeout_and_independent_outcomes(fake_idp: FakeIdP):
    http = _client(fake_idp.transport)
    body = _code_grant(fake_idp, http)
    fake_idp.refresh_outcome = "timeout"
    with pytest.raises(httpx2.TimeoutException):
        _token(
            fake_idp,
            http,
            grant_type="refresh_token",
            refresh_token=body["refresh_token"],
        )
    # A failed refresh does not consume the token; userinfo is independent.
    fake_idp.refresh_outcome = "no_refresh_token"
    ok = _token(
        fake_idp, http, grant_type="refresh_token", refresh_token=body["refresh_token"]
    ).json()
    assert "refresh_token" not in ok
    info = http.get(
        f"{fake_idp.issuer}userinfo",
        headers={"Authorization": f"Bearer {ok['access_token']}"},
    )
    assert info.status_code == 200
    assert fake_idp.calls["userinfo"] == 1


def test_idp_users_and_userinfo_variants(fake_idp: FakeIdP):
    http = _client(fake_idp.transport)
    fake_idp.login_user = "bob"
    body = _code_grant(fake_idp, http)
    auth = {"Authorization": f"Bearer {body['access_token']}"}
    url = f"{fake_idp.issuer}userinfo"
    assert http.get(url, headers=auth).json()["groups"] == []
    fake_idp.userinfo_omit_groups = True
    assert "groups" not in http.get(url, headers=auth).json()
    fake_idp.userinfo_sub = "other"
    assert http.get(url, headers=auth).json()["sub"] == "other"
    assert http.get(url, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_netbox_failures_and_recording(fake_netbox_tokens: FakeNetBoxTokens):
    nb = fake_netbox_tokens
    http = _client(nb.transport)
    service = {
        "Authorization": f"Bearer {nb.service_token}",
        "X-NetBox-Branch": "abc12345",
    }
    url = f"{NB}/api/users/tokens/"

    nb.fail("tokens.create", "timeout", times=1)
    with pytest.raises(httpx2.TimeoutException):
        http.post(url, json={"user": 1, "description": "d"}, headers=service)
    assert nb.tokens == {}

    nb.fail("tokens.create", "commit_then_timeout", times=1)
    with pytest.raises(httpx2.TimeoutException):
        http.post(url, json={"user": 1, "description": "d"}, headers=service)
    assert len(nb.tokens) == 1

    nb.fail("tokens.list", 503, times=1)
    assert http.get(url, headers=service).status_code == 503
    nb.fail("tokens.list", "html", times=1)
    assert "text/html" in http.get(url, headers=service).headers["content-type"]
    nb.fail("tokens.list", "malformed", times=1)
    with pytest.raises(json.JSONDecodeError):
        http.get(url, headers=service).json()
    assert http.get(url, headers=service).json()["count"] == 1

    last = nb.requests[-1]
    assert last.method == "GET"
    assert last.path == "/api/users/tokens/"
    assert last.headers["X-NetBox-Branch"] == "abc12345"
    assert last.authenticated_as == "service"
    assert nb.sent("POST")[0].json == {"user": 1, "description": "d"}


def test_netbox_pagination_and_auth(fake_netbox_tokens: FakeNetBoxTokens):
    nb = fake_netbox_tokens
    nb.page_size = 2
    http = _client(nb.transport)
    service = {"Authorization": f"Bearer {nb.service_token}"}
    for i in range(3):
        nb.add_token("alice", description=f"t{i}")
    page = http.get(f"{NB}/api/users/tokens/", headers=service).json()
    assert page["count"] == 3
    assert len(page["results"]) == 2
    nxt = http.get(page["next"], headers=service).json()
    assert len(nxt["results"]) == 1
    assert nxt["next"] is None

    assert http.get(f"{NB}/api/users/users/").status_code in (401, 403)
    carol = http.get(
        f"{NB}/api/users/users/", params={"username": "carol"}, headers=service
    ).json()
    assert carol["count"] == 0


def test_netbox_expired_and_disabled_tokens_rejected(
    fake_netbox_tokens: FakeNetBoxTokens,
):
    nb = fake_netbox_tokens
    http = _client(nb.transport)
    record = nb.add_token("alice", expires="2999-01-01T00:00:00Z")
    auth = {"Authorization": f"Bearer {nb.bearer_for(record)}"}
    assert http.get(f"{NB}/api/status/", headers=auth).status_code == 200
    nb.expire_token(record["id"])
    assert http.get(f"{NB}/api/status/", headers=auth).status_code == 403
    nb.tokens[record["id"]]["expires"] = None
    nb.disable_token(record["id"])
    assert http.get(f"{NB}/api/status/", headers=auth).status_code == 403
