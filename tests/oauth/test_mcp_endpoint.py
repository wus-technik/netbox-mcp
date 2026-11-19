"""MCP endpoint behind the outer app (spec 4, 6.3, 7.1-7.5)."""

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncGenerator
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.auth import AccessToken
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS
from mcp_types.version import KNOWN_PROTOCOL_VERSIONS
from mcp_types.version import LATEST_HANDSHAKE_VERSION
from mcp_types.version import SUPPORTED_PROTOCOL_VERSIONS

from netbox_mcp import netbox_client
from netbox_mcp.auth import rate_limit_client_id
from netbox_mcp.models import NetBoxConfig
from netbox_mcp.netbox_client import NetBoxAPIError
from netbox_mcp.netbox_client import NetBoxClient
from netbox_mcp.oauth.app import HTTP_CLIENT_LOGGERS
from netbox_mcp.oauth.app import build_oauth_app
from netbox_mcp.oauth.app import configure_oauth_logging
from netbox_mcp.oauth.app import oauth_launch_guard
from netbox_mcp.oauth.metadata import challenge_header
from netbox_mcp.oauth.sessions import SessionManager
from netbox_mcp.oauth.state import Session
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import StoreError
from netbox_mcp.oauth.tokens import AccessTokens
from netbox_mcp.oauth.verifier import OAuthTokenVerifier
from netbox_mcp.tools import register_tools
from tests.oauth.fakes import FakeIdP
from tests.oauth.fakes import FakeNetBoxTokens
from tests.oauth.test_token_endpoint import tokens_for

BASE = "https://mcp.example.com"


@contextlib.asynccontextmanager
async def idle_background(_manager: SessionManager) -> AsyncGenerator[None]:
    """No background jobs: these tests inspect the cleanup queue themselves."""
    yield


ACCEPT = "application/json, text/event-stream"
DAY = 86400


@dataclass
class Env:
    http: httpx2.AsyncClient
    manager: SessionManager
    config: Any
    idp: FakeIdP
    netbox: FakeNetBoxTokens
    tool_requests: list[httpx2.Request]
    app: Any

    def session(self) -> Session:
        (session,) = self.manager.store.snapshot().sessions.values()
        return session


class ToolTransport:
    """Tool-side NetBox transport: records requests, optional async hook."""

    def __init__(self, fake: FakeNetBoxTokens) -> None:
        self.fake = fake
        self.requests: list[httpx2.Request] = []
        self.before = None  # async callable(request) run before serving
        self.transport = httpx2.MockTransport(self.handle)

    async def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if self.before is not None:
            await self.before(request)
        return self.fake.handle(request)


@contextlib.asynccontextmanager
async def running(app) -> AsyncGenerator[None]:
    """Run the app's lifespan in its own task.

    The FastMCP lifespan holds an anyio task group, which must be left in the
    task that entered it; async fixtures may tear down in another task.
    """
    started = asyncio.Event()
    stop = asyncio.Event()

    async def runner() -> None:
        async with app.router.lifespan_context(app):
            started.set()
            await stop.wait()

    task = asyncio.create_task(runner())
    waiter = asyncio.create_task(started.wait())
    await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        waiter.cancel()
        task.result()  # raises the startup error
    try:
        yield
    finally:
        stop.set()
        await task


@pytest.fixture
async def env(
    oauth_config, fake_idp, fake_netbox_tokens, clock
) -> AsyncIterator[tuple[Env, ToolTransport]]:
    fake_idp.now = clock
    fake_netbox_tokens.now = clock
    StateStore.create(oauth_config.state_path, oauth_config.state_key)
    nb_config = NetBoxConfig(netbox_url=fake_netbox_tokens.base_url, token=None)
    tools = ToolTransport(fake_netbox_tokens)
    mcp = FastMCP(
        "test", auth=OAuthTokenVerifier(oauth_config), lifespan=oauth_launch_guard
    )
    register_tools(mcp, nb_config, tools.transport)
    app = build_oauth_app(
        mcp,
        oauth_config,
        netbox_config=nb_config,
        idp_transport=fake_idp.transport,
        netbox_transport=fake_netbox_tokens.transport,
        background=idle_background,
    )
    async with (
        running(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url=BASE
        ) as http,
    ):
        yield (
            Env(
                http,
                app.state.oauth_manager,
                oauth_config,
                fake_idp,
                fake_netbox_tokens,
                tools.requests,
                app,
            ),
            tools,
        )


# ----------------------------------------------------------------- helpers


def rpc(method: str, params: dict | None = None, rid: int | None = 1) -> dict:
    body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    if rid is not None:
        body["id"] = rid
    return body


INIT = rpc(
    "initialize",
    {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    },
)


def sites_call(rid: int = 1) -> dict:
    return rpc(
        "tools/call",
        {
            "name": "netbox_get_objects",
            "arguments": {"object_type": "dcim.site", "fields": ["id"]},
        },
        rid,
    )


async def post(
    http,
    body: Any,
    token: str | None = None,
    *,
    path: str = "/mcp",
    version: str | None = None,
    scheme: str = "Bearer",
    headers: dict | None = None,
):
    h = {"Accept": ACCEPT, "Content-Type": "application/json"}
    if token is not None:
        h["Authorization"] = f"{scheme} {token}"
    if version is not None:
        h["MCP-Protocol-Version"] = version
    h.update(headers or {})
    return await http.post(BASE + path, content=json.dumps(body), headers=h)


async def login(env: Env) -> str:
    _client, body = await tokens_for(env.http, env.idp)
    return body["access_token"]


def dcim_requests(env: Env) -> list[httpx2.Request]:
    return [r for r in env.tool_requests if r.url.path == "/api/dcim/sites/"]


def is_tool_error(resp) -> bool:
    assert resp.status_code == 200, resp.text
    return resp.json()["result"].get("isError", False)


# ------------------------------------------------------------ 401 challenge


async def test_unauthenticated_initialize_with_2026_07_28_is_401_challenge(env):
    e, _ = env
    resp = await post(e.http, INIT, version="2026-07-28")
    assert resp.status_code == 401
    assert resp.headers.get_list("www-authenticate") == [
        challenge_header(e.config, invalid_token=False)
    ]
    assert "error=" not in resp.headers["www-authenticate"]


async def test_invalid_token_challenge_has_error_invalid_token(env):
    e, _ = env
    resp = await post(e.http, INIT, "not-a-jwt")
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == challenge_header(
        e.config, invalid_token=True
    )


async def test_non_bearer_scheme_is_unauthenticated(env):
    e, _ = env
    resp = await post(e.http, INIT, "dXNlcjpwYXNz", scheme="Basic")
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == challenge_header(
        e.config, invalid_token=False
    )


@pytest.mark.parametrize("scheme", ["bearer", "BEARER", "Bearer"])
async def test_bearer_scheme_case_insensitive(env, scheme):
    e, _ = env
    token = await login(e)
    resp = await post(e.http, INIT, token, scheme=scheme)
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"]["protocolVersion"] == "2025-06-18"


async def test_token_for_other_client_rejected(env):
    e, _ = env
    await login(e)
    session = e.session()
    forged, _ = AccessTokens(e.config).issue(
        session.sid, session.user_key, "some-other-client"
    )
    resp = await post(e.http, INIT, forged)
    assert resp.status_code == 401
    assert 'error="invalid_token"' in resp.headers["www-authenticate"]


async def test_token_of_ended_session_rejected(env):
    e, _ = env
    token = await login(e)
    await e.manager.end_session(e.session().sid, "revoked")
    resp = await post(e.http, INIT, token)
    assert resp.status_code == 401
    assert 'error="invalid_token"' in resp.headers["www-authenticate"]


async def test_expired_access_token_rejected(env, clock):
    e, _ = env
    token = await login(e)
    clock.advance(3601)
    resp = await post(e.http, INIT, token)
    assert resp.status_code == 401
    assert 'error="invalid_token"' in resp.headers["www-authenticate"]


async def test_store_failure_answers_503(env, monkeypatch):
    e, _ = env
    token = await login(e)

    def broken():
        raise StoreError("state store failed; reopen required")

    monkeypatch.setattr(e.manager.store, "snapshot", broken)
    resp = await post(e.http, INIT, token)
    assert resp.status_code == 503


# ------------------------------------------------------- session NetBox token


async def test_tool_call_uses_session_netbox_token(env):
    e, _ = env
    token = await login(e)
    resp = await post(e.http, sites_call(), token)
    assert not is_tool_error(resp), resp.text
    (request,) = dcim_requests(e)
    assert request.headers["authorization"] == f"Bearer {e.session().netbox_token}"
    assert e.session().netbox_token.startswith("nbt_")


async def test_superseded_token_retries_once(env, clock):
    e, tools = env
    token = await login(e)
    old = e.session()

    async def renew_and_delete_old(request: httpx2.Request) -> None:
        # NetBox renews the session token while this call is in flight, and
        # the cleanup deletes the old one before the call reaches NetBox.
        if request.url.path != "/api/dcim/sites/" or tools.before is None:
            return
        tools.before = None
        clock.advance(6 * DAY)
        await e.manager.renew_if_due(old.sid)
        e.netbox.delete_token(old.netbox_token_id)

    # The renewal must happen inside the call, not in the verifier: the
    # verifier ran before the hook is armed and found nothing due.
    tools.before = renew_and_delete_old
    resp = await post(e.http, sites_call(), token)

    assert not is_tool_error(resp), resp.text
    first, second = dcim_requests(e)
    assert first.headers["authorization"] == f"Bearer {old.netbox_token}"
    new = e.session()
    assert new.token_version == old.token_version + 1
    assert second.headers["authorization"] == f"Bearer {new.netbox_token}"
    assert new.sid == old.sid


async def test_deleted_token_ends_session(env):
    e, _ = env
    token = await login(e)
    session = e.session()
    e.netbox.delete_token(session.netbox_token_id)

    resp = await post(e.http, sites_call(), token)

    assert is_tool_error(resp)
    text = resp.json()["result"]["content"][0]["text"]
    assert "reconnect" in text
    assert len(dcim_requests(e)) == 1  # no retry loop
    state = e.manager.store.snapshot()
    assert state.sessions == {}
    (entry,) = state.cleanup.values()
    assert entry.netbox_token_id == session.netbox_token_id

    again = await post(e.http, sites_call(2), token)
    assert again.status_code == 401
    assert again.headers["www-authenticate"] == challenge_header(
        e.config, invalid_token=True
    )
    assert len(dcim_requests(e)) == 1
    assert len(e.manager.store.snapshot().cleanup) == 1


async def test_permission_403_passes_through(env):
    e, _ = env
    token = await login(e)
    e.netbox.fail("other", 403, times=1)

    resp = await post(e.http, sites_call(), token)

    assert is_tool_error(resp)
    assert "HTTP 403" in resp.json()["result"]["content"][0]["text"]
    assert len(dcim_requests(e)) == 1
    session = e.session()
    assert session.token_version == 1
    assert e.manager.store.snapshot().cleanup == {}


async def test_expired_netbox_token_renews_and_retries(env):
    e, _ = env
    token = await login(e)
    old = e.session()
    e.netbox.expire_token(old.netbox_token_id)

    resp = await post(e.http, sites_call(), token)

    assert not is_tool_error(resp), resp.text
    new = e.session()
    assert new.token_version == old.token_version + 1
    first, second = dcim_requests(e)
    assert first.headers["authorization"] == f"Bearer {old.netbox_token}"
    assert second.headers["authorization"] == f"Bearer {new.netbox_token}"


async def test_netbox_check_unavailable_is_tool_error_and_keeps_session(env):
    e, _ = env
    token = await login(e)
    session = e.session()
    e.netbox.fail("other", 403, times=1)
    e.netbox.fail("tokens.get", 503)

    resp = await post(e.http, sites_call(), token)

    assert is_tool_error(resp)
    assert "retry" in resp.json()["result"]["content"][0]["text"].lower()
    assert e.session().sid == session.sid
    assert e.manager.store.snapshot().cleanup == {}


async def test_verifier_renews_due_token_on_use(env, clock):
    e, _ = env
    token = await login(e)
    old = e.session()
    clock.advance(5 * DAY + 60)  # under 2 days of the 7-day token remain
    token, _ = AccessTokens(e.config).issue(old.sid, old.user_key, old.client_id)

    resp = await post(e.http, sites_call(), token)

    assert not is_tool_error(resp), resp.text
    new = e.session()
    assert new.token_version == old.token_version + 1
    (request,) = dcim_requests(e)
    assert request.headers["authorization"] == f"Bearer {new.netbox_token}"


async def test_renewal_failure_keeps_current_token(env, clock):
    e, _ = env
    await login(e)
    old = e.session()
    clock.advance(5 * DAY + 60)
    token, _ = AccessTokens(e.config).issue(old.sid, old.user_key, old.client_id)
    e.netbox.fail("tokens.create", 503)

    resp = await post(e.http, sites_call(), token)

    assert not is_tool_error(resp), resp.text
    assert e.session().token_version == old.token_version
    (request,) = dcim_requests(e)
    assert request.headers["authorization"] == f"Bearer {old.netbox_token}"


@pytest.mark.parametrize("change", ["delete", "disable"])
async def test_token_gone_in_netbox_while_renewal_due_ends_session(env, clock, change):
    e, _ = env
    await login(e)
    old = e.session()
    clock.advance(5 * DAY + 60)  # renewal due
    token, _ = AccessTokens(e.config).issue(old.sid, old.user_key, old.client_id)
    getattr(e.netbox, f"{change}_token")(old.netbox_token_id)
    created = len(e.netbox.sent("POST", "tokens.create"))

    resp = await post(e.http, sites_call(), token)

    # Spec 6.3: the call fails with "reconnect", no replacement token is made.
    assert is_tool_error(resp)
    assert "reconnect" in resp.json()["result"]["content"][0]["text"]
    # No request with the ended session's token reaches NetBox's data endpoints.
    assert dcim_requests(e) == []
    assert not [
        r
        for r in e.tool_requests
        if r.headers.get("authorization") == f"Bearer {old.netbox_token}"
    ]
    assert len(e.netbox.sent("POST", "tokens.create")) == created
    state = e.manager.store.snapshot()
    assert state.sessions == {}
    assert state.pending == {}
    (entry,) = state.cleanup.values()
    assert entry.netbox_token_id == old.netbox_token_id

    again = await post(e.http, sites_call(2), token)
    assert again.status_code == 401
    assert len(e.netbox.sent("POST", "tokens.create")) == created


async def test_ended_session_fails_tool_without_netbox_client(env, clock):
    """A tool that never opens a NetBox client fails on the ending call too."""
    e, _ = env
    await login(e)
    old = e.session()
    clock.advance(5 * DAY + 60)  # renewal due
    token, _ = AccessTokens(e.config).issue(old.sid, old.user_key, old.client_id)
    e.netbox.delete_token(old.netbox_token_id)
    call = rpc("tools/call", {"name": "netbox_list_object_types", "arguments": {}}, 1)

    resp = await post(e.http, call, token)

    assert is_tool_error(resp)
    assert "reconnect" in resp.json()["result"]["content"][0]["text"]
    assert e.tool_requests == []
    again = await post(e.http, call, token)
    assert again.status_code == 401


async def test_token_check_unavailable_while_renewal_due_keeps_token(env, clock):
    e, _ = env
    await login(e)
    old = e.session()
    clock.advance(5 * DAY + 60)
    token, _ = AccessTokens(e.config).issue(old.sid, old.user_key, old.client_id)
    e.netbox.fail("tokens.get", 503, times=1)
    created = len(e.netbox.sent("POST", "tokens.create"))

    resp = await post(e.http, sites_call(), token)

    assert not is_tool_error(resp), resp.text
    assert len(e.netbox.sent("POST", "tokens.create")) == created
    assert e.session().token_version == old.token_version
    (request,) = dcim_requests(e)
    assert request.headers["authorization"] == f"Bearer {old.netbox_token}"


async def test_unbound_verifier_rejects(oauth_config):
    verifier = OAuthTokenVerifier(oauth_config)
    token, _ = AccessTokens(oauth_config).issue("sid", "user", "client")
    assert await verifier.verify_token(token) is None


# ------------------------------------------------------ transport behaviour


async def test_get_and_delete_mcp_405_allow_post(env):
    e, _ = env
    token = await login(e)
    auth = {"Authorization": f"Bearer {token}", "Accept": ACCEPT}
    for method in ("GET", "DELETE"):
        resp = await e.http.request(method, BASE + "/mcp", headers=auth)
        assert resp.status_code == 405, method
        assert resp.headers["allow"] == "POST"


async def test_notification_202_empty_body(env):
    e, _ = env
    token = await login(e)
    resp = await post(e.http, rpc("notifications/initialized", rid=None), token)
    assert resp.status_code == 202
    assert resp.content == b""


async def test_no_mcp_session_id_header(env):
    e, _ = env
    token = await login(e)
    resp = await post(e.http, INIT, token)
    assert resp.status_code == 200
    assert "mcp-session-id" not in resp.headers
    resp = await post(e.http, rpc("tools/list", {}, 2), token)
    assert resp.status_code == 200
    assert "mcp-session-id" not in resp.headers
    assert resp.json()["result"]["tools"]


@pytest.mark.parametrize("path", ["/mcp", "/mcp/"])
async def test_mcp_and_trailing_slash_served(env, path):
    e, _ = env
    token = await login(e)
    resp = await post(e.http, INIT, token, path=path)
    assert resp.status_code == 200, resp.text
    assert "location" not in resp.headers


@pytest.mark.parametrize("path", ["//mcp", "/mcp//", "/MCP", "/Mcp/", "///mcp/"])
async def test_noncanonical_paths_404(env, path):
    e, _ = env
    token = await login(e)
    resp = await post(e.http, INIT, token, path=path)
    assert resp.status_code == 404
    assert "location" not in resp.headers


async def test_oauth_routes_still_served_under_base(env):
    e, _ = env
    resp = await e.http.get(BASE + "/mcp/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    resp = await e.http.get(BASE + "/.well-known/oauth-authorization-server/mcp")
    assert resp.status_code == 200


@pytest.mark.parametrize("method", ["POST", "GET"])
async def test_origin_allowlist_all_methods(env, method):
    e, _ = env
    token = await login(e)

    async def send(origin: str | None):
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": ACCEPT,
            "Content-Type": "application/json",
        }
        if origin is not None:
            headers["Origin"] = origin
        return await e.http.request(
            method, BASE + "/mcp", content=json.dumps(INIT), headers=headers
        )

    expected = 200 if method == "POST" else 405
    assert (await send("https://evil.example")).status_code == 403
    assert (await send("null")).status_code == 403
    for origin in (
        "https://claude.ai",
        "https://claude.com",
        "https://chatgpt.com",
        "https://mcp.example.com",
        "HTTPS://MCP.EXAMPLE.COM",
        None,
    ):
        assert (await send(origin)).status_code == expected, origin


async def test_origin_checked_before_authentication(env):
    e, _ = env
    resp = await post(e.http, INIT, headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403


async def test_extra_origins_allowed(oauth_config, fake_idp, fake_netbox_tokens):
    config = oauth_config.model_copy(
        update={"extra_origins": ["https://tools.example.org"]}
    )
    StateStore.create(config.state_path, config.state_key)
    nb_config = NetBoxConfig(netbox_url=fake_netbox_tokens.base_url, token=None)
    mcp = FastMCP("t", auth=OAuthTokenVerifier(config), lifespan=oauth_launch_guard)
    app = build_oauth_app(
        mcp,
        config,
        netbox_config=nb_config,
        idp_transport=fake_idp.transport,
        netbox_transport=fake_netbox_tokens.transport,
        background=idle_background,
    )
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url=BASE
        ) as http,
    ):
        allowed = await post(
            http, INIT, headers={"Origin": "https://tools.example.org"}
        )
        denied = await post(http, INIT, headers={"Origin": "https://other.example.org"})
    assert allowed.status_code == 401  # passed the Origin check
    assert denied.status_code == 403


# ---------------------------------------------------------- protocol version


async def test_version_rules(env):
    e, _ = env
    token = await login(e)

    async def call(version):
        return await post(e.http, rpc("tools/list", {}, 7), token, version=version)

    for ok in ("2026-07-28", "2025-11-25", "2025-06-18", "2027-01-01", None):
        resp = await call(ok)
        assert resp.status_code == 200, (ok, resp.text)
        assert resp.json()["result"]["tools"], ok
    for bad in ("2099-01-01", "2026-02-30", "garbage", "2026-7-28", "2024-01-01"):
        resp = await call(bad)
        assert resp.status_code == 400, bad
        assert resp.json()["error"]["code"] == -32600
        assert resp.json()["id"] == 7


@pytest.mark.parametrize("header", ["2026-07-28", "2027-01-01", "2099-01-01", "junk"])
async def test_initialize_never_rejected_for_header(env, header):
    e, _ = env
    token = await login(e)
    body = rpc(
        "initialize",
        {
            "protocolVersion": "2099-01-01",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    )
    resp = await post(e.http, body, token, version=header)
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"]["protocolVersion"] == LATEST_HANDSHAKE_VERSION


async def test_tool_call_with_2026_07_28_header(env):
    e, _ = env
    token = await login(e)
    resp = await post(e.http, sites_call(), token, version="2026-07-28")
    assert not is_tool_error(resp), resp.text


async def test_body_too_large_413(env, monkeypatch):
    e, _ = env
    token = await login(e)
    monkeypatch.setattr("netbox_mcp.oauth.app.MAX_BODY_BYTES", 100)
    resp = await post(e.http, rpc("tools/list", {"pad": "x" * 200}), token)
    assert resp.status_code == 413


# --------------------------------------------------------------- rate limit


def test_rate_limit_keyed_by_user_not_client():
    def key_for(client_id: str, sub: str) -> str:
        access = AccessToken(
            token="nbt_x.y",
            client_id=client_id,
            scopes=["netbox"],
            claims={"netbox_mcp_auth_mode": "oauth", "sub": sub, "sid": "s"},
        )
        marker = auth_context_var.set(AuthenticatedUser(access))
        try:
            return rate_limit_client_id(None)
        finally:
            auth_context_var.reset(marker)

    assert key_for("client-a", "user-1") == key_for("client-b", "user-1")
    assert key_for("client-a", "user-1") != key_for("client-a", "user-2")
    # Outside OAuth mode the key stays the verified client_id.
    passthrough = AccessToken(token="t", client_id="user:5", scopes=[])
    marker = auth_context_var.set(AuthenticatedUser(passthrough))
    try:
        assert rate_limit_client_id(None) == "user:5"
    finally:
        auth_context_var.reset(marker)


# ------------------------------------------------------------------ logging


@pytest.fixture
def oauth_logging():
    """Apply main()'s OAuth logging setup; restore the levels afterwards."""
    saved = {n: logging.getLogger(n).level for n in HTTP_CLIENT_LOGGERS}
    configure_oauth_logging()
    yield
    for name, level in saved.items():
        logging.getLogger(name).setLevel(level)


def _test_client_record(record: logging.LogRecord) -> bool:
    """Records of this test's own HTTP clients: requests to the server under
    test and the browser leg of the IdP login (the server never calls it)."""
    message = record.getMessage()
    return BASE in message or "/authorize?" in message


@pytest.mark.usefixtures("oauth_logging")
async def test_log_events_contain_no_secrets(env, caplog):
    e, _ = env
    caplog.set_level(logging.DEBUG)
    _client, body = await tokens_for(e.http, e.idp)
    access, refresh = body["access_token"], body["refresh_token"]
    resp = await post(e.http, sites_call(), access)
    assert not is_tool_error(resp)
    refreshed = await e.http.post(
        "/mcp/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh},
    )
    assert refreshed.status_code == 200
    session = e.session()
    e.netbox.delete_token(session.netbox_token_id)
    await post(e.http, sites_call(2), refreshed.json()["access_token"])

    records = [r for r in caplog.records if not _test_client_record(r)]
    text = "\n".join(r.getMessage() for r in records)
    # NetBox and IdP lookups carry user names and filters in the query.
    assert "?" not in "".join(
        r.getMessage() for r in records if r.name.startswith(HTTP_CLIENT_LOGGERS)
    )
    assert "tool_call user=alice " in text
    tool_lines = [line for line in text.splitlines() if "tool_call" in line]
    assert all(session.user_key not in line for line in tool_lines)
    assert "session_ended" in text
    assert "token_refreshed" in text
    for secret in (
        access,
        refresh,
        refreshed.json()["access_token"],
        refreshed.json()["refresh_token"],
        session.netbox_token,
        session.sid,
        session.idp_refresh_token,
        e.config.broker_token.get_secret_value(),
    ):
        assert secret not in text
    assert "code=" not in text
    assert "state=" not in text
    assert "__Secure-" not in text
    assert session.sid[:8] in text


async def test_disabled_token_ends_session(env):
    e, _ = env
    token = await login(e)
    e.netbox.disable_token(e.session().netbox_token_id)

    resp = await post(e.http, sites_call(), token)

    assert is_tool_error(resp)
    assert "reconnect" in resp.json()["result"]["content"][0]["text"]
    assert e.manager.store.snapshot().sessions == {}


async def test_explicit_token_never_reports_rejection(monkeypatch):
    """The broker passes its own token: a 403 must not reach the session hook."""
    calls = []

    class Spy:
        async def handle_netbox_rejection(self, sid, used_version):  # noqa: ARG002
            calls.append(sid)
            return "retry"

        def current_token(self, sid):  # noqa: ARG002
            return ("nbt_new.secret", 2)

    monkeypatch.setattr(netbox_client, "_oauth_sessions", Spy())
    access = AccessToken(
        token="nbt_session.secret",
        client_id="c",
        scopes=["netbox"],
        claims={
            "netbox_mcp_auth_mode": "oauth",
            "sub": "u",
            "sid": "s" * 32,
            "token_version": 1,
        },
    )
    transport = httpx2.MockTransport(
        lambda _request: httpx2.Response(403, json={"detail": "denied"})
    )
    config = NetBoxConfig(netbox_url="https://netbox.example.com", token=None)
    marker = auth_context_var.set(AuthenticatedUser(access))
    try:
        async with NetBoxClient(
            config, token="nbt_broker.secret", transport=transport
        ) as nb:
            with pytest.raises(NetBoxAPIError):
                await nb.get("users/tokens")
        assert calls == []
        # The same request with the session's token does report it.
        async with NetBoxClient(config, transport=transport) as nb:
            with pytest.raises(NetBoxAPIError):
                await nb.get("users/tokens")
        assert calls == ["s" * 32]
    finally:
        auth_context_var.reset(marker)


def test_sdk_protocol_version_contract():
    """F1 relies on these SDK constants (mcp-types 2.3.0)."""
    assert LATEST_HANDSHAKE_VERSION in HANDSHAKE_PROTOCOL_VERSIONS
    assert "2026-07-28" in SUPPORTED_PROTOCOL_VERSIONS
    assert "2026-07-28" not in HANDSHAKE_PROTOCOL_VERSIONS
    assert max(KNOWN_PROTOCOL_VERSIONS) == "2026-07-28"


# ------------------------------------------------- fix round 1 (review)

MODERN_LIST = rpc(
    "tools/list",
    {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
    9,
)
OUR_VERSION_ERROR = "Unsupported MCP-Protocol-Version"


@pytest.mark.parametrize("header", ["garbage", "2027-01-01", "2099-01-01", None])
async def test_modern_body_needs_supported_header(env, header):
    e, _ = env
    token = await login(e)
    resp = await post(e.http, MODERN_LIST, token, version=header)
    assert resp.status_code == 400, resp.text
    assert OUR_VERSION_ERROR in resp.json()["error"]["message"]
    assert resp.json()["id"] == 9


async def test_modern_body_with_supported_header_passes(env):
    e, _ = env
    token = await login(e)
    resp = await post(e.http, MODERN_LIST, token, version="2026-07-28")
    assert OUR_VERSION_ERROR not in resp.text


async def test_disconnect_mid_body_is_not_dispatched(env):
    e, _ = env
    token = await login(e)
    chunks = [
        {"type": "http.request", "body": b'{"jsonrpc": "2.0", ', "more_body": True},
        {"type": "http.disconnect"},
    ]
    sent: list = []

    async def receive():
        return chunks.pop(0)

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "server": ("mcp.example.com", 443),
        "client": ("127.0.0.1", 5000),
        "path": "/mcp",
        "raw_path": b"/mcp",
        "root_path": "",
        "query_string": b"",
        "headers": [
            (b"host", b"mcp.example.com"),
            (b"authorization", f"Bearer {token}".encode()),
            (b"content-type", b"application/json"),
            (b"accept", ACCEPT.encode()),
        ],
    }
    await e.app(scope, receive, send)
    assert sent == []


async def test_root_path_does_not_bypass_classification(
    oauth_config, fake_idp, fake_netbox_tokens
):
    StateStore.create(oauth_config.state_path, oauth_config.state_key)
    nb_config = NetBoxConfig(netbox_url=fake_netbox_tokens.base_url, token=None)
    mcp = FastMCP(
        "t", auth=OAuthTokenVerifier(oauth_config), lifespan=oauth_launch_guard
    )
    app = build_oauth_app(
        mcp,
        oauth_config,
        netbox_config=nb_config,
        idp_transport=fake_idp.transport,
        netbox_transport=fake_netbox_tokens.transport,
        background=idle_background,
    )
    async with (
        running(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app, root_path="/prefix"),
            base_url=BASE,
        ) as http,
    ):
        served = await post(http, INIT, path="/prefix/mcp")
        slash = await post(http, INIT, path="/prefix/mcp/")
        bad = [
            await post(http, INIT, path=p)
            for p in ("/prefix/mcp//", "/prefix/MCP", "/prefix//mcp")
        ]
        evil = await post(
            http, INIT, path="/prefix/mcp", headers={"Origin": "https://evil.example"}
        )
    # Reaching the outer authentication proves the layer classified the path.
    assert served.status_code == 401
    assert served.headers["www-authenticate"] == challenge_header(
        oauth_config, invalid_token=False
    )
    assert slash.status_code == 401
    assert [r.status_code for r in bad] == [404, 404, 404]
    assert all("location" not in r.headers for r in bad)
    assert evil.status_code == 403
