"""End to end: the built OAuth app against the fake IdP and fake NetBox (spec 10).

Every test here drives the app ``main()`` serves (:func:`build_oauth_app`)
through HTTP only, the way an MCP client and a browser would. Background jobs
are replaced by a no-op; where a job's effect matters the test calls the
session manager's job method itself, so nothing depends on sleeping.
"""

import base64
import contextlib
import io
from collections.abc import AsyncGenerator
from typing import Any
from urllib.parse import urlsplit

import httpx2
import pytest
from fastmcp import FastMCP
from starlette.applications import Starlette

from netbox_mcp.models import NetBoxConfig
from netbox_mcp.oauth.app import build_oauth_app
from netbox_mcp.oauth.app import oauth_launch_guard
from netbox_mcp.oauth.cli import oauth_cli
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.metadata import authorization_server_metadata
from netbox_mcp.oauth.metadata import challenge_header
from netbox_mcp.oauth.metadata import protected_resource_metadata
from netbox_mcp.oauth.sessions import REPLAY_WINDOW
from netbox_mcp.oauth.sessions import SessionManager
from netbox_mcp.oauth.state import Session
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import StoreError
from netbox_mcp.oauth.verifier import OAuthTokenVerifier
from netbox_mcp.tools import register_tools
from tests.oauth.fakes import FakeIdP
from tests.oauth.fakes import FakeNetBoxTokens
from tests.oauth.test_flow import CHALLENGE
from tests.oauth.test_flow import VERIFIER
from tests.oauth.test_flow import approve
from tests.oauth.test_flow import idp_round_trip
from tests.oauth.test_flow import qs
from tests.oauth.test_flow import register
from tests.oauth.test_mcp_endpoint import INIT
from tests.oauth.test_mcp_endpoint import ToolTransport
from tests.oauth.test_mcp_endpoint import idle_background
from tests.oauth.test_mcp_endpoint import is_tool_error
from tests.oauth.test_mcp_endpoint import post
from tests.oauth.test_mcp_endpoint import running
from tests.oauth.test_mcp_endpoint import sites_call
from tests.oauth.test_token_endpoint import assert_error
from tests.oauth.test_token_endpoint import refresh
from tests.oauth.test_token_endpoint import tokens_for

BASE = "https://mcp.example.com"
PUBLIC = BASE + "/mcp"
# Loopback redirect as a CLI client registers it; it may come back on another port.
LOOPBACK_REGISTERED = "http://127.0.0.1:33418/callback"
LOOPBACK_USED = "http://127.0.0.1:51234/callback"

PRM_PATHS = [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/mcp/.well-known/oauth-protected-resource",
]
AS_PATHS = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/mcp",
    "/mcp/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration/mcp",
    "/mcp/.well-known/openid-configuration",
]


# ----------------------------------------------------------------- helpers


class Server:
    """One server process: a FastMCP instance and the outer app around it."""

    def __init__(
        self, config: OAuthConfig, idp: FakeIdP, netbox: FakeNetBoxTokens
    ) -> None:
        nb_config = NetBoxConfig(netbox_url=netbox.base_url, token=None)
        self.tools = ToolTransport(netbox)
        mcp = FastMCP(
            "e2e", auth=OAuthTokenVerifier(config), lifespan=oauth_launch_guard
        )
        register_tools(mcp, nb_config, self.tools.transport)
        self.app: Starlette = build_oauth_app(
            mcp,
            config,
            netbox_config=nb_config,
            idp_transport=idp.transport,
            netbox_transport=netbox.transport,
            background=idle_background,
        )

    @property
    def manager(self) -> SessionManager:
        return self.app.state.oauth_manager

    def dcim_requests(self) -> list[httpx2.Request]:
        return [r for r in self.tools.requests if r.url.path == "/api/dcim/sites/"]


@contextlib.asynccontextmanager
async def serving(
    config: OAuthConfig, idp: FakeIdP, netbox: FakeNetBoxTokens
) -> AsyncGenerator[tuple[Server, httpx2.AsyncClient]]:
    server = Server(config, idp, netbox)
    async with (
        running(server.app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=server.app), base_url=BASE
        ) as http,
    ):
        yield server, http


def oauth_init(config: OAuthConfig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Create the state file the documented way: ``netbox-mcp oauth init``."""
    monkeypatch.setenv("OAUTH_STATE_PATH", str(config.state_path))
    monkeypatch.setenv("OAUTH_STATE_KEY", base64.b64encode(config.state_key).decode())
    out, err = io.StringIO(), io.StringIO()
    assert oauth_cli(["init"], out=out, err=err) == 0, err.getvalue()


def only_session(server: Server) -> Session:
    (session,) = server.manager.store.snapshot().sessions.values()
    return session


def auth_params(client_id: str, redirect_uri: str, **over: Any) -> dict[str, str]:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": "e2e-state",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "scope": "netbox",
        "resource": PUBLIC,
    }
    params.update(over)
    return {k: v for k, v in params.items() if v is not None}


def tool_text(resp: httpx2.Response) -> str:
    return resp.json()["result"]["content"][0]["text"]


@pytest.fixture
def e2e_fakes(fake_idp, fake_netbox_tokens, clock) -> tuple[FakeIdP, FakeNetBoxTokens]:
    fake_idp.now = clock
    fake_netbox_tokens.now = clock
    return fake_idp, fake_netbox_tokens


# --------------------------------------------------------------- lifecycle


async def test_e2e_full_lifecycle(oauth_config, e2e_fakes, monkeypatch) -> None:
    idp, netbox = e2e_fakes
    oauth_init(oauth_config, monkeypatch)

    async with serving(oauth_config, idp, netbox) as (server, http):
        # 1. Discovery, starting from the 401 challenge as a client does.
        challenge = await post(http, INIT, version="2026-07-28")
        assert challenge.status_code == 401
        assert challenge.headers["www-authenticate"] == challenge_header(
            oauth_config, invalid_token=False
        )
        prm_url = (
            challenge.headers["www-authenticate"]
            .split('resource_metadata="')[1]
            .split('"')[0]
        )
        assert urlsplit(prm_url).path in PRM_PATHS
        prm_docs = [(await http.get(p)) for p in PRM_PATHS]
        assert all(r.status_code == 200 for r in prm_docs)
        assert all(
            r.json() == protected_resource_metadata(oauth_config) for r in prm_docs
        )
        (as_issuer,) = prm_docs[0].json()["authorization_servers"]
        assert as_issuer == PUBLIC
        as_docs = [(await http.get(p)) for p in AS_PATHS]
        assert all(r.status_code == 200 for r in as_docs)
        as_doc = as_docs[0].json()
        assert all(r.json() == as_doc for r in as_docs)
        assert as_doc == authorization_server_metadata(oauth_config)
        assert (await http.get("/.well-known/openid-configuration")).status_code == 404

        # 2. Dynamic Client Registration with a loopback redirect URI.
        reg = await http.post(
            as_doc["registration_endpoint"],
            json={
                "redirect_uris": [LOOPBACK_REGISTERED],
                "client_name": "E2E CLI",
                "token_endpoint_auth_method": "client_secret_basic",
            },
        )
        assert reg.status_code == 201, reg.text
        client_id = reg.json()["client_id"]
        assert reg.json()["token_endpoint_auth_method"] == "none"

        # 3. Authorize (other loopback port), IdP login, consent, code.
        auth = await http.get(
            as_doc["authorization_endpoint"],
            params=auth_params(client_id, LOOPBACK_USED),
        )
        assert auth.status_code == 302, auth.text
        assert auth.headers["location"].startswith(idp.issuer)
        callback = await http.get(await idp_round_trip(idp, auth.headers["location"]))
        assert callback.status_code == 303, callback.text
        approved = await approve(http, callback.headers["location"])
        assert approved.status_code == 303, approved.text
        location = approved.headers["location"]
        assert location.startswith(LOOPBACK_USED + "?")
        params = qs(location)
        assert params["state"] == "e2e-state"
        assert params["iss"] == PUBLIC

        # 4. Token.
        tok = await http.post(
            as_doc["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": params["code"],
                "client_id": client_id,
                "redirect_uri": LOOPBACK_USED,
                "code_verifier": VERIFIER,
                "resource": PUBLIC,
            },
        )
        assert tok.status_code == 200, tok.text
        tokens = tok.json()
        assert tokens["token_type"].lower() == "bearer"
        assert tokens["scope"] == "netbox"
        session = only_session(server)
        assert session.client_id == client_id
        netbox_token_id = session.netbox_token_id
        assert netbox_token_id in netbox.tokens
        assert netbox.users[netbox.tokens[netbox_token_id]["user"]].username == "alice"

        # 5. MCP initialize and a tool call that reaches NetBox as the user.
        init = await post(http, INIT, tokens["access_token"], version="2026-07-28")
        assert init.status_code == 200, init.text
        assert "serverInfo" in init.json()["result"]
        call = await post(http, sites_call(), tokens["access_token"])
        assert not is_tool_error(call), call.text
        (sites,) = server.dcim_requests()
        assert sites.headers["authorization"] == f"Bearer {session.netbox_token}"
        (seen,) = [r for r in netbox.requests if r.path == "/api/dcim/sites/"]
        assert seen.authenticated_as == "alice"

        # 6. Refresh rotates both tokens; the new access token works.
        refreshed = await refresh(http, tokens["refresh_token"], client_id=client_id)
        assert refreshed.status_code == 200, refreshed.text
        tokens = refreshed.json()
        call = await post(http, sites_call(2), tokens["access_token"])
        assert not is_tool_error(call), call.text

    logins = idp.calls["authorize"]
    state_after_first_run = oauth_config.state_path.read_bytes()
    assert state_after_first_run  # the store is on disk, encrypted

    # 7. Server restart: a new process on the same state file, no new login.
    async with serving(oauth_config, idp, netbox) as (server, http):
        assert only_session(server).netbox_token_id == netbox_token_id
        call = await post(http, sites_call(3), tokens["access_token"])
        assert not is_tool_error(call), call.text
        (sites,) = server.dcim_requests()
        assert sites.headers["authorization"] == (
            f"Bearer {only_session(server).netbox_token}"
        )
        refreshed = await refresh(http, tokens["refresh_token"])
        assert refreshed.status_code == 200, refreshed.text
        tokens = refreshed.json()
        assert idp.calls["authorize"] == logins

        # 8. Group removal at the IdP: the next refresh ends the session.
        idp.users["alice"]["groups"] = []
        assert_error(await refresh(http, tokens["refresh_token"]), 400, "invalid_grant")
        state = server.manager.store.snapshot()
        assert state.sessions == {}
        assert [e.netbox_token_id for e in state.cleanup.values()] == [netbox_token_id]
        assert netbox_token_id in netbox.tokens  # not yet deleted

        # 9. Cleanup (the job the hourly loop and every session end trigger).
        await server.manager.run_cleanup()
        assert netbox_token_id not in netbox.tokens
        (deleted,) = netbox.sent("DELETE", "tokens.delete")
        assert deleted.authenticated_as == "service"
        assert server.manager.store.snapshot().cleanup == {}

        # The old access token is dead too.
        gone = await post(http, sites_call(4), tokens["access_token"])
        assert gone.status_code == 401
        assert gone.headers["www-authenticate"] == challenge_header(
            oauth_config, invalid_token=True
        )


async def test_e2e_netbox_restart_during_session(
    oauth_config, e2e_fakes, monkeypatch
) -> None:
    """Spec 10: NetBox briefly gone during a tool call and a refresh."""
    idp, netbox = e2e_fakes
    oauth_init(oauth_config, monkeypatch)

    async with serving(oauth_config, idp, netbox) as (server, http):
        _client, tokens = await tokens_for(http, idp)
        session = only_session(server)

        # NetBox is down: the tool call times out (a timeout is not retried,
        # so no backoff sleep) and the refresh's NetBox check gets 503s.
        netbox.fail("other", "timeout")
        for endpoint in ("users.get", "users.list", "tokens.get", "tokens.list"):
            netbox.fail(endpoint, 503)

        call = await post(http, sites_call(), tokens["access_token"])
        assert is_tool_error(call)
        assert session.netbox_token not in tool_text(call)
        assert_error(
            await refresh(http, tokens["refresh_token"]),
            503,
            "temporarily_unavailable",
        )
        # Nothing was ended or rotated.
        after = only_session(server)
        assert after.sid == session.sid
        assert after.refresh_hash == session.refresh_hash
        assert after.netbox_token == session.netbox_token
        assert server.manager.store.snapshot().cleanup == {}

        # A daily check during the outage keeps the session as well.
        await server.manager.daily_netbox_check()
        assert only_session(server).sid == session.sid

        # NetBox is back: the same tokens work, without a new login.
        netbox.clear_failures()
        call = await post(http, sites_call(2), tokens["access_token"])
        assert not is_tool_error(call), call.text
        refreshed = await refresh(http, tokens["refresh_token"])
        assert refreshed.status_code == 200, refreshed.text
        call = await post(http, sites_call(3), refreshed.json()["access_token"])
        assert not is_tool_error(call), call.text
        assert only_session(server).sid == session.sid
        assert idp.calls["authorize"] == 1


# ---------------------------------------------------------- spike checklist


async def test_spike_checklist(oauth_config, e2e_fakes, monkeypatch, clock) -> None:
    """Spec Appendix A: each failure of the rejected approach, against the built app."""
    idp, netbox = e2e_fakes
    oauth_init(oauth_config, monkeypatch)

    async with serving(oauth_config, idp, netbox) as (server, http):
        # 1. Every AS/OIDC discovery alias serves the AS metadata (and the
        #    root OIDC document is deliberately absent, spec 5.1).
        docs = [await http.get(p) for p in AS_PATHS]
        assert [r.status_code for r in docs] == [200] * len(AS_PATHS)
        assert all(
            r.json() == authorization_server_metadata(oauth_config) for r in docs
        )
        assert (await http.get("/.well-known/openid-configuration")).status_code == 404

        # 2. POST /mcp// is a 404, never a redirect.
        slash = await post(http, INIT, path="/mcp//")
        assert slash.status_code == 404
        assert "location" not in slash.headers

        # 3. DCR refuses redirect URIs carrying ?iss= or ?code=.
        for param in ("iss", "code"):
            resp = await http.post(
                "/mcp/oauth/register",
                json={"redirect_uris": [f"http://localhost:8080/cb?{param}=x"]},
            )
            assert resp.status_code == 400
            assert resp.json()["error"] == "invalid_redirect_uri"

        # 4. /authorize without state never reaches the IdP or consent.
        client_id = await register(http, uris=[LOOPBACK_REGISTERED])
        flows_before = dict(server.manager.store.snapshot().flows)
        no_state = await http.get(
            "/mcp/oauth/authorize",
            params=auth_params(client_id, LOOPBACK_REGISTERED, state=None),
        )
        assert no_state.status_code == 400
        assert "location" not in no_state.headers
        assert server.manager.store.snapshot().flows == flows_before

        # 5. /authorize without resource is allowed in this design (spec 5.3):
        #    it goes on to the IdP login.
        no_resource = await http.get(
            "/mcp/oauth/authorize",
            params=auth_params(client_id, LOOPBACK_REGISTERED, resource=None),
        )
        assert no_resource.status_code == 302
        assert no_resource.headers["location"].startswith(idp.issuer)
        http.cookies.clear()

        # 6. A foreign resource at the refresh endpoint is refused.
        _cid, first = await tokens_for(http, idp)
        assert_error(
            await refresh(
                http, first["refresh_token"], resource="https://other.example/mcp"
            ),
            400,
            "invalid_target",
        )

        # 7. Replaying an old refresh token (outside the 30 s replay window)
        #    ends the session, so its successor is dead too.
        second = (await refresh(http, first["refresh_token"])).json()
        clock.advance(REPLAY_WINDOW + 1)
        assert_error(await refresh(http, first["refresh_token"]), 400, "invalid_grant")
        assert_error(await refresh(http, second["refresh_token"]), 400, "invalid_grant")
        assert server.manager.store.snapshot().sessions == {}

        # 8. A public client revokes without any client_secret field.
        _cid, third = await tokens_for(http, idp)
        revoke = await http.post(
            "/mcp/oauth/revoke", data={"token": third["refresh_token"]}
        )
        assert revoke.status_code == 200, revoke.text
        assert server.manager.store.snapshot().sessions == {}

    # 9. With a changed encryption key the server refuses to start; the
    #    store is neither emptied nor rewritten.
    before = oauth_config.state_path.read_bytes()
    wrong_key = oauth_config.model_copy(update={"state_key": b"x" * 32})
    with pytest.raises(StoreError):
        async with serving(wrong_key, idp, netbox):
            pass
    assert oauth_config.state_path.read_bytes() == before
    reopened = StateStore.open(oauth_config.state_path, oauth_config.state_key)
    try:
        assert len(reopened.snapshot().cleanup) == 2  # both ended sessions' tokens
    finally:
        reopened.close()


async def test_e2e_tool_call_rejects_body_without_token_before_parsing(
    oauth_config, e2e_fakes, monkeypatch
) -> None:
    """Pilot lesson 1 end to end: 401 comes before body or version checks."""
    idp, netbox = e2e_fakes
    oauth_init(oauth_config, monkeypatch)
    async with serving(oauth_config, idp, netbox) as (_server, http):
        resp = await http.post(
            "/mcp",
            content=b"{not json",
            headers={"MCP-Protocol-Version": "1999-01-01"},
        )
        assert resp.status_code == 401
        assert resp.headers["www-authenticate"] == challenge_header(
            oauth_config, invalid_token=False
        )
