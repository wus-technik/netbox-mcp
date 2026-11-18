"""Launch paths of OAuth mode: entry point vs. ``fastmcp run`` (spec 4, 9)."""

import logging
from unittest.mock import MagicMock

import httpx2
import pytest

from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import StoreError
from netbox_mcp.oauth.store import StoreLocked
from netbox_mcp.oauth.verifier import OAuthTokenVerifier
from netbox_mcp.utils import HEALTH_PATH
from tests.oauth.conftest import OAUTH_ENV
from tests.test_server import load_server  # noqa: F401 - fixture

LAUNCH_ERROR = "OAuth mode must be started with the netbox-mcp entry point"


@pytest.fixture
def oauth_env(load_server, monkeypatch, tmp_path):  # noqa: ARG001, F811
    # Depends on load_server, which clears OIDC_ISSUER: set the OAuth
    # variables after it.
    for name, value in OAUTH_ENV.items():
        monkeypatch.setenv(name, value)
    state = tmp_path / "state.json"
    monkeypatch.setenv("OAUTH_STATE_PATH", str(state))
    return state


@pytest.fixture
def run_uvicorn(monkeypatch):
    import uvicorn

    run = MagicMock()
    monkeypatch.setattr(uvicorn, "run", run)
    return run


def test_import_has_no_side_effects(load_server, oauth_env):  # noqa: F811
    server = load_server(MCP_TRANSPORT="http")

    assert isinstance(server.mcp.auth, OAuthTokenVerifier)
    assert server.mcp.auth.manager is None
    assert not oauth_env.exists()
    assert list(oauth_env.parent.iterdir()) == []


async def test_fastmcp_run_refused_in_oauth_mode(load_server, oauth_env):  # noqa: F811
    StateStore.create(oauth_env, b"k" * 32)
    server = load_server(MCP_TRANSPORT="http")
    app = server.mcp.http_app()

    with pytest.raises(RuntimeError, match=LAUNCH_ERROR):
        async with app.router.lifespan_context(app):
            pass
    # The refusal happens before the store is touched.
    StateStore.open(oauth_env, b"k" * 32).close()


async def test_other_modes_start_without_marker(load_server):  # noqa: F811
    server = load_server(MCP_TRANSPORT="http", MCP_HTTP_BEARER_TOKEN="secret")
    app = server.mcp.http_app()
    async with app.router.lifespan_context(app):
        pass


async def test_main_builds_outer_app(load_server, oauth_env, run_uvicorn, monkeypatch):  # noqa: F811
    StateStore.create(oauth_env, b"k" * 32)
    discovered = []

    async def discover(self):
        discovered.append(self)

    monkeypatch.setattr("netbox_mcp.oauth.idp.IdpClient.discover", discover)
    server = load_server(MCP_TRANSPORT="http")

    server.main()

    server.mcp.run.assert_not_called()
    run_uvicorn.assert_called_once()
    app = run_uvicorn.call_args.args[0]
    assert app.state.netbox_mcp_outer is True
    async with app.router.lifespan_context(app):
        assert len(discovered) == 1
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="https://mcp.example.com"
        ) as http:
            assert (await http.get(HEALTH_PATH)).status_code == 200
            assert (await http.post("/mcp", json={})).status_code == 401
        assert server.mcp.auth.manager is app.state.oauth_manager
        with pytest.raises(StoreLocked):
            StateStore.open(oauth_env, b"k" * 32)
    assert server.mcp.auth.manager is None
    StateStore.open(oauth_env, b"k" * 32).close()


@pytest.mark.usefixtures("oauth_env")
def test_main_runs_uvicorn_without_access_log(load_server, run_uvicorn):  # noqa: F811
    server = load_server(MCP_TRANSPORT="http", MCP_HTTP_PORT="8123")

    server.main()

    kwargs = run_uvicorn.call_args.kwargs
    assert kwargs["access_log"] is False
    assert kwargs["port"] == 8123


@pytest.mark.usefixtures("oauth_env")
def test_main_ignores_netbox_token_with_warning(
    load_server,  # noqa: F811
    run_uvicorn,
    caplog,
):
    caplog.set_level(logging.INFO)
    server = load_server(MCP_TRANSPORT="http", NETBOX_TOKEN="nbt_abc.secret")

    server.main()

    assert "NETBOX_TOKEN is ignored" in caplog.text
    assert "WITHOUT authentication" not in caplog.text
    assert server.NETBOX_CONFIG.token is None
    run_uvicorn.assert_called_once()


@pytest.mark.usefixtures("oauth_env")
def test_main_without_netbox_token_starts(load_server, run_uvicorn):  # noqa: F811
    server = load_server(MCP_TRANSPORT="http", NETBOX_TOKEN="")

    server.main()

    run_uvicorn.assert_called_once()


@pytest.mark.usefixtures("oauth_env")
async def test_startup_fails_when_state_file_missing(
    load_server,  # noqa: F811
    run_uvicorn,
):
    server = load_server(MCP_TRANSPORT="http")
    server.main()
    app = run_uvicorn.call_args.args[0]

    with pytest.raises(StoreError, match="state file not found"):
        async with app.router.lifespan_context(app):
            pass
    assert server.mcp.auth.manager is None


async def test_launch_marker_is_bound_to_the_started_server():
    """A marker set for one FastMCP server does not let another one start."""
    from fastmcp import FastMCP

    from netbox_mcp.oauth import app as oauth_app

    started, other = FastMCP("started"), FastMCP("other")
    marker = oauth_app._launched.set(started)
    try:
        with pytest.raises(RuntimeError, match=LAUNCH_ERROR):
            async with oauth_app.oauth_launch_guard(other):
                pass
        async with oauth_app.oauth_launch_guard(started) as state:
            assert state == {}
    finally:
        oauth_app._launched.reset(marker)


@pytest.mark.usefixtures("oauth_env")
def test_main_quiets_http_client_loggers(load_server, run_uvicorn):  # noqa: F811
    names = ("httpx", "httpx2", "httpcore", "httpcore2")
    saved = {n: logging.getLogger(n).level for n in names}
    try:
        for name in names:
            logging.getLogger(name).setLevel(logging.NOTSET)
        load_server(MCP_TRANSPORT="http").main()
        assert {n: logging.getLogger(n).level for n in names} == dict.fromkeys(
            names, logging.WARNING
        )
    finally:
        for name, level in saved.items():
            logging.getLogger(name).setLevel(level)
    run_uvicorn.assert_called_once()
