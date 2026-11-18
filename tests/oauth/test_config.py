import base64

import pytest
from fastmcp.server.auth.auth import TokenVerifier

from netbox_mcp.auth import build_auth_provider
from netbox_mcp.models import NetBoxConfig
from netbox_mcp.models import TransportConfig
from netbox_mcp.oauth.config import get_oauth_config_from_env

from .conftest import OAUTH_ENV

REQUIRED = [name for name in OAUTH_ENV if name != "OIDC_ISSUER"] + ["OAUTH_STATE_PATH"]


@pytest.fixture
def env(monkeypatch, tmp_path):
    for name, value in OAUTH_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("OAUTH_STATE_PATH", str(tmp_path / "state.json"))
    return monkeypatch


def test_unset_issuer_returns_none(monkeypatch):
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    assert get_oauth_config_from_env() is None


@pytest.mark.usefixtures("env")
def test_valid_env_and_defaults():
    config = get_oauth_config_from_env()
    assert config.base_path == "/mcp"
    assert config.username_claim == "preferred_username"
    assert config.groups_claim == "groups"
    assert config.allowed_groups == ["netbox-users"]
    assert config.state_key == b"k" * 32
    assert config.auth_debug is False
    shown = repr(config)
    for secret in (
        "client-secret",
        "nbt_broker.secret",
        OAUTH_ENV["OAUTH_SIGNING_KEY"],
    ):
        assert secret not in shown
    assert "kkkk" not in shown
    assert repr(b"k" * 32) not in shown


def test_optional_values(env):
    env.setenv("OIDC_ALLOWED_GROUPS", "a, b")
    env.setenv("NETBOX_USER_DENYLIST", "root,svc")
    env.setenv("AUTH_DEBUG", "true")
    config = get_oauth_config_from_env()
    assert config.allowed_groups == ["a", "b"]
    assert config.user_denylist == {"root", "svc"}
    assert config.auth_debug is True


@pytest.mark.parametrize("name", REQUIRED)
def test_missing_required_var_names_it(env, name):
    env.delenv(name)
    with pytest.raises(ValueError, match=name):
        get_oauth_config_from_env()


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/mcp",
        "https://example.com/mcp/",
        "https://example.com/mcp?a=1",
        "https://example.com/mcp#x",
        "https://u@example.com/mcp",
        "https://exa mple.com/mcp",
        "https://example.com/m\tcp",
        "https://example.com/m\x01cp",
    ],
)
def test_public_url_rules(env, url):
    env.setenv("MCP_PUBLIC_URL", url)
    with pytest.raises(ValueError, match="MCP_PUBLIC_URL"):
        get_oauth_config_from_env()


def test_public_url_accepts_loopback_http(env):
    env.setenv("MCP_PUBLIC_URL", "http://127.0.0.1:8000/mcp")
    assert get_oauth_config_from_env().base_path == "/mcp"


@pytest.mark.parametrize(("size", "ok"), [(31, False), (32, True), (64, True)])
def test_signing_key_min_32_bytes(env, size, ok):
    env.setenv("OAUTH_SIGNING_KEY", base64.b64encode(b"x" * size).decode())
    if ok:
        get_oauth_config_from_env()
    else:
        with pytest.raises(ValueError, match="OAUTH_SIGNING_KEY"):
            get_oauth_config_from_env()


def test_signing_key_must_be_base64(env):
    env.setenv("OAUTH_SIGNING_KEY", "not base64 !!" * 5)
    with pytest.raises(ValueError, match="OAUTH_SIGNING_KEY"):
        get_oauth_config_from_env()


@pytest.mark.parametrize("value", [base64.b64encode(b"k" * 31).decode(), "%%%"])
def test_state_key_must_be_32_bytes_base64(env, value):
    env.setenv("OAUTH_STATE_KEY", value)
    with pytest.raises(ValueError, match="OAUTH_STATE_KEY"):
        get_oauth_config_from_env()


def test_state_path_parent_must_exist(env, tmp_path):
    env.setenv("OAUTH_STATE_PATH", str(tmp_path / "missing" / "state.json"))
    with pytest.raises(ValueError, match="OAUTH_STATE_PATH"):
        get_oauth_config_from_env()


def _netbox(**kwargs):
    return NetBoxConfig(netbox_url="https://netbox.test", token="t", **kwargs)


async def test_oauth_provider_denies_every_token(oauth_config):
    provider = build_auth_provider(
        _netbox(), TransportConfig(transport_type="http"), oauth_config
    )
    assert isinstance(provider, TokenVerifier)
    assert await provider.verify_token("anything") is None


def test_oauth_excludes_passthrough_and_static_bearer(oauth_config):
    http = TransportConfig(transport_type="http")
    with pytest.raises(ValueError, match="NETBOX_TOKEN_PASSTHROUGH"):
        build_auth_provider(_netbox(token_passthrough=True), http, oauth_config)
    bearer = TransportConfig(transport_type="http", http_bearer_token="x")
    with pytest.raises(ValueError, match="MCP_HTTP_BEARER_TOKEN"):
        build_auth_provider(_netbox(), bearer, oauth_config)


@pytest.mark.parametrize("kind", ["stdio", "sse"])
def test_oauth_requires_http_transport(oauth_config, kind):
    with pytest.raises(ValueError, match="MCP_TRANSPORT=http"):
        build_auth_provider(
            _netbox(), TransportConfig(transport_type=kind), oauth_config
        )


def test_max_session_days_default_and_override(env):
    env.delenv("OAUTH_MAX_SESSION_DAYS", raising=False)
    assert get_oauth_config_from_env().max_session_days == 365
    env.setenv("OAUTH_MAX_SESSION_DAYS", "1")
    assert get_oauth_config_from_env().max_session_days == 1


@pytest.mark.parametrize("value", ["0", "-5", "abc"])
def test_max_session_days_invalid(env, value):
    env.setenv("OAUTH_MAX_SESSION_DAYS", value)
    with pytest.raises(ValueError, match="OAUTH_MAX_SESSION_DAYS"):
        get_oauth_config_from_env()
