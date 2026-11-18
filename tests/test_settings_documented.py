"""Every setting read from the environment must be documented."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
# netbox_client.py reads the settings; utils.py holds the transport helpers
# shared with the container healthcheck.
SOURCES = [
    (ROOT / "src" / "netbox_mcp" / name).read_text(encoding="utf-8")
    for name in ("netbox_client.py", "utils.py", "oauth/config.py")
]
# Settings are read with os.getenv or the env_* helpers in utils.py.
ENV_VAR_READ = re.compile(r'(?:os\.getenv|env_[a-z]+)\(\s*"([A-Z_]+)"')
ENV_VARS = sorted({name for src in SOURCES for name in ENV_VAR_READ.findall(src)})


def test_env_vars_found():
    assert "NETBOX_URL" in ENV_VARS
    assert "NETBOX_VERIFY_SSL" in ENV_VARS
    assert "RATE_LIMIT_MAX_REQUESTS" in ENV_VARS
    assert "DRY_RUN_MODE" in ENV_VARS
    assert "MCP_HTTP_PORT" in ENV_VARS


@pytest.mark.parametrize("name", ENV_VARS)
def test_env_var_in_env_example(name):
    assert name in (ROOT / ".env.example").read_text(encoding="utf-8")


@pytest.mark.parametrize("name", ENV_VARS)
def test_env_var_in_readme(name):
    assert name in (ROOT / "README.md").read_text(encoding="utf-8")


# The registry manifest configures a local install; binding and HTTP auth are
# left to the operator, as in the MCP registry examples.
REGISTRY_EXCLUDED = {
    "MCP_HTTP_HOST",
    "MCP_HTTP_BEARER_TOKEN",
    "NETBOX_TOKEN_PASSTHROUGH",
    # OAuth mode: server-side deployment settings, like the HTTP auth above.
    "OIDC_ISSUER",
    "MCP_PUBLIC_URL",
    "OIDC_CLIENT_ID",
    "OIDC_CLIENT_SECRET",
    "OIDC_ALLOWED_GROUPS",
    "OIDC_USERNAME_CLAIM",
    "OIDC_GROUPS_CLAIM",
    "OIDC_EXTRA_SCOPES",
    "NETBOX_TOKEN_BROKER_TOKEN",
    "OAUTH_SIGNING_KEY",
    "OAUTH_STATE_KEY",
    "OAUTH_STATE_PATH",
    "EXTRA_REDIRECT_URIS",
    "EXTRA_ORIGINS",
    "NETBOX_USER_DENYLIST",
    "AUTH_DEBUG",
    "OAUTH_MAX_SESSION_DAYS",
}


@pytest.mark.parametrize("name", sorted(set(ENV_VARS) - REGISTRY_EXCLUDED))
def test_env_var_in_server_json(name):
    assert name in (ROOT / "server.json").read_text(encoding="utf-8")
