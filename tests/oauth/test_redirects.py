import pytest

from netbox_mcp.oauth.redirects import matches_registered
from netbox_mcp.oauth.redirects import validate_registered_uri

CLAUDE = "https://claude.ai/api/mcp/auth_callback"


@pytest.mark.parametrize(
    "uri",
    [
        "http://localhost:53111/callback",
        "http://127.0.0.1:1/cb",
        CLAUDE,
        "https://claude.com/api/mcp/auth_callback",
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://chatgpt.com/connector/oauth/abc_123-X",
    ],
)
def test_allowlist_accepts(uri):
    assert validate_registered_uri(uri, []) is None


@pytest.mark.parametrize(
    "uri",
    [
        "http://[::1]:5/cb",
        "http://LOCALHOST:5/cb",
        "http://127.0.0.2:5/cb",
        "http://foo.localhost:5/cb",
        "https://chatgpt.com/connector/oauth/a/b",
        "https://evil.example/cb",
        CLAUDE + "?iss=x",
        CLAUDE + "?Code=x",
        CLAUDE + "?error_description=x",
        CLAUDE + "#f",
        "http://u@localhost:5/cb",
        "http://localhost:5/a/%2e%2e/b",
        "http://localhost:5/a/../b",
        "http://localhost:5/a b",
        "http://localhost:5/a\\b",
        "javascript:x",
        "http://localhost:5/" + "a" * 2049,
    ],
)
def test_allowlist_rejects(uri):
    assert validate_registered_uri(uri, []) is not None


def test_extra_exact_only():
    extra = ["https://app.example.com/cb"]
    assert validate_registered_uri("https://app.example.com/cb", extra) is None
    assert validate_registered_uri("https://app.example.com/cb2", extra) is not None


def test_loopback_port_may_differ_only_port():
    reg = ["http://localhost:5000/cb"]
    assert matches_registered("http://localhost:6000/cb", reg)
    assert not matches_registered("http://localhost:6000/other", reg)
    assert not matches_registered("http://127.0.0.1:5000/cb", reg)
    assert not matches_registered("http://localhost:5000/cb?x=1", reg)
    assert matches_registered(CLAUDE, [CLAUDE])
    assert not matches_registered(
        "https://claude.ai:444/api/mcp/auth_callback", [CLAUDE]
    )
