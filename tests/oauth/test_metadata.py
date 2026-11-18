import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from netbox_mcp.oauth.metadata import ROOT_ALIAS_PATHS
from netbox_mcp.oauth.metadata import authorization_server_metadata
from netbox_mcp.oauth.metadata import challenge_header
from netbox_mcp.oauth.metadata import metadata_routes
from netbox_mcp.oauth.metadata import protected_resource_metadata

PRM = [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/mcp/.well-known/oauth-protected-resource",
]
AS = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/mcp",
    "/mcp/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration/mcp",
    "/mcp/.well-known/openid-configuration",
]


@pytest.fixture
def client(oauth_config):
    return TestClient(Starlette(routes=metadata_routes(oauth_config)))


def test_all_discovery_paths_identical(client, oauth_config):
    prm = [client.get(p) for p in PRM]
    assert all(r.status_code == 200 for r in prm)
    assert all(r.json() == prm[0].json() for r in prm)
    assert prm[0].json() == protected_resource_metadata(oauth_config)
    as_docs = [client.get(p) for p in AS]
    assert all(r.status_code == 200 for r in as_docs)
    assert all(r.json() == as_docs[0].json() for r in as_docs)
    assert as_docs[0].json() != prm[0].json()
    assert client.get("/.well-known/openid-configuration").status_code == 404


def test_as_metadata_values(oauth_config):
    base = oauth_config.public_url
    doc = authorization_server_metadata(oauth_config)
    assert doc["issuer"] == base
    assert protected_resource_metadata(oauth_config)["resource"] == base
    assert doc["registration_endpoint"] == f"{base}/oauth/register"
    assert doc["authorization_endpoint"] == f"{base}/oauth/authorize"
    assert doc["token_endpoint"] == f"{base}/oauth/token"
    assert doc["revocation_endpoint"] == f"{base}/oauth/revoke"
    assert doc["scopes_supported"] == ["netbox"]
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert doc["token_endpoint_auth_methods_supported"] == ["none"]
    assert doc["authorization_response_iss_parameter_supported"] is True
    assert doc["response_types_supported"] == ["code"]
    assert doc["grant_types_supported"] == ["authorization_code", "refresh_token"]


def test_challenge_header_exact(oauth_config):
    cfg = oauth_config.model_copy(
        update={"public_url": "https://inventory.example.com/mcp"}
    )
    expected = (
        'Bearer realm="https://inventory.example.com/mcp", '
        'resource_metadata="https://inventory.example.com/mcp/.well-known/oauth-protected-resource", '
        'scope="netbox"'
    )
    assert challenge_header(cfg, invalid_token=False) == expected
    assert (
        challenge_header(cfg, invalid_token=True)
        == expected + ', error="invalid_token"'
    )


def test_root_alias_paths():
    assert ROOT_ALIAS_PATHS == (
        "/register",
        "/authorize",
        "/token",
        "/revoke",
        "/oauth/revoke",
    )
