"""Discovery documents, the 401 challenge and their routes (spec 5.1, 7.1)."""

from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from netbox_mcp.oauth.config import OAuthConfig

ROOT_ALIAS_PATHS = ("/register", "/authorize", "/token", "/revoke", "/oauth/revoke")
SCOPE = "netbox"
PRM_SUFFIX = "/.well-known/oauth-protected-resource"
_AS = "/.well-known/oauth-authorization-server"
_OIDC = "/.well-known/openid-configuration"


def protected_resource_metadata(config: OAuthConfig) -> dict[str, Any]:
    return {
        "resource": config.public_url,
        "authorization_servers": [config.public_url],
        "scopes_supported": [SCOPE],
        "bearer_methods_supported": ["header"],
    }


def authorization_server_metadata(config: OAuthConfig) -> dict[str, Any]:
    base = config.public_url
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "scopes_supported": [SCOPE],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "authorization_response_iss_parameter_supported": True,
    }


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def challenge_header(config: OAuthConfig, *, invalid_token: bool) -> str:
    """WWW-Authenticate value; ``error`` only for a presented invalid token."""
    parts = [
        f'realm="{_quote(config.public_url)}"',
        f'resource_metadata="{_quote(config.public_url + PRM_SUFFIX)}"',
        f'scope="{SCOPE}"',
    ]
    if invalid_token:
        parts.append('error="invalid_token"')
    return "Bearer " + ", ".join(parts)


def metadata_routes(config: OAuthConfig) -> list[Route]:
    base = config.base_path
    prm = protected_resource_metadata(config)
    as_doc = authorization_server_metadata(config)

    async def prm_endpoint(_request: Request) -> JSONResponse:
        return JSONResponse(prm)

    async def as_endpoint(_request: Request) -> JSONResponse:
        return JSONResponse(as_doc)

    prm_paths = list(
        dict.fromkeys([PRM_SUFFIX, f"{PRM_SUFFIX}{base}", f"{base}{PRM_SUFFIX}"])
    )
    as_paths = [_AS, f"{_AS}{base}", f"{base}{_AS}"]
    if base:  # without a base path these would collapse onto a root OIDC document
        as_paths += [f"{_OIDC}{base}", f"{base}{_OIDC}"]
    as_paths = list(dict.fromkeys(as_paths))
    routes = [Route(p, prm_endpoint, methods=["GET"]) for p in prm_paths]
    routes += [Route(p, as_endpoint, methods=["GET"]) for p in as_paths]
    return routes
