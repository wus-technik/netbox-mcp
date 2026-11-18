"""OAuth mode configuration, read from the environment.

OAuth mode is on when ``OIDC_ISSUER`` is set; everything else is then required
or optional as listed in the design spec (section 9). Invalid values raise
``ValueError`` naming the variable, so startup fails with a clear message.
"""

import base64
import binascii
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel
from pydantic import Field
from pydantic import SecretStr

from netbox_mcp.utils import env_bool
from netbox_mcp.utils import env_str

# Plain http is accepted for the public URL only on these literal loopback hosts.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
MIN_SIGNING_KEY_BYTES = 32
STATE_KEY_BYTES = 32


class OAuthConfig(BaseModel):
    """Settings of the built-in OAuth authorization server."""

    public_url: str
    issuer_url: str
    client_id: str
    client_secret: SecretStr
    allowed_groups: list[str]
    username_claim: str = "preferred_username"
    groups_claim: str = "groups"
    extra_scopes: list[str] = []
    broker_token: SecretStr
    signing_key: SecretStr
    state_key: bytes = Field(repr=False)
    state_path: Path
    extra_redirect_uris: list[str] = []
    extra_origins: list[str] = []
    user_denylist: set[str] = set()
    auth_debug: bool = False

    @property
    def base_path(self) -> str:
        """Path of the public URL, e.g. ``/mcp`` (no trailing slash)."""
        return urlsplit(self.public_url).path


def _required(name: str, value: str | None) -> str:
    if value is None:
        raise ValueError(f"{name} is required when OIDC_ISSUER is set")
    return value


def _csv(value: str | None) -> list[str]:
    if value is None:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _decode_key(name: str, value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{name} must be base64") from None


def _check_public_url(name: str, value: str) -> str:
    try:
        parts = urlsplit(value)
        host = parts.hostname
        _ = parts.port  # raises ValueError on an invalid port
    except ValueError:
        raise ValueError(f"{name} is not a valid URL: {value!r}") from None
    if any(c.isspace() or not c.isprintable() for c in value):
        raise ValueError(f"{name} must not contain whitespace or control characters")
    if parts.scheme not in ("http", "https") or not host:
        raise ValueError(f"{name} must be an absolute http(s) URL, got {value!r}")
    if parts.scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise ValueError(f"{name} must use https unless the host is loopback")
    if "@" in parts.netloc:
        raise ValueError(f"{name} must not contain credentials")
    if "?" in value or "#" in value:
        raise ValueError(f"{name} must not contain a query or fragment")
    if parts.path.endswith("/"):
        raise ValueError(f"{name} must not end with a slash")
    return value


def get_oauth_config_from_env() -> OAuthConfig | None:
    """Read the OAuth settings; None when OAuth mode is off.

    Raises:
        ValueError: With the variable name, if a required value is missing or
            any value is invalid.
    """
    issuer = env_str("OIDC_ISSUER")
    if issuer is None:
        return None

    public_url = _check_public_url(
        "MCP_PUBLIC_URL", _required("MCP_PUBLIC_URL", env_str("MCP_PUBLIC_URL"))
    )
    client_id = _required("OIDC_CLIENT_ID", env_str("OIDC_CLIENT_ID"))
    client_secret = _required("OIDC_CLIENT_SECRET", env_str("OIDC_CLIENT_SECRET"))
    allowed_groups = _csv(
        _required("OIDC_ALLOWED_GROUPS", env_str("OIDC_ALLOWED_GROUPS"))
    )
    if not allowed_groups:
        raise ValueError("OIDC_ALLOWED_GROUPS must name at least one group")
    broker_token = _required(
        "NETBOX_TOKEN_BROKER_TOKEN", env_str("NETBOX_TOKEN_BROKER_TOKEN")
    )

    signing_key = _required("OAUTH_SIGNING_KEY", env_str("OAUTH_SIGNING_KEY"))
    if len(_decode_key("OAUTH_SIGNING_KEY", signing_key)) < MIN_SIGNING_KEY_BYTES:
        raise ValueError(
            f"OAUTH_SIGNING_KEY must decode to at least {MIN_SIGNING_KEY_BYTES} bytes"
        )
    state_key = _decode_key(
        "OAUTH_STATE_KEY", _required("OAUTH_STATE_KEY", env_str("OAUTH_STATE_KEY"))
    )
    if len(state_key) != STATE_KEY_BYTES:
        raise ValueError(f"OAUTH_STATE_KEY must decode to {STATE_KEY_BYTES} bytes")

    state_path = Path(_required("OAUTH_STATE_PATH", env_str("OAUTH_STATE_PATH")))
    if not state_path.parent.is_dir():
        raise ValueError(
            f"OAUTH_STATE_PATH: directory {str(state_path.parent)!r} does not exist"
        )

    return OAuthConfig(
        public_url=public_url,
        issuer_url=issuer,
        client_id=client_id,
        client_secret=SecretStr(client_secret),
        allowed_groups=allowed_groups,
        username_claim=env_str("OIDC_USERNAME_CLAIM", "preferred_username"),
        groups_claim=env_str("OIDC_GROUPS_CLAIM", "groups"),
        extra_scopes=_csv(env_str("OIDC_EXTRA_SCOPES")),
        broker_token=SecretStr(broker_token),
        signing_key=SecretStr(signing_key),
        state_key=state_key,
        state_path=state_path,
        extra_redirect_uris=_csv(env_str("EXTRA_REDIRECT_URIS")),
        extra_origins=_csv(env_str("EXTRA_ORIGINS")),
        user_denylist=set(_csv(env_str("NETBOX_USER_DENYLIST"))),
        auth_debug=env_bool("AUTH_DEBUG", False),
    )
