"""Redirect URI validation for dynamic client registration (spec section 5.2).

Own literal host check instead of fastmcp's ``is_loopback_host``, which also
accepts ``::1``, ``127.0.0.2`` and ``*.localhost``.
"""

import re
from urllib.parse import parse_qsl
from urllib.parse import unquote
from urllib.parse import urlsplit

MAX_URI_LENGTH = 2048

_LOOPBACK_RE = re.compile(r"^http://(?:localhost|127\.0\.0\.1)(?::(\d{1,5}))?(?:/|$)")
_LOOPBACK_PORT_RE = re.compile(
    r"^(http://(?:localhost|127\.0\.0\.1))(?::\d{1,5})?(?=/|$)"
)
_FIXED_URIS = frozenset(
    {
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
        "https://chatgpt.com/connector_platform_oauth_redirect",
    }
)
_CHATGPT_RE = re.compile(r"https://chatgpt\.com/connector/oauth/[A-Za-z0-9_-]{1,128}")
_RESERVED_PARAMS = ("iss", "code", "state")


def _has_dot_segment(path: str) -> bool:
    return any(unquote(segment) in (".", "..") for segment in path.split("/"))


def _generic_error(uri: str) -> str | None:
    if not uri or len(uri) > MAX_URI_LENGTH:
        return f"redirect URI must be 1 to {MAX_URI_LENGTH} characters"
    if any(c.isspace() or not c.isprintable() or c == "\\" for c in uri):
        return "redirect URI contains whitespace, control characters or a backslash"
    if "#" in uri:
        return "redirect URI must not contain a fragment"
    try:
        parts = urlsplit(uri)
        _ = parts.port
    except ValueError:
        return "redirect URI is not a valid URL"
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return "redirect URI must be an absolute http(s) URL"
    if "@" in parts.netloc:
        return "redirect URI must not contain credentials"
    if _has_dot_segment(parts.path):
        return "redirect URI must not contain dot segments"
    for name, _value in parse_qsl(parts.query, keep_blank_values=True):
        lowered = name.lower()
        if lowered in _RESERVED_PARAMS or lowered.startswith("error"):
            return f"redirect URI must not use the reserved parameter {name!r}"
    return None


def _is_loopback(uri: str) -> bool:
    match = _LOOPBACK_RE.match(uri)
    if match is None:
        return False
    port = match.group(1)
    return port is None or 0 < int(port) <= 65535


def validate_registered_uri(uri: str, extra: list[str]) -> str | None:
    """Return an error message for a redirect URI that may not be registered."""
    error = _generic_error(uri)
    if error is not None:
        return error
    if (
        _is_loopback(uri)
        or uri in _FIXED_URIS
        or _CHATGPT_RE.fullmatch(uri)
        or uri in extra
    ):
        return None
    return "redirect URI is not allowed"


def matches_registered(uri: str, registered: list[str]) -> bool:
    """Exact match against the client's URIs; a loopback port may differ."""
    if uri in registered:
        return True
    if not _is_loopback(uri):
        return False
    stripped = _LOOPBACK_PORT_RE.sub(r"\1", uri)
    return any(
        _is_loopback(reg) and _LOOPBACK_PORT_RE.sub(r"\1", reg) == stripped
        for reg in registered
    )
