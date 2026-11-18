"""Outer app of OAuth mode: OAuth routes, MCP endpoint rules, lifespan (spec 4, 7).

``main()`` serves this app instead of FastMCP's own. It hosts the metadata and
authorization-server routes and mounts the FastMCP app, and one ASGI layer in
front of it applies the MCP endpoint rules in the order of spec 7.4:

1. Origin allowlist (every method, when an ``Origin`` header is present).
2. Canonical path: ``<base>`` and ``<base>/`` are served (the latter rewritten
   internally, never redirected); ``//mcp``, ``/mcp//`` and case variants 404.
3. Authentication with this server's access token and the exact challenge of
   spec 7.1. FastMCP keeps the same verifier as ``auth=`` only so that tools
   see the ``AccessToken``; its own 401 answer is unreachable from here.
4. Method: only POST; GET and DELETE answer 405 with ``Allow: POST``.
5. Body parsing and the protocol-version rule (spec 7.2, as adapted to the
   SDK's two protocol eras).

FastMCP's Host/Origin guard is switched off for the mounted app: this layer is
the single Origin check and has to run before authentication. The ``Host``
header is not checked, because the server sits behind a reverse proxy that
sets it.
"""

import contextlib
import contextvars
import datetime
import json
import logging
import re
from collections.abc import AsyncGenerator
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any
from urllib.parse import urlsplit

import httpx2
from fastmcp import FastMCP
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS
from mcp_types.version import KNOWN_PROTOCOL_VERSIONS
from mcp_types.version import LATEST_HANDSHAKE_VERSION
from mcp_types.version import SUPPORTED_PROTOCOL_VERSIONS
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.responses import Response
from starlette.routing import Mount
from starlette.types import ASGIApp
from starlette.types import Message
from starlette.types import Receive
from starlette.types import Scope
from starlette.types import Send

from netbox_mcp import netbox_client
from netbox_mcp.models import NetBoxConfig
from netbox_mcp.oauth import tokens as token_time
from netbox_mcp.oauth.broker import NetBoxBroker
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.idp import IdpClient
from netbox_mcp.oauth.metadata import challenge_header
from netbox_mcp.oauth.metadata import metadata_routes
from netbox_mcp.oauth.routes import oauth_routes
from netbox_mcp.oauth.sessions import SessionManager
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import StoreError
from netbox_mcp.oauth.tokens import AccessTokens
from netbox_mcp.oauth.verifier import OAuthTokenVerifier

logger = logging.getLogger(__name__)

LAUNCH_ERROR = "OAuth mode must be started with the netbox-mcp entry point"
FIXED_ORIGINS = ("https://claude.ai", "https://claude.com", "https://chatgpt.com")
MAX_BODY_BYTES = 10 * 1024 * 1024
# Body key that marks a request of the SDK's modern (2026) protocol era.
MODERN_VERSION_META = "io.modelcontextprotocol/protocolVersion"
_PROTOCOL_HEADER = b"mcp-protocol-version"
_DISCONNECTED = object()
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
# Future protocol dates tolerated beyond the newest the SDK knows (spec 7.2).
FUTURE_TOLERANCE_YEARS = 2

# The FastMCP server the outer lifespan is starting; its OAuth-mode lifespan
# refuses to start unless it is that very server (``fastmcp run``).
_launched: contextvars.ContextVar[FastMCP | None] = contextvars.ContextVar(
    "netbox_mcp_oauth_launched", default=None
)
# HTTP client loggers print full request URLs, query strings included.
HTTP_CLIENT_LOGGERS = ("httpx", "httpx2", "httpcore", "httpcore2")


@contextlib.asynccontextmanager
async def oauth_launch_guard(server: FastMCP) -> AsyncGenerator[dict[str, Any]]:
    """FastMCP lifespan for OAuth mode: only the outer app may start it.

    Raises:
        RuntimeError: When started by anything but :func:`build_oauth_app`'s
            lifespan, e.g. ``fastmcp run`` / ``fastmcp.json``.
    """
    if _launched.get() is not server:
        raise RuntimeError(LAUNCH_ERROR)
    yield {}


def configure_oauth_logging() -> None:
    """Keep URLs with query strings out of the log in OAuth mode (spec 9).

    The HTTP client libraries log every request URL at INFO; NetBox and IdP
    lookups carry user names and filters in the query.
    """
    for name in HTTP_CLIENT_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


@contextlib.asynccontextmanager
async def start_background(_manager: SessionManager) -> AsyncGenerator[None]:
    """Hook for background jobs running alongside the server (none yet)."""
    yield


# ------------------------------------------------------------- endpoint rules


def _origin_key(value: str) -> str | None:
    """``scheme://host[:port]`` in lower case, or None if not an origin."""
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    default = 443 if parts.scheme == "https" else 80
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    suffix = f":{port}" if port is not None and port != default else ""
    return f"{parts.scheme}://{host}{suffix}"


def allowed_origins(config: OAuthConfig) -> frozenset[str]:
    """The Origin allowlist of spec 7.3."""
    candidates = [*FIXED_ORIGINS, config.public_url, *config.extra_origins]
    return frozenset(key for c in candidates if (key := _origin_key(c)) is not None)


def _tolerated_future(version: str, today: datetime.date) -> bool:
    """A real calendar date newer than every known version, at most two years
    ahead (spec 7.2)."""
    if not _DATE.fullmatch(version):
        return False
    try:
        day = datetime.date.fromisoformat(version)
    except ValueError:
        return False
    try:
        limit = today.replace(year=today.year + FUTURE_TOLERANCE_YEARS)
    except ValueError:  # 29 February
        limit = today.replace(year=today.year + FUTURE_TOLERANCE_YEARS, day=28)
    return version > max(KNOWN_PROTOCOL_VERSIONS) and day <= limit


def protocol_decision(header: str | None, body: Any, today: datetime.date) -> str:
    """``"pass"``, ``"rewrite"`` (to the newest handshake version) or ``"reject"``.

    The SDK serves 2025-style requests only for handshake versions and routes
    every other header to its 2026 handler, which knows no ``initialize``.
    Clients that send ``2026-07-28`` (or a later date) with 2025-style bodies
    are therefore served as ``LATEST_HANDSHAKE_VERSION``. Requests in the 2026
    shape carry their version in the body and pass unchanged, but only with
    a supported header: the SDK routes on the header alone.
    """
    message = body if isinstance(body, dict) else {}
    params = message.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    if isinstance(meta, dict) and MODERN_VERSION_META in meta:
        return "pass" if header in SUPPORTED_PROTOCOL_VERSIONS else "reject"
    if header is None or header in HANDSHAKE_PROTOCOL_VERSIONS:
        return "pass"
    if header in SUPPORTED_PROTOCOL_VERSIONS or _tolerated_future(header, today):
        return "rewrite"
    if message.get("method") == "initialize":
        return "rewrite"  # never rejected for its header
    return "reject"


def _today() -> datetime.date:
    return datetime.datetime.fromtimestamp(token_time.now(), datetime.UTC).date()


def _printable(value: str, limit: int = 100) -> str:
    return "".join(c if c.isprintable() else "?" for c in value[:limit])


class McpEndpointLayer:
    """The outer ASGI layer in front of the MCP endpoint (see module doc)."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: OAuthConfig,
        verifier: OAuthTokenVerifier,
        mcp_path: str,
    ) -> None:
        self.app = app
        self.config = config
        self.verifier = verifier
        self.mcp_path = mcp_path
        self.origins = allowed_origins(config)

    def _classify(self, path: str) -> str | None:
        """``"mcp"``, ``"noncanonical"`` or None (not the MCP endpoint)."""
        canonical = self.mcp_path
        if path == canonical or (canonical != "/" and path == canonical + "/"):
            return "mcp"
        collapsed = re.sub("/+", "/", path).rstrip("/") or "/"
        if collapsed.lower() == canonical.lower():
            return "noncanonical"
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        root = scope.get("root_path", "")
        path = scope["path"]
        if root and path.startswith(root):
            path = path[len(root) :]  # the path below the mount point
        kind = self._classify(path)
        if kind is None:
            await self.app(scope, receive, send)
            return
        if kind == "noncanonical":
            await Response("Not Found", 404, media_type="text/plain")(
                scope, receive, send
            )
            return
        headers = Headers(scope=scope)
        origin = headers.get("origin")
        if origin is not None and _origin_key(origin) not in self.origins:
            logger.warning("mcp request refused: origin not allowed")
            await Response("Forbidden Origin", 403, media_type="text/plain")(
                scope, receive, send
            )
            return
        scope = dict(scope)
        scope["path"] = root + self.mcp_path
        scope["raw_path"] = scope["path"].encode()
        await self._authenticated(scope, receive, send, headers)

    async def _authenticated(
        self, scope: Scope, receive: Receive, send: Send, headers: Headers
    ) -> None:
        scheme, _, token = headers.get("authorization", "").partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            await self._challenge(scope, receive, send, invalid=False)
            return
        try:
            access = await self.verifier.verify_token(token)
        except StoreError:
            logger.warning("mcp request: state store unavailable")
            await JSONResponse(
                {"error": "temporarily_unavailable"},
                503,
                headers={"Cache-Control": "no-store"},
            )(scope, receive, send)
            return
        if access is None:
            await self._challenge(scope, receive, send, invalid=True)
            return
        if scope["method"] != "POST":
            await Response(
                status_code=405, headers={"Allow": "POST"}, media_type="text/plain"
            )(scope, receive, send)
            return
        body = await self._read_body(receive)
        if body is None:
            await Response("Request body too large", 413, media_type="text/plain")(
                scope, receive, send
            )
            return
        if not isinstance(body, bytes):  # _DISCONNECTED: nobody to answer
            logger.info("mcp request: client disconnected before the body arrived")
            return
        try:
            message = json.loads(body)
        except ValueError:
            message = None  # the SDK answers the parse error
        header = headers.get("mcp-protocol-version")
        decision = protocol_decision(header, message, _today())
        if decision == "reject":
            await self._unsupported_version(scope, receive, send, message)
            return
        if decision == "rewrite":
            scope["headers"] = [
                (k, LATEST_HANDSHAKE_VERSION.encode())
                if k == _PROTOCOL_HEADER
                else (k, v)
                for k, v in scope["headers"]
            ]
        self._log_tool_call(scope, access.claims, message)
        marker = self.verifier.remember(token, access)
        try:
            await self.app(scope, _replay(body, receive), send)
        finally:
            self.verifier.forget(marker)

    async def _challenge(
        self, scope: Scope, receive: Receive, send: Send, *, invalid: bool
    ) -> None:
        error = "invalid_token" if invalid else "unauthorized"
        await JSONResponse(
            {"error": error},
            401,
            headers={
                "WWW-Authenticate": challenge_header(self.config, invalid_token=invalid)
            },
        )(scope, receive, send)

    async def _unsupported_version(
        self, scope: Scope, receive: Receive, send: Send, message: Any
    ) -> None:
        rid = message.get("id") if isinstance(message, dict) else None
        supported = ", ".join(SUPPORTED_PROTOCOL_VERSIONS)
        await JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": rid,
                "error": {
                    "code": -32600,
                    "message": "Unsupported MCP-Protocol-Version; supported: "
                    + supported,
                },
            },
            400,
        )(scope, receive, send)

    @staticmethod
    async def _read_body(receive: Receive) -> bytes | object | None:
        """The whole body; None if too large, ``_DISCONNECTED`` if the client
        went away before it was complete."""
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return _DISCONNECTED
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                return None
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        return b"".join(chunks)

    def _log_tool_call(
        self, scope: Scope, claims: dict[str, Any], message: Any
    ) -> None:
        if not isinstance(message, dict) or message.get("method") != "tools/call":
            return
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        sid = str(claims.get("sid", ""))
        manager = self.verifier.manager
        user, client = manager.session_labels(sid) if manager else ("-", "-")
        logger.info(
            "tool_call user=%s client=%s sid=%s tool=%s path=%s",
            _printable(user),
            _printable(client),
            sid[:8],
            _printable(name) if isinstance(name, str) else "-",
            scope["path"],
        )


def _replay(body: bytes, receive: Receive) -> Receive:
    """Hand the already-read body to the app, then defer to ``receive``."""
    sent = False

    async def replay() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay


# ---------------------------------------------------------------- the app


Background = Callable[[SessionManager], AbstractAsyncContextManager[None]]


def build_oauth_app(
    mcp: FastMCP,
    config: OAuthConfig,
    *,
    netbox_config: NetBoxConfig,
    idp_transport: httpx2.AsyncBaseTransport | None = None,
    netbox_transport: httpx2.AsyncBaseTransport | None = None,
    background: Background = start_background,
) -> Starlette:
    """Build the app ``main()`` serves in OAuth mode.

    Nothing is opened here; the lifespan opens the store, discovers the IdP,
    binds the verifier and starts the FastMCP app and the background hook,
    and undoes it all in reverse on shutdown.

    Args:
        mcp: The FastMCP server; its ``auth`` must be an
            :class:`OAuthTokenVerifier` and its lifespan
            :func:`oauth_launch_guard`.
        config: OAuth settings.
        netbox_config: NetBox connection settings for the service credential.
        idp_transport: Transport for IdP requests (tests).
        netbox_transport: Transport for service-credential requests (tests).
        background: Context manager run for the server's lifetime with the
            session manager (background jobs).

    Raises:
        ValueError: If ``mcp.auth`` is not an :class:`OAuthTokenVerifier`.
    """
    verifier = mcp.auth
    if not isinstance(verifier, OAuthTokenVerifier):
        raise ValueError("OAuth mode needs FastMCP(auth=OAuthTokenVerifier(...))")
    mcp_path = config.base_path or "/"
    mcp_app = mcp.http_app(
        path=mcp_path,
        stateless_http=True,
        json_response=True,
        host_origin_protection=False,
    )
    base_routes = [*metadata_routes(config), Mount("/", app=mcp_app)]

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncGenerator[None]:
        store = StateStore.open(config.state_path, config.state_key)
        try:
            idp = IdpClient(config, transport=idp_transport)
            await idp.discover()
            broker = NetBoxBroker(
                netbox_config,
                config.broker_token.get_secret_value(),
                transport=netbox_transport,
            )
            manager = SessionManager(config, store, broker, idp, AccessTokens(config))
            # The AS routes need the manager, which exists only from here on.
            app.router.routes[:] = [
                *metadata_routes(config),
                *oauth_routes(config, manager),
                Mount("/", app=mcp_app),
            ]
            app.state.oauth_manager = manager
            verifier.bind(manager)
            netbox_client.set_oauth_sessions(manager)
            launched = _launched.set(mcp)
            try:
                async with mcp_app.lifespan(mcp_app), background(manager):
                    logger.info("OAuth mode: serving MCP at %s", config.public_url)
                    yield
            finally:
                _launched.reset(launched)
                netbox_client.set_oauth_sessions(None)
                verifier.bind(None)
                app.router.routes[:] = base_routes
        finally:
            await store.aclose()

    app = Starlette(
        routes=list(base_routes),
        middleware=[
            Middleware(
                McpEndpointLayer,
                config=config,
                verifier=verifier,
                mcp_path=mcp_path,
            )
        ],
        lifespan=lifespan,
    )
    app.state.netbox_mcp_outer = True
    return app
