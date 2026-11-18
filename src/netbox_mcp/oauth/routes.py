"""Registration, authorization, IdP callback and consent endpoints.

Spec sections 5.2 and 5.3. The IdP is reached through ``manager.idp`` (the
``IdpClient`` the ``SessionManager`` was built with), so the routes and the
session lifecycle always talk to the same, already discovered client.

A login flow goes through these phases, all kept in ``OAuthState.flows``:

1. ``/authorize`` stores the flow (``claimed=False``, ``user_key=None``) and
   sets the flow cookie, whose value is the flow ID.
2. ``/callback`` claims the flow (``claimed=True``) in a store write before the
   first await, so concurrent completions cannot both proceed. It exchanges the
   IdP code and maps the identity. With an existing consent grant it creates the
   session at once; otherwise it hands the flow over to consent by storing the
   user key and the IdP refresh token (only now, after eligibility passed) and
   releasing the claim.
3. ``/consent`` (GET) shows the page; (POST) claims the flow again, records the
   grant on approval and creates the session.

Every terminal outcome deletes the flow, so a later ``/authorize`` starts from
a clean slate. Token and revocation endpoints are added by a later task.
"""

import base64
import hashlib
import hmac
import html
import json
import logging
import re
import uuid
from collections.abc import Awaitable
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.responses import JSONResponse
from starlette.responses import RedirectResponse
from starlette.responses import Response
from starlette.routing import Route

from netbox_mcp.oauth import tokens as token_time
from netbox_mcp.oauth.broker import BrokerError
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.idp import IdpRejected
from netbox_mcp.oauth.idp import IdpUnavailable
from netbox_mcp.oauth.redirects import matches_registered
from netbox_mcp.oauth.redirects import validate_registered_uri
from netbox_mcp.oauth.sessions import LoginDenied
from netbox_mcp.oauth.sessions import LoginFailed
from netbox_mcp.oauth.sessions import SessionManager
from netbox_mcp.oauth.state import Client
from netbox_mcp.oauth.state import Flow
from netbox_mcp.oauth.state import Grant
from netbox_mcp.oauth.state import Link
from netbox_mcp.oauth.store import StoreWriteError

logger = logging.getLogger(__name__)

FLOW_COOKIE = "__Secure-netbox-mcp-flow"
FLOW_TTL = 600
MAX_FLOWS = 1000
MAX_CLIENTS = 1000
MAX_REDIRECT_URIS = 20
CLIENT_NAME_MAX = 100
REGISTER_LIMIT = 10
REGISTER_WINDOW = 60.0
MAX_REGISTER_BODY = 64 * 1024
MAX_FORM_BODY = 4 * 1024
_RATE_KEYS_MAX = 10_000
GRANT_TYPES = ["authorization_code", "refresh_token"]
RESPONSE_TYPES = ["code"]

# S256 challenge: base64url of a SHA-256 digest, without padding.
_CHALLENGE_RE = re.compile(r"[A-Za-z0-9_-]{43}")

_CSS = (
    "body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;"
    "padding:0 1rem;color:#1f2328;line-height:1.5}"
    "h1{font-size:1.4rem}.muted{color:#59636e}code{font-size:.95em}"
    "button{font-size:1rem;padding:.45rem 1.1rem;margin-right:.6rem}"
)
_CSS_HASH = base64.b64encode(hashlib.sha256(_CSS.encode()).digest()).decode()
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        f"default-src 'none'; style-src 'sha256-{_CSS_HASH}'; "
        "base-uri 'none'; frame-ancestors 'none'"
    ),
}


def consent_csrf(config: OAuthConfig, flow_id: str) -> str:
    """CSRF value of the consent form: HMAC(signing key, ``consent:<flow_id>``)."""
    key = base64.b64decode(config.signing_key.get_secret_value())
    digest = hmac.new(key, f"consent:{flow_id}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _clean_name(raw: Any) -> str:
    """Flatten whitespace and control characters; cap the length."""
    if not isinstance(raw, str):
        return ""
    flat = " ".join("".join(c if c.isprintable() else " " for c in raw).split())
    return flat[:CLIENT_NAME_MAX].rstrip()


def _client_ip(request: Request) -> str:
    # The ASGI peer only: no proxy header is trusted.
    return request.client.host if request.client else "unknown"


async def _read_body(request: Request, limit: int) -> bytes | None:
    """The request body, or None if it exceeds ``limit`` bytes."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


class _RateLimiter:
    """Sliding window per key, in memory (per process)."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit = limit
        self.window = window
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = token_time.now()
        cutoff = now - self.window
        if len(self._hits) > _RATE_KEYS_MAX:
            self._hits = {
                k: kept
                for k, v in self._hits.items()
                if (kept := [t for t in v if t > cutoff])
            }
        hits = [t for t in self._hits.get(key, ()) if t > cutoff]
        allowed = len(hits) < self.limit
        if allowed:
            hits.append(now)
        self._hits[key] = hits
        return allowed


class _FlowUnusable(Exception):  # noqa: N818 - internal control flow
    """The flow is missing, expired, or not in the expected phase."""


class _Full(Exception):  # noqa: N818 - internal control flow
    """A capacity limit was reached."""


def _secure(response: Response) -> Response:
    response.headers.update(SECURITY_HEADERS)
    return response


def _page(title: str, body: str, status: int = 200) -> Response:
    document = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
        f"<body>{body}</body></html>"
    )
    return _secure(HTMLResponse(document, status_code=status))


def _error_page(status: int, error: str, message: str) -> Response:
    body = (
        "<h1>Sign-in failed</h1>"
        f"<p>{html.escape(message)}</p>"
        f'<p class="muted">Error: <code>{html.escape(error)}</code>. '
        "Start the connection again from your client.</p>"
    )
    return _page("Sign-in failed", body, status)


def _json_error(status: int, error: str, description: str) -> Response:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


class OAuthEndpoints:
    """Request handlers of the authorization server (one instance per app)."""

    def __init__(self, config: OAuthConfig, manager: SessionManager) -> None:
        self.config = config
        self.manager = manager
        self.store = manager.store
        self.base = config.base_path
        self.callback_url = f"{config.public_url}/oauth/callback"
        self.consent_url = f"{config.public_url}/oauth/consent"
        self.cookie_path = f"{self.base}/oauth"
        self._register_limiter = _RateLimiter(REGISTER_LIMIT, REGISTER_WINDOW)

    # ----------------------------------------------------------- cookies

    def _set_flow_cookie(self, response: Response, flow_id: str) -> None:
        # Built by hand: Starlette writes "SameSite=lax". Never Strict, the
        # cookie must survive the cross-site return from the IdP.
        response.headers.append(
            "set-cookie",
            f"{FLOW_COOKIE}={flow_id}; HttpOnly; Secure; SameSite=Lax; "
            f"Path={self.cookie_path}; Max-Age={FLOW_TTL}",
        )

    def _clear_flow_cookie(self, response: Response) -> Response:
        response.headers.append(
            "set-cookie",
            f"{FLOW_COOKIE}=; HttpOnly; Secure; SameSite=Lax; "
            f"Path={self.cookie_path}; Max-Age=0",
        )
        return response

    # ------------------------------------------------------------- flows

    @staticmethod
    def _fresh(flow: Flow) -> bool:
        return token_time.now() - flow.created_at < FLOW_TTL

    async def _claim(self, flow_id: str, *, consent: bool, grant: bool = False) -> Flow:
        """Atomically take over a flow before any await on IdP or NetBox.

        ``consent`` selects the phase: False for the IdP callback (no user
        yet), True for the consent step. ``grant`` records the consent grant
        in the same write.

        Raises:
            _FlowUnusable: Missing, expired, already claimed or wrong phase.
            StoreWriteError: The claim could not be persisted.
        """
        async with self.store.mutate() as state:
            flow = state.flows.get(flow_id)
            if (
                flow is None
                or flow.claimed
                or (flow.user_key is not None) != consent
                or not self._fresh(flow)
            ):
                raise _FlowUnusable
            flow.claimed = True
            if grant and flow.user_key is not None:
                state.grants[f"{flow.user_key}|{flow.client_id}"] = Grant(
                    user_key=flow.user_key,
                    client_id=flow.client_id,
                    created_at=token_time.now(),
                )
            return flow.model_copy()

    async def _drop_flow(self, flow_id: str, client_id: str | None = None) -> None:
        """Delete a finished flow (best effort; expired flows are purged too)."""
        try:
            async with self.store.mutate() as state:
                state.flows.pop(flow_id, None)
                client = state.clients.get(client_id) if client_id else None
                if client is not None:
                    client.last_used_at = token_time.now()
        except StoreWriteError:
            logger.warning("oauth: could not delete a finished login flow")

    # ---------------------------------------------------------- redirects

    def _to_client(self, flow: Flow, params: dict[str, str], status: int) -> Response:
        query = dict(params)
        if flow.state is not None:
            query["state"] = flow.state
        query["iss"] = self.config.public_url
        sep = "&" if "?" in flow.redirect_uri else "?"
        response = RedirectResponse(
            f"{flow.redirect_uri}{sep}{urlencode(query)}", status_code=status
        )
        return self._clear_flow_cookie(_secure(response))

    async def _deny(self, flow: Flow, reason: str, status: int) -> Response:
        await self._drop_flow(flow.flow_id)
        logger.warning(
            "login_denied reason=%s client=%s", reason, self._client_name(flow)
        )
        return self._to_client(flow, {"error": "access_denied"}, status)

    async def _fail(
        self, flow: Flow, status: int, error: str, message: str
    ) -> Response:
        await self._drop_flow(flow.flow_id)
        return self._clear_flow_cookie(_error_page(status, error, message))

    def _client_name(self, flow: Flow) -> str:
        client = self.store.snapshot().clients.get(flow.client_id)
        return client.client_name if client else "?"

    # -------------------------------------------------------- /register

    async def register(self, request: Request) -> Response:
        if not self._register_limiter.allow(_client_ip(request)):
            return _json_error(
                429, "invalid_client_metadata", "too many registrations, retry later"
            )
        body = await _read_body(request, MAX_REGISTER_BODY)
        if body is None:
            return _json_error(400, "invalid_client_metadata", "request too large")
        try:
            meta = json.loads(body)
        except ValueError:
            return _json_error(400, "invalid_client_metadata", "body is not JSON")
        if not isinstance(meta, dict):
            return _json_error(
                400, "invalid_client_metadata", "body is not a JSON object"
            )

        uris = meta.get("redirect_uris")
        if (
            not isinstance(uris, list)
            or not uris
            or not all(isinstance(u, str) for u in uris)
        ):
            return _json_error(
                400,
                "invalid_redirect_uri",
                "redirect_uris must be a non-empty list of strings",
            )
        if len(uris) > MAX_REDIRECT_URIS:
            return _json_error(
                400,
                "invalid_redirect_uri",
                f"at most {MAX_REDIRECT_URIS} redirect URIs per client",
            )
        for uri in uris:
            problem = validate_registered_uri(uri, self.config.extra_redirect_uris)
            if problem is not None:
                return _json_error(400, "invalid_redirect_uri", problem)

        now = token_time.now()
        client = Client(
            client_id=uuid.uuid4().hex,
            client_name=_clean_name(meta.get("client_name")),
            redirect_uris=list(dict.fromkeys(uris)),
            created_at=now,
            last_used_at=now,
        )
        try:
            async with self.store.mutate() as state:
                if len(state.clients) >= MAX_CLIENTS:
                    raise _Full
                state.clients[client.client_id] = client
        except _Full:
            logger.warning("oauth: client registration cap reached")
            return _json_error(
                429, "invalid_client_metadata", "registration limit reached"
            )
        except StoreWriteError:
            return _json_error(
                503, "temporarily_unavailable", "registration could not be stored"
            )
        logger.info("client_registered client=%s", client.client_name or "-")
        return JSONResponse(
            {
                "client_id": client.client_id,
                "client_id_issued_at": int(now),
                "client_name": client.client_name,
                "redirect_uris": client.redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": GRANT_TYPES,
                "response_types": RESPONSE_TYPES,
            },
            status_code=201,
            headers={"Cache-Control": "no-store"},
        )

    # ------------------------------------------------------- /authorize

    def _authorize_problem(
        self, params: Any, client: Client | None
    ) -> tuple[str, str] | None:
        """Validation of spec 5.3 step 1; ``(error, message)`` or None."""
        if client is None:
            return "invalid_request", "Unknown client."
        redirect_uri = params.get("redirect_uri")
        if not redirect_uri or not matches_registered(
            redirect_uri, client.redirect_uris
        ):
            return "invalid_request", "The redirect URI is not registered."
        if params.get("response_type") != "code":
            return "unsupported_response_type", "Only response_type=code is supported."
        if not params.get("state"):
            return "invalid_request", "The state parameter is required."
        if params.get("code_challenge_method") != "S256":
            return (
                "invalid_request",
                "PKCE with code_challenge_method=S256 is required.",
            )
        if not _CHALLENGE_RE.fullmatch(params.get("code_challenge") or ""):
            return "invalid_request", "A valid S256 code_challenge is required."
        resource = params.get("resource")
        if resource is not None:
            stripped = resource.removesuffix("/")
            if stripped != self.config.public_url:
                return "invalid_target", "The requested resource is not this server."
        return None

    async def authorize(self, request: Request) -> Response:
        params = request.query_params
        client = self.store.snapshot().clients.get(params.get("client_id") or "")
        problem = self._authorize_problem(params, client)
        if problem is not None or client is None:
            return _error_page(
                400, *(problem or ("invalid_request", "Unknown client."))
            )

        now = token_time.now()
        flow = Flow(
            flow_id=token_time.new_secret(),
            client_id=client.client_id,
            redirect_uri=params["redirect_uri"],
            state=params["state"],
            code_challenge=params["code_challenge"],
            resource=params.get("resource"),
            idp_state=token_time.new_secret(),
            idp_nonce=token_time.new_secret(),
            idp_verifier=token_time.new_secret(),
            created_at=now,
        )
        try:
            async with self.store.mutate() as state:
                for flow_id in [
                    k for k, v in state.flows.items() if now - v.created_at >= FLOW_TTL
                ]:
                    del state.flows[flow_id]
                if len(state.flows) >= MAX_FLOWS:
                    raise _Full
                state.flows[flow.flow_id] = flow
        except _Full:
            logger.warning("oauth: too many login flows in progress")
            return _error_page(
                503, "temporarily_unavailable", "Too many sign-ins in progress."
            )
        except StoreWriteError:
            return _error_page(
                503, "temporarily_unavailable", "The sign-in could not be started."
            )
        target = self.manager.idp.authorization_url(
            flow.idp_state, flow.idp_nonce, flow.idp_verifier, self.callback_url
        )
        response = _secure(RedirectResponse(target, status_code=302))
        self._set_flow_cookie(response, flow.flow_id)
        return response

    # -------------------------------------------------------- /callback

    async def callback(self, request: Request) -> Response:
        flow_id = request.cookies.get(FLOW_COOKIE) or ""
        known = self.store.snapshot().flows.get(flow_id)
        if known is None:
            return _error_page(
                400, "invalid_request", "This sign-in has expired or is unknown."
            )
        params = request.query_params
        if not hmac.compare_digest(
            (params.get("state") or "").encode(), known.idp_state.encode()
        ):
            return _error_page(
                400, "invalid_request", "The sign-in response does not match."
            )
        try:
            flow = await self._claim(flow_id, consent=False)
        except _FlowUnusable:
            return _error_page(
                400,
                "invalid_request",
                "This sign-in has already been completed or has expired.",
            )
        except StoreWriteError:
            return _error_page(
                503, "temporarily_unavailable", "The sign-in could not be continued."
            )

        if params.get("error"):
            return await self._deny(flow, "idp_error", 302)
        code = params.get("code")
        if not code:
            return await self._fail(
                flow, 400, "invalid_request", "The identity provider sent no code."
            )
        try:
            login = await self.manager.idp.exchange_code(
                code, flow.idp_verifier, self.callback_url, flow.idp_nonce
            )
        except IdpRejected as exc:
            return await self._deny(flow, f"idp_rejected ({exc.reason})", 302)
        except IdpUnavailable as exc:
            logger.warning("oauth login: identity provider unavailable: %s", exc.reason)
            return await self._fail(
                flow,
                503,
                "temporarily_unavailable",
                "The identity provider is not reachable. Try again later.",
            )
        try:
            link = await self.manager.resolve_identity(self.config.issuer_url, login)
        except LoginDenied as exc:
            return await self._deny(flow, exc.reason_code, 302)
        except BrokerError:
            logger.warning("oauth login: NetBox unavailable during user mapping")
            return await self._fail(
                flow,
                503,
                "temporarily_unavailable",
                "NetBox is not reachable. Try again later.",
            )
        except StoreWriteError:
            return await self._fail(
                flow, 503, "temporarily_unavailable", "The sign-in could not be saved."
            )

        grants = self.store.snapshot().grants
        if f"{link.user_key}|{flow.client_id}" in grants:
            return await self._complete(flow, link, login.refresh_token, 302)

        # Hand over to consent: only now, with eligibility passed, is the IdP
        # refresh token stored (encrypted, with the flow) until the session.
        try:
            async with self.store.mutate() as state:
                stored = state.flows.get(flow_id)
                if stored is None:
                    raise _FlowUnusable
                stored.claimed = False
                stored.user_key = link.user_key
                stored.idp_refresh_token = login.refresh_token
        except (_FlowUnusable, StoreWriteError):
            return await self._fail(
                flow, 503, "temporarily_unavailable", "The sign-in could not be saved."
            )
        return _secure(RedirectResponse(self.consent_url, status_code=303))

    # --------------------------------------------------------- /consent

    def _consent_flow(self, request: Request) -> Flow | None:
        flow = self.store.snapshot().flows.get(request.cookies.get(FLOW_COOKIE) or "")
        if (
            flow is None
            or flow.claimed
            or flow.user_key is None
            or not self._fresh(flow)
        ):
            return None
        return flow

    async def consent(self, request: Request) -> Response:
        if request.method == "POST":
            return await self._consent_post(request)
        flow = self._consent_flow(request)
        client = self.store.snapshot().clients.get(flow.client_id) if flow else None
        if flow is None or client is None:
            return _error_page(
                400, "invalid_request", "This sign-in has expired or is unknown."
            )
        name = client.client_name or "(no name given)"
        host = urlsplit(flow.redirect_uri).netloc
        csrf = consent_csrf(self.config, flow.flow_id)
        body = (
            "<h1>Allow access to NetBox?</h1>"
            f"<p>The application <strong>{html.escape(name)}</strong> "
            '<span class="muted">(unverified name)</span> wants to use NetBox '
            "with your account.</p>"
            f"<p>It will receive access at <code>{html.escape(host)}</code>.</p>"
            f'<form method="post" action="{html.escape(self.consent_url)}">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            '<button type="submit" name="decision" value="approve">Allow</button>'
            '<button type="submit" name="decision" value="deny">Deny</button>'
            "</form>"
        )
        return _page("Allow access", body)

    async def _consent_post(self, request: Request) -> Response:
        raw = await _read_body(request, MAX_FORM_BODY)
        form = parse_qs(raw.decode("utf-8", "replace")) if raw is not None else {}
        flow_id = request.cookies.get(FLOW_COOKIE) or ""
        sent = (form.get("csrf") or [""])[0]
        expected = consent_csrf(self.config, flow_id)
        if not flow_id or not hmac.compare_digest(sent.encode(), expected.encode()):
            return _error_page(403, "access_denied", "The form could not be verified.")
        decision = (form.get("decision") or [""])[0]
        if decision not in ("approve", "deny"):
            return _error_page(400, "invalid_request", "No decision was made.")
        try:
            flow = await self._claim(flow_id, consent=True, grant=decision == "approve")
        except _FlowUnusable:
            return _error_page(
                400,
                "invalid_request",
                "This sign-in has already been completed or has expired.",
            )
        except StoreWriteError:
            return _error_page(
                503, "temporarily_unavailable", "The decision could not be saved."
            )
        if decision == "deny":
            return await self._deny(flow, "consent_denied", 303)
        link = self.store.snapshot().links.get(flow.user_key or "")
        if link is None or flow.idp_refresh_token is None:
            return await self._fail(
                flow, 400, "invalid_request", "This sign-in is no longer valid."
            )
        return await self._complete(flow, link, flow.idp_refresh_token, 303)

    # ------------------------------------------------------ completion

    async def _complete(
        self, flow: Flow, link: Link, idp_refresh_token: str, status: int
    ) -> Response:
        """Create the session and NetBox token, then redirect with the code."""
        client = self.store.snapshot().clients.get(flow.client_id)
        if client is None:
            return await self._fail(
                flow, 400, "invalid_client", "The client registration has expired."
            )
        try:
            session, code = await self.manager.create_session(
                link, client, idp_refresh_token
            )
        except LoginFailed:
            return await self._fail(
                flow,
                502,
                "server_error",
                "NetBox could not create an access token. Try again later.",
            )
        except BrokerError:
            return await self._fail(
                flow,
                503,
                "temporarily_unavailable",
                "NetBox is not reachable. Try again later.",
            )
        except StoreWriteError:
            return await self._fail(
                flow, 503, "temporarily_unavailable", "The sign-in could not be saved."
            )
        await self._drop_flow(flow.flow_id, flow.client_id)
        logger.info(
            "login_completed user=%s client=%s sid=%s",
            link.netbox_username,
            client.client_name or "-",
            session.sid[:8],
        )
        return self._to_client(flow, {"code": code}, status)


def oauth_routes(config: OAuthConfig, manager: SessionManager) -> list[Route]:
    """Routes under ``<base>/oauth/`` plus the root aliases with the same handlers.

    The root aliases reuse the very handler objects (spec 5.1). The token and
    revocation endpoints are added here by a later task.
    """
    endpoints = OAuthEndpoints(config, manager)
    base = f"{config.base_path}/oauth"
    handlers: list[tuple[str, Callable[[Request], Awaitable[Response]], list[str]]] = [
        ("register", endpoints.register, ["POST"]),
        ("authorize", endpoints.authorize, ["GET"]),
        ("callback", endpoints.callback, ["GET"]),
        ("consent", endpoints.consent, ["GET", "POST"]),
    ]
    routes = [Route(f"{base}/{name}", fn, methods=m) for name, fn, m in handlers]
    for name, fn, methods in handlers:
        if name in ("register", "authorize") and f"/{name}" != f"{base}/{name}":
            routes.append(Route(f"/{name}", fn, methods=methods))
    return routes
