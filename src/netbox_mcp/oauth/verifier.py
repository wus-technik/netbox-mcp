"""Verifier for the server's own access tokens (spec 4, 5.4, 6.2).

The verifier is created when ``server.py`` is imported, without touching the
state store, and bound to the :class:`SessionManager` by the outer app's
lifespan. Unbound it rejects every token, so ``fastmcp run`` never serves the
tools unauthenticated.

The ``AccessToken`` it returns carries the session's *NetBox* token, which the
NetBox client sends on the user's behalf. Its claims are built here from the
session, never copied from the JWT.
"""

import contextvars
import logging
from typing import TYPE_CHECKING

from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.auth import TokenVerifier

from netbox_mcp.netbox_client import SESSION_ENDED_CLAIM
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.store import StoreError
from netbox_mcp.oauth.tokens import SCOPE
from netbox_mcp.oauth.tokens import AccessTokens
from netbox_mcp.oauth.tokens import InvalidToken

if TYPE_CHECKING:
    from netbox_mcp.oauth.sessions import SessionManager

logger = logging.getLogger(__name__)

OAUTH_AUTH_MODE = "oauth"

# Result of the outer layer's check for the request being served. FastMCP's own
# bearer middleware verifies the same token again further in; this lets it
# reuse the result instead of repeating the session lookup and renewal check.
_verified: contextvars.ContextVar[tuple[str, AccessToken] | None] = (
    contextvars.ContextVar("netbox_mcp_oauth_verified", default=None)
)


class OAuthTokenVerifier(TokenVerifier):
    """Accepts this server's access JWTs for sessions that still exist."""

    def __init__(self, config: OAuthConfig) -> None:
        super().__init__(required_scopes=[SCOPE])
        self._config = config
        self._tokens = AccessTokens(config)
        self._manager: SessionManager | None = None

    @property
    def manager(self) -> "SessionManager | None":
        return self._manager

    def bind(self, manager: "SessionManager | None") -> None:
        """Attach the session manager (outer lifespan); ``None`` detaches it."""
        self._manager = manager

    @staticmethod
    def remember(token: str, access: AccessToken) -> contextvars.Token:
        """Cache ``access`` for the current request; reset with :meth:`forget`."""
        return _verified.set((token, access))

    @staticmethod
    def forget(marker: contextvars.Token) -> None:
        _verified.reset(marker)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return the session's ``AccessToken``, or None if not acceptable.

        Raises:
            StoreError: The state store failed; the caller answers 503.
        """
        cached = _verified.get()
        if cached is not None and cached[0] == token:
            return cached[1]
        manager = self._manager
        if manager is None:
            return None
        try:
            claims = self._tokens.verify(token)
        except InvalidToken:
            return None
        sid = claims["sid"]
        session = manager.store.snapshot().sessions.get(sid)
        # sub and client_id must match the session (spec 5.4): a token for
        # another client of the same user does not unlock this session.
        if (
            session is None
            or session.client_id != claims["client_id"]
            or session.user_key != claims.get("sub")
            or not session.code_redeemed
        ):
            return None
        current = manager.current_token(sid)
        ended = False
        if current is not None and manager.renewal_due(sid):
            try:
                ended = await manager.renew_if_due(sid)
            except StoreError:
                # The current token is still valid; renewal is retried on use.
                logger.warning("oauth: token renewal failed sid=%s", sid[:8])
                ended = False
            if not ended:
                current = manager.current_token(sid)
            # Otherwise NetBox has just confirmed that this token is deleted or
            # disabled and the session is ended. The dead bearer is not handed
            # on: the token is empty and flagged, the NetBox client fails the
            # call with the "reconnect" tool error of spec 6.3 without a
            # request to NetBox, and the next request is answered 401.
        if current is None:
            return None
        bearer, version = current
        if ended:
            return AccessToken(
                token="",
                client_id=session.client_id,
                scopes=[SCOPE],
                expires_at=int(claims["exp"]),
                claims={
                    "netbox_mcp_auth_mode": OAUTH_AUTH_MODE,
                    SESSION_ENDED_CLAIM: True,
                    "sub": session.user_key,
                    "sid": sid,
                },
            )
        return AccessToken(
            token=bearer,
            client_id=session.client_id,
            scopes=[SCOPE],
            expires_at=int(claims["exp"]),
            claims={
                "netbox_mcp_auth_mode": OAUTH_AUTH_MODE,
                "sub": session.user_key,
                "sid": sid,
                "token_version": version,
            },
        )
