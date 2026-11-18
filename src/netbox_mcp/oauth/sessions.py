"""Session management: identity mapping, links and (later) session lifecycle.

``SessionManager`` is the single owner of per-session and per-user locking.
Later tasks add session creation, token exchange, verification and cleanup jobs
to this class; this first part maps IdP identities to NetBox users.
"""

import asyncio
import logging
import uuid
import weakref

from netbox_mcp.oauth import tokens as token_time
from netbox_mcp.oauth.broker import BrokerAmbiguous
from netbox_mcp.oauth.broker import BrokerConflict
from netbox_mcp.oauth.broker import BrokerDefinite
from netbox_mcp.oauth.broker import NetBoxBroker
from netbox_mcp.oauth.broker import NetBoxUser
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.idp import IdpClient
from netbox_mcp.oauth.idp import IdpLogin
from netbox_mcp.oauth.state import CleanupEntry
from netbox_mcp.oauth.state import Client
from netbox_mcp.oauth.state import Link
from netbox_mcp.oauth.state import OAuthState
from netbox_mcp.oauth.state import PendingCreate
from netbox_mcp.oauth.state import Session
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import StoreWriteError
from netbox_mcp.oauth.tokens import AccessTokens

logger = logging.getLogger(__name__)

NETBOX_TOKEN_TTL = 7 * 86400
RENEW_BELOW = 2 * 86400
CODE_TTL = 300
REFRESH_TTL = 30 * 86400

_NO_USER_MESSAGE = (
    "No active NetBox account matches your identity. "
    "Log in to NetBox via SSO once, then try again."
)

_MESSAGES = {
    "no_group": "Your account is not in a group allowed to use this server.",
    "no_netbox_user": _NO_USER_MESSAGE,
    "ambiguous_user": "More than one NetBox account matches your username.",
    "inactive_user": "Your NetBox account is inactive.",
    "superuser": "Superuser accounts cannot use this server.",
    "denylisted": "This NetBox account cannot use this server.",
    "linked_elsewhere": "This NetBox account is linked to a different identity.",
}


class LoginDenied(Exception):  # noqa: N818 - name fixed by the interface
    """The login is refused; ``reason_code`` is safe to log and show."""

    def __init__(self, reason_code: str, message: str | None = None) -> None:
        self.reason_code = reason_code
        self.message = message or _MESSAGES.get(reason_code, reason_code)
        super().__init__(self.message)


class LoginFailed(Exception):  # noqa: N818 - name fixed by the interface
    """The session could not be created (NetBox token creation failed)."""


class SessionManager:
    def __init__(
        self,
        config: OAuthConfig,
        store: StateStore,
        broker: NetBoxBroker,
        idp: IdpClient,
        tokens: AccessTokens,
    ) -> None:
        self.config = config
        self.store = store
        self.broker = broker
        self.idp = idp
        self.tokens = tokens
        # Locks vanish once no caller holds them, so the registries stay small.
        self._session_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )
        self._user_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )
        # Set whenever a cleanup entry is enqueued; the background job waits on it.
        self.cleanup_wanted = asyncio.Event()

    # ------------------------------------------------------------------ locks

    def lock_for(self, sid: str) -> asyncio.Lock:
        """Per-session lock. Hold the returned lock while using it."""
        return self._lock(self._session_locks, sid)

    def user_lock(self, user_key: str) -> asyncio.Lock:
        """Per-user lock (login mapping, token recovery)."""
        return self._lock(self._user_locks, user_key)

    @staticmethod
    def _lock(
        registry: "weakref.WeakValueDictionary[str, asyncio.Lock]", key: str
    ) -> asyncio.Lock:
        lock = registry.get(key)
        if lock is None:
            lock = registry[key] = asyncio.Lock()
        return lock

    # ------------------------------------------------------- identity mapping

    def _deny(self, reason: str, user_key: str) -> LoginDenied:
        logger.warning("oauth login denied: reason=%s user_key=%s", reason, user_key)
        return LoginDenied(reason)

    def _check_eligible(self, user: NetBoxUser, user_key: str) -> None:
        # Case-insensitive: the denylist is the only superuser guard when
        # is_superuser is unknown, so over-denying is the safe direction.
        denied = {name.casefold() for name in self.config.user_denylist}
        if user.username.casefold() in denied:
            raise self._deny("denylisted", user_key)
        # is_superuser is None when the REST API does not expose it; the
        # mandatory denylist covers that case.
        if user.is_superuser is True:
            raise self._deny("superuser", user_key)
        if not user.is_active:
            raise self._deny("inactive_user", user_key)

    async def _find(self, username: str, user_key: str) -> NetBoxUser | None:
        try:
            return await self.broker.find_user(username)
        except BrokerConflict:
            raise self._deny("ambiguous_user", user_key) from None

    async def resolve_identity(self, iss: str, login: IdpLogin) -> Link:
        """Map an IdP login to its NetBox user and return (recording) the link.

        An existing link is followed by NetBox user ID, so a renamed NetBox
        account stays linked (the stored username is refreshed), but the IdP
        username claim must still resolve to that same user: no match denies
        with ``no_netbox_user``, a different user with ``linked_elsewhere``.

        Raises:
            LoginDenied: With a reason code, if the identity is not eligible.
            BrokerUnavailable: If NetBox cannot be reached.
            StoreWriteError: If the link cannot be persisted.
        """
        user_key = f"{iss}|{login.sub}"
        if not set(login.groups) & set(self.config.allowed_groups):
            raise self._deny("no_group", user_key)

        async with self.user_lock(user_key):
            link = self.store.snapshot().links.get(user_key)
            if link is not None:
                return await self._existing(link, login, user_key)
            return await self._first_login(iss, login, user_key)

    async def _existing(self, link: Link, login: IdpLogin, user_key: str) -> Link:
        user = await self.broker.get_user(link.netbox_user_id)
        if user is None:
            raise self._deny("no_netbox_user", user_key)
        claimed = await self._find(login.username, user_key)
        if claimed is None:
            raise self._deny("no_netbox_user", user_key)
        if claimed.id != link.netbox_user_id:
            raise self._deny("linked_elsewhere", user_key)
        self._check_eligible(user, user_key)
        if user.username == link.netbox_username:
            return link
        async with self.store.mutate() as state:
            stored = state.links.get(user_key)
            if stored is None:
                raise self._deny("no_netbox_user", user_key)
            stored.netbox_username = user.username
            return stored.model_copy()

    async def _first_login(self, iss: str, login: IdpLogin, user_key: str) -> Link:
        user = await self._find(login.username, user_key)
        if user is None:
            raise self._deny("no_netbox_user", user_key)
        self._check_eligible(user, user_key)
        async with self.store.mutate() as state:
            if any(
                other.netbox_user_id == user.id and other.user_key != user_key
                for other in state.links.values()
            ):
                raise self._deny("linked_elsewhere", user_key)
            link = Link(
                user_key=user_key,
                iss=iss,
                sub=login.sub,
                netbox_user_id=user.id,
                netbox_username=user.username,
                created_at=token_time.now(),
            )
            state.links[user_key] = link
        logger.info("oauth link created: user_key=%s", user_key)
        return link

    # -------------------------------------------------------- session lifecycle

    @staticmethod
    def _description(client_name: str, sid: str, nonce: str) -> str:
        return f"NetBox MCP (OAuth) {client_name} {sid[:8]} {nonce}"

    @staticmethod
    def _enqueue(state: OAuthState, token_id: int, user_id: int, reason: str) -> None:
        entry_id = uuid.uuid4().hex
        state.cleanup[entry_id] = CleanupEntry(
            entry_id=entry_id,
            netbox_token_id=token_id,
            netbox_user_id=user_id,
            reason=reason,
            created_at=token_time.now(),
        )

    async def _drop_marker(self, nonce: str) -> None:
        """Best effort: a marker left behind is cleaned up by recovery."""
        try:
            async with self.store.mutate() as state:
                state.pending.pop(nonce, None)
        except StoreWriteError:
            logger.warning("oauth: could not drop pending marker %s", nonce[:4])

    async def create_session(
        self, link: Link, client: Client, idp_refresh_token: str
    ) -> tuple[Session, str]:
        """Create a session with its own NetBox token; return it and the code.

        Raises:
            LoginFailed: The token create outcome is unknown or refused.
            StoreWriteError: A store write failed. If it was the final one the
                marker is still on disk and recovery deletes any created token.
        """
        sid = uuid.uuid4().hex
        nonce = uuid.uuid4().hex
        now = token_time.now()
        async with self.store.mutate() as state:
            state.pending[nonce] = PendingCreate(
                nonce=nonce, netbox_user_id=link.netbox_user_id, sid=sid, created_at=now
            )
        try:
            created = await self.broker.create_token(
                link.netbox_user_id,
                self._description(client.client_name, sid, nonce),
                now + NETBOX_TOKEN_TTL,
            )
        except BrokerAmbiguous:
            logger.warning("oauth: token create outcome unknown sid=%s", sid[:8])
            raise LoginFailed("NetBox token creation failed") from None
        except BrokerDefinite:
            await self._drop_marker(nonce)
            logger.warning("oauth: token create refused sid=%s", sid[:8])
            raise LoginFailed("NetBox refused to create a token") from None
        code = token_time.new_secret()
        session = Session(
            sid=sid,
            user_key=link.user_key,
            client_id=client.client_id,
            netbox_user_id=link.netbox_user_id,
            created_at=now,
            code_hash=token_time.hash_secret(code),
            code_expires_at=now + CODE_TTL,
            refresh_deadline=now + REFRESH_TTL,
            idp_refresh_token=idp_refresh_token,
            last_idp_check_at=now,
            netbox_token=created.bearer,
            netbox_token_id=created.token_id,
            netbox_token_expires_at=created.expires_at,
            token_version=1,
        )
        async with self.store.mutate() as state:
            state.sessions[sid] = session
            state.pending.pop(nonce, None)
        logger.info("oauth session created sid=%s", sid[:8])
        return session.model_copy(deep=True), code

    def current_token(self, sid: str) -> tuple[str, int] | None:
        """Return ``(bearer, token_version)`` of the session, if it exists."""
        session = self.store.snapshot().sessions.get(sid)
        if session is None:
            return None
        return session.netbox_token, session.token_version

    async def renew_if_due(self, sid: str) -> None:
        """Replace the session's NetBox token if under 2 days remain.

        Failures keep the current token (it is still valid) and are logged.
        """
        async with self.lock_for(sid):
            snap = self.store.snapshot()
            session = snap.sessions.get(sid)
            if session is None or session.netbox_token_expires_at is None:
                return
            now = token_time.now()
            if session.netbox_token_expires_at - now >= RENEW_BELOW:
                return
            client = snap.clients.get(session.client_id)
            name = client.client_name if client else session.client_id
            nonce = uuid.uuid4().hex
            async with self.store.mutate() as state:
                state.pending[nonce] = PendingCreate(
                    nonce=nonce,
                    netbox_user_id=session.netbox_user_id,
                    sid=sid,
                    created_at=now,
                )
            try:
                created = await self.broker.create_token(
                    session.netbox_user_id,
                    self._description(name, sid, nonce),
                    now + NETBOX_TOKEN_TTL,
                )
            except BrokerDefinite:
                await self._drop_marker(nonce)
                logger.warning("oauth: renewal refused sid=%s", sid[:8])
                return
            except Exception:  # ambiguous or unavailable: keep marker and token
                logger.warning("oauth: renewal failed sid=%s", sid[:8], exc_info=True)
                return
            async with self.store.mutate() as state:
                state.pending.pop(nonce, None)
                stored = state.sessions.get(sid)
                if stored is None:
                    self._enqueue(
                        state, created.token_id, session.netbox_user_id, "orphaned"
                    )
                else:
                    self._enqueue(
                        state, stored.netbox_token_id, stored.netbox_user_id, "renewed"
                    )
                    stored.netbox_token = created.bearer
                    stored.netbox_token_id = created.token_id
                    stored.netbox_token_expires_at = created.expires_at
                    stored.token_version += 1
            self.cleanup_wanted.set()

    async def end_session(self, sid: str, reason: str) -> None:
        """End a session and enqueue its NetBox token. Idempotent.

        Takes the session lock; use :meth:`end_session_locked` when already
        holding it.
        """
        async with self.lock_for(sid):
            await self.end_session_locked(sid, reason)

    async def end_session_locked(self, sid: str, reason: str) -> None:
        async with self.store.mutate() as state:
            session = state.sessions.pop(sid, None)
            if session is None:
                return
            self._enqueue(
                state, session.netbox_token_id, session.netbox_user_id, reason
            )
        logger.info("oauth session ended sid=%s reason=%s", sid[:8], reason)
        self.cleanup_wanted.set()
