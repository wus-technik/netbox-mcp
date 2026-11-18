"""Session management: identity mapping, session lifecycle and token grants.

``SessionManager`` is the single owner of per-session and per-user locking. It
maps IdP identities to NetBox users, creates sessions with their own NetBox
token, redeems authorization codes, rotates refresh tokens (spec 5.4, 6.4) and
revokes sessions (spec 5.5).
"""

import asyncio
import base64
import hashlib
import hmac
import logging
import uuid
import weakref
from typing import Literal

from netbox_mcp.oauth import tokens as token_time
from netbox_mcp.oauth.broker import BrokerAmbiguous
from netbox_mcp.oauth.broker import BrokerConflict
from netbox_mcp.oauth.broker import BrokerDefinite
from netbox_mcp.oauth.broker import BrokerError
from netbox_mcp.oauth.broker import BrokerUnavailable
from netbox_mcp.oauth.broker import NetBoxBroker
from netbox_mcp.oauth.broker import NetBoxUser
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.idp import IdpClient
from netbox_mcp.oauth.idp import IdpLogin
from netbox_mcp.oauth.idp import IdpRejected
from netbox_mcp.oauth.idp import IdpUnavailable
from netbox_mcp.oauth.state import Client
from netbox_mcp.oauth.state import Link
from netbox_mcp.oauth.state import OAuthState
from netbox_mcp.oauth.state import PendingCreate
from netbox_mcp.oauth.state import Replay
from netbox_mcp.oauth.state import Session
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import StoreError
from netbox_mcp.oauth.store import StoreWriteError
from netbox_mcp.oauth.tokens import SCOPE
from netbox_mcp.oauth.tokens import AccessTokens
from netbox_mcp.oauth.tokens import InvalidToken

logger = logging.getLogger(__name__)

NETBOX_TOKEN_TTL = 7 * 86400
RENEW_BELOW = 2 * 86400
CODE_TTL = 300
REFRESH_TTL = 30 * 86400
REPLAY_WINDOW = 30
DESCRIPTION_MAX = 200
# Orphan sessions, pending-create markers and login flows share a 10 minute age.
ORPHAN_TTL = 600
MARKER_MIN_AGE = 600
FLOW_MAX_AGE = 600
CLIENT_IDLE_TTL = 30 * 86400
CLEANUP_WARN_AGE = 7 * 86400
CLEANUP_WARN_EVERY = 86400

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


class GrantError(Exception):
    """An OAuth token request is refused (RFC 6749 section 5.2, HTTP 400)."""

    def __init__(self, error: str, description: str) -> None:
        super().__init__(description)
        self.error = error
        self.description = description


class GrantUnavailable(Exception):  # noqa: N818 - mirrors IdpUnavailable
    """IdP or NetBox could not answer; the client retries (HTTP 503)."""


class _Reject(Exception):  # noqa: N818 - internal control flow
    """A refresh check failed definitively: end the session."""

    def __init__(self, reason: str, *, eligibility: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        # Eligibility lost (spec 5.3.5): the user's consent grants are dropped.
        self.eligibility = eligibility


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
        # hash -> sid for code, current, replay-slot and spent refresh hashes.
        # Built from the store on first use and updated only after the store
        # write succeeded, so it never runs ahead of disk. Entries are hints:
        # every hit is re-checked against the session under its lock.
        self._hash_index: dict[str, str] | None = None
        # Background jobs are single-flight: a trigger while one runs is dropped.
        self._job_locks: dict[str, asyncio.Lock] = {}

    # ------------------------------------------------------------------ locks

    def lock_for(self, sid: str) -> asyncio.Lock:
        """Per-session lock. Hold the returned lock while using it."""
        return self._lock(self._session_locks, sid)

    def _netbox_user_lock(self, netbox_user_id: int) -> asyncio.Lock:
        """Per-NetBox-user lock around token creation and recovery.

        Lock order: session lock before this lock; never the reverse.
        """
        return self.user_lock(f"netbox-user|{netbox_user_id}")

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

    def _ineligible(self, user: NetBoxUser) -> str | None:
        """Reason code if the NetBox user may not use this server, else None."""
        # Case-insensitive: the denylist is the only superuser guard when
        # is_superuser is unknown, so over-denying is the safe direction.
        denied = {name.casefold() for name in self.config.user_denylist}
        if user.username.casefold() in denied:
            return "denylisted"
        # is_superuser is None when the REST API does not expose it; the
        # mandatory denylist covers that case.
        if user.is_superuser is True:
            return "superuser"
        if not user.is_active:
            return "inactive_user"
        return None

    def _check_eligible(self, user: NetBoxUser, user_key: str) -> None:
        reason = self._ineligible(user)
        if reason is not None:
            raise self._deny(reason, user_key)

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
        prefix = "NetBox MCP (OAuth) "
        tail = f" {sid[:8]} {nonce}"
        # client_name is attacker-chosen (dynamic registration): flatten
        # whitespace and control characters, and fit NetBox's 200 char limit.
        clean = " ".join(
            "".join(" " if not c.isprintable() else c for c in client_name).split()
        )
        room = max(DESCRIPTION_MAX - len(prefix) - len(tail), 0)
        return f"{prefix}{clean[:room].rstrip()}{tail}"

    @staticmethod
    def _enqueue(state: OAuthState, token_id: int, user_id: int, reason: str) -> None:
        token_time.enqueue_cleanup(state, token_id, user_id, reason)

    async def _drop_marker(self, nonce: str) -> None:
        """Best effort: a marker left behind is cleaned up by recovery."""
        try:
            async with self.store.mutate() as state:
                state.pending.pop(nonce, None)
        except StoreWriteError:
            logger.warning("oauth: could not drop pending marker")

    async def create_session(
        self,
        link: Link,
        client: Client,
        idp_refresh_token: str,
        *,
        redirect_uri: str,
        code_challenge: str,
        resource: str | None,
    ) -> tuple[Session, str]:
        """Create a session with its own NetBox token; return it and the code.

        ``redirect_uri``, ``code_challenge`` and ``resource`` come from the
        authorization request and are stored with the code hash, so the token
        endpoint can check them when the code is redeemed.

        Raises:
            LoginFailed: The token create outcome is unknown or refused.
            StoreWriteError: A store write failed. If it was the final one the
                marker is still on disk and recovery deletes any created token.
        """
        sid = uuid.uuid4().hex
        nonce = uuid.uuid4().hex
        now = token_time.now()
        # Held across marker, POST and final write so recovery cannot run in
        # between. Lock order everywhere: session lock, then NetBox-user lock.
        async with self._netbox_user_lock(link.netbox_user_id):
            async with self.store.mutate() as state:
                state.pending[nonce] = PendingCreate(
                    nonce=nonce,
                    netbox_user_id=link.netbox_user_id,
                    sid=sid,
                    created_at=now,
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
            now = token_time.now()  # after the POST, which may have taken a while
            code = token_time.new_secret()
            session = Session(
                sid=sid,
                user_key=link.user_key,
                client_id=client.client_id,
                netbox_user_id=link.netbox_user_id,
                created_at=now,
                code_hash=token_time.hash_secret(code),
                code_expires_at=now + CODE_TTL,
                code_redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                code_resource=resource,
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
        self._index_add(token_time.hash_secret(code), sid)
        logger.info("oauth session created sid=%s", sid[:8])
        return session.model_copy(deep=True), code

    def current_token(self, sid: str) -> tuple[str, int] | None:
        """Return ``(bearer, token_version)`` of the session, if it exists."""
        session = self.store.snapshot().sessions.get(sid)
        if session is None:
            return None
        return session.netbox_token, session.token_version

    async def renew_if_due(self, sid: str) -> bool:
        """Replace the session's NetBox token if under 2 days remain.

        Before renewing, the current token is checked in NetBox (spec 6.3): a
        token the user deleted or disabled ends the session instead of being
        replaced. NetBox being unavailable keeps the current token without
        renewing. Renewal failures keep the current token and are logged.
        Takes the session lock; use :meth:`renew_if_due_locked` when already
        holding it (it does not check the current token).

        Returns:
            True if the session was ended because NetBox no longer has its
            token or the token is disabled.
        """
        async with self.lock_for(sid):
            if not self.renewal_due(sid):
                await self.renew_if_due_locked(sid)  # no-op or expiry warning
                return False
            session = self.store.snapshot().sessions[sid]
            try:
                info = await self.broker.get_token(session.netbox_token_id)
            except BrokerError:
                logger.warning(
                    "oauth: renewal deferred, NetBox unavailable sid=%s", sid[:8]
                )
                return False
            if info is None or not info.enabled:
                reason = (
                    "netbox_token_missing" if info is None else "netbox_token_disabled"
                )
                await self.end_session_locked(sid, reason)
                return True
            await self.renew_if_due_locked(sid)
            return False

    def renewal_due(self, sid: str) -> bool:
        """True if the session's NetBox token has less than 2 days left.

        A cheap check without the session lock, so a request does not wait on
        a refresh holding the lock when nothing is due.
        """
        session = self.store.snapshot().sessions.get(sid)
        if session is None or session.netbox_token_expires_at is None:
            return False
        return session.netbox_token_expires_at - token_time.now() < RENEW_BELOW

    async def renew_if_due_locked(self, sid: str, *, force: bool = False) -> None:
        """Body of :meth:`renew_if_due`; ``force`` renews regardless of expiry
        (NetBox reported the token expired)."""
        snap = self.store.snapshot()
        session = snap.sessions.get(sid)
        if session is None:
            return
        now = token_time.now()
        if not force:
            if session.netbox_token_expires_at is None:
                logger.warning("oauth: session %s has no token expiry", sid[:8])
                return
            if session.netbox_token_expires_at - now >= RENEW_BELOW:
                return
        client = snap.clients.get(session.client_id)
        name = client.client_name if client else session.client_id
        # Lock order everywhere: session lock, then NetBox-user lock.
        async with self._netbox_user_lock(session.netbox_user_id):
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
            except (BrokerAmbiguous, BrokerUnavailable):
                # Keep marker and current token; recovery handles the marker.
                logger.warning("oauth: renewal failed sid=%s", sid[:8])
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

    async def end_session_locked(
        self, sid: str, reason: str, *, drop_grants: bool = False
    ) -> None:
        """End a session (caller holds its lock).

        ``drop_grants`` also removes every consent grant of the session's user
        in the same write (eligibility lost, spec 5.3.5).
        """
        async with self.store.mutate() as state:
            session = state.sessions.pop(sid, None)
            if session is None:
                return
            self._enqueue(
                state, session.netbox_token_id, session.netbox_user_id, reason
            )
            if drop_grants:
                for key in [
                    k for k, g in state.grants.items() if g.user_key == session.user_key
                ]:
                    del state.grants[key]
            ended = session
        self._index_drop(*self._session_hashes(ended))
        logger.info("session_ended sid=%s reason=%s", sid[:8], reason)
        self.cleanup_wanted.set()

    def session_labels(self, sid: str) -> tuple[str, str]:
        """``(NetBox username, client name)`` of a session for log lines;
        ``"-"`` where unknown."""
        try:
            state = self.store.snapshot()
        except StoreError:
            return "-", "-"
        session = state.sessions.get(sid)
        if session is None:
            return "-", "-"
        link = state.links.get(session.user_key)
        client = state.clients.get(session.client_id)
        return (
            link.netbox_username if link else "-",
            (client.client_name or "-") if client else "-",
        )

    # ------------------------------------------------- NetBox rejections

    async def handle_netbox_rejection(
        self, sid: str, used_version: int
    ) -> Literal["retry", "ended", "permission", "unavailable"]:
        """Classify a 401/403 NetBox gave a tool call (spec 6.3).

        ``retry``: the session holds a newer token now; call once more with it.
        ``ended``: the token is gone or disabled; the session was ended.
        ``permission``: the token is fine, the 403 is an ordinary refusal.
        ``unavailable``: NetBox could not confirm either way; nothing changed.
        """
        async with self.lock_for(sid):
            try:
                session = self.store.snapshot().sessions.get(sid)
            except StoreError:
                return "unavailable"
            if session is None:
                return "ended"
            if session.token_version != used_version:
                # Superseded meanwhile: never end a session over an old token.
                return "retry"
            try:
                info = await self.broker.get_token(session.netbox_token_id)
            except BrokerError:
                logger.warning("oauth: NetBox token check unavailable sid=%s", sid[:8])
                return "unavailable"
            reason = None
            if info is None:
                reason = "netbox_token_missing"
            elif not info.enabled:
                reason = "netbox_token_disabled"
            if reason is not None:
                try:
                    await self.end_session_locked(sid, reason)
                except StoreError:
                    logger.warning("oauth: could not end session sid=%s", sid[:8])
                    return "unavailable"
                return "ended"
            if info is None or info.expires_at is None:
                return "permission"
            if info.expires_at > token_time.now():
                return "permission"
            # Expired: renew and retry once. A failed renewal is logged by
            # renew_if_due_locked and leaves the version unchanged.
            try:
                await self.renew_if_due_locked(sid, force=True)
                current = self.store.snapshot().sessions.get(sid)
            except StoreError:
                return "unavailable"
            if current is not None and current.token_version != used_version:
                return "retry"
            return "unavailable"

    # -------------------------------------------------------------- hash index

    @staticmethod
    def _session_hashes(session: Session) -> list[str]:
        hashes = list(session.spent_hashes)
        if session.code_hash is not None:
            hashes.append(session.code_hash)
        if session.refresh_hash is not None:
            hashes.append(session.refresh_hash)
        if session.replay is not None:
            hashes.append(session.replay.hash)
        return hashes

    @staticmethod
    def _holds_refresh(session: Session, token_hash: str) -> bool:
        return (
            session.refresh_hash == token_hash
            or (session.replay is not None and session.replay.hash == token_hash)
            or token_hash in session.spent_hashes
        )

    def _index(self) -> dict[str, str]:
        if self._hash_index is None:
            index: dict[str, str] = {}
            for session in self.store.snapshot().sessions.values():
                for value in self._session_hashes(session):
                    index[value] = session.sid
            self._hash_index = index
        return self._hash_index

    def _index_add(self, value: str, sid: str) -> None:
        if self._hash_index is not None:
            self._hash_index[value] = sid

    def _index_drop(self, *values: str) -> None:
        if self._hash_index is not None:
            for value in values:
                self._hash_index.pop(value, None)

    def _drop_if_stale(self, session: Session | None, value: str) -> None:
        """Drop an index entry only if the session no longer holds the hash in
        any role. Code and refresh hashes share the index: a lookup of the
        wrong type must not erase, e.g., a spent hash (reuse detection)."""
        if session is None or value not in self._session_hashes(session):
            self._index_drop(value)

    def _lookup(self, value: str) -> str | None:
        """Session ID for a hash, or None. Verify under the session lock."""
        return self._index().get(value)

    # ------------------------------------------------------------ token grants

    def _resource_ok(self, resource: str | None) -> bool:
        """Spec 5.3: absent, or this server's URL with at most one trailing /."""
        return resource is None or resource.removesuffix("/") == self.config.public_url

    def _token_response(self, session: Session) -> tuple[dict, str]:
        """New access and refresh token; returns the response and the refresh token."""
        access, expires_in = self.tokens.issue(
            session.sid, session.user_key, session.client_id
        )
        refresh_token = token_time.new_secret()
        response = {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": refresh_token,
            "scope": SCOPE,
        }
        return response, refresh_token

    @staticmethod
    def _pkce_ok(verifier: str, challenge: str | None) -> bool:
        if not challenge:
            return False
        digest = hashlib.sha256(verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return hmac.compare_digest(computed.encode(), challenge.encode())

    async def burn_code(self, code: str) -> None:
        """Burn a known, unredeemed code without redeeming it (a malformed
        request still counts as the first attempt, spec 5.4).

        Raises:
            StoreWriteError: The burn could not be persisted.
        """
        code_hash = token_time.hash_secret(code)
        sid = self._session_by_code(code_hash)
        if sid is None:
            return
        async with self.lock_for(sid):
            current = self.store.snapshot().sessions.get(sid)
            if current is None or current.code_hash != code_hash:
                self._drop_if_stale(current, code_hash)
                return
            async with self.store.mutate() as state:
                stored = state.sessions.get(sid)
                if stored is None or stored.code_hash != code_hash:
                    return
                self._clear_code(stored)
            self._index_drop(code_hash)
        logger.warning("code_rejected sid=%s error=invalid_request", sid[:8])

    @staticmethod
    def _clear_code(session: Session) -> None:
        session.code_hash = None
        session.code_expires_at = None
        session.code_redirect_uri = None
        session.code_challenge = None
        session.code_resource = None

    def _session_by_code(self, code_hash: str) -> str | None:
        return self._lookup(code_hash)

    async def redeem_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        verifier: str,
        resource: str | None,
    ) -> dict:
        """Exchange an authorization code for the first token pair (spec 5.4).

        The code is burned on the first attempt, also a failed one; a session
        whose code was burned without success stays unredeemed and is ended by
        the orphan cleanup.

        Raises:
            GrantError: ``invalid_grant`` or ``invalid_target``.
            StoreWriteError: The redemption could not be persisted (nothing
                was issued; the code is still unburned).
        """
        code_hash = token_time.hash_secret(code)
        sid = self._session_by_code(code_hash)
        if sid is None:
            raise GrantError("invalid_grant", "unknown, used or expired code")
        async with self.lock_for(sid):
            session = self.store.snapshot().sessions.get(sid)
            if session is None or session.code_hash != code_hash:
                self._drop_if_stale(session, code_hash)
                raise GrantError("invalid_grant", "unknown, used or expired code")
            now = token_time.now()
            problem: GrantError | None = None
            if session.code_expires_at is None or now >= session.code_expires_at:
                problem = GrantError("invalid_grant", "code expired")
            elif client_id != session.client_id:
                problem = GrantError(
                    "invalid_grant", "code was issued to another client"
                )
            elif redirect_uri != session.code_redirect_uri:
                problem = GrantError("invalid_grant", "redirect_uri does not match")
            elif not self._pkce_ok(verifier, session.code_challenge):
                problem = GrantError("invalid_grant", "code_verifier does not match")
            elif not self._resource_ok(resource) or (
                resource is not None
                and session.code_resource is not None
                and resource.removesuffix("/")
                != session.code_resource.removesuffix("/")
            ):
                problem = GrantError("invalid_target", "resource does not match")
            response, refresh_token = (
                self._token_response(session) if problem is None else ({}, "")
            )
            async with self.store.mutate() as state:
                stored = state.sessions.get(sid)
                if stored is None:
                    raise GrantError("invalid_grant", "session ended")
                self._clear_code(stored)
                if problem is None:
                    stored.code_redeemed = True
                    stored.refresh_hash = token_time.hash_secret(refresh_token)
                    stored.refresh_deadline = now + REFRESH_TTL
                    client = state.clients.get(stored.client_id)
                    if client is not None:
                        client.last_used_at = now
            self._index_drop(code_hash)
            if problem is None:
                self._index_add(token_time.hash_secret(refresh_token), sid)
        if problem is not None:
            logger.warning(
                "code_rejected sid=%s error=%s reason=%s",
                sid[:8],
                problem.error,
                problem.description,
            )
            raise problem
        logger.info("code_redeemed sid=%s", sid[:8])
        return response

    def _session_by_refresh(self, token_hash: str) -> str | None:
        """Session holding this refresh token as current, replay slot or spent."""
        return self._lookup(token_hash)

    def _refresh_rejected(self, sid: str | None, reason: str) -> GrantError:
        logger.warning(
            "refresh_rejected reason=%s sid=%s", reason, sid[:8] if sid else "-"
        )
        return GrantError("invalid_grant", "refresh token is invalid or expired")

    async def refresh(
        self, refresh_token: str, client_id: str | None, resource: str | None
    ) -> dict:
        """Refresh-token grant with rotation, replay window and IdP check.

        Under the session lock, in this order (spec 5.4, 6.4):

        1. Look up the token: current, replay slot (< 30 s: return the stored
           response, no other call), or spent (end the session). Check client,
           deadline and a leftover IdP refresh mark (fail closed).
        2. Write: mark the IdP refresh as started.
        3. Refresh the IdP token.
        4. Write: store the rotated IdP refresh token and clear the mark.
        5. Userinfo: subject and group check.
        6. NetBox: user still eligible, session token exists and is enabled;
           renew the NetBox token if due.
        7. Write: rotate our refresh token, record the spent hash and the
           replay slot, extend the sliding deadline.

        The response is returned only after the final write succeeded.

        Raises:
            GrantError: ``invalid_grant`` or ``invalid_target``.
            GrantUnavailable: IdP or NetBox unavailable; nothing rotated.
            StoreWriteError: A write failed; the previous token stays valid.
        """
        if not self._resource_ok(resource):
            raise GrantError("invalid_target", "resource is not this server")
        token_hash = token_time.hash_secret(refresh_token)
        sid = self._session_by_refresh(token_hash)
        if sid is None:
            raise self._refresh_rejected(None, "unknown_token")
        async with self.lock_for(sid):
            return await self._refresh_locked(sid, token_hash, client_id)

    async def _refresh_locked(
        self, sid: str, token_hash: str, client_id: str | None
    ) -> dict:
        snap = self.store.snapshot()
        session = snap.sessions.get(sid)
        if session is None or not self._holds_refresh(session, token_hash):
            # Not a refresh token of this session: unknown. The entry is kept
            # if the hash is still the session's (e.g. its code).
            self._drop_if_stale(session, token_hash)
            raise self._refresh_rejected(sid, "unknown_token")
        if session.idp_refresh_started_at is not None:
            # A previous IdP refresh has an unknown outcome (crash before its
            # result was stored): the stored IdP token may be spent. Checked
            # first, so not even a replay is served (fail closed).
            await self.end_session_locked(sid, "idp_refresh_unknown")
            raise self._refresh_rejected(sid, "idp_refresh_unknown")
        now = token_time.now()
        if now - session.created_at >= self.config.max_session_days * 86400:
            # Absolute cap: the sliding deadline alone would let a session
            # (and its list of spent hashes) live forever.
            await self.end_session_locked(sid, "max_age")
            raise self._refresh_rejected(sid, "max_age")
        replay = session.replay
        if session.refresh_hash != token_hash:
            if (
                replay is not None
                and replay.hash == token_hash
                and now - replay.rotated_at < REPLAY_WINDOW
            ):
                if client_id is not None and client_id != session.client_id:
                    raise self._refresh_rejected(sid, "client_mismatch")
                logger.info("token_replayed sid=%s", sid[:8])
                return dict(replay.response)
            # Spent token (or the replay slot after its window).
            await self.end_session_locked(sid, "refresh_reuse")
            raise self._refresh_rejected(sid, "refresh_reuse")
        if client_id is not None and client_id != session.client_id:
            raise self._refresh_rejected(sid, "client_mismatch")
        if now >= session.refresh_deadline:
            await self.end_session_locked(sid, "expired")
            raise self._refresh_rejected(sid, "expired")
        link = snap.links.get(session.user_key)
        if link is None or session.idp_refresh_token is None:
            await self.end_session_locked(sid, "identity_missing", drop_grants=True)
            raise self._refresh_rejected(sid, "identity_missing")

        try:
            await self._check_upstream(session, link.sub, session.idp_refresh_token)
        except _Reject as exc:
            await self.end_session_locked(sid, exc.reason, drop_grants=exc.eligibility)
            raise self._refresh_rejected(sid, exc.reason) from None

        # Step 7: one write rotates our refresh token.
        response, refresh_token = self._token_response(session)
        now = token_time.now()
        async with self.store.mutate() as state:
            stored = state.sessions.get(sid)
            if stored is None or stored.refresh_hash != token_hash:
                raise self._refresh_rejected(sid, "session_ended")
            stored.spent_hashes.append(token_hash)
            stored.refresh_hash = token_time.hash_secret(refresh_token)
            stored.replay = Replay(hash=token_hash, rotated_at=now, response=response)
            stored.refresh_deadline = now + REFRESH_TTL
            stored.last_idp_check_at = now
            client = state.clients.get(stored.client_id)
            name = client.client_name if client else "-"
            if client is not None:
                client.last_used_at = now
        self._index_add(token_time.hash_secret(refresh_token), sid)
        logger.info("token_refreshed sid=%s client=%s", sid[:8], name or "-")
        return response

    async def _check_upstream(
        self, session: Session, sub: str, idp_refresh_token: str
    ) -> None:
        """Steps 2 to 6 of :meth:`refresh` (caller holds the session lock).

        Raises:
            _Reject: The session must end.
            GrantUnavailable: IdP or NetBox unavailable; session unchanged
                except for a rotated IdP refresh token.
            StoreWriteError: A write failed.
        """
        sid = session.sid
        # Step 2: mark, so a crash after the IdP rotated fails closed.
        async with self.store.mutate() as state:
            stored = state.sessions.get(sid)
            if stored is None:
                raise _Reject("session_ended")
            stored.idp_refresh_started_at = token_time.now()
        # Step 3.
        try:
            idp_tokens = await self.idp.refresh(idp_refresh_token)
        except IdpRejected as exc:
            logger.warning("oauth refresh: IdP rejected: %s", exc.reason)
            raise _Reject("idp_rejected") from None
        except IdpUnavailable as exc:
            logger.warning("oauth refresh: IdP unavailable: %s", exc.reason)
            await self._persist_idp_refresh(sid, None)
            raise GrantUnavailable("identity provider unavailable") from None
        # Step 4: persist the rotated IdP token first, in its own write.
        await self._persist_idp_refresh(sid, idp_tokens.refresh_token)
        # Step 5.
        try:
            groups = await self.idp.userinfo(idp_tokens.access_token, sub)
        except IdpRejected as exc:
            logger.warning("oauth refresh: userinfo rejected: %s", exc.reason)
            raise _Reject("userinfo_rejected", eligibility=True) from None
        except IdpUnavailable as exc:
            logger.warning("oauth refresh: userinfo unavailable: %s", exc.reason)
            raise GrantUnavailable("identity provider unavailable") from None
        if not set(groups) & set(self.config.allowed_groups):
            raise _Reject("no_group", eligibility=True)
        # Step 6.
        try:
            user = await self.broker.get_user(session.netbox_user_id)
            if user is None:
                raise _Reject("no_netbox_user", eligibility=True)
            reason = self._ineligible(user)
            if reason is not None:
                raise _Reject(reason, eligibility=True)
            info = await self.broker.get_token(session.netbox_token_id)
        except BrokerError as exc:
            logger.warning("oauth refresh: NetBox unavailable: %s", exc)
            raise GrantUnavailable("NetBox unavailable") from None
        if info is None:
            raise _Reject("netbox_token_missing")
        if not info.enabled:
            raise _Reject("netbox_token_disabled")
        await self.renew_if_due_locked(sid)

    async def _persist_idp_refresh(self, sid: str, new_token: str | None) -> None:
        """Store a rotated IdP refresh token (if any) and clear the mark."""
        async with self.store.mutate() as state:
            stored = state.sessions.get(sid)
            if stored is None:
                return
            if new_token is not None:
                stored.idp_refresh_token = new_token
            stored.idp_refresh_started_at = None

    # -------------------------------------------------------------- revocation

    async def revoke(self, token: str, client_id: str | None) -> None:
        """RFC 7009 revocation (spec 5.5): end the token's session, if any.

        Unknown or invalid tokens and a ``client_id`` mismatch have no effect.

        Raises:
            StoreWriteError: The session could not be ended.
        """
        sid: str | None = None
        owner: str | None = None
        token_hash: str | None = None
        try:
            claims = self.tokens.verify(token, allow_expired=True)
        except InvalidToken:
            token_hash = token_time.hash_secret(token)
            sid = self._session_by_refresh(token_hash)
        else:
            sid, owner = claims["sid"], claims["client_id"]
        if sid is None:
            return
        async with self.lock_for(sid):
            session = self.store.snapshot().sessions.get(sid)
            if token_hash is not None and (
                session is None or not self._holds_refresh(session, token_hash)
            ):
                self._drop_if_stale(session, token_hash)
                return
            if session is None:
                return
            if owner is not None and owner != session.client_id:
                return
            if client_id is not None and client_id != session.client_id:
                logger.warning("revoke ignored: client mismatch sid=%s", sid[:8])
                return
            await self.end_session_locked(sid, "revoked")

    # ---------------------------------------------------------- background jobs

    def _single_flight(self, name: str) -> asyncio.Lock | None:
        """The job's lock if the job is idle, else None (caller skips)."""
        lock = self._job_locks.setdefault(name, asyncio.Lock())
        return None if lock.locked() else lock

    async def run_cleanup(self) -> None:
        """Delete the NetBox tokens in the cleanup queue (spec 6.3).

        Single-flight; each entry is tried once per run. A 404 counts as
        deleted. Failed entries stay queued and are retried by the next run;
        one older than 7 days logs a warning at most once per 24 hours.
        """
        lock = self._single_flight("cleanup")
        if lock is None:
            return
        async with lock:
            for entry in list(self.store.snapshot().cleanup.values()):
                try:
                    await self.broker.delete_token(entry.netbox_token_id)
                except BrokerError:
                    await self._cleanup_failed(entry.entry_id)
                    continue
                try:
                    async with self.store.mutate() as state:
                        state.cleanup.pop(entry.entry_id, None)
                except StoreError:
                    logger.warning("oauth: could not drop cleanup entry")

    async def _cleanup_failed(self, entry_id: str) -> None:
        now = token_time.now()
        try:
            async with self.store.mutate() as state:
                entry = state.cleanup.get(entry_id)
                if entry is None:
                    return
                entry.last_attempt_at = now
                if now - entry.created_at > CLEANUP_WARN_AGE and (
                    entry.warned_at is None
                    or now - entry.warned_at >= CLEANUP_WARN_EVERY
                ):
                    entry.warned_at = now
                    logger.warning(
                        "oauth: cleanup entry %s for NetBox token %d is %d days old",
                        entry_id[:8],
                        entry.netbox_token_id,
                        int((now - entry.created_at) // 86400),
                    )
        except StoreError:
            logger.warning("oauth: could not record cleanup attempt")

    async def recover_pending(self) -> None:
        """Delete tokens left behind by interrupted creations (spec 6.2).

        Markers younger than 10 minutes are skipped: their POST may still be in
        flight. Single-flight.
        """
        lock = self._single_flight("recovery")
        if lock is None:
            return
        async with lock:
            now = token_time.now()
            due = [
                m.nonce
                for m in self.store.snapshot().pending.values()
                if now - m.created_at >= MARKER_MIN_AGE
            ]
            for nonce in due:
                await self._recover_marker(nonce)

    async def _recover_marker(self, nonce: str) -> None:
        marker = self.store.snapshot().pending.get(nonce)
        if marker is None:
            return
        async with self._netbox_user_lock(marker.netbox_user_id):
            marker = self.store.snapshot().pending.get(nonce)
            if marker is None or token_time.now() - marker.created_at < MARKER_MIN_AGE:
                return
            try:
                found = await self.broker.list_tokens(marker.netbox_user_id, nonce)
                # list_tokens matches substrings; delete only tokens that carry
                # the nonce as the description's last word and belong to the
                # marker's user.
                found = [
                    t
                    for t in found
                    if t.user_id == marker.netbox_user_id
                    and t.description.endswith(" " + nonce)
                ]
                for info in found:
                    await self.broker.delete_token(info.id)
            except BrokerError:
                logger.warning("oauth: token recovery deferred, NetBox unavailable")
                return
            try:
                async with self.store.mutate() as state:
                    state.pending.pop(nonce, None)
            except StoreError:
                logger.warning("oauth: could not drop recovered marker")
                return
            if found:
                logger.info("oauth: recovered %d orphaned NetBox token(s)", len(found))

    async def end_orphans(self) -> None:
        """End sessions whose code was never exchanged within 10 minutes."""
        now = token_time.now()
        for session in list(self.store.snapshot().sessions.values()):
            if session.code_redeemed or now - session.created_at < ORPHAN_TTL:
                continue
            async with self.lock_for(session.sid):
                current = self.store.snapshot().sessions.get(session.sid)
                if current is None or current.code_redeemed:
                    continue
                await self._end_guarded(session.sid, "orphan")

    async def end_expired(self) -> None:
        """End sessions past the sliding 30 day deadline or the absolute cap."""
        now = token_time.now()
        cap = self.config.max_session_days * 86400
        for session in list(self.store.snapshot().sessions.values()):
            if self._expiry_reason(session, now, cap) is None:
                continue
            async with self.lock_for(session.sid):
                # A refresh may have moved the deadline while we waited.
                current = self.store.snapshot().sessions.get(session.sid)
                if current is None:
                    continue
                reason = self._expiry_reason(current, token_time.now(), cap)
                if reason is not None:
                    await self._end_guarded(session.sid, reason)

    @staticmethod
    def _expiry_reason(session: Session, now: float, cap: float) -> str | None:
        if now >= session.refresh_deadline:
            return "expired"
        if now - session.created_at >= cap:
            return "max_age"
        return None

    async def _end_guarded(
        self, sid: str, reason: str, *, drop_grants: bool = False
    ) -> None:
        """End a session (lock held); a store failure is logged, not raised."""
        try:
            await self.end_session_locked(sid, reason, drop_grants=drop_grants)
        except StoreError:
            logger.warning("oauth: could not end session sid=%s", sid[:8])

    async def expire_clients(self) -> None:
        """Remove registrations unused for 30 days that have no sessions, with
        their grants (spec 5.2)."""
        now = token_time.now()
        try:
            async with self.store.mutate() as state:
                live = {s.client_id for s in state.sessions.values()}
                for client_id in [
                    c.client_id
                    for c in state.clients.values()
                    if now - c.last_used_at >= CLIENT_IDLE_TTL
                    and c.client_id not in live
                ]:
                    del state.clients[client_id]
                    for key in [
                        k for k, g in state.grants.items() if g.client_id == client_id
                    ]:
                        del state.grants[key]
        except StoreError:
            logger.warning("oauth: client expiry failed")

    async def drop_stale_flows(self) -> None:
        """Remove login flows older than 10 minutes."""
        now = token_time.now()
        try:
            async with self.store.mutate() as state:
                for flow_id in [
                    k
                    for k, f in state.flows.items()
                    if now - f.created_at >= FLOW_MAX_AGE
                ]:
                    del state.flows[flow_id]
        except StoreError:
            logger.warning("oauth: flow cleanup failed")

    async def daily_netbox_check(self) -> None:
        """Check every session against NetBox (spec 6.4): the user exists and is
        active, the token exists and is enabled; renew a token that is due.

        Does not contact the IdP. NetBox being unavailable keeps the session.
        Single-flight.
        """
        lock = self._single_flight("daily")
        if lock is None:
            return
        async with lock:
            for sid in list(self.store.snapshot().sessions):
                try:
                    await self._check_session(sid)
                except StoreError:
                    logger.warning("oauth: daily check store failure sid=%s", sid[:8])

    async def _check_session(self, sid: str) -> None:
        async with self.lock_for(sid):
            session = self.store.snapshot().sessions.get(sid)
            if session is None:
                return
            try:
                user = await self.broker.get_user(session.netbox_user_id)
                if user is None or not user.is_active:
                    reason = "no_netbox_user" if user is None else "inactive_user"
                    await self._end_guarded(sid, reason, drop_grants=True)
                    return
                info = await self.broker.get_token(session.netbox_token_id)
            except BrokerError:
                logger.warning("oauth: daily check deferred sid=%s", sid[:8])
                return
            if info is None or not info.enabled:
                reason = (
                    "netbox_token_missing" if info is None else "netbox_token_disabled"
                )
                await self._end_guarded(sid, reason)
                return
            await self.renew_if_due_locked(sid)
