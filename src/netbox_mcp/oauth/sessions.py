"""Session management: identity mapping, links and (later) session lifecycle.

``SessionManager`` is the single owner of per-session and per-user locking.
Later tasks add session creation, token exchange, verification and cleanup jobs
to this class; this first part maps IdP identities to NetBox users.
"""

import asyncio
import logging
import weakref

from netbox_mcp.oauth import tokens as token_time
from netbox_mcp.oauth.broker import BrokerConflict
from netbox_mcp.oauth.broker import NetBoxBroker
from netbox_mcp.oauth.broker import NetBoxUser
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.idp import IdpClient
from netbox_mcp.oauth.idp import IdpLogin
from netbox_mcp.oauth.state import Link
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.tokens import AccessTokens

logger = logging.getLogger(__name__)

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
