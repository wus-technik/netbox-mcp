"""NetBox broker: looks up users and manages each session's personal NetBox token.

All calls use the NetBox service credential (the broker token) with
``retry=False`` and ``use_branch=False``. The token POST is never retried, and
no ``X-NetBox-Branch`` header is sent, so tokens are never created inside a
branch.

Known deviation: ``NetBoxClient`` follows redirects for GET requests (and logs
a warning once). A redirected write is rejected there, so a token is never
created through a redirect that turned the POST into a GET.

Error contract:

- ``BrokerUnavailable``: NetBox did not give a usable answer to a read or a
  delete (timeout, 5xx, 429, 401/403, HTML or non-JSON body). Safe to retry.
- ``BrokerAmbiguous`` (create only): the POST may have created a token. The
  caller keeps its pending-create marker and recovers by nonce.
- ``BrokerDefinite`` (create only): the answer proves no token was created
  (a 4xx, including 429, or a redirect that swallowed the POST).
"""

import logging
from dataclasses import dataclass
from dataclasses import field
from datetime import UTC
from datetime import datetime
from typing import Any

import httpx2

from netbox_mcp.models import NetBoxConfig
from netbox_mcp.netbox_client import AmbiguousWriteError
from netbox_mcp.netbox_client import MissingTokenError
from netbox_mcp.netbox_client import NetBoxAPIError
from netbox_mcp.netbox_client import NetBoxClient

logger = logging.getLogger(__name__)

USERS_PATH = "users/users"
TOKENS_PATH = "users/tokens"
PAGE_SIZE = 100


class BrokerError(Exception):
    """Base class of all broker failures."""


class BrokerUnavailable(BrokerError):  # noqa: N818 - name fixed by the interface
    """NetBox gave no usable answer; nothing is known to have changed."""


class BrokerAmbiguous(BrokerError):  # noqa: N818 - name fixed by the interface
    """A token create may or may not have happened."""


class BrokerDefinite(BrokerError):  # noqa: N818 - name fixed by the interface
    """A token create was refused; the answer proves no token exists."""


class BrokerConflict(BrokerError):  # noqa: N818 - name fixed by the interface
    """More than one NetBox user matches the username."""


@dataclass(frozen=True)
class NetBoxUser:
    id: int
    username: str
    is_active: bool
    # None when NetBox's REST API does not expose the flag (unknown).
    is_superuser: bool | None


@dataclass(frozen=True)
class CreatedToken:
    token_id: int
    bearer: str = field(repr=False)
    expires_at: float


@dataclass(frozen=True)
class TokenInfo:
    id: int
    enabled: bool
    expires_at: float | None
    user_id: int | None


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(raw: Any) -> float | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def _user(row: Any) -> NetBoxUser:
    if not isinstance(row, dict) or not isinstance(row.get("id"), int):
        raise BrokerUnavailable("NetBox returned a malformed user")
    return NetBoxUser(
        id=row["id"],
        username=str(row.get("username", "")),
        is_active=bool(row.get("is_active")),
        is_superuser=bool(row["is_superuser"]) if "is_superuser" in row else None,
    )


def _token_info(row: Any) -> TokenInfo:
    if not isinstance(row, dict) or not isinstance(row.get("id"), int):
        raise BrokerUnavailable("NetBox returned a malformed token")
    owner = row.get("user")
    user_id = owner.get("id") if isinstance(owner, dict) else owner
    return TokenInfo(
        id=row["id"],
        enabled=bool(row.get("enabled")),
        expires_at=_parse_time(row.get("expires")),
        user_id=user_id if isinstance(user_id, int) else None,
    )


class NetBoxBroker:
    """Service-credential client for users and personal tokens."""

    def __init__(
        self,
        netbox_config: NetBoxConfig,
        broker_token: str,
        *,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = netbox_config
        self._token = broker_token
        self._transport = transport

    def _client(self) -> NetBoxClient:
        return NetBoxClient(
            self._config, token=self._token, retry=False, transport=self._transport
        )

    async def _call(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: bool = True,
    ) -> Any:
        """Run one non-create call, mapping failures to broker errors.

        Raises:
            NetBoxAPIError: Only for a 404, for the caller to interpret.
            BrokerUnavailable: For anything else that is not a JSON answer.
        """
        try:
            async with self._client() as nb:
                body = await nb.request(method, path, params=params, use_branch=False)
        except NetBoxAPIError as exc:
            if exc.status == 404:
                raise
            # No cause: it would carry NetBox's response body.
            raise BrokerUnavailable(
                f"NetBox answered {method} {path} with HTTP {exc.status}"
            ) from None
        except (
            AmbiguousWriteError,
            MissingTokenError,
            ValueError,
            httpx2.HTTPError,
            httpx2.InvalidURL,
            TimeoutError,
        ) as exc:
            raise BrokerUnavailable(
                f"NetBox did not answer {method} {path}: {type(exc).__name__}"
            ) from exc
        if json_body and not isinstance(body, (dict, list)):
            raise BrokerUnavailable(f"NetBox answered {method} {path} with non-JSON")
        return body

    async def _results(self, path: str, params: dict[str, Any]) -> list[Any]:
        """Collect the rows of a paginated list."""
        rows: list[Any] = []
        offset = 0
        while True:
            page = await self._call(
                "GET", path, params={**params, "limit": PAGE_SIZE, "offset": offset}
            )
            if not isinstance(page, dict) or not isinstance(page.get("results"), list):
                raise BrokerUnavailable(f"NetBox answered GET {path} with a bad page")
            batch = page["results"]
            rows.extend(batch)
            if not page.get("next"):
                return rows
            if not batch:
                raise BrokerUnavailable(
                    f"NetBox answered GET {path} with an empty page"
                )
            # Advance by rows received: NetBox may clamp the page size.
            offset += len(batch)

    # ----------------------------------------------------------------- users

    async def find_user(self, username: str) -> NetBoxUser | None:
        """Return the one user with this username, or None.

        Raises:
            BrokerConflict: If more than one user matches.
        """
        rows = [
            row
            for row in await self._results(USERS_PATH, {"username": username})
            if isinstance(row, dict) and row.get("username") == username
        ]
        if len(rows) > 1:
            raise BrokerConflict(f"More than one NetBox user matches {username!r}")
        return _user(rows[0]) if rows else None

    async def get_user(self, user_id: int) -> NetBoxUser | None:
        try:
            return _user(await self._call("GET", f"{USERS_PATH}/{user_id}"))
        except NetBoxAPIError:
            return None

    # ---------------------------------------------------------------- tokens

    async def create_token(
        self, user_id: int, description: str, expires_at: float
    ) -> CreatedToken:
        """Create a write-enabled token for ``user_id``. Sent exactly once.

        Raises:
            BrokerDefinite: The answer proves no token was created.
            BrokerAmbiguous: The outcome is unknown, or the success answer was
                unusable (a token may exist; recovery deletes it by nonce).
        """
        payload = {
            "user": user_id,
            "description": description,
            "write_enabled": True,
            "expires": _iso(expires_at),
        }
        try:
            async with self._client() as nb:
                http = nb._http
                if http is None:
                    raise BrokerAmbiguous("The broker client was not opened")
                # A 307/308 would make httpx send the token POST a second time.
                http.follow_redirects = False
                seen: list[int] = []

                async def tap(response: httpx2.Response) -> None:
                    seen.append(response.status_code)

                http.event_hooks["response"].append(tap)
                body = await nb.request(
                    "POST", TOKENS_PATH, json=payload, use_branch=False
                )
            if any(300 <= code < 400 for code in seen):
                # NetBox redirected before the view ran: no token was created.
                raise BrokerDefinite("The token create was redirected, not applied")
        except NetBoxAPIError as exc:
            if 400 <= exc.status < 500:
                raise BrokerDefinite(
                    f"NetBox refused the token create with HTTP {exc.status}"
                ) from None
            raise BrokerAmbiguous(
                f"NetBox answered the token create with HTTP {exc.status}"
            ) from None
        except ValueError as exc:
            # A redirect turned the POST into a GET: nothing was created.
            raise BrokerDefinite(
                "The token create was redirected, not applied"
            ) from exc
        except (
            AmbiguousWriteError,
            MissingTokenError,
            httpx2.HTTPError,
            TimeoutError,
        ) as exc:
            raise BrokerAmbiguous(
                f"The token create got no usable answer: {type(exc).__name__}"
            ) from exc
        if not isinstance(body, dict):
            raise BrokerAmbiguous("The token create returned a non-JSON answer")
        key, secret, token_id = body.get("key"), body.get("token"), body.get("id")
        if (
            not isinstance(key, str)
            or not key
            or not isinstance(secret, str)
            or not secret
            or not isinstance(token_id, int)
        ):
            raise BrokerAmbiguous("The token create answer lacked id, key or token")
        return CreatedToken(
            token_id=token_id, bearer=f"nbt_{key}.{secret}", expires_at=expires_at
        )

    async def get_token(self, token_id: int) -> TokenInfo | None:
        try:
            return _token_info(await self._call("GET", f"{TOKENS_PATH}/{token_id}"))
        except NetBoxAPIError:
            return None

    async def list_tokens(
        self, user_id: int | None, description_contains: str
    ) -> list[TokenInfo]:
        params: dict[str, Any] = {"description__ic": description_contains}
        if user_id is not None:
            params["user_id"] = user_id
        return [_token_info(row) for row in await self._results(TOKENS_PATH, params)]

    async def delete_token(self, token_id: int) -> bool:
        """Delete a token; one that is already gone counts as deleted."""
        try:
            await self._call("DELETE", f"{TOKENS_PATH}/{token_id}", json_body=False)
        except NetBoxAPIError:
            return True
        return True
