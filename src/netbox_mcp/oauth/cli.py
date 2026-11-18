"""Offline admin commands: ``netbox-mcp oauth init|unlink|restore-reset|sweep``.

The commands work directly on the encrypted state file while the server is
stopped. Each takes the exclusive store lock (spec 8), so a running server, or
a second admin command, makes them exit 2 without touching anything.

Exit codes: 0 success, 1 error (bad usage, bad configuration, store or NetBox
failure), 2 the store is locked. Nothing here prints token values, keys or
state content; ``sweep`` reports counts only.

Environment, per command:

- ``init``, ``unlink``, ``restore-reset``: ``OAUTH_STATE_PATH``, ``OAUTH_STATE_KEY``.
- ``sweep``: additionally ``NETBOX_URL`` and ``NETBOX_TOKEN_BROKER_TOKEN``
  (and the optional ``NETBOX_VERIFY_SSL`` / ``NETBOX_TIMEOUT``).
"""

import asyncio
import base64
import binascii
import sys
import uuid
from collections.abc import Awaitable
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO
from typing import TypeVar
from urllib.parse import urlparse

import httpx2

from netbox_mcp.oauth import tokens as token_time
from netbox_mcp.oauth.broker import BrokerError
from netbox_mcp.oauth.broker import NetBoxBroker
from netbox_mcp.oauth.state import CleanupEntry
from netbox_mcp.oauth.state import OAuthState
from netbox_mcp.oauth.store import KEY_BYTES
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import StoreError
from netbox_mcp.oauth.store import StoreLocked
from netbox_mcp.utils import env_str

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_LOCKED = 2

# Same prefix SessionManager puts on every token description.
DESCRIPTION_PREFIX = "NetBox MCP (OAuth) "

USAGE = """usage: netbox-mcp oauth <command>

commands:
  init                     create the empty encrypted state file
  unlink <netbox-user>     remove the identity link of a NetBox user and end its sessions
  restore-reset            end all sessions (after restoring a backup)
  sweep [--apply]          delete NetBox tokens the state does not track (dry run by default)

All commands need the server to be stopped (exit code 2 if the store is locked).
"""

T = TypeVar("T")


class _CliError(Exception):
    """A failure to report on stderr; ``code`` is the exit code."""

    def __init__(self, message: str, code: int = EXIT_ERROR) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class _StoreSettings:
    path: Path
    key: bytes


def _required(name: str) -> str:
    value = env_str(name)
    if value is None:
        raise _CliError(f"{name} is required")
    return value


def _store_settings() -> _StoreSettings:
    path = Path(_required("OAUTH_STATE_PATH"))
    raw = _required("OAUTH_STATE_KEY")
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise _CliError("OAUTH_STATE_KEY must be base64") from None
    if len(key) != KEY_BYTES:
        raise _CliError(f"OAUTH_STATE_KEY must decode to {KEY_BYTES} bytes")
    if not path.parent.is_dir():
        raise _CliError(f"OAUTH_STATE_PATH: directory {str(path.parent)!r} not found")
    return _StoreSettings(path, key)


def _open_store(settings: _StoreSettings) -> StateStore:
    try:
        return StateStore.open(settings.path, settings.key)
    except StoreLocked:
        raise _CliError(
            "the state store is locked: the server (or another admin command) "
            "is running. Stop it and retry.",
            EXIT_LOCKED,
        ) from None
    except StoreError as exc:
        raise _CliError(f"cannot open the state store: {exc}") from None


def _enqueue(state: OAuthState, token_id: int, user_id: int, reason: str) -> None:
    """Queue a token for deletion, exactly like ``SessionManager._enqueue``."""
    entry_id = uuid.uuid4().hex
    state.cleanup[entry_id] = CleanupEntry(
        entry_id=entry_id,
        netbox_token_id=token_id,
        netbox_user_id=user_id,
        reason=reason,
        created_at=token_time.now(),
    )


def _end_sessions(state: OAuthState, sids: list[str], reason: str) -> int:
    for sid in sids:
        session = state.sessions.pop(sid)
        _enqueue(state, session.netbox_token_id, session.netbox_user_id, reason)
    return len(sids)


def _run_locked(
    settings: _StoreSettings, work: Callable[[StateStore], Awaitable[T]]
) -> T:
    """Open the store (exclusive lock), run ``work``, always release the lock."""
    store = _open_store(settings)
    try:
        return asyncio.run(work(store))
    except StoreError as exc:
        raise _CliError(f"state store error: {exc}") from None
    finally:
        store.close()


# --------------------------------------------------------------------- commands


def _cmd_init(args: list[str], out: TextIO) -> int:
    if args:
        raise _CliError("init takes no arguments")
    settings = _store_settings()
    try:
        StateStore.create(settings.path, settings.key)
    except StoreLocked:
        raise _CliError("the state store is locked", EXIT_LOCKED) from None
    except StoreError as exc:
        raise _CliError(f"cannot create the state store: {exc}") from None
    print(f"Created a new empty OAuth state store at {settings.path}", file=out)
    print("Keep OAUTH_STATE_KEY safe: without it the file cannot be read.", file=out)
    return EXIT_OK


def _cmd_unlink(args: list[str], out: TextIO) -> int:
    if len(args) != 1 or args[0].startswith("-"):
        raise _CliError("usage: netbox-mcp oauth unlink <netbox-username>")
    wanted = args[0].casefold()
    settings = _store_settings()

    async def work(store: StateStore) -> tuple[int, int]:
        async with store.mutate() as state:
            # Offline and store-only: the username recorded in the link, compared
            # casefolded like the denylist. No NetBox lookup is made.
            keys = {
                k
                for k, link in state.links.items()
                if link.netbox_username.casefold() == wanted
            }
            if not keys:
                return 0, 0
            for key in keys:
                del state.links[key]
            sids = [s.sid for s in state.sessions.values() if s.user_key in keys]
            ended = _end_sessions(state, sids, "unlink")
            # A new identity must consent again, and a login flow of the old one
            # would otherwise finish against a link that no longer exists.
            for gk in [k for k, g in state.grants.items() if g.user_key in keys]:
                del state.grants[gk]
            for fid in [f for f, fl in state.flows.items() if fl.user_key in keys]:
                del state.flows[fid]
        return len(keys), ended

    links, sessions = _run_locked(settings, work)
    if not links:
        raise _CliError(f"no identity link found for NetBox user {args[0]!r}")
    print(
        f"Removed {links} link(s) and ended {sessions} session(s); their NetBox "
        "tokens are deleted at the next server start.",
        file=out,
    )
    return EXIT_OK


def _cmd_restore_reset(args: list[str], out: TextIO) -> int:
    if args:
        raise _CliError("restore-reset takes no arguments")
    settings = _store_settings()

    async def work(store: StateStore) -> tuple[int, int]:
        async with store.mutate() as state:
            ended = _end_sessions(state, list(state.sessions), "restore-reset")
            flows = len(state.flows)
            state.flows.clear()
        return ended, flows

    ended, flows = _run_locked(settings, work)
    print(
        f"Ended {ended} session(s) and dropped {flows} login flow(s). Links, "
        "consent grants and client registrations are kept; the NetBox tokens "
        "of the ended sessions are deleted at the next server start.",
        file=out,
    )
    print("Next: run 'netbox-mcp oauth sweep' to find untracked tokens.", file=out)
    return EXIT_OK


def _netbox_broker(transport: httpx2.AsyncBaseTransport | None) -> NetBoxBroker:
    # Imported here: only sweep needs NetBox settings.
    from netbox_mcp.netbox_client import get_netbox_config_from_env

    url = _required("NETBOX_URL")
    if urlparse(url).scheme.lower() not in {"http", "https"}:
        raise _CliError("NETBOX_URL must start with https:// or http://")
    broker_token = _required("NETBOX_TOKEN_BROKER_TOKEN")
    try:
        config = get_netbox_config_from_env()
    except ValueError as exc:
        raise _CliError(f"invalid NetBox configuration: {exc}") from None
    return NetBoxBroker(config, broker_token, transport=transport)


def _tracked(state: OAuthState) -> tuple[set[int], list[str]]:
    """Token IDs held by sessions and the cleanup queue, and marker nonces."""
    ids = {s.netbox_token_id for s in state.sessions.values()}
    ids |= {c.netbox_token_id for c in state.cleanup.values()}
    return ids, [m.nonce for m in state.pending.values()]


def _cmd_sweep(
    args: list[str], out: TextIO, transport: httpx2.AsyncBaseTransport | None
) -> int:
    apply = False
    for arg in args:
        if arg != "--apply":
            raise _CliError("usage: netbox-mcp oauth sweep [--apply]")
        apply = True
    settings = _store_settings()
    broker = _netbox_broker(transport)

    async def work(store: StateStore) -> dict[str, int]:
        # The lock stays held until this returns, so the server cannot start
        # and create sessions while the sweep decides what is untracked.
        ids, nonces = _tracked(store.snapshot())
        try:
            listed = [
                t
                for t in await broker.list_tokens(None, DESCRIPTION_PREFIX)
                if t.description.startswith(DESCRIPTION_PREFIX)
            ]
        except BrokerError as exc:
            raise _CliError(f"cannot list NetBox tokens: {exc}") from None
        untracked = [
            t
            for t in listed
            if t.id not in ids
            and not any(t.description.endswith(" " + n) for n in nonces)
        ]
        deleted = failed = 0
        if apply:
            for token in untracked:
                try:
                    await broker.delete_token(token.id)
                    deleted += 1
                except BrokerError:
                    failed += 1
        return {
            "listed": len(listed),
            "untracked": len(untracked),
            "deleted": deleted,
            "failed": failed,
        }

    counts = _run_locked(settings, work)
    print(
        f"NetBox tokens with the OAuth prefix: {counts['listed']}; "
        f"tracked: {counts['listed'] - counts['untracked']}; "
        f"untracked: {counts['untracked']}.",
        file=out,
    )
    if not apply:
        print("Dry run: nothing deleted. Use --apply to delete.", file=out)
        return EXIT_OK
    print(f"Deleted {counts['deleted']}; failed {counts['failed']}.", file=out)
    return EXIT_ERROR if counts["failed"] else EXIT_OK


def oauth_cli(
    argv: list[str],
    *,
    transport: httpx2.AsyncBaseTransport | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Run ``netbox-mcp oauth <argv>``; returns the process exit code.

    ``transport`` replaces the NetBox HTTP transport (tests).
    """
    out = out or sys.stdout
    err = err or sys.stderr
    if not argv:
        print(USAGE, file=err)
        return EXIT_ERROR
    if argv[0] in {"-h", "--help", "help"}:
        print(USAGE, file=out)
        return EXIT_OK
    command, rest = argv[0], argv[1:]
    try:
        if command == "init":
            return _cmd_init(rest, out)
        if command == "unlink":
            return _cmd_unlink(rest, out)
        if command == "restore-reset":
            return _cmd_restore_reset(rest, out)
        if command == "sweep":
            return _cmd_sweep(rest, out, transport)
        raise _CliError(f"unknown command {command!r}\n\n{USAGE}")
    except _CliError as exc:
        print(f"error: {exc}", file=err)
        return exc.code
