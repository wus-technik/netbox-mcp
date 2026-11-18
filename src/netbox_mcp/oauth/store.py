"""Encrypted single-file state store.

File format: ``MAGIC + nonce(12) + AES-256-GCM(json, aad=AAD)``. Writes go to a
temp file in the same directory, are fsynced and renamed over the state file.
An exclusive OS lock on ``<path>.lock`` (not on the state file, so the rename
works on Windows) keeps a second process out.

Error messages never contain state content or key material.
"""

import asyncio
import contextlib
import errno
import json
import os
import secrets
import sys
from collections.abc import AsyncIterator
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError

from netbox_mcp.oauth.state import OAuthState

MAGIC = b"NBMCPOA1"
AAD = b"netbox-mcp-oauth-state-v1"
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32

if sys.platform == "win32":
    import msvcrt

    def _lock_file(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock_file(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _lock_file(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock_file(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


class StoreError(Exception):
    """The state file cannot be used; the server must not start."""


class StoreLocked(StoreError):  # noqa: N818 - name fixed by the plan
    """Another process holds the state file lock."""


class _CommitUncertainError(Exception):
    """The rename happened but its durability could not be confirmed."""


class StoreWriteError(StoreError):
    """A change could not be persisted; it was discarded."""


def _check_key(key: bytes) -> None:
    if len(key) != KEY_BYTES:
        raise StoreError(f"state key must be {KEY_BYTES} bytes")


def _encrypt(state: OAuthState, key: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_BYTES)
    plain = state.model_dump_json().encode()
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, plain, AAD)


def _decrypt(data: bytes, key: bytes) -> OAuthState:
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + NONCE_BYTES + TAG_BYTES:
        raise StoreError("state file is not a valid encrypted state file")
    nonce = data[len(MAGIC) : len(MAGIC) + NONCE_BYTES]
    try:
        plain = AESGCM(key).decrypt(nonce, data[len(MAGIC) + NONCE_BYTES :], AAD)
    except InvalidTag:
        raise StoreError(
            "state file cannot be decrypted (wrong key or corrupt file)"
        ) from None
    try:
        raw = json.loads(plain)
        if not isinstance(raw, dict) or set(raw) != set(OAuthState.model_fields):
            raise ValueError("top-level keys")
        return OAuthState.model_validate(raw)
    except (ValueError, ValidationError):
        raise StoreError("state file content does not match the schema") from None


def _fsync_dir(directory: Path) -> None:
    """fsync the directory so the rename is durable (no-op on Windows)."""
    if sys.platform == "win32":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_atomic(path: Path, data: bytes, *, overwrite: bool = True) -> None:
    """Publish ``data`` at ``path``: temp file in the same dir, fsync, rename.

    With ``overwrite=False`` an existing file is never replaced
    (``FileExistsError``). Raises ``_CommitUncertainError`` if the file is in
    place but the directory fsync failed.
    """
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with tmp.open("xb") as f:  # exclusive: never reuse a leftover inode
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if overwrite:
            tmp.replace(path)
        else:
            os.link(tmp, path)
            # Published; a leftover temp file must not turn this into a failure.
            with contextlib.suppress(OSError):
                tmp.unlink()
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    try:
        _fsync_dir(path.parent)
    except OSError:
        raise _CommitUncertainError from None


_CONTENTION = frozenset({errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK, errno.EDEADLK})


def _remove_stale_tmp(path: Path) -> None:
    """Best-effort removal of temp files left by an interrupted write."""
    for stale in (
        *path.parent.glob(f"{path.name}.*.tmp"),
        path.with_name(path.name + ".tmp"),
    ):
        with contextlib.suppress(OSError):
            stale.unlink()


def _acquire_lock(path: Path) -> int:
    lock_path = path.with_name(path.name + ".lock")
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        raise StoreError(f"cannot open lock file: {exc.strerror}") from None
    try:
        _lock_file(fd)
    except OSError as exc:
        os.close(fd)
        if exc.errno in _CONTENTION:
            raise StoreLocked("state file is locked by another process") from None
        raise StoreError(f"cannot lock state file: {exc.strerror}") from None
    return fd


def _release_lock(fd: int) -> None:
    with contextlib.suppress(OSError):
        _unlock_file(fd)
    with contextlib.suppress(OSError):
        os.close(fd)


class StateStore:
    """Holds the state in memory and persists every change atomically."""

    def __init__(self, path: Path, key: bytes, state: OAuthState, lock_fd: int):
        self._path = path
        self._key = key
        self._state = state
        self._lock_fd: int | None = lock_fd
        self._mutex = asyncio.Lock()
        self._owner: asyncio.Task | None = None
        self._failed = False

    @classmethod
    def create(cls, path: Path, key: bytes) -> None:
        """Write an empty state file; never overwrites an existing file."""
        _check_key(key)
        path = Path(path)
        if path.exists():
            raise StoreError(f"state file already exists: {path}")
        lock_fd = _acquire_lock(path)
        try:
            _write_atomic(path, _encrypt(OAuthState(), key), overwrite=False)
        except FileExistsError:
            raise StoreError(f"state file already exists: {path}") from None
        except _CommitUncertainError:
            raise StoreError("state file created but not confirmed durable") from None
        except OSError as exc:
            raise StoreError(f"cannot create state file: {exc.strerror}") from None
        finally:
            _release_lock(lock_fd)

    @classmethod
    def open(cls, path: Path, key: bytes) -> "StateStore":
        """Lock and load the state file.

        Raises:
            StoreLocked: another process holds the lock.
            StoreError: file missing, unreadable, undecryptable or invalid.
        """
        _check_key(key)
        path = Path(path)
        if not path.is_file():
            raise StoreError(f"state file not found: {path}")
        lock_fd = _acquire_lock(path)
        try:
            try:
                data = path.read_bytes()
            except OSError as exc:
                raise StoreError(f"cannot read state file: {exc.strerror}") from None
            state = _decrypt(data, key)
            _remove_stale_tmp(path)
        except BaseException:
            _release_lock(lock_fd)
            raise
        return cls(path, key, state, lock_fd)

    def snapshot(self) -> OAuthState:
        """Deep copy of the current state; refused after an uncertain commit."""
        if self._failed:
            raise StoreError("state store failed; reopen required")
        return self._state.model_copy(deep=True)

    @contextlib.asynccontextmanager
    async def mutate(self) -> AsyncIterator[OAuthState]:
        """Serialized read-modify-write; persists on clean exit.

        On an exception in the body the changes are discarded and the exception
        propagates. If persisting fails, the previous in-memory state is kept
        and ``StoreWriteError`` is raised. If the outcome of the commit is
        indeterminate, the store is marked failed: every further ``mutate``
        raises ``StoreWriteError`` until the file is reopened.
        """
        task = asyncio.current_task()
        if task is not None and task is self._owner:
            raise StoreError("nested mutate() would deadlock")
        async with self._mutex:
            if self._lock_fd is None:
                raise StoreError("state store is closed")
            if self._failed:
                raise StoreWriteError("state store failed; reopen required")
            self._owner = task
            try:
                working = self._state.model_copy(deep=True)
                yield working
                try:
                    self._write_file(_encrypt(working, self._key))
                except _CommitUncertainError:
                    self._failed = True
                    raise StoreWriteError(
                        "state write not confirmed; reopen required"
                    ) from None
                except Exception:
                    raise StoreWriteError(
                        "cannot write state file; change discarded"
                    ) from None
                self._state = working.model_copy(deep=True)
            finally:
                self._owner = None

    def _write_file(self, data: bytes) -> None:
        """The single place that writes the state file."""
        _write_atomic(self._path, data)

    async def aclose(self) -> None:
        """Release the lock after any in-flight mutate has finished."""
        task = asyncio.current_task()
        if task is not None and task is self._owner:
            raise StoreError("aclose() inside mutate() would deadlock")
        async with self._mutex:
            self._release()

    def close(self) -> None:
        """Release the lock (non-async callers); refuses while a mutate runs."""
        if self._mutex.locked():
            raise StoreError("cannot close while a mutate is in flight")
        self._release()

    def _release(self) -> None:
        if self._lock_fd is not None:
            _release_lock(self._lock_fd)
            self._lock_fd = None
