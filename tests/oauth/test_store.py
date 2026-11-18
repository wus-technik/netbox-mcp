import asyncio
import errno
import os
import stat
import sys
from pathlib import Path

import pytest

from netbox_mcp.oauth import store as store_module
from netbox_mcp.oauth.state import Client
from netbox_mcp.oauth.state import OAuthState
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import StoreError
from netbox_mcp.oauth.store import StoreLocked
from netbox_mcp.oauth.store import StoreWriteError

KEY = b"k" * 32


def _client(cid: str = "c1") -> Client:
    return Client(
        client_id=cid,
        client_name="Test",
        redirect_uris=["https://example.com/cb"],
        created_at=1.0,
        last_used_at=2.0,
    )


def test_create_then_open_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    opened = StateStore.open(path, KEY)
    try:
        assert opened.snapshot() == OAuthState()
        assert path.read_bytes().startswith(b"NBMCPOA1")
    finally:
        opened.close()


@pytest.mark.asyncio
async def test_mutation_persists_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    s = StateStore.open(path, KEY)
    async with s.mutate() as state:
        state.clients["c1"] = _client()
    s.close()
    again = StateStore.open(path, KEY)
    try:
        assert again.snapshot().clients["c1"] == _client()
    finally:
        again.close()


def test_open_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(StoreError):
        StateStore.open(tmp_path / "nope.bin", KEY)


def test_create_refuses_existing(tmp_path: Path) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    before = path.read_bytes()
    with pytest.raises(StoreError):
        StateStore.create(path, KEY)
    assert path.read_bytes() == before


def test_wrong_key_raises(tmp_path: Path) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    with pytest.raises(StoreError):
        StateStore.open(path, b"x" * 32)
    # the lock was released on failure
    StateStore.open(path, KEY).close()


def test_corrupt_file_raises(tmp_path: Path) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    data = bytearray(path.read_bytes())
    data[-1] ^= 0xFF
    path.write_bytes(bytes(data))
    with pytest.raises(StoreError):
        StateStore.open(path, KEY)
    path.write_bytes(b"garbage")
    with pytest.raises(StoreError):
        StateStore.open(path, KEY)


def test_schema_invalid_raises(tmp_path: Path) -> None:
    path = tmp_path / "state.bin"
    nonce = b"n" * 12
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    blob = b"NBMCPOA1" + nonce
    blob += AESGCM(KEY).encrypt(
        nonce, b'{"version": 1, "clients": {"c": {}}}', b"netbox-mcp-oauth-state-v1"
    )
    path.write_bytes(blob)
    with pytest.raises(StoreError, match="schema"):
        StateStore.open(path, KEY)


def test_second_open_is_locked(tmp_path: Path) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    first = StateStore.open(path, KEY)
    try:
        with pytest.raises(StoreLocked):
            StateStore.open(path, KEY)
    finally:
        first.close()
    StateStore.open(path, KEY).close()


@pytest.mark.asyncio
async def test_mutate_exception_discards(tmp_path: Path) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    s = StateStore.open(path, KEY)
    before = path.read_bytes()
    try:
        with pytest.raises(RuntimeError):  # noqa: PT012
            async with s.mutate() as state:
                state.clients["c1"] = _client()
                raise RuntimeError("boom")
        assert s.snapshot().clients == {}
        assert path.read_bytes() == before
    finally:
        s.close()


@pytest.mark.asyncio
async def test_write_failure_raises_and_keeps_old_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    s = StateStore.open(path, KEY)
    try:
        async with s.mutate() as state:
            state.clients["c1"] = _client("c1")
        on_disk = path.read_bytes()

        def boom(*_a: object, **_k: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(os, "replace", boom)
        with pytest.raises(StoreWriteError) as exc:
            async with s.mutate() as state:
                state.clients["c2"] = _client("c2")
        assert "disk full" not in str(exc.value)
        assert path.read_bytes() == on_disk
        assert set(s.snapshot().clients) == {"c1"}
        assert not list(tmp_path.glob("*.tmp"))
    finally:
        s.close()


@pytest.mark.asyncio
async def test_write_goes_through_write_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    s = StateStore.open(path, KEY)
    try:

        def fail(_data: bytes) -> None:
            raise OSError("nope")

        monkeypatch.setattr(s, "_write_file", fail)
        with pytest.raises(StoreWriteError):
            async with s.mutate() as state:
                state.clients["c1"] = _client()
        assert s.snapshot().clients == {}
    finally:
        s.close()


@pytest.mark.asyncio
async def test_write_is_atomic_tmp_in_same_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    s = StateStore.open(path, KEY)
    replaced: list[tuple[str, str]] = []
    fsyncs: list[int] = []
    real_replace, real_fsync = os.replace, os.fsync

    def spy_replace(src: object, dst: object) -> None:
        replaced.append((str(src), str(dst)))
        real_replace(src, dst)

    def spy_fsync(fd: int) -> None:
        fsyncs.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "replace", spy_replace)
    monkeypatch.setattr(os, "fsync", spy_fsync)
    try:
        async with s.mutate() as state:
            state.clients["c1"] = _client()
    finally:
        s.close()
    assert len(replaced) == 1
    src, dst = replaced[0]
    assert Path(src).parent == Path(dst).parent == tmp_path
    assert Path(dst) == path
    # file fsync always; directory fsync additionally on POSIX
    assert len(fsyncs) >= (1 if sys.platform == "win32" else 2)


@pytest.mark.skipif(
    sys.platform == "win32", reason="directory fsync is a no-op on Windows"
)
@pytest.mark.asyncio
async def test_file_and_directory_are_fsynced_separately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    s = StateStore.open(path, KEY)
    calls: list[str] = []
    real_replace, real_fsync = os.replace, os.fsync

    def spy_fsync(fd: int) -> None:
        mode = os.fstat(fd).st_mode
        calls.append(
            "dir" if stat.S_ISDIR(mode) else "file" if stat.S_ISREG(mode) else "?"
        )
        real_fsync(fd)

    def spy_replace(a: object, b: object) -> None:
        calls.append("replace")
        real_replace(a, b)

    monkeypatch.setattr(os, "replace", spy_replace)
    monkeypatch.setattr(os, "fsync", spy_fsync)
    try:
        async with s.mutate() as state:
            state.clients["c1"] = _client()
    finally:
        s.close()
    assert calls == ["file", "replace", "dir"]


def test_error_messages_hold_no_key_material(tmp_path: Path) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    with pytest.raises(StoreError) as exc:
        StateStore.open(path, b"x" * 32)
    assert "x" * 32 not in str(exc.value)


@pytest.mark.asyncio
async def test_store_fixture(store: StateStore) -> None:
    async with store.mutate() as state:
        state.clients["c1"] = _client()
    assert "c1" in store.snapshot().clients
    assert store_module.MAGIC == b"NBMCPOA1"


def _write_raw(path: Path, payload: bytes) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = b"n" * 12
    path.write_bytes(
        b"NBMCPOA1"
        + nonce
        + AESGCM(KEY).encrypt(nonce, payload, b"netbox-mcp-oauth-state-v1")
    )


_EMPTY = (
    b'"clients": {}, "grants": {}, "flows": {}, "links": {},'
    b' "sessions": {}, "pending": {}, "cleanup": {}'
)


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b'{"version": 2, ' + _EMPTY + b"}",
        b'{"version": 1, ' + _EMPTY + b', "extra": 1}',
        b'{"version": 1, "clients": {"c": {"client_id": "c", "client_name": "n",'
        b' "redirect_uris": [], "created_at": 1, "last_used_at": 1, "bogus": 1}},'
        b' "grants": {}, "flows": {}, "links": {}, "sessions": {}, "pending": {},'
        b' "cleanup": {}}',
        b"[]",
    ],
)
def test_strict_schema_rejected(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "state.bin"
    _write_raw(path, payload)
    with pytest.raises(StoreError, match="schema"):
        StateStore.open(path, KEY)


@pytest.mark.asyncio
async def test_dir_fsync_failure_marks_store_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    s = StateStore.open(path, KEY)

    def bad_fsync_dir(_d: Path) -> None:
        raise OSError("io error")

    monkeypatch.setattr(store_module, "_fsync_dir", bad_fsync_dir)
    try:
        with pytest.raises(StoreWriteError):
            async with s.mutate() as state:
                state.clients["c1"] = _client()
        monkeypatch.undo()
        with pytest.raises(StoreWriteError, match="reopen"):
            async with s.mutate():
                pass
    finally:
        s.close()
    again = StateStore.open(path, KEY)
    try:
        assert "c1" in again.snapshot().clients
    finally:
        again.close()


@pytest.mark.asyncio
async def test_close_during_mutate_is_refused_and_aclose_waits(tmp_path: Path) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    s = StateStore.open(path, KEY)
    async with s.mutate() as state:
        state.clients["c1"] = _client()
        with pytest.raises(StoreError, match="in flight"):
            s.close()
        closer = asyncio.create_task(s.aclose())
        await asyncio.sleep(0.01)
        assert not closer.done()
    await closer
    with pytest.raises(StoreError, match="closed"):
        async with s.mutate():
            pass
    again = StateStore.open(path, KEY)
    try:
        assert "c1" in again.snapshot().clients
    finally:
        again.close()


@pytest.mark.asyncio
async def test_committed_object_is_not_live_memory(store: StateStore) -> None:
    async with store.mutate() as state:
        state.clients["c1"] = _client()
    state.clients["c2"] = _client("c2")  # edit after commit, never written
    assert set(store.snapshot().clients) == {"c1"}


def test_create_never_overwrites_a_file_appearing_late(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.bin"
    path.write_bytes(b"precious")
    monkeypatch.setattr(Path, "exists", lambda _self: False)
    with pytest.raises(StoreError, match="exists"):
        StateStore.create(path, KEY)
    assert path.read_bytes() == b"precious"
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.asyncio
async def test_nested_mutate_raises_instead_of_deadlocking(store: StateStore) -> None:
    async def nested() -> None:
        async with store.mutate(), store.mutate():
            pass

    with pytest.raises(StoreError, match="nested"):
        await asyncio.wait_for(nested(), timeout=2)
    async with store.mutate() as state:
        state.clients["c1"] = _client()


@pytest.mark.parametrize(
    ("code", "locked"),
    [
        (errno.EACCES, True),
        (errno.EAGAIN, True),
        (errno.EDEADLK, True),
        (errno.EIO, False),
        (errno.ENOSPC, False),
    ],
)
def test_lock_errno_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int, locked: bool
) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)

    def fail(_fd: int) -> None:
        raise OSError(code, "x")

    monkeypatch.setattr(store_module, "_lock_file", fail)
    with pytest.raises(StoreError) as exc:
        StateStore.open(path, KEY)
    assert isinstance(exc.value, StoreLocked) is locked


@pytest.mark.asyncio
async def test_snapshot_refused_after_uncertain_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    s = StateStore.open(path, KEY)

    def bad_fsync_dir(_d: Path) -> None:
        raise OSError("io error")

    monkeypatch.setattr(store_module, "_fsync_dir", bad_fsync_dir)
    try:
        with pytest.raises(StoreWriteError):
            async with s.mutate() as state:
                state.clients["c1"] = _client()
        with pytest.raises(StoreError, match="reopen"):
            s.snapshot()
    finally:
        s.close()


@pytest.mark.asyncio
async def test_aclose_inside_mutate_raises_instead_of_deadlocking(
    store: StateStore,
) -> None:
    async def inner() -> None:
        async with store.mutate():
            await store.aclose()

    with pytest.raises(StoreError, match="aclose"):
        await asyncio.wait_for(inner(), timeout=2)


def test_create_survives_tmp_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.bin"
    real_unlink = Path.unlink

    def flaky_unlink(self: Path, *a: object, **k: object) -> None:
        if self.name.endswith(".tmp"):
            raise OSError(errno.EACCES, "busy")
        real_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", flaky_unlink)
    StateStore.create(path, KEY)
    monkeypatch.undo()
    StateStore.open(path, KEY).close()
