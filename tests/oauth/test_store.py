import os
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
async def test_directory_is_fsynced_after_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.bin"
    StateStore.create(path, KEY)
    s = StateStore.open(path, KEY)
    calls: list[str] = []
    real_replace, real_fsync = os.replace, os.fsync

    monkeypatch.setattr(
        os, "replace", lambda a, b: (calls.append("replace"), real_replace(a, b))
    )
    monkeypatch.setattr(os, "fsync", lambda fd: (calls.append("fsync"), real_fsync(fd)))
    try:
        async with s.mutate() as state:
            state.clients["c1"] = _client()
    finally:
        s.close()
    assert calls == ["fsync", "replace", "fsync"]


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
