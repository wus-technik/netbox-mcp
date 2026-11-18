import asyncio
import base64
import io
from pathlib import Path

import pytest

from netbox_mcp.oauth.cli import oauth_cli
from netbox_mcp.oauth.state import CleanupEntry
from netbox_mcp.oauth.state import Client
from netbox_mcp.oauth.state import Flow
from netbox_mcp.oauth.state import Grant
from netbox_mcp.oauth.state import Link
from netbox_mcp.oauth.state import OAuthState
from netbox_mcp.oauth.state import PendingCreate
from netbox_mcp.oauth.state import Replay
from netbox_mcp.oauth.state import Session
from netbox_mcp.oauth.store import StateStore
from tests.oauth.fakes import FakeNetBoxTokens

KEY = b"k" * 32
PREFIX = "NetBox MCP (OAuth) "


@pytest.fixture
def state_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "state.bin"
    monkeypatch.setenv("OAUTH_STATE_PATH", str(path))
    monkeypatch.setenv("OAUTH_STATE_KEY", base64.b64encode(KEY).decode())
    return path


def run(*argv: str, transport=None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = oauth_cli(list(argv), transport=transport, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def _session(sid: str, user_key: str, token_id: int, user_id: int = 1) -> Session:
    return Session(
        sid=sid,
        user_key=user_key,
        client_id="c1",
        netbox_user_id=user_id,
        created_at=1.0,
        refresh_hash="h-" + sid,
        spent_hashes=["old-" + sid],
        replay=Replay(hash="r", rotated_at=1.0, response={"a": 1}),
        refresh_deadline=9e9,
        last_idp_check_at=1.0,
        netbox_token="nbt_x.y",
        netbox_token_id=token_id,
    )


def _populate() -> OAuthState:
    state = OAuthState()
    state.clients["c1"] = Client(
        client_id="c1",
        client_name="C",
        redirect_uris=["https://e.example/cb"],
        created_at=1.0,
        last_used_at=1.0,
    )
    for name, uid in (("Alice", 1), ("bob", 2)):
        key = f"https://idp|{name.lower()}"
        state.links[key] = Link(
            user_key=key,
            iss="https://idp",
            sub=name.lower(),
            netbox_user_id=uid,
            netbox_username=name,
            created_at=1.0,
        )
        state.grants[f"{key}|c1"] = Grant(user_key=key, client_id="c1", created_at=1.0)
    state.sessions["s-alice"] = _session("s-alice", "https://idp|alice", 11, 1)
    state.sessions["s-bob"] = _session("s-bob", "https://idp|bob", 12, 2)
    state.flows["f1"] = Flow(
        flow_id="f1",
        client_id="c1",
        redirect_uri="https://e.example/cb",
        code_challenge="x",
        idp_state="s",
        idp_nonce="n",
        idp_verifier="v",
        created_at=1.0,
        user_key="https://idp|alice",
    )
    state.flows["f2"] = state.flows["f1"].model_copy(
        update={"flow_id": "f2", "user_key": None}
    )
    state.pending["n1"] = PendingCreate(
        nonce="n1", netbox_user_id=1, sid="s-x", created_at=1.0
    )
    return state


@pytest.fixture
def populated(state_path: Path) -> Path:
    StateStore.create(state_path, KEY)
    store = StateStore.open(state_path, KEY)

    async def fill() -> None:
        async with store.mutate() as state:
            full = _populate()
            for name in OAuthState.model_fields:
                setattr(state, name, getattr(full, name))

    asyncio.run(fill())
    store.close()
    return state_path


def load(path: Path) -> OAuthState:
    store = StateStore.open(path, KEY)
    try:
        return store.snapshot()
    finally:
        store.close()


def test_init_creates_file_and_refuses_existing(state_path: Path) -> None:
    code, _, _ = run("init")
    assert code == 0
    assert state_path.is_file()
    assert load(state_path) == OAuthState()
    before = state_path.read_bytes()
    code, _, err = run("init")
    assert code == 1
    assert "already exists" in err
    assert state_path.read_bytes() == before


def test_init_names_missing_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OAUTH_STATE_PATH", raising=False)
    monkeypatch.delenv("OAUTH_STATE_KEY", raising=False)
    code, _, err = run("init")
    assert code == 1
    assert "OAUTH_STATE_PATH" in err


def test_bad_key_is_refused_without_echo(
    state_path: Path,  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OAUTH_STATE_KEY", base64.b64encode(b"short").decode())
    code, _, err = run("init")
    assert code == 1
    assert "OAUTH_STATE_KEY" in err
    assert "c2hvcnQ" not in err


@pytest.mark.parametrize("argv", [("unlink", "alice"), ("restore-reset",), ("sweep",)])
def test_commands_refuse_when_locked(
    populated: Path, monkeypatch: pytest.MonkeyPatch, argv: tuple[str, ...]
) -> None:
    monkeypatch.setenv("NETBOX_URL", "https://netbox.example.com")
    monkeypatch.setenv("NETBOX_TOKEN_BROKER_TOKEN", "nbt_broker.secret")
    holder = StateStore.open(populated, KEY)
    try:
        before = populated.read_bytes()
        code, _, err = run(*argv)
        assert code == 2
        assert "locked" in err
        assert populated.read_bytes() == before
    finally:
        holder.close()


def test_missing_store_is_an_error(state_path: Path) -> None:  # noqa: ARG001
    code, _, err = run("restore-reset")
    assert code == 1
    assert "not found" in err


def test_unlink_removes_link_ends_sessions_enqueues_tokens(populated: Path) -> None:
    code, out, _ = run("unlink", "ALICE")
    assert code == 0
    state = load(populated)
    assert list(state.links) == ["https://idp|bob"]
    assert list(state.sessions) == ["s-bob"]
    assert [c.netbox_token_id for c in state.cleanup.values()] == [11]
    entry = next(iter(state.cleanup.values()))
    assert entry.netbox_user_id == 1
    assert entry.reason == "unlink"
    assert list(state.grants) == ["https://idp|bob|c1"]
    assert list(state.flows) == ["f2"]
    assert "nbt_" not in out


def test_unlink_unknown_user_changes_nothing(populated: Path) -> None:
    before = load(populated)
    code, _, err = run("unlink", "nobody")
    assert code == 1
    assert "no identity link" in err
    assert load(populated) == before


def test_unlink_needs_one_argument(populated: Path) -> None:  # noqa: ARG001
    assert run("unlink")[0] == 1
    assert run("unlink", "a", "b")[0] == 1


def test_restore_reset_ends_all_sessions_keeps_links_and_grants(
    populated: Path,
) -> None:
    code, _, _ = run("restore-reset")
    assert code == 0
    state = load(populated)
    assert state.sessions == {}
    assert sorted(c.netbox_token_id for c in state.cleanup.values()) == [11, 12]
    assert {c.reason for c in state.cleanup.values()} == {"restore-reset"}
    assert state.flows == {}
    assert len(state.links) == 2
    assert len(state.grants) == 2
    assert list(state.clients) == ["c1"]
    assert list(state.pending) == ["n1"]


@pytest.fixture
def netbox(populated: Path, monkeypatch: pytest.MonkeyPatch) -> FakeNetBoxTokens:
    monkeypatch.setenv("NETBOX_URL", FakeNetBoxTokens.base_url)
    monkeypatch.setenv("NETBOX_TOKEN_BROKER_TOKEN", "nbt_broker.secret")
    fake = FakeNetBoxTokens()
    # IDs 1..5: held by a session (1, 2), carrying a marker nonce (3),
    # untracked (4), and a foreign token without the prefix (5).
    fake.add_token("alice", description=PREFIX + "C s-alice1 aaaa")
    fake.add_token("bob", description=PREFIX + "C s-bob0001 bbbb")
    fake.add_token("alice", description=PREFIX + "C s-xxxxxxx n1")
    fake.add_token("bob", description=PREFIX + "C s-gone0000 gggg")
    fake.add_token("bob", description="my own token")
    state_store = StateStore.open(populated, KEY)

    async def track() -> None:
        async with state_store.mutate() as state:
            state.sessions["s-alice"].netbox_token_id = 1
            state.sessions["s-bob"].netbox_token_id = 2
            # Token 4 is on the cleanup queue; 3 is tracked by the marker.
            state.cleanup["e1"] = CleanupEntry(
                entry_id="e1",
                netbox_token_id=99,
                netbox_user_id=1,
                reason="x",
                created_at=1,
            )

    asyncio.run(track())
    state_store.close()
    return fake


def test_sweep_dry_run_deletes_nothing(
    netbox: FakeNetBoxTokens,
    populated: Path,  # noqa: ARG001
) -> None:
    code, out, _ = run("sweep", transport=netbox.transport)
    assert code == 0
    assert set(netbox.tokens) == {1, 2, 3, 4, 5}
    assert not netbox.sent("DELETE")
    assert "untracked: 1" in out
    assert "Dry run" in out
    assert "s-gone0000" not in out
    assert "bbbb" not in out


def test_sweep_apply_deletes_only_untracked(
    netbox: FakeNetBoxTokens,
    populated: Path,  # noqa: ARG001
) -> None:
    code, out, _ = run("sweep", "--apply", transport=netbox.transport)
    assert code == 0
    assert set(netbox.tokens) == {1, 2, 3, 5}
    assert "Deleted 1" in out


def test_sweep_requires_netbox_settings(
    populated: Path,  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NETBOX_URL", raising=False)
    monkeypatch.delenv("NETBOX_TOKEN_BROKER_TOKEN", raising=False)
    code, _, err = run("sweep")
    assert code == 1
    assert "NETBOX_URL" in err
    monkeypatch.setenv("NETBOX_URL", "https://netbox.example.com")
    code, _, err = run("sweep")
    assert "NETBOX_TOKEN_BROKER_TOKEN" in err


def test_sweep_netbox_failure_is_exit_1(
    netbox: FakeNetBoxTokens,
    populated: Path,  # noqa: ARG001
) -> None:
    netbox.fail("tokens.list", 500)
    code, _, err = run("sweep", "--apply", transport=netbox.transport)
    assert code == 1
    assert "cannot list" in err
    assert set(netbox.tokens) == {1, 2, 3, 4, 5}


def test_sweep_unknown_flag(populated: Path) -> None:  # noqa: ARG001
    assert run("sweep", "--force")[0] == 1


def test_unknown_command_and_help() -> None:
    assert run("bogus")[0] == 1
    assert run()[0] == 1
    code, out, _ = run("--help")
    assert code == 0
    assert "restore-reset" in out


def test_main_dispatches_oauth_before_any_server_checks(
    state_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netbox_mcp import server

    monkeypatch.setattr("sys.argv", ["netbox-mcp", "oauth", "init"])
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 0
    assert state_path.is_file()
