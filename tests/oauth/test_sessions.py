import asyncio

import pytest

from netbox_mcp.models import NetBoxConfig
from netbox_mcp.oauth import tokens as token_time
from netbox_mcp.oauth.broker import NetBoxBroker
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.idp import IdpClient
from netbox_mcp.oauth.sessions import LoginFailed
from netbox_mcp.oauth.sessions import SessionManager
from netbox_mcp.oauth.state import Client
from netbox_mcp.oauth.state import Link
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import StoreWriteError
from netbox_mcp.oauth.tokens import AccessTokens
from tests.oauth.fakes import FakeNetBoxTokens

DAY = 86400


@pytest.fixture
def manager(
    oauth_config: OAuthConfig,
    store: StateStore,
    fake_netbox_tokens: FakeNetBoxTokens,
    clock,
) -> SessionManager:
    fake_netbox_tokens.now = clock
    config = NetBoxConfig(netbox_url=fake_netbox_tokens.base_url, token="nbt_o.o")
    broker = NetBoxBroker(
        config, "nbt_broker.secret", transport=fake_netbox_tokens.transport
    )
    return SessionManager(
        oauth_config, store, broker, IdpClient(oauth_config), AccessTokens(oauth_config)
    )


@pytest.fixture
def link(clock) -> Link:
    return Link(
        user_key="iss|sub-a",
        iss="iss",
        sub="sub-a",
        netbox_user_id=1,
        netbox_username="alice",
        created_at=clock(),
    )


@pytest.fixture
def client(clock) -> Client:
    return Client(
        client_id="cid",
        client_name="Test Client",
        redirect_uris=["http://localhost/cb"],
        created_at=clock(),
        last_used_at=clock(),
    )


def posts(fake: FakeNetBoxTokens) -> list:
    return fake.sent("POST", "tokens.create")


async def _make(manager, link, client):
    session, _ = await manager.create_session(link, client, "rt")
    return session


async def test_create_session_marker_removed_in_same_write(
    manager, store, fake_netbox_tokens, link, client, monkeypatch
) -> None:
    writes: list = []
    original = store._write_file

    def spy(data: bytes) -> None:
        writes.append(len(posts(fake_netbox_tokens)))
        original(data)

    monkeypatch.setattr(store, "_write_file", spy)
    session, code = await manager.create_session(link, client, "idp-rt")
    # Write 1 (marker) is before the POST, write 2 (session, no marker) after it.
    assert writes == [0, 1]
    state = store.snapshot()
    assert session.sid in state.sessions
    assert state.pending == {}
    assert state.sessions[session.sid].token_version == 1
    assert session.netbox_token.startswith("nbt_")
    assert session.netbox_token_expires_at == pytest.approx(token_time.now() + 7 * DAY)
    assert session.code_hash == token_time.hash_secret(code)
    assert session.code_expires_at == token_time.now() + 300
    assert len(code) >= 43  # 256 bit base64url
    assert code not in str(state.model_dump())


async def test_create_token_ambiguous_keeps_marker(
    manager, store, fake_netbox_tokens, link, client
) -> None:
    fake_netbox_tokens.fail("tokens.create", "commit_then_timeout")
    with pytest.raises(LoginFailed):
        await manager.create_session(link, client, "rt")
    state = store.snapshot()
    assert len(state.pending) == 1
    assert state.sessions == {}
    assert len(posts(fake_netbox_tokens)) == 1


async def test_create_token_definite_drops_marker(
    manager, store, fake_netbox_tokens, link, client
) -> None:
    fake_netbox_tokens.fail("tokens.create", 403)
    with pytest.raises(LoginFailed):
        await manager.create_session(link, client, "rt")
    state = store.snapshot()
    assert state.pending == {}
    assert state.sessions == {}


async def test_create_final_write_failure_leaves_marker(
    manager, store, link, client, monkeypatch
) -> None:
    original = store._write_file
    calls = 0

    def flaky(data: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("disk")
        original(data)

    monkeypatch.setattr(store, "_write_file", flaky)
    with pytest.raises(StoreWriteError):
        await manager.create_session(link, client, "rt")
    state = store.snapshot()
    assert len(state.pending) == 1
    assert state.sessions == {}


async def test_description_format(manager, fake_netbox_tokens, link, client) -> None:
    session = await _make(manager, link, client)
    record = fake_netbox_tokens.tokens[session.netbox_token_id]
    desc = record["description"] if isinstance(record, dict) else record.description
    prefix = f"NetBox MCP (OAuth) Test Client {session.sid[:8]} "
    assert desc.startswith(prefix)
    nonce = desc[len(prefix) :]
    assert nonce
    assert " " not in nonce
    assert posts(fake_netbox_tokens)[0].json["write_enabled"] is True


async def test_renew_swaps_and_enqueues_old(
    manager, store, fake_netbox_tokens, link, client, clock
) -> None:
    session = await _make(manager, link, client)
    old_id = session.netbox_token_id
    clock.advance(5 * DAY - 1)  # 2 days + 1 s left
    await manager.renew_if_due(session.sid)
    assert len(posts(fake_netbox_tokens)) == 1
    assert manager.current_token(session.sid)[1] == 1
    clock.advance(2)
    await manager.renew_if_due(session.sid)
    assert len(posts(fake_netbox_tokens)) == 2
    state = store.snapshot()
    new = state.sessions[session.sid]
    assert new.token_version == 2
    assert new.netbox_token_id != old_id
    assert new.netbox_token != session.netbox_token
    assert new.netbox_token_expires_at == pytest.approx(token_time.now() + 7 * DAY)
    assert state.pending == {}
    assert [e.netbox_token_id for e in state.cleanup.values()] == [old_id]
    assert manager.cleanup_wanted.is_set()
    assert manager.current_token(session.sid) == (new.netbox_token, 2)


async def test_renew_after_session_end_enqueues_new(
    manager, store, fake_netbox_tokens, link, client, clock, monkeypatch
) -> None:
    session = await _make(manager, link, client)
    clock.advance(6 * DAY)
    original = manager.broker.create_token

    async def ending(*args, **kwargs):
        result = await original(*args, **kwargs)
        async with store.mutate() as state:
            state.sessions.pop(session.sid)
        return result

    monkeypatch.setattr(manager.broker, "create_token", ending)
    await manager.renew_if_due(session.sid)
    state = store.snapshot()
    new_id = max(fake_netbox_tokens.tokens)
    assert [e.netbox_token_id for e in state.cleanup.values()] == [new_id]
    assert state.pending == {}
    assert state.sessions == {}


async def test_renew_ambiguous_keeps_marker_and_token(
    manager, store, fake_netbox_tokens, link, client, clock
) -> None:
    session = await _make(manager, link, client)
    clock.advance(6 * DAY)
    fake_netbox_tokens.fail("tokens.create", "commit_then_timeout")
    await manager.renew_if_due(session.sid)  # does not raise
    state = store.snapshot()
    assert len(state.pending) == 1
    assert state.cleanup == {}
    assert manager.current_token(session.sid) == (session.netbox_token, 1)


async def test_renew_definite_drops_marker(
    manager, store, fake_netbox_tokens, link, client, clock
) -> None:
    session = await _make(manager, link, client)
    clock.advance(6 * DAY)
    fake_netbox_tokens.fail("tokens.create", 403)
    await manager.renew_if_due(session.sid)
    assert store.snapshot().pending == {}
    assert manager.current_token(session.sid) == (session.netbox_token, 1)


async def test_concurrent_renew_posts_once(
    manager, fake_netbox_tokens, link, client, clock
) -> None:
    session = await _make(manager, link, client)
    clock.advance(6 * DAY)
    await asyncio.gather(
        manager.renew_if_due(session.sid), manager.renew_if_due(session.sid)
    )
    assert len(posts(fake_netbox_tokens)) == 2  # create + exactly one renewal
    assert manager.current_token(session.sid)[1] == 2


async def test_renew_unknown_session_noop(manager, fake_netbox_tokens) -> None:
    await manager.renew_if_due("nope")
    assert posts(fake_netbox_tokens) == []


async def test_end_session_idempotent(manager, store, link, client) -> None:
    session = await _make(manager, link, client)
    assert not manager.cleanup_wanted.is_set()
    await manager.end_session(session.sid, "revoked")
    state = store.snapshot()
    assert state.sessions == {}
    (entry,) = state.cleanup.values()
    assert entry.netbox_token_id == session.netbox_token_id
    assert entry.netbox_user_id == 1
    assert entry.reason == "revoked"
    assert manager.cleanup_wanted.is_set()
    await manager.end_session(session.sid, "revoked")
    assert len(store.snapshot().cleanup) == 1
    assert manager.current_token(session.sid) is None
