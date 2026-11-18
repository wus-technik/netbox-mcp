import asyncio
import logging

import pytest

from netbox_mcp.models import NetBoxConfig
from netbox_mcp.oauth.broker import NetBoxBroker
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.idp import IdpClient
from netbox_mcp.oauth.jobs import Jobs
from netbox_mcp.oauth.sessions import SessionManager
from netbox_mcp.oauth.state import CleanupEntry
from netbox_mcp.oauth.state import Client
from netbox_mcp.oauth.state import Flow
from netbox_mcp.oauth.state import Grant
from netbox_mcp.oauth.state import Link
from netbox_mcp.oauth.state import PendingCreate
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.tokens import AccessTokens
from tests.oauth.fakes import FakeNetBoxTokens

DAY = 86400
BINDING = {
    "redirect_uri": "http://localhost/cb",
    "code_challenge": "c" * 43,
    "resource": None,
}


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


async def _session(manager, link, client, *, redeemed=True):
    session, _ = await manager.create_session(link, client, "rt", **BINDING)
    if redeemed:
        async with manager.store.mutate() as state:
            state.sessions[session.sid].code_redeemed = True
            state.sessions[session.sid].code_hash = None
    return session.sid


def _entry(state, token_id=77, *, created_at, user=1, **kw) -> CleanupEntry:
    entry = CleanupEntry(
        entry_id=f"e{token_id}",
        netbox_token_id=token_id,
        netbox_user_id=user,
        reason="t",
        created_at=created_at,
        **kw,
    )
    state.cleanup[entry.entry_id] = entry
    return entry


# ------------------------------------------------------------------ expiry


async def test_session_ends_30_days_without_refresh(manager, link, client, clock):
    sid = await _session(manager, link, client)
    clock.advance(30 * DAY - 1)
    await manager.end_expired()
    assert sid in manager.store.snapshot().sessions
    clock.advance(1)
    await manager.end_expired()
    state = manager.store.snapshot()
    assert sid not in state.sessions
    assert len(state.cleanup) == 1


async def test_session_ends_at_absolute_cap(manager, link, client, clock):
    sid = await _session(manager, link, client)
    async with manager.store.mutate() as state:
        state.sessions[sid].refresh_deadline = clock() + 1000 * DAY
    clock.advance(manager.config.max_session_days * DAY)
    await manager.end_expired()
    assert sid not in manager.store.snapshot().sessions


async def test_expiry_keeps_hash_index_consistent(manager, link, client, clock):
    sid = await _session(manager, link, client, redeemed=False)
    code_hash = manager.store.snapshot().sessions[sid].code_hash
    assert manager._lookup(code_hash) == sid
    clock.advance(30 * DAY)
    await manager.end_expired()
    assert manager._lookup(code_hash) is None


# ----------------------------------------------------------------- orphans


async def test_orphan_session_ended_after_10_minutes(manager, link, client, clock):
    sid = await _session(manager, link, client, redeemed=False)
    clock.advance(599)
    await manager.end_orphans()
    assert sid in manager.store.snapshot().sessions
    clock.advance(1)
    await manager.end_orphans()
    state = manager.store.snapshot()
    assert sid not in state.sessions
    assert len(state.cleanup) == 1


async def test_orphan_with_burned_code_is_ended(manager, link, client, clock):
    sid = await _session(manager, link, client, redeemed=False)
    async with manager.store.mutate() as state:
        state.sessions[sid].code_hash = None  # failed attempt burned the code
    clock.advance(601)
    await manager.end_orphans()
    assert sid not in manager.store.snapshot().sessions


async def test_redeemed_session_is_not_an_orphan(manager, link, client, clock):
    sid = await _session(manager, link, client)
    clock.advance(DAY)
    await manager.end_orphans()
    assert sid in manager.store.snapshot().sessions


# ----------------------------------------------------------------- cleanup


async def test_cleanup_404_counts_deleted(manager, fake_netbox_tokens, clock):
    record = fake_netbox_tokens.add_token("alice")
    async with manager.store.mutate() as state:
        _entry(state, 999, created_at=clock())  # unknown to NetBox: 404
        _entry(state, record["id"], created_at=clock())
    await manager.run_cleanup()
    assert manager.store.snapshot().cleanup == {}
    assert record["id"] not in fake_netbox_tokens.tokens


async def test_cleanup_failure_retries_next_run(manager, fake_netbox_tokens, clock):
    record = fake_netbox_tokens.add_token("alice")
    async with manager.store.mutate() as state:
        _entry(state, record["id"], created_at=clock())
    fake_netbox_tokens.fail("tokens.delete", 500, times=1)
    await manager.run_cleanup()
    entries = manager.store.snapshot().cleanup
    assert len(entries) == 1
    assert next(iter(entries.values())).last_attempt_at == clock()
    # Each entry is attempted once per run.
    assert len(fake_netbox_tokens.sent("DELETE", "tokens.delete")) == 1
    await manager.run_cleanup()
    assert manager.store.snapshot().cleanup == {}
    assert record["id"] not in fake_netbox_tokens.tokens


async def test_cleanup_warns_once_per_day_after_7_days(
    manager, fake_netbox_tokens, clock, caplog
):
    async with manager.store.mutate() as state:
        _entry(state, 5, created_at=clock())
    fake_netbox_tokens.fail("tokens.delete", 500)
    caplog.set_level(logging.WARNING)
    clock.advance(6 * DAY)
    await manager.run_cleanup()
    assert "cleanup entry" not in caplog.text
    clock.advance(2 * DAY)
    await manager.run_cleanup()
    assert caplog.text.count("cleanup entry") == 1
    clock.advance(3600)
    await manager.run_cleanup()
    assert caplog.text.count("cleanup entry") == 1
    clock.advance(DAY)
    await manager.run_cleanup()
    assert caplog.text.count("cleanup entry") == 2


async def test_cleanup_is_single_flight(manager, fake_netbox_tokens, clock):
    record = fake_netbox_tokens.add_token("alice")
    async with manager.store.mutate() as state:
        _entry(state, record["id"], created_at=clock())
    await asyncio.gather(manager.run_cleanup(), manager.run_cleanup())
    assert len(fake_netbox_tokens.sent("DELETE", "tokens.delete")) == 1


async def test_session_end_then_cleanup_deletes_token(
    manager, fake_netbox_tokens, link, client
):
    sid = await _session(manager, link, client)
    token_id = manager.store.snapshot().sessions[sid].netbox_token_id
    await manager.end_session(sid, "revoked")
    await manager.run_cleanup()
    assert token_id not in fake_netbox_tokens.tokens


# ---------------------------------------------------------------- recovery


async def _marker(manager, clock, *, nonce="n" * 32, user=1, age=0.0):
    async with manager.store.mutate() as state:
        state.pending[nonce] = PendingCreate(
            nonce=nonce, netbox_user_id=user, sid="s" * 32, created_at=clock() - age
        )
    return nonce


async def test_recovery_skips_young_marker(manager, fake_netbox_tokens, clock):
    nonce = await _marker(manager, clock, age=599)
    fake_netbox_tokens.add_token("alice", description=f"NetBox MCP (OAuth) x {nonce}")
    await manager.recover_pending()
    assert nonce in manager.store.snapshot().pending
    assert len(fake_netbox_tokens.tokens) == 1
    assert fake_netbox_tokens.sent("GET", "tokens.list") == []


async def test_recovery_deletes_matching_token(manager, fake_netbox_tokens, clock):
    nonce = await _marker(manager, clock, age=600)
    orphan = fake_netbox_tokens.add_token(
        "alice", description=f"NetBox MCP (OAuth) x abcd1234 {nonce}"
    )
    other = fake_netbox_tokens.add_token(
        "alice", description="NetBox MCP (OAuth) x abcd1234 " + "o" * 32
    )
    await manager.recover_pending()
    assert manager.store.snapshot().pending == {}
    assert orphan["id"] not in fake_netbox_tokens.tokens
    assert other["id"] in fake_netbox_tokens.tokens


async def test_recovery_without_token_drops_marker(manager, clock):
    await _marker(manager, clock, age=700)
    await manager.recover_pending()
    assert manager.store.snapshot().pending == {}


async def test_recovery_unavailable_keeps_marker(manager, fake_netbox_tokens, clock):
    nonce = await _marker(manager, clock, age=700)
    fake_netbox_tokens.fail("tokens.list", 500, times=1)
    await manager.recover_pending()
    assert nonce in manager.store.snapshot().pending
    await manager.recover_pending()
    assert manager.store.snapshot().pending == {}


async def test_recovery_delete_failure_keeps_marker(manager, fake_netbox_tokens, clock):
    nonce = await _marker(manager, clock, age=700)
    record = fake_netbox_tokens.add_token("alice", description=f"d {nonce}")
    fake_netbox_tokens.fail("tokens.delete", 500, times=1)
    await manager.recover_pending()
    assert nonce in manager.store.snapshot().pending
    await manager.recover_pending()
    assert manager.store.snapshot().pending == {}
    assert record["id"] not in fake_netbox_tokens.tokens


async def test_recovery_serialized_per_user(manager, clock):
    await _marker(manager, clock, nonce="a" * 32, age=700)
    await _marker(manager, clock, nonce="b" * 32, age=700)
    running = 0
    peak = 0
    original = manager.broker.list_tokens

    async def spy(*args, **kwargs):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0)
        try:
            return await original(*args, **kwargs)
        finally:
            running -= 1

    manager.broker.list_tokens = spy
    await asyncio.gather(manager.recover_pending(), manager._recover_marker("b" * 32))
    assert peak == 1


# ----------------------------------------------------------- client expiry


async def test_client_expiry_30_days_drops_grants(manager, client, clock):
    busy = client.model_copy(update={"client_id": "busy"})
    async with manager.store.mutate() as state:
        state.clients["cid"] = client
        state.clients["busy"] = busy
        state.grants["u|cid"] = Grant(user_key="u", client_id="cid", created_at=clock())
        state.grants["u|busy"] = Grant(
            user_key="u", client_id="busy", created_at=clock()
        )
    link = Link(
        user_key="u",
        iss="i",
        sub="s",
        netbox_user_id=1,
        netbox_username="alice",
        created_at=clock(),
    )
    sid = await _session(manager, link, busy)  # a live session keeps "busy"
    clock.advance(30 * DAY - 1)
    await manager.expire_clients()
    assert "cid" in manager.store.snapshot().clients
    clock.advance(1)
    await manager.expire_clients()
    state = manager.store.snapshot()
    assert "cid" not in state.clients
    assert "u|cid" not in state.grants
    assert "busy" in state.clients
    assert "u|busy" in state.grants
    assert sid in state.sessions


async def test_stale_flows_dropped(manager, clock):
    flow = Flow(
        flow_id="f1",
        client_id="cid",
        redirect_uri="http://localhost/cb",
        code_challenge="c" * 43,
        idp_state="s",
        idp_nonce="n",
        idp_verifier="v",
        created_at=clock(),
    )
    async with manager.store.mutate() as state:
        state.flows["f1"] = flow
    clock.advance(599)
    await manager.drop_stale_flows()
    assert "f1" in manager.store.snapshot().flows
    clock.advance(1)
    await manager.drop_stale_flows()
    assert manager.store.snapshot().flows == {}


# -------------------------------------------------------------- daily check


async def test_daily_check_inactive_user_ends_session(
    manager, fake_netbox_tokens, link, client
):
    sid = await _session(manager, link, client)
    fake_netbox_tokens.users[1].is_active = False
    await manager.daily_netbox_check()
    state = manager.store.snapshot()
    assert sid not in state.sessions
    assert len(state.cleanup) == 1


async def test_daily_check_missing_user_ends_session(
    manager, fake_netbox_tokens, link, client
):
    sid = await _session(manager, link, client)
    del fake_netbox_tokens.users[1]
    await manager.daily_netbox_check()
    assert sid not in manager.store.snapshot().sessions


async def test_daily_check_missing_or_disabled_token_ends_session(
    manager, fake_netbox_tokens, link, client
):
    sid1 = await _session(manager, link, client)
    sid2 = await _session(manager, link, client)
    snap = manager.store.snapshot().sessions
    fake_netbox_tokens.delete_token(snap[sid1].netbox_token_id)
    fake_netbox_tokens.disable_token(snap[sid2].netbox_token_id)
    await manager.daily_netbox_check()
    assert manager.store.snapshot().sessions == {}


async def test_daily_check_unavailable_keeps_session(
    manager, fake_netbox_tokens, link, client
):
    sid = await _session(manager, link, client)
    fake_netbox_tokens.fail("users.get", 500)
    await manager.daily_netbox_check()
    assert sid in manager.store.snapshot().sessions
    fake_netbox_tokens.clear_failures()
    fake_netbox_tokens.fail("tokens.get", "timeout")
    await manager.daily_netbox_check()
    assert sid in manager.store.snapshot().sessions


async def test_daily_check_healthy_session_untouched(manager, link, client):
    sid = await _session(manager, link, client)
    before = manager.store.snapshot().sessions[sid]
    await manager.daily_netbox_check()
    after = manager.store.snapshot().sessions[sid]
    assert after.token_version == before.token_version
    assert after.refresh_deadline == before.refresh_deadline


async def test_daily_check_renews_due_token(manager, link, client, clock):
    sid = await _session(manager, link, client)
    old_id = manager.store.snapshot().sessions[sid].netbox_token_id
    clock.advance(6 * DAY)  # under 2 days left
    await manager.daily_netbox_check()
    session = manager.store.snapshot().sessions[sid]
    assert session.token_version == 2
    assert session.netbox_token_id != old_id
    assert len(manager.store.snapshot().cleanup) == 1


# -------------------------------------------------------------------- Jobs


class Gate:
    """Injectable sleep: each call blocks until the test releases one tick."""

    def __init__(self) -> None:
        self.calls: list[float] = []
        self.waiting: asyncio.Queue[asyncio.Future] = asyncio.Queue()

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        fut = asyncio.get_running_loop().create_future()
        await self.waiting.put(fut)
        await fut

    async def tick(self, which: float) -> None:
        """Release the pending sleep of ``which`` seconds."""
        pending = []
        while not self.waiting.empty():
            pending.append(self.waiting.get_nowait())
        # Futures are queued in call order; match them to the recorded calls.
        index = self.calls.index(which)
        pending[index].set_result(None)
        self.calls.pop(index)
        for fut in pending:
            if not fut.done():
                self.waiting.put_nowait(fut)


async def _settle(times: int = 30) -> None:
    for _ in range(times):
        await asyncio.sleep(0)


async def test_jobs_run_at_startup_and_on_cleanup_wanted(
    manager, fake_netbox_tokens, link, client
):
    sid = await _session(manager, link, client)
    token_id = manager.store.snapshot().sessions[sid].netbox_token_id
    jobs = Jobs(manager, sleep=Gate())
    jobs.start()
    try:
        await _settle()
        await manager.end_session(sid, "revoked")
        for _ in range(300):
            if token_id not in fake_netbox_tokens.tokens:
                break
            await asyncio.sleep(0)
        assert token_id not in fake_netbox_tokens.tokens
    finally:
        await jobs.stop()


async def test_jobs_schedule_hourly_and_daily(manager):
    gate = Gate()
    jobs = Jobs(manager, sleep=gate)
    calls: list[str] = []
    for name in (
        "end_expired",
        "end_orphans",
        "recover_pending",
        "drop_stale_flows",
        "run_cleanup",
        "expire_clients",
        "daily_netbox_check",
    ):

        async def rec(name=name):
            calls.append(name)

        setattr(manager, name, rec)
    jobs.start()
    try:
        await _settle()
        assert sorted(gate.calls) == [3600, 86400]
        assert len(calls) == 7
        assert len(set(calls)) == 7
        calls.clear()
        await gate.tick(3600)
        await _settle()
        assert "daily_netbox_check" not in calls
        assert {"end_expired", "end_orphans", "recover_pending", "run_cleanup"} <= set(
            calls
        )
        calls.clear()
        await gate.tick(86400)
        await _settle()
        assert set(calls) == {"daily_netbox_check", "expire_clients"}
    finally:
        await jobs.stop()


async def test_jobs_survive_failures(manager):
    runs = []

    async def boom():
        runs.append("x")
        raise RuntimeError("boom")

    manager.end_expired = boom
    manager.daily_netbox_check = boom
    gate = Gate()
    jobs = Jobs(manager, sleep=gate)
    jobs.start()
    try:
        await _settle()
        await gate.tick(3600)
        await _settle()
        assert len(runs) >= 3
        assert all(not t.done() for t in jobs._tasks)
    finally:
        await jobs.stop()


async def test_jobs_stop_awaits_tasks(manager):
    jobs = Jobs(manager, sleep=Gate())
    jobs.start()
    await _settle()
    tasks = list(jobs._tasks)
    assert tasks
    assert all(not t.done() for t in tasks)
    await jobs.stop()
    assert all(t.done() for t in tasks)
    await jobs.stop()  # idempotent


# ------------------------------------------------------------- fix round 1


async def test_expiry_rechecked_under_lock_after_refresh(manager, link, client, clock):
    sid = await _session(manager, link, client)
    clock.advance(30 * DAY)
    async with manager.lock_for(sid):
        task = asyncio.create_task(manager.end_expired())
        await _settle()
        assert not task.done()  # waiting on the session lock
        async with manager.store.mutate() as state:  # a refresh extends the deadline
            state.sessions[sid].refresh_deadline = clock() + 30 * DAY
    await task
    assert sid in manager.store.snapshot().sessions


async def _blocked_create(manager):
    """Make the next create_token POST block until released; returns controls."""
    started, release = asyncio.Event(), asyncio.Event()
    original = manager.broker.create_token

    async def slow(*args, **kwargs):
        started.set()
        await release.wait()
        return await original(*args, **kwargs)

    manager.broker.create_token = slow
    return started, release


async def test_recovery_waits_for_in_flight_create(
    manager, fake_netbox_tokens, link, client, clock
):
    started, release = await _blocked_create(manager)
    create = asyncio.create_task(manager.create_session(link, client, "rt", **BINDING))
    await started.wait()
    clock.advance(700)  # the marker is now old enough for recovery
    recovery = asyncio.create_task(manager.recover_pending())
    await _settle()
    assert not recovery.done()
    assert fake_netbox_tokens.sent("GET", "tokens.list") == []
    release.set()
    session, _ = await create
    await recovery
    assert manager.store.snapshot().pending == {}
    assert session.netbox_token_id in fake_netbox_tokens.tokens
    assert session.sid in manager.store.snapshot().sessions


async def test_recovery_waits_for_in_flight_renewal(
    manager, fake_netbox_tokens, link, client, clock
):
    sid = await _session(manager, link, client)
    clock.advance(6 * DAY)
    started, release = await _blocked_create(manager)
    renew = asyncio.create_task(manager.renew_if_due(sid))
    await started.wait()
    clock.advance(700)
    recovery = asyncio.create_task(manager.recover_pending())
    await _settle()
    assert not recovery.done()
    release.set()
    await renew
    await recovery
    session = manager.store.snapshot().sessions[sid]
    assert session.token_version == 2
    assert session.netbox_token_id in fake_netbox_tokens.tokens
    assert manager.store.snapshot().pending == {}


async def test_recovery_ignores_decoy_descriptions(manager, fake_netbox_tokens, clock):
    nonce = await _marker(manager, clock, age=700)
    real = fake_netbox_tokens.add_token(
        "alice", description=f"NetBox MCP x 12345678 {nonce}"
    )
    decoys = [
        fake_netbox_tokens.add_token("alice", description=f"{nonce} trailing text"),
        fake_netbox_tokens.add_token("alice", description=f"x{nonce}"),
        fake_netbox_tokens.add_token(
            "bob", description=f"NetBox MCP x 12345678 {nonce}"
        ),
    ]
    await manager.recover_pending()
    assert real["id"] not in fake_netbox_tokens.tokens
    assert all(d["id"] in fake_netbox_tokens.tokens for d in decoys)
    assert manager.store.snapshot().pending == {}
