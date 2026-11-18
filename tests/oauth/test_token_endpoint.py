"""Token and revocation endpoints (spec 5.4, 5.5, 6.4)."""

import asyncio
import base64
import logging
from collections.abc import AsyncIterator

import httpx2
import pytest
from starlette.applications import Starlette

from netbox_mcp.models import NetBoxConfig
from netbox_mcp.oauth.broker import NetBoxBroker
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.idp import IdpClient
from netbox_mcp.oauth.routes import oauth_routes
from netbox_mcp.oauth.sessions import REPLAY_WINDOW
from netbox_mcp.oauth.sessions import SessionManager
from netbox_mcp.oauth.state import Session
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import _decrypt
from netbox_mcp.oauth.tokens import AccessTokens
from netbox_mcp.oauth.tokens import hash_secret
from tests.oauth.fakes import FakeIdP
from tests.oauth.fakes import FakeNetBoxTokens
from tests.oauth.test_flow import REDIRECT
from tests.oauth.test_flow import VERIFIER
from tests.oauth.test_flow import approve
from tests.oauth.test_flow import callback_url
from tests.oauth.test_flow import login_with_consent
from tests.oauth.test_flow import qs
from tests.oauth.test_flow import register

PUBLIC = "https://mcp.example.com/mcp"
TOKEN = "/mcp/oauth/token"
REVOKE = "/mcp/oauth/revoke"
DAY = 86400


async def build_manager(
    config: OAuthConfig,
    store: StateStore,
    fake_idp: FakeIdP,
    fake_netbox_tokens: FakeNetBoxTokens,
) -> SessionManager:
    nb_config = NetBoxConfig(netbox_url=fake_netbox_tokens.base_url, token="nbt_o.o")
    broker = NetBoxBroker(
        nb_config, "nbt_broker.secret", transport=fake_netbox_tokens.transport
    )
    idp = IdpClient(config, transport=fake_idp.transport)
    await idp.discover()
    return SessionManager(config, store, broker, idp, AccessTokens(config))


def app_client(config: OAuthConfig, manager: SessionManager) -> httpx2.AsyncClient:
    app = Starlette(routes=oauth_routes(config, manager))
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="https://mcp.example.com"
    )


@pytest.fixture
async def manager(
    oauth_config, store, fake_idp, fake_netbox_tokens, clock
) -> SessionManager:
    fake_idp.now = clock
    fake_netbox_tokens.now = clock
    return await build_manager(oauth_config, store, fake_idp, fake_netbox_tokens)


@pytest.fixture
async def http(oauth_config, manager) -> AsyncIterator[httpx2.AsyncClient]:
    async with app_client(oauth_config, manager) as client:
        yield client


# ----------------------------------------------------------------- helpers


async def get_code(http, fake_idp) -> tuple[str, str]:
    """Register a client, log in with consent; return ``(client_id, code)``."""
    client_id = await register(http)
    resp = await login_with_consent(http, fake_idp, client_id)
    assert resp.status_code == 303, resp.text
    return client_id, qs(resp.headers["location"])["code"]


async def exchange(http, client_id, code, path=TOKEN, *, as_json=False, **over):
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "code_verifier": VERIFIER,
    }
    body.update(over)
    body = {k: v for k, v in body.items() if v is not None}
    if as_json:
        return await http.post(path, json=body)
    return await http.post(path, data=body)


async def tokens_for(http, fake_idp) -> tuple[str, dict]:
    client_id, code = await get_code(http, fake_idp)
    resp = await exchange(http, client_id, code)
    assert resp.status_code == 200, resp.text
    return client_id, resp.json()


async def refresh(http, refresh_token, path=TOKEN, **over):
    body = {"grant_type": "refresh_token", "refresh_token": refresh_token, **over}
    return await http.post(path, data={k: v for k, v in body.items() if v is not None})


def only_session(store) -> Session:
    (session,) = store.snapshot().sessions.values()
    return session


def idp_refreshes(fake_idp: FakeIdP) -> int:
    return sum(
        1
        for r in fake_idp.requests_to("token")
        if r.form.get("grant_type") == "refresh_token"
    )


def assert_error(resp, status: int, error: str) -> None:
    assert resp.status_code == status, resp.text
    assert resp.json()["error"] == error
    assert resp.headers["cache-control"] == "no-store"


def spy_writes(store, monkeypatch, fail_at: int | None = None) -> list:
    """Record every decrypted state write; optionally fail write number ``fail_at``."""
    writes: list = []
    original = store._write_file

    def spy(data: bytes) -> None:
        if fail_at is not None and len(writes) + 1 == fail_at:
            writes.append(None)
            raise OSError("disk full")
        writes.append(_decrypt(data, store._key))
        original(data)

    monkeypatch.setattr(store, "_write_file", spy)
    return writes


# ----------------------------------------------------- authorization_code


@pytest.mark.parametrize("as_json", [False, True])
async def test_code_exchange_happy(
    http, store, fake_idp, oauth_config, as_json
) -> None:
    client_id, code = await get_code(http, fake_idp)
    # client_secret is ignored for public clients.
    resp = await exchange(
        http,
        client_id,
        code,
        as_json=as_json,
        client_secret="ignored",
        resource=PUBLIC,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {
        "access_token",
        "token_type",
        "expires_in",
        "refresh_token",
        "scope",
    }
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert body["scope"] == "netbox"
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["pragma"] == "no-cache"
    session = only_session(store)
    claims = AccessTokens(oauth_config).verify(body["access_token"])
    assert claims["sid"] == session.sid
    assert claims["client_id"] == client_id
    assert claims["sub"] == session.user_key
    assert claims["scope"] == "netbox"
    assert claims["iss"] == claims["aud"] == PUBLIC
    assert claims["jti"]
    assert session.refresh_hash == hash_secret(body["refresh_token"])
    assert len(body["refresh_token"]) >= 43
    assert session.code_hash is None
    assert session.code_redeemed is True
    assert session.code_challenge is None
    assert session.code_redirect_uri is None


async def test_code_exchange_basic_auth_ignored(http, fake_idp) -> None:
    client_id, code = await get_code(http, fake_idp)
    basic = base64.b64encode(b"someone-else:secret").decode()
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "code_verifier": VERIFIER,
    }
    resp = await http.post(
        TOKEN, data=body, headers={"authorization": f"Basic {basic}"}
    )
    assert resp.status_code == 200, resp.text


async def test_code_exchange_wrong_verifier_burns_code(http, store, fake_idp) -> None:
    client_id, code = await get_code(http, fake_idp)
    bad = await exchange(http, client_id, code, code_verifier="wrong-" + "y" * 50)
    assert_error(bad, 400, "invalid_grant")
    good = await exchange(http, client_id, code)
    assert_error(good, 400, "invalid_grant")
    session = only_session(store)
    assert session.code_hash is None
    assert session.code_redeemed is False  # left for the orphan cleanup
    assert session.refresh_hash is None


async def test_code_reuse_invalid_grant_session_survives(http, store, fake_idp) -> None:
    client_id, code = await get_code(http, fake_idp)
    first = await exchange(http, client_id, code)
    assert first.status_code == 200
    again = await exchange(http, client_id, code)
    assert_error(again, 400, "invalid_grant")
    session = only_session(store)
    assert session.refresh_hash == hash_secret(first.json()["refresh_token"])
    assert (await refresh(http, first.json()["refresh_token"])).status_code == 200


async def test_code_expires_after_5_minutes(http, store, fake_idp, clock) -> None:
    client_id, code = await get_code(http, fake_idp)
    clock.advance(301)
    assert_error(await exchange(http, client_id, code), 400, "invalid_grant")
    assert only_session(store).code_hash is None


async def test_code_valid_just_before_5_minutes(http, fake_idp, clock) -> None:
    client_id, code = await get_code(http, fake_idp)
    clock.advance(299)
    assert (await exchange(http, client_id, code)).status_code == 200


@pytest.mark.parametrize(
    ("over", "error"),
    [
        ({"redirect_uri": "https://claude.com/api/mcp/auth_callback"}, "invalid_grant"),
        ({"redirect_uri": REDIRECT + "/"}, "invalid_grant"),
        ({"client": "other-client"}, "invalid_grant"),
        ({"resource": "https://other.example/mcp"}, "invalid_target"),
        ({"resource": PUBLIC + "//"}, "invalid_target"),
    ],
)
async def test_code_exchange_bindings_checked_and_code_burned(
    http, store, fake_idp, over, error
) -> None:
    client_id, code = await get_code(http, fake_idp)
    sent_as = over.pop("client", client_id)
    assert_error(await exchange(http, sent_as, code, **over), 400, error)
    assert_error(await exchange(http, client_id, code), 400, "invalid_grant")
    assert only_session(store).code_hash is None


@pytest.mark.parametrize("resource", [None, PUBLIC, PUBLIC + "/"])
async def test_code_exchange_resource_optional(http, fake_idp, resource) -> None:
    client_id, code = await get_code(http, fake_idp)
    resp = await exchange(http, client_id, code, resource=resource)
    assert resp.status_code == 200, resp.text


async def test_code_exchange_unknown_code(http, fake_idp) -> None:
    client_id, _ = await get_code(http, fake_idp)
    assert_error(await exchange(http, client_id, "nope"), 400, "invalid_grant")


@pytest.mark.parametrize(
    ("body", "error"),
    [
        ({}, "invalid_request"),
        ({"grant_type": "client_credentials"}, "unsupported_grant_type"),
        ({"grant_type": "password"}, "unsupported_grant_type"),
        ({"grant_type": "authorization_code", "code": "x"}, "invalid_request"),
        ({"grant_type": "refresh_token"}, "invalid_request"),
    ],
)
async def test_token_request_validation(http, body, error) -> None:
    assert_error(await http.post(TOKEN, data=body), 400, error)


@pytest.mark.parametrize(
    "content", [b"[]", b"{bad", b'{"grant_type": 1, "refresh_token": "x"}']
)
async def test_token_bad_json_body(http, content) -> None:
    resp = await http.post(
        TOKEN, content=content, headers={"content-type": "application/json"}
    )
    assert_error(resp, 400, "invalid_request")


async def test_concurrent_code_exchange_one_wins(http, fake_idp) -> None:
    client_id, code = await get_code(http, fake_idp)
    first, second = await asyncio.gather(
        exchange(http, client_id, code), exchange(http, client_id, code)
    )
    assert sorted([first.status_code, second.status_code]) == [200, 400]


# ----------------------------------------------------------------- refresh


async def test_refresh_rotates_and_checks_idp(
    http, store, fake_idp, oauth_config
) -> None:
    client_id, first = await tokens_for(http, fake_idp)
    refreshes, userinfos = idp_refreshes(fake_idp), fake_idp.calls["userinfo"]
    resp = await refresh(http, first["refresh_token"], client_id=client_id)
    assert resp.status_code == 200, resp.text
    second = resp.json()
    assert set(second) == set(first)
    assert second["refresh_token"] != first["refresh_token"]
    assert second["access_token"] != first["access_token"]
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["pragma"] == "no-cache"
    assert idp_refreshes(fake_idp) == refreshes + 1
    assert fake_idp.calls["userinfo"] == userinfos + 1
    session = only_session(store)
    assert session.refresh_hash == hash_secret(second["refresh_token"])
    assert hash_secret(first["refresh_token"]) in session.spent_hashes
    assert session.replay is not None
    assert session.replay.hash == hash_secret(first["refresh_token"])
    assert session.idp_refresh_started_at is None
    # The IdP refresh token rotated and the new one is stored.
    assert session.idp_refresh_token in fake_idp.refresh_tokens
    AccessTokens(oauth_config).verify(second["access_token"])
    # The new refresh token works again.
    third = await refresh(http, second["refresh_token"])
    assert third.status_code == 200
    assert idp_refreshes(fake_idp) == refreshes + 2


async def test_refresh_persists_rotated_idp_token_first(
    http, store, fake_idp, manager, monkeypatch
) -> None:
    _, first = await tokens_for(http, fake_idp)
    old_idp_token = only_session(store).idp_refresh_token
    writes = spy_writes(store, monkeypatch)
    seen: dict = {}
    original = manager.idp.userinfo

    async def userinfo(access_token, expected_sub):
        seen["writes"] = list(writes)
        seen["issued"] = set(fake_idp.refresh_tokens)
        return await original(access_token, expected_sub)

    monkeypatch.setattr(manager.idp, "userinfo", userinfo)
    resp = await refresh(http, first["refresh_token"])
    assert resp.status_code == 200, resp.text
    before = seen["writes"]
    assert len(before) == 2
    # Write 1 marks the IdP refresh as started, before the IdP is contacted.
    marked = next(iter(before[0].sessions.values()))
    assert marked.idp_refresh_started_at is not None
    assert marked.idp_refresh_token == old_idp_token
    # Write 2 (before userinfo) holds the rotated IdP token and clears the mark.
    persisted = next(iter(before[1].sessions.values()))
    assert persisted.idp_refresh_token != old_idp_token
    assert persisted.idp_refresh_token in seen["issued"]
    assert persisted.idp_refresh_started_at is None
    # Our own refresh token is only rotated by the final write.
    assert persisted.refresh_hash == hash_secret(first["refresh_token"])
    assert len(writes) == 3


async def test_refresh_idp_without_rotation_keeps_old_idp_token(
    http, store, fake_idp
) -> None:
    _, first = await tokens_for(http, fake_idp)
    old = only_session(store).idp_refresh_token
    fake_idp.fail_next("refresh", "no_refresh_token")
    assert (await refresh(http, first["refresh_token"])).status_code == 200
    assert only_session(store).idp_refresh_token == old


async def test_refresh_concurrent_duplicate_gets_replay(
    http, store, fake_idp, manager, monkeypatch
) -> None:
    _, first = await tokens_for(http, fake_idp)
    original = manager.idp.refresh

    async def slow_refresh(token):
        await asyncio.sleep(0.05)
        return await original(token)

    monkeypatch.setattr(manager.idp, "refresh", slow_refresh)
    before = idp_refreshes(fake_idp)
    one, two = await asyncio.gather(
        refresh(http, first["refresh_token"]), refresh(http, first["refresh_token"])
    )
    assert one.status_code == two.status_code == 200
    assert one.json() == two.json()
    assert idp_refreshes(fake_idp) == before + 1
    session = only_session(store)
    assert session.refresh_hash == hash_secret(one.json()["refresh_token"])
    assert (await refresh(http, one.json()["refresh_token"])).status_code == 200


async def test_replay_window_strict_30s(http, store, fake_idp, clock) -> None:
    assert REPLAY_WINDOW == 30
    _, first = await tokens_for(http, fake_idp)
    rotated = await refresh(http, first["refresh_token"])
    assert rotated.status_code == 200
    calls = (idp_refreshes(fake_idp), fake_idp.calls["userinfo"])
    clock.advance(29.9)
    replay = await refresh(http, first["refresh_token"])
    assert replay.status_code == 200
    assert replay.json() == rotated.json()
    assert (idp_refreshes(fake_idp), fake_idp.calls["userinfo"]) == calls
    clock.advance(0.1)  # exactly 30 s after the rotation
    late = await refresh(http, first["refresh_token"])
    assert_error(late, 400, "invalid_grant")
    assert store.snapshot().sessions == {}
    assert (idp_refreshes(fake_idp), fake_idp.calls["userinfo"]) == calls


async def test_replay_client_id_must_match(http, store, fake_idp) -> None:
    client_id, first = await tokens_for(http, fake_idp)
    rotated = await refresh(http, first["refresh_token"])
    assert rotated.status_code == 200
    wrong = await refresh(http, first["refresh_token"], client_id="other")
    assert_error(wrong, 400, "invalid_grant")
    ok = await refresh(http, first["refresh_token"], client_id=client_id)
    assert ok.json() == rotated.json()
    assert len(store.snapshot().sessions) == 1


async def test_older_spent_token_ends_session(http, store, fake_idp) -> None:
    _, a = await tokens_for(http, fake_idp)
    token_id = only_session(store).netbox_token_id
    b = (await refresh(http, a["refresh_token"])).json()
    c = (await refresh(http, b["refresh_token"])).json()
    assert_error(await refresh(http, a["refresh_token"]), 400, "invalid_grant")
    state = store.snapshot()
    assert state.sessions == {}
    assert [e.netbox_token_id for e in state.cleanup.values()] == [token_id]
    # The family is gone: the current token no longer works either.
    assert_error(await refresh(http, c["refresh_token"]), 400, "invalid_grant")


async def test_refresh_unknown_token(http, fake_idp, store) -> None:
    await tokens_for(http, fake_idp)
    assert_error(await refresh(http, "unknown-token"), 400, "invalid_grant")
    assert len(store.snapshot().sessions) == 1


async def test_refresh_client_id_mismatch_rejected(http, store, fake_idp) -> None:
    _, first = await tokens_for(http, fake_idp)
    before = idp_refreshes(fake_idp)
    resp = await refresh(http, first["refresh_token"], client_id="other-client")
    assert_error(resp, 400, "invalid_grant")
    assert idp_refreshes(fake_idp) == before
    assert only_session(store).refresh_hash == hash_secret(first["refresh_token"])
    assert (await refresh(http, first["refresh_token"])).status_code == 200


@pytest.mark.parametrize("resource", ["https://other.example/mcp", PUBLIC + "//"])
async def test_refresh_foreign_resource_invalid_target(
    http, store, fake_idp, resource
) -> None:
    _, first = await tokens_for(http, fake_idp)
    resp = await refresh(http, first["refresh_token"], resource=resource)
    assert_error(resp, 400, "invalid_target")
    assert only_session(store).refresh_hash == hash_secret(first["refresh_token"])
    ok = await refresh(http, first["refresh_token"], resource=PUBLIC + "/")
    assert ok.status_code == 200


async def test_refresh_idp_rejected_ends_session(http, store, fake_idp) -> None:
    _, first = await tokens_for(http, fake_idp)
    token_id = only_session(store).netbox_token_id
    fake_idp.fail_next("refresh", 400)
    assert_error(await refresh(http, first["refresh_token"]), 400, "invalid_grant")
    state = store.snapshot()
    assert state.sessions == {}
    assert [e.netbox_token_id for e in state.cleanup.values()] == [token_id]
    # An IdP-side token rejection is not an eligibility loss: consent stays.
    assert len(state.grants) == 1


@pytest.mark.parametrize("outcome", [503, "timeout", 429, "html"])
async def test_refresh_idp_unavailable_503_keeps_token(
    http, store, fake_idp, outcome
) -> None:
    _, first = await tokens_for(http, fake_idp)
    fake_idp.fail_next("refresh", outcome)
    resp = await refresh(http, first["refresh_token"])
    assert_error(resp, 503, "temporarily_unavailable")
    session = only_session(store)
    assert session.refresh_hash == hash_secret(first["refresh_token"])
    assert session.idp_refresh_started_at is None
    retry = await refresh(http, first["refresh_token"])
    assert retry.status_code == 200, retry.text


async def test_refresh_userinfo_unavailable_503_keeps_token(http, fake_idp) -> None:
    _, first = await tokens_for(http, fake_idp)
    fake_idp.fail_next("userinfo", 503)
    assert_error(
        await refresh(http, first["refresh_token"]), 503, "temporarily_unavailable"
    )
    assert (await refresh(http, first["refresh_token"])).status_code == 200


async def test_crash_between_idp_refresh_and_write_fails_closed(
    http, store, fake_idp, fake_netbox_tokens, oauth_config
) -> None:
    _, first = await tokens_for(http, fake_idp)
    token_id = only_session(store).netbox_token_id
    # Write 1 (mark) succeeds, write 2 (rotated IdP token) fails: the outcome of
    # the IdP rotation is not on disk, as after a crash at that point.
    with pytest.MonkeyPatch.context() as mp:
        spy_writes(store, mp, fail_at=2)
        assert_error(
            await refresh(http, first["refresh_token"]),
            503,
            "temporarily_unavailable",
        )
    store.close()
    reopened = StateStore.open(oauth_config.state_path, oauth_config.state_key)
    try:
        assert only_session(reopened).idp_refresh_started_at is not None
        manager2 = await build_manager(
            oauth_config, reopened, fake_idp, fake_netbox_tokens
        )
        before = idp_refreshes(fake_idp)
        async with app_client(oauth_config, manager2) as http2:
            resp = await refresh(http2, first["refresh_token"])
        assert_error(resp, 400, "invalid_grant")
        assert idp_refreshes(fake_idp) == before
        state = reopened.snapshot()
        assert state.sessions == {}
        assert [e.netbox_token_id for e in state.cleanup.values()] == [token_id]
    finally:
        reopened.close()


async def test_refresh_write_failure_keeps_previous_token(
    http, store, fake_idp, fake_netbox_tokens, oauth_config
) -> None:
    _, first = await tokens_for(http, fake_idp)
    before = only_session(store)
    # Writes: 1 mark, 2 rotated IdP token, 3 final rotation (fails).
    with pytest.MonkeyPatch.context() as mp:
        spy_writes(store, mp, fail_at=3)
        assert_error(
            await refresh(http, first["refresh_token"]),
            503,
            "temporarily_unavailable",
        )
    store.close()
    reopened = StateStore.open(oauth_config.state_path, oauth_config.state_key)
    try:
        session = only_session(reopened)
        assert session.refresh_hash == before.refresh_hash
        assert session.spent_hashes == before.spent_hashes
        assert session.replay == before.replay
        assert session.refresh_deadline == before.refresh_deadline
        assert session.idp_refresh_started_at is None
        assert session.idp_refresh_token in fake_idp.refresh_tokens
        manager2 = await build_manager(
            oauth_config, reopened, fake_idp, fake_netbox_tokens
        )
        async with app_client(oauth_config, manager2) as http2:
            resp = await refresh(http2, first["refresh_token"])
        assert resp.status_code == 200, resp.text
    finally:
        reopened.close()


async def test_refresh_mark_write_failure_contacts_no_idp(
    http, store, fake_idp
) -> None:
    _, first = await tokens_for(http, fake_idp)
    before = idp_refreshes(fake_idp)
    with pytest.MonkeyPatch.context() as mp:
        spy_writes(store, mp, fail_at=1)
        assert_error(
            await refresh(http, first["refresh_token"]),
            503,
            "temporarily_unavailable",
        )
    assert idp_refreshes(fake_idp) == before
    assert (await refresh(http, first["refresh_token"])).status_code == 200


@pytest.mark.parametrize("change", ["inactive", "user_gone", "superuser"])
async def test_refresh_netbox_user_ineligible_ends_session(
    http, store, fake_idp, fake_netbox_tokens, change
) -> None:
    _, first = await tokens_for(http, fake_idp)
    alice = fake_netbox_tokens.user_id("alice")
    if change == "inactive":
        fake_netbox_tokens.users[alice].is_active = False
    elif change == "superuser":
        fake_netbox_tokens.expose_is_superuser = True
        fake_netbox_tokens.users[alice].is_superuser = True
    else:
        del fake_netbox_tokens.users[alice]
    assert_error(await refresh(http, first["refresh_token"]), 400, "invalid_grant")
    state = store.snapshot()
    assert state.sessions == {}
    assert len(state.cleanup) == 1
    assert state.grants == {}  # eligibility lost: consent is dropped


@pytest.mark.parametrize("change", ["deleted", "disabled"])
async def test_refresh_netbox_token_missing_ends_session(
    http, store, fake_idp, fake_netbox_tokens, change
) -> None:
    _, first = await tokens_for(http, fake_idp)
    token_id = only_session(store).netbox_token_id
    if change == "deleted":
        fake_netbox_tokens.delete_token(token_id)
    else:
        fake_netbox_tokens.disable_token(token_id)
    assert_error(await refresh(http, first["refresh_token"]), 400, "invalid_grant")
    assert store.snapshot().sessions == {}


@pytest.mark.parametrize(
    ("endpoint", "mode"),
    [("users.get", 503), ("users.get", "timeout"), ("tokens.get", "html")],
)
async def test_refresh_netbox_unavailable_503_keeps_token(
    http, store, fake_idp, fake_netbox_tokens, endpoint, mode
) -> None:
    _, first = await tokens_for(http, fake_idp)
    fake_netbox_tokens.fail(endpoint, mode, times=1)
    resp = await refresh(http, first["refresh_token"])
    assert_error(resp, 503, "temporarily_unavailable")
    assert only_session(store).refresh_hash == hash_secret(first["refresh_token"])
    assert (await refresh(http, first["refresh_token"])).status_code == 200


@pytest.mark.parametrize("change", ["no_group", "no_groups_claim", "sub_mismatch"])
async def test_grant_dropped_on_eligibility_loss(http, store, fake_idp, change) -> None:
    _, first = await tokens_for(http, fake_idp)
    assert len(store.snapshot().grants) == 1
    if change == "no_group":
        fake_idp.users["alice"]["groups"] = ["other"]
    elif change == "no_groups_claim":
        fake_idp.userinfo_omit_groups = True
    else:
        fake_idp.userinfo_sub = "sub-mallory"
    assert_error(await refresh(http, first["refresh_token"]), 400, "invalid_grant")
    state = store.snapshot()
    assert state.sessions == {}
    assert state.grants == {}
    assert len(state.cleanup) == 1


async def test_refresh_renews_netbox_token_when_due(
    http, store, fake_idp, clock
) -> None:
    _, first = await tokens_for(http, fake_idp)
    old = only_session(store)
    clock.advance(6 * DAY)
    resp = await refresh(http, first["refresh_token"])
    assert resp.status_code == 200, resp.text
    session = only_session(store)
    assert session.netbox_token_id != old.netbox_token_id
    assert session.token_version == old.token_version + 1


async def test_sliding_deadline_30_days(http, store, fake_idp, clock) -> None:
    _, first = await tokens_for(http, fake_idp)
    clock.advance(29 * DAY)
    second = await refresh(http, first["refresh_token"])
    assert second.status_code == 200, second.text
    assert only_session(store).refresh_deadline == clock() + 30 * DAY
    clock.advance(29 * DAY)
    third = await refresh(http, second.json()["refresh_token"])
    assert third.status_code == 200, third.text
    clock.advance(30 * DAY)
    late = await refresh(http, third.json()["refresh_token"])
    assert_error(late, 400, "invalid_grant")
    assert store.snapshot().sessions == {}


# ------------------------------------------------------------------ revoke


async def test_revoke_missing_token_400(http) -> None:
    assert_error(await http.post(REVOKE, data={}), 400, "invalid_request")


async def test_revoke_unknown_token_200(http, fake_idp, store) -> None:
    await tokens_for(http, fake_idp)
    resp = await http.post(REVOKE, data={"token": "garbage"})
    assert resp.status_code == 200
    assert len(store.snapshot().sessions) == 1


async def test_revoke_access_token_even_expired(http, fake_idp, store, clock) -> None:
    _, body = await tokens_for(http, fake_idp)
    token_id = only_session(store).netbox_token_id
    clock.advance(3700)
    resp = await http.post(REVOKE, data={"token": body["access_token"]})
    assert resp.status_code == 200
    state = store.snapshot()
    assert state.sessions == {}
    assert [e.netbox_token_id for e in state.cleanup.values()] == [token_id]
    assert len(state.grants) == 1  # revoking keeps consent


async def test_revoke_current_refresh_token_json(http, fake_idp, store) -> None:
    client_id, body = await tokens_for(http, fake_idp)
    resp = await http.post(
        REVOKE,
        json={
            "token": body["refresh_token"],
            "token_type_hint": "refresh_token",
            "client_id": client_id,
        },
    )
    assert resp.status_code == 200
    assert store.snapshot().sessions == {}


@pytest.mark.parametrize("which", ["replay_slot", "older"])
async def test_revoke_spent_refresh_token_maps_to_session(
    http, fake_idp, store, which
) -> None:
    _, a = await tokens_for(http, fake_idp)
    b = (await refresh(http, a["refresh_token"])).json()
    await refresh(http, b["refresh_token"])
    token = b["refresh_token"] if which == "replay_slot" else a["refresh_token"]
    resp = await http.post(REVOKE, data={"token": token})
    assert resp.status_code == 200
    assert store.snapshot().sessions == {}


@pytest.mark.parametrize("kind", ["access_token", "refresh_token"])
async def test_revoke_client_id_mismatch_no_effect(http, fake_idp, store, kind) -> None:
    _, body = await tokens_for(http, fake_idp)
    resp = await http.post(REVOKE, data={"token": body[kind], "client_id": "other"})
    assert resp.status_code == 200
    assert len(store.snapshot().sessions) == 1


async def test_revoke_foreign_signed_token_no_effect(http, fake_idp, store) -> None:
    await tokens_for(http, fake_idp)
    resp = await http.post(REVOKE, data={"token": "eyJhbGciOiJIUzI1NiJ9.e30.x"})
    assert resp.status_code == 200
    assert len(store.snapshot().sessions) == 1


async def test_revoke_store_failure_503(http, fake_idp, store) -> None:
    _, body = await tokens_for(http, fake_idp)
    with pytest.MonkeyPatch.context() as mp:
        spy_writes(store, mp, fail_at=1)
        resp = await http.post(REVOKE, data={"token": body["refresh_token"]})
    assert_error(resp, 503, "temporarily_unavailable")
    assert len(store.snapshot().sessions) == 1


async def test_revoke_rules_summary(http, fake_idp, store) -> None:
    """Brief: test_revoke_rules (no client_secret field is needed anywhere)."""
    _, body = await tokens_for(http, fake_idp)
    assert (await http.post(REVOKE, data={})).status_code == 400
    assert (await http.post(REVOKE, data={"token": "x"})).status_code == 200
    resp = await http.post(REVOKE, data={"token": body["refresh_token"]})
    assert resp.status_code == 200
    assert store.snapshot().sessions == {}
    # Revoking again is harmless.
    again = await http.post(REVOKE, data={"token": body["refresh_token"]})
    assert again.status_code == 200


# ----------------------------------------------------------- routes, logs


async def test_root_aliases_token_and_revoke(
    oauth_config, manager, http, fake_idp, store
) -> None:
    by_path = {r.path: r.endpoint for r in oauth_routes(oauth_config, manager)}
    assert by_path["/token"] is by_path["/mcp/oauth/token"]
    assert by_path["/revoke"] is by_path["/mcp/oauth/revoke"]
    assert by_path["/oauth/revoke"] is by_path["/mcp/oauth/revoke"]
    client_id, code = await get_code(http, fake_idp)
    body = (await exchange(http, client_id, code, path="/token")).json()
    resp = await refresh(http, body["refresh_token"], path="/token")
    assert resp.status_code == 200
    assert (await http.post("/oauth/revoke", data={"token": "x"})).status_code == 200
    resp = await http.post("/revoke", data={"token": resp.json()["refresh_token"]})
    assert resp.status_code == 200
    assert store.snapshot().sessions == {}


async def test_token_endpoint_methods(http) -> None:
    assert (await http.get(TOKEN)).status_code == 405
    assert (await http.get(REVOKE)).status_code == 405


async def test_failed_store_answers_503_on_token(
    http, fake_idp, store, monkeypatch
) -> None:
    from netbox_mcp.oauth.store import _CommitUncertainError

    _, body = await tokens_for(http, fake_idp)

    def uncertain(_data: bytes) -> None:
        raise _CommitUncertainError

    monkeypatch.setattr(store, "_write_file", uncertain)
    resp = await refresh(http, body["refresh_token"])
    assert_error(resp, 503, "temporarily_unavailable")
    # The store is now failed: snapshot() raises, still answered as JSON 503.
    # Known tokens reach the store, whose snapshot() now raises StoreError.
    for path, data in (
        (
            TOKEN,
            {"grant_type": "refresh_token", "refresh_token": body["refresh_token"]},
        ),
        (REVOKE, {"token": body["refresh_token"]}),
    ):
        resp = await http.post(path, data=data)
        assert_error(resp, 503, "temporarily_unavailable")


async def test_logs_events_without_secrets(http, fake_idp, store, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    client_id, code = await get_code(http, fake_idp)
    first = (await exchange(http, client_id, code)).json()
    second = (await refresh(http, first["refresh_token"])).json()
    sid = only_session(store).sid
    await refresh(http, "unknown-token")
    fake_idp.fail_next("refresh", 400)
    await refresh(http, second["refresh_token"])
    text = caplog.text
    assert "token_refreshed" in text
    assert "refresh_rejected reason=" in text
    assert "session_ended" in text
    assert sid[:8] in text
    assert sid not in text
    secrets = [
        code,
        first["access_token"],
        first["refresh_token"],
        second["access_token"],
        second["refresh_token"],
        *fake_idp.refresh_tokens,
        *fake_idp.access_tokens,
    ]
    for secret in secrets:
        assert secret not in text


# ------------------------------------------------------------ fix round 1


async def test_replay_refused_when_fail_closed_marker_set(
    http, store, fake_idp
) -> None:
    _, a = await tokens_for(http, fake_idp)
    rotated = await refresh(http, a["refresh_token"])
    assert rotated.status_code == 200
    async with store.mutate() as state:
        (session,) = state.sessions.values()
        session.idp_refresh_started_at = session.created_at
    calls = (idp_refreshes(fake_idp), fake_idp.calls["userinfo"])
    resp = await refresh(http, a["refresh_token"])  # within the replay window
    assert_error(resp, 400, "invalid_grant")
    assert store.snapshot().sessions == {}
    assert len(store.snapshot().cleanup) == 1
    assert (idp_refreshes(fake_idp), fake_idp.calls["userinfo"]) == calls


@pytest.mark.parametrize("drop", ["client_id", "redirect_uri", "code_verifier"])
async def test_malformed_code_request_burns_code(http, store, fake_idp, drop) -> None:
    client_id, code = await get_code(http, fake_idp)
    if drop == "client_id":
        resp = await exchange(http, None, code)
    else:
        resp = await exchange(http, client_id, code, **{drop: None})
    assert_error(resp, 400, "invalid_request")
    assert only_session(store).code_hash is None
    assert_error(await exchange(http, client_id, code), 400, "invalid_grant")


@pytest.mark.parametrize("bad", ["json_number", "json_list", "duplicate_field"])
async def test_unparseable_code_request_burns_code(http, store, fake_idp, bad) -> None:
    client_id, code = await get_code(http, fake_idp)
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "code_verifier": VERIFIER,
    }
    if bad == "duplicate_field":
        form = httpx2.QueryParams(body).add("redirect_uri", REDIRECT)
        resp = await http.post(
            TOKEN,
            content=str(form),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
    else:
        body["code_verifier"] = 7 if bad == "json_number" else [VERIFIER]
        resp = await http.post(TOKEN, json=body)
    assert_error(resp, 400, "invalid_request")
    assert only_session(store).code_hash is None
    assert_error(await exchange(http, client_id, code), 400, "invalid_grant")


@pytest.mark.parametrize(
    "body",
    [
        # The code itself is ambiguous: nothing to burn.
        "grant_type=authorization_code&code={c}&code=other",
        # Not a code grant.
        "grant_type=refresh_token&code={c}&refresh_token=a&refresh_token=b",
    ],
)
async def test_unparseable_request_without_unambiguous_code_grant_keeps_code(
    http, store, fake_idp, body
) -> None:
    client_id, code = await get_code(http, fake_idp)
    resp = await http.post(
        TOKEN,
        content=body.format(c=code),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert_error(resp, 400, "invalid_request")
    assert only_session(store).code_hash is not None
    assert (await exchange(http, client_id, code)).status_code == 200


async def code_with_resource(http, fake_idp, resource: str) -> tuple[str, str]:
    client_id = await register(http)
    resp = await http.get(
        await callback_url(http, fake_idp, client_id, resource=resource)
    )
    assert resp.status_code == 303, resp.text
    resp = await approve(http, resp.headers["location"])
    assert resp.status_code == 303, resp.text
    return client_id, qs(resp.headers["location"])["code"]


@pytest.mark.parametrize("sent", [None, PUBLIC, PUBLIC + "/"])
async def test_code_resource_binding_accepts_same_resource(
    http, fake_idp, sent
) -> None:
    client_id, code = await code_with_resource(http, fake_idp, PUBLIC)
    resp = await exchange(http, client_id, code, resource=sent)
    assert resp.status_code == 200, resp.text


async def test_code_resource_binding_mismatch_invalid_target(
    http, store, fake_idp
) -> None:
    client_id, code = await code_with_resource(http, fake_idp, PUBLIC)
    # A code bound to another resource of ours (not reachable via /authorize
    # today, which only accepts this server) must not redeem for this one.
    async with store.mutate() as state:
        (session,) = state.sessions.values()
        session.code_resource = "https://mcp.example.com/other"
    resp = await exchange(http, client_id, code, resource=PUBLIC)
    assert_error(resp, 400, "invalid_target")
    assert only_session(store).code_hash is None
    assert_error(await exchange(http, client_id, code), 400, "invalid_grant")


# ------------------------------------------------------------ fix round 2


async def test_index_follows_rotation_and_session_end(
    http, store, fake_idp, manager
) -> None:
    client_id, code = await get_code(http, fake_idp)
    sid = only_session(store).sid
    assert manager._lookup(hash_secret(code)) == sid
    a = (await exchange(http, client_id, code)).json()
    assert manager._lookup(hash_secret(code)) is None
    b = (await refresh(http, a["refresh_token"])).json()
    c = (await refresh(http, b["refresh_token"])).json()
    hashes = [hash_secret(t["refresh_token"]) for t in (a, b, c)]
    assert [manager._lookup(h) for h in hashes] == [sid, sid, sid]
    # Replay of b (slot) and reuse of a still resolve to the session.
    replay = await refresh(http, b["refresh_token"])
    assert replay.json() == c
    assert_error(await refresh(http, a["refresh_token"]), 400, "invalid_grant")
    assert store.snapshot().sessions == {}
    assert [manager._lookup(h) for h in hashes] == [None, None, None]


async def test_index_rebuilt_after_reopen(
    http, store, fake_idp, fake_netbox_tokens, oauth_config
) -> None:
    _, a = await tokens_for(http, fake_idp)
    b = await refresh(http, a["refresh_token"])
    store.close()
    reopened = StateStore.open(oauth_config.state_path, oauth_config.state_key)
    try:
        manager2 = await build_manager(
            oauth_config, reopened, fake_idp, fake_netbox_tokens
        )
        async with app_client(oauth_config, manager2) as http2:
            replay = await refresh(http2, a["refresh_token"])
            assert replay.json() == b.json()
            nxt = await refresh(http2, b.json()["refresh_token"])
            assert nxt.status_code == 200, nxt.text
    finally:
        reopened.close()


async def test_stale_index_entry_is_unknown_and_dropped(
    http, store, fake_idp, manager
) -> None:
    _, a = await tokens_for(http, fake_idp)
    sid = only_session(store).sid
    stale = hash_secret("stale-token")
    manager._index()[stale] = sid
    assert_error(await refresh(http, "stale-token"), 400, "invalid_grant")
    assert stale not in manager._index()
    assert len(store.snapshot().sessions) == 1
    resp = await http.post(REVOKE, data={"token": "stale-token"})
    assert resp.status_code == 200
    manager._index()[stale] = sid
    assert (await http.post(REVOKE, data={"token": "stale-token"})).status_code == 200
    assert len(store.snapshot().sessions) == 1
    assert (await refresh(http, a["refresh_token"])).status_code == 200


async def test_refresh_lookup_does_not_scan_sessions(
    http, store, fake_idp, manager, monkeypatch
) -> None:
    await tokens_for(http, fake_idp)
    manager._index()  # built
    calls = []
    original = store.snapshot

    def counting():
        calls.append(1)
        return original()

    monkeypatch.setattr(store, "snapshot", counting)
    assert_error(await refresh(http, "unknown-token"), 400, "invalid_grant")
    assert calls == []


def test_default_max_session_days(oauth_config) -> None:
    assert oauth_config.max_session_days == 365


async def test_max_session_age_boundaries(
    http, store, fake_idp, manager, clock, caplog
) -> None:
    manager.config.max_session_days = 60
    _, a = await tokens_for(http, fake_idp)
    created = only_session(store).created_at
    clock.advance(created + 29 * DAY - clock())
    b = (await refresh(http, a["refresh_token"])).json()
    clock.advance(created + 58 * DAY - clock())
    c = (await refresh(http, b["refresh_token"])).json()
    clock.advance(created + 60 * DAY - 1 - clock())
    d = await refresh(http, c["refresh_token"])
    assert d.status_code == 200, d.text
    clock.advance(1)  # exactly 60 days after creation
    caplog.set_level(logging.INFO)
    late = await refresh(http, d.json()["refresh_token"])
    assert_error(late, 400, "invalid_grant")
    assert store.snapshot().sessions == {}
    assert len(store.snapshot().cleanup) >= 1
    assert "reason=max_age" in caplog.text


# ------------------------------------------------------------ fix round 3


@pytest.mark.parametrize("malformed", [True, False])
async def test_spent_refresh_token_sent_as_code_keeps_reuse_detection(
    http, store, fake_idp, manager, malformed
) -> None:
    client_id, a = await tokens_for(http, fake_idp)
    b = (await refresh(http, a["refresh_token"])).json()
    await refresh(http, b["refresh_token"])  # a is now an older spent token
    spent = a["refresh_token"]
    if malformed:
        resp = await http.post(
            TOKEN, data={"grant_type": "authorization_code", "code": spent}
        )
        assert_error(resp, 400, "invalid_request")
    else:
        assert_error(await exchange(http, client_id, spent), 400, "invalid_grant")
    assert manager._lookup(hash_secret(spent)) is not None
    assert_error(await refresh(http, spent), 400, "invalid_grant")
    assert store.snapshot().sessions == {}  # reuse still ends the session


async def test_code_sent_to_refresh_and_revoke_still_redeems(
    http, store, fake_idp, manager
) -> None:
    client_id, code = await get_code(http, fake_idp)
    assert_error(await refresh(http, code), 400, "invalid_grant")
    assert (await http.post(REVOKE, data={"token": code})).status_code == 200
    assert manager._lookup(hash_secret(code)) is not None
    assert len(store.snapshot().sessions) == 1
    resp = await exchange(http, client_id, code)
    assert resp.status_code == 200, resp.text


def test_config_model_rejects_max_session_days_below_one(oauth_config) -> None:
    from pydantic import ValidationError

    data = oauth_config.model_dump()
    data["max_session_days"] = 0
    with pytest.raises(ValidationError):
        type(oauth_config)(**data)


# ------------------------------------------- write failures and restart (F9)


async def test_renewal_swap_write_failure_keeps_previous_state(
    http, store, fake_idp, fake_netbox_tokens, oauth_config, clock
) -> None:
    _, first = await tokens_for(http, fake_idp)
    before = only_session(store)
    clock.advance(5 * DAY + 60)  # the NetBox token is due for renewal
    tokens_before = set(fake_netbox_tokens.tokens)
    # Writes: 1 mark, 2 rotated IdP token, 3 renewal marker, 4 swap (fails).
    with pytest.MonkeyPatch.context() as mp:
        writes = spy_writes(store, mp, fail_at=4)
        assert_error(
            await refresh(http, first["refresh_token"]),
            503,
            "temporarily_unavailable",
        )
    assert len(writes) == 4
    (created,) = set(fake_netbox_tokens.tokens) - tokens_before
    store.close()
    reopened = StateStore.open(oauth_config.state_path, oauth_config.state_key)
    try:
        state = reopened.snapshot()
        session = only_session(reopened)
        # Nothing of the failed swap or rotation is visible.
        assert session.netbox_token == before.netbox_token
        assert session.netbox_token_id == before.netbox_token_id
        assert session.token_version == before.token_version
        assert session.refresh_hash == before.refresh_hash
        assert session.replay == before.replay
        assert session.idp_refresh_started_at is None
        assert state.cleanup == {}
        # The renewal marker survived, so recovery removes the orphaned token.
        (marker,) = state.pending.values()
        assert marker.sid == session.sid
        manager2 = await build_manager(
            oauth_config, reopened, fake_idp, fake_netbox_tokens
        )
        clock.advance(601)
        await manager2.recover_pending()
        assert created not in fake_netbox_tokens.tokens
        assert reopened.snapshot().pending == {}
        # The previous refresh token still works.
        async with app_client(oauth_config, manager2) as http2:
            resp = await refresh(http2, first["refresh_token"])
        assert resp.status_code == 200, resp.text
        assert only_session(reopened).token_version == before.token_version + 1
    finally:
        reopened.close()


async def test_code_redemption_write_failure_keeps_code_usable(
    http, store, fake_idp, fake_netbox_tokens, oauth_config
) -> None:
    client_id, code = await get_code(http, fake_idp)
    before = only_session(store)
    with pytest.MonkeyPatch.context() as mp:
        spy_writes(store, mp, fail_at=1)
        assert_error(
            await exchange(http, client_id, code), 503, "temporarily_unavailable"
        )
    store.close()
    reopened = StateStore.open(oauth_config.state_path, oauth_config.state_key)
    try:
        session = only_session(reopened)
        assert session.code_hash == before.code_hash
        assert session.code_redeemed is False
        assert session.refresh_hash is None
        manager2 = await build_manager(
            oauth_config, reopened, fake_idp, fake_netbox_tokens
        )
        async with app_client(oauth_config, manager2) as http2:
            resp = await exchange(http2, client_id, code)
        assert resp.status_code == 200, resp.text
        assert only_session(reopened).code_redeemed is True
    finally:
        reopened.close()
