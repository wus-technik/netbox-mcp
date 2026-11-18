import time

import httpx2
import pytest

from netbox_mcp.models import NetBoxConfig
from netbox_mcp.oauth.broker import BrokerAmbiguous
from netbox_mcp.oauth.broker import BrokerConflict
from netbox_mcp.oauth.broker import BrokerDefinite
from netbox_mcp.oauth.broker import BrokerUnavailable
from netbox_mcp.oauth.broker import NetBoxBroker
from tests.oauth.fakes import FakeNetBoxTokens

SERVICE = "nbt_broker.secret"


def make_broker(fake: FakeNetBoxTokens, **config_kwargs) -> NetBoxBroker:
    config = NetBoxConfig(
        netbox_url=fake.base_url, token="nbt_other.other", **config_kwargs
    )
    return NetBoxBroker(config, SERVICE, transport=fake.transport)


@pytest.fixture
def broker(fake_netbox_tokens: FakeNetBoxTokens) -> NetBoxBroker:
    return make_broker(fake_netbox_tokens)


async def test_find_user_unique_inactive_superuser_fields(
    broker: NetBoxBroker, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    alice = await broker.find_user("alice")
    assert alice is not None
    assert (alice.id, alice.username) == (1, "alice")
    assert alice.is_active
    assert alice.is_superuser is None  # real NetBox rows omit the flag
    fake_netbox_tokens.expose_is_superuser = True
    alice = await broker.find_user("alice")
    assert alice is not None
    assert alice.is_superuser is False
    admin = await broker.find_user("admin")
    assert admin is not None
    assert admin.is_superuser is True
    dave = await broker.find_user("dave")
    assert dave is not None
    assert not dave.is_active
    assert await broker.find_user("carol") is None
    got = await broker.get_user(1)
    assert got is not None
    assert got.username == "alice"
    assert await broker.get_user(999) is None
    assert {r.authenticated_as for r in fake_netbox_tokens.requests} == {"service"}


async def test_find_user_conflict(
    broker: NetBoxBroker, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    fake_netbox_tokens.add_user("alice")
    with pytest.raises(BrokerConflict):
        await broker.find_user("alice")


async def test_create_token_payload(
    broker: NetBoxBroker, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    expires = time.time() + 7 * 86400
    created = await broker.create_token(1, "NetBox MCP (OAuth) c s1 n1", expires)
    posts = fake_netbox_tokens.sent("POST", "tokens.create")
    assert len(posts) == 1
    body = posts[0].json
    assert body["write_enabled"] is True
    assert body["user"] == 1
    assert body["description"] == "NetBox MCP (OAuth) c s1 n1"
    assert body["expires"].endswith("Z")
    assert "T" in body["expires"]
    record = fake_netbox_tokens.tokens[created.token_id]
    assert created.bearer == fake_netbox_tokens.bearer_for(record)
    assert created.bearer.startswith("nbt_")
    assert created.expires_at == expires
    assert created.bearer not in repr(created)
    assert record["token"] not in repr(created)


async def test_create_token_429_is_definite_and_not_retried(
    broker: NetBoxBroker, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    fake_netbox_tokens.fail("tokens.create", 429)
    with pytest.raises(BrokerDefinite):
        await broker.create_token(1, "d", time.time() + 100)
    assert len(fake_netbox_tokens.sent("POST", "tokens.create")) == 1
    assert not fake_netbox_tokens.tokens


async def test_create_token_4xx_is_definite(broker: NetBoxBroker) -> None:
    with pytest.raises(BrokerDefinite):
        await broker.create_token(999, "d", time.time() + 100)


@pytest.mark.parametrize("mode", ["timeout", "commit_then_timeout", 500, 503, "html"])
async def test_create_token_ambiguous_on_timeout_and_5xx(
    broker: NetBoxBroker, fake_netbox_tokens: FakeNetBoxTokens, mode
) -> None:
    fake_netbox_tokens.fail("tokens.create", mode)
    with pytest.raises(BrokerAmbiguous):
        await broker.create_token(1, "d", time.time() + 100)
    assert len(fake_netbox_tokens.sent("POST", "tokens.create")) == 1


@pytest.mark.parametrize("mode", ["token_null", "token_missing"])
async def test_create_token_missing_secret_is_ambiguous(
    broker: NetBoxBroker, fake_netbox_tokens: FakeNetBoxTokens, mode
) -> None:
    fake_netbox_tokens.fail("tokens.create", mode)
    with pytest.raises(BrokerAmbiguous):
        await broker.create_token(1, "d", time.time() + 100)
    assert len(fake_netbox_tokens.sent("POST", "tokens.create")) == 1


async def test_create_token_redirect_is_definite(
    fake_netbox_tokens: FakeNetBoxTokens,
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST":
            return httpx2.Response(302, headers={"Location": "/api/users/tokens/"})
        return httpx2.Response(200, json={"count": 0, "next": None, "results": []})

    config = NetBoxConfig(netbox_url=fake_netbox_tokens.base_url)
    broker = NetBoxBroker(config, SERVICE, transport=httpx2.MockTransport(handler))
    with pytest.raises(BrokerDefinite):
        await broker.create_token(1, "d", time.time() + 100)


async def test_html_200_is_unavailable(
    broker: NetBoxBroker, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    fake_netbox_tokens.fail("users.list", "html")
    with pytest.raises(BrokerUnavailable):
        await broker.find_user("alice")
    fake_netbox_tokens.fail("tokens.get", "html")
    with pytest.raises(BrokerUnavailable):
        await broker.get_token(1)


@pytest.mark.parametrize("mode", ["timeout", 500, 429, 403, "malformed"])
async def test_reads_map_failures_to_unavailable(
    broker: NetBoxBroker, fake_netbox_tokens: FakeNetBoxTokens, mode
) -> None:
    fake_netbox_tokens.fail("users.list", mode)
    with pytest.raises(BrokerUnavailable):
        await broker.find_user("alice")
    assert len(fake_netbox_tokens.sent("GET", "users.list")) == 1


async def test_no_branch_header(fake_netbox_tokens: FakeNetBoxTokens) -> None:
    broker = make_broker(
        fake_netbox_tokens, branching_enabled=True, default_branch="feature1"
    )
    await broker.find_user("alice")
    created = await broker.create_token(1, "d", time.time() + 100)
    await broker.get_token(created.token_id)
    await broker.list_tokens(1, "d")
    await broker.delete_token(created.token_id)
    assert len(fake_netbox_tokens.requests) == 5
    assert all(r.branch is None for r in fake_netbox_tokens.requests)


async def test_get_token_and_list(
    broker: NetBoxBroker, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    expires = time.time() + 1000
    created = await broker.create_token(1, "NetBox MCP (OAuth) x", expires)
    info = await broker.get_token(created.token_id)
    assert info is not None
    assert info.id == created.token_id
    assert info.enabled
    assert info.user_id == 1
    assert info.expires_at is not None
    assert abs(info.expires_at - expires) < 1
    assert await broker.get_token(999) is None
    fake_netbox_tokens.add_token("bob", description="NetBox MCP (OAuth) y")
    fake_netbox_tokens.add_token("alice", description="unrelated")
    assert len(await broker.list_tokens(1, "netbox mcp (oauth)")) == 1
    assert len(await broker.list_tokens(None, "NetBox MCP (OAuth)")) == 2


async def test_list_tokens_paginates(
    broker: NetBoxBroker,
    fake_netbox_tokens: FakeNetBoxTokens,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("netbox_mcp.oauth.broker.PAGE_SIZE", 2)
    for i in range(5):
        fake_netbox_tokens.add_token("alice", description=f"NetBox MCP (OAuth) {i}")
    tokens = await broker.list_tokens(1, "NetBox MCP")
    assert len(tokens) == 5
    assert len({t.id for t in tokens}) == 5
    assert len(fake_netbox_tokens.sent("GET", "tokens.list")) == 3


async def test_delete_404_counts_as_deleted(
    broker: NetBoxBroker, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    record = fake_netbox_tokens.add_token("alice", description="x")
    assert await broker.delete_token(record["id"]) is True
    assert record["id"] not in fake_netbox_tokens.tokens
    assert await broker.delete_token(record["id"]) is True
    fake_netbox_tokens.fail("tokens.delete", 500)
    with pytest.raises(BrokerUnavailable):
        await broker.delete_token(1)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
async def test_create_token_redirect_never_resends_post(status: int) -> None:
    posts: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST":
            posts.append(str(request.url))
        return httpx2.Response(status, headers={"Location": "/api/users/tokens/"})

    config = NetBoxConfig(netbox_url="https://netbox.example.com")
    broker = NetBoxBroker(config, SERVICE, transport=httpx2.MockTransport(handler))
    with pytest.raises(BrokerDefinite):
        await broker.create_token(1, "d", time.time() + 100)
    assert len(posts) == 1


async def test_error_cause_does_not_carry_response_body(
    broker: NetBoxBroker, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    fake_netbox_tokens.fail("users.list", 500)
    with pytest.raises(BrokerUnavailable) as info:
        await broker.find_user("alice")
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


async def test_empty_page_with_next_is_unavailable() -> None:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200, json={"count": 9, "next": "https://x/?offset=2", "results": []}
        )

    config = NetBoxConfig(netbox_url="https://netbox.example.com")
    broker = NetBoxBroker(config, SERVICE, transport=httpx2.MockTransport(handler))
    with pytest.raises(BrokerUnavailable):
        await broker.list_tokens(1, "x")


async def test_find_user_ignores_inexact_username_rows() -> None:
    def row(pk: int, name: str) -> dict:
        return {"id": pk, "username": name, "is_active": True}

    def handler(_request: httpx2.Request) -> httpx2.Response:
        results = [row(1, "Alice"), row(2, "alice"), row(3, "alice2")]
        return httpx2.Response(200, json={"next": None, "results": results})

    config = NetBoxConfig(netbox_url="https://netbox.example.com")
    broker = NetBoxBroker(config, SERVICE, transport=httpx2.MockTransport(handler))
    user = await broker.find_user("alice")
    assert user is not None
    assert user.id == 2
    assert await broker.find_user("bob") is None


@pytest.mark.parametrize(
    ("status", "error"), [(400, BrokerDefinite), (500, BrokerAmbiguous)]
)
async def test_create_errors_drop_response_body(status: int, error: type) -> None:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, json={"detail": "SECRET-BODY-TEXT"})

    config = NetBoxConfig(netbox_url="https://netbox.example.com")
    broker = NetBoxBroker(config, SERVICE, transport=httpx2.MockTransport(handler))
    with pytest.raises(error) as info:
        await broker.create_token(1, "d", time.time() + 100)
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__
    assert "SECRET-BODY-TEXT" not in str(info.value)
