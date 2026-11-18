import gc

import pytest

from netbox_mcp.models import NetBoxConfig
from netbox_mcp.oauth.broker import BrokerUnavailable
from netbox_mcp.oauth.broker import NetBoxBroker
from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.idp import IdpClient
from netbox_mcp.oauth.idp import IdpLogin
from netbox_mcp.oauth.sessions import LoginDenied
from netbox_mcp.oauth.sessions import SessionManager
from netbox_mcp.oauth.store import StateStore
from netbox_mcp.oauth.store import StoreWriteError
from netbox_mcp.oauth.tokens import AccessTokens
from tests.oauth.fakes import ISSUER
from tests.oauth.fakes import FakeNetBoxTokens

IDP_ISS = ISSUER


def login(sub: str, username: str, groups: list[str] | None = None) -> IdpLogin:
    return IdpLogin(
        sub=sub,
        username=username,
        groups=["netbox-users"] if groups is None else groups,
        refresh_token="rt",
    )


@pytest.fixture
def manager(
    oauth_config: OAuthConfig,
    store: StateStore,
    fake_netbox_tokens: FakeNetBoxTokens,
) -> SessionManager:
    config = NetBoxConfig(netbox_url=fake_netbox_tokens.base_url, token="nbt_o.o")
    broker = NetBoxBroker(
        config, "nbt_broker.secret", transport=fake_netbox_tokens.transport
    )
    idp = IdpClient(oauth_config)
    return SessionManager(oauth_config, store, broker, idp, AccessTokens(oauth_config))


async def test_first_login_creates_link(
    manager: SessionManager, store: StateStore, clock
) -> None:
    link = await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    assert link.user_key == f"{IDP_ISS}|sub-a"
    assert (link.iss, link.sub) == (IDP_ISS, "sub-a")
    assert (link.netbox_user_id, link.netbox_username) == (1, "alice")
    assert link.created_at == clock()
    assert store.snapshot().links[link.user_key] == link


async def test_second_login_same_sub_reuses_link(
    manager: SessionManager, store: StateStore, clock
) -> None:
    first = await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    clock.advance(60)
    second = await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    assert second == first
    assert len(store.snapshot().links) == 1


async def test_other_sub_for_linked_user_denied(
    manager: SessionManager, store: StateStore
) -> None:
    await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    before = store.snapshot().links
    with pytest.raises(LoginDenied) as exc:
        await manager.resolve_identity(IDP_ISS, login("sub-b", "alice"))
    assert exc.value.reason_code == "linked_elsewhere"
    assert store.snapshot().links == before


async def test_group_missing_denied(manager: SessionManager, store: StateStore) -> None:
    with pytest.raises(LoginDenied) as exc:
        await manager.resolve_identity(IDP_ISS, login("sub-a", "alice", ["other"]))
    assert exc.value.reason_code == "no_group"
    assert not store.snapshot().links


async def test_no_netbox_user_denied(manager: SessionManager) -> None:
    with pytest.raises(LoginDenied) as exc:
        await manager.resolve_identity(IDP_ISS, login("sub-c", "carol"))
    assert exc.value.reason_code == "no_netbox_user"
    assert "NetBox" in exc.value.message


async def test_superuser_denied(
    manager: SessionManager, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    fake_netbox_tokens.expose_is_superuser = True
    with pytest.raises(LoginDenied) as exc:
        await manager.resolve_identity(IDP_ISS, login("sub-x", "admin"))
    assert exc.value.reason_code == "superuser"


async def test_unknown_superuser_flag_does_not_deny(manager: SessionManager) -> None:
    # The REST API omits is_superuser (None); the denylist is the safeguard.
    link = await manager.resolve_identity(IDP_ISS, login("sub-x", "admin"))
    assert link.netbox_username == "admin"


async def test_denylisted_denied(
    manager: SessionManager, oauth_config: OAuthConfig, store: StateStore
) -> None:
    oauth_config.user_denylist = {"alice"}
    with pytest.raises(LoginDenied) as exc:
        await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    assert exc.value.reason_code == "denylisted"
    assert not store.snapshot().links


async def test_denylist_is_case_insensitive(
    manager: SessionManager, oauth_config: OAuthConfig
) -> None:
    oauth_config.user_denylist = {"Alice"}
    with pytest.raises(LoginDenied) as exc:
        await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    assert exc.value.reason_code == "denylisted"


async def test_inactive_denied(manager: SessionManager) -> None:
    with pytest.raises(LoginDenied) as exc:
        await manager.resolve_identity(IDP_ISS, login("sub-d", "dave"))
    assert exc.value.reason_code == "inactive_user"


async def test_ambiguous_denied(
    manager: SessionManager, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    fake_netbox_tokens.add_user("alice")
    with pytest.raises(LoginDenied) as exc:
        await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    assert exc.value.reason_code == "ambiguous_user"


async def test_broker_unavailable_propagates(
    manager: SessionManager, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    fake_netbox_tokens.fail("users.list", "timeout")
    with pytest.raises(BrokerUnavailable):
        await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))


async def test_store_write_error_propagates(
    manager: SessionManager, store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_data: bytes) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(store, "_write_file", boom)
    with pytest.raises(StoreWriteError):
        await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))


async def test_username_change_in_netbox_follows_link_id(
    manager: SessionManager,
    store: StateStore,
    fake_netbox_tokens: FakeNetBoxTokens,
) -> None:
    first = await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    # NetBox renames the account and the IdP claim carries the new name.
    fake_netbox_tokens.users[first.netbox_user_id].username = "alice2"
    link = await manager.resolve_identity(IDP_ISS, login("sub-a", "alice2"))
    assert link.netbox_user_id == first.netbox_user_id
    assert link.netbox_username == "alice2"
    assert store.snapshot().links[link.user_key].netbox_username == "alice2"


async def test_unresolved_claim_for_linked_user_denied(
    manager: SessionManager,
    store: StateStore,
    fake_netbox_tokens: FakeNetBoxTokens,
) -> None:
    first = await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    fake_netbox_tokens.users[first.netbox_user_id].username = "alice2"
    with pytest.raises(LoginDenied) as exc:
        await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    assert exc.value.reason_code == "no_netbox_user"
    assert store.snapshot().links[first.user_key] == first


async def test_claim_resolving_to_other_user_denied(
    manager: SessionManager, store: StateStore
) -> None:
    await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    before = store.snapshot().links
    with pytest.raises(LoginDenied) as exc:
        await manager.resolve_identity(IDP_ISS, login("sub-a", "bob"))
    assert exc.value.reason_code == "linked_elsewhere"
    assert store.snapshot().links == before


async def test_linked_user_later_inactive_denied(
    manager: SessionManager, fake_netbox_tokens: FakeNetBoxTokens
) -> None:
    await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    fake_netbox_tokens.users[1].is_active = False
    with pytest.raises(LoginDenied) as exc:
        await manager.resolve_identity(IDP_ISS, login("sub-a", "alice"))
    assert exc.value.reason_code == "inactive_user"


async def test_locks_are_shared_and_released(manager: SessionManager) -> None:
    lock = manager.lock_for("sid-1")
    user_lock = manager.user_lock("u|1")
    assert manager.lock_for("sid-1") is lock
    assert manager.user_lock("u|1") is user_lock
    del lock, user_lock
    gc.collect()
    assert not manager._session_locks
    assert not manager._user_locks
