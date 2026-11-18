import base64
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from netbox_mcp.oauth.config import OAuthConfig
from netbox_mcp.oauth.store import StateStore
from tests.oauth.fakes import FakeIdP
from tests.oauth.fakes import FakeNetBoxTokens

OAUTH_ENV = {
    "OIDC_ISSUER": "https://idp.example.com/realm",
    "MCP_PUBLIC_URL": "https://mcp.example.com/mcp",
    "OIDC_CLIENT_ID": "netbox-mcp",
    "OIDC_CLIENT_SECRET": "client-secret",
    "OIDC_ALLOWED_GROUPS": "netbox-users",
    "NETBOX_TOKEN_BROKER_TOKEN": "nbt_broker.secret",
    "OAUTH_SIGNING_KEY": base64.b64encode(b"s" * 32).decode(),
    "OAUTH_STATE_KEY": base64.b64encode(b"k" * 32).decode(),
}


@pytest.fixture
def oauth_config(tmp_path: Path) -> OAuthConfig:
    return OAuthConfig(
        public_url="https://mcp.example.com/mcp",
        issuer_url="https://idp.example.com/realm",
        client_id="netbox-mcp",
        client_secret="client-secret",
        allowed_groups=["netbox-users"],
        broker_token="nbt_broker.secret",
        signing_key=OAUTH_ENV["OAUTH_SIGNING_KEY"],
        state_key=b"k" * 32,
        state_path=tmp_path / "state.json",
    )


class Clock:
    """Frozen time source sampled once from the real clock; ``advance`` moves it."""

    def __init__(self) -> None:
        self.base = time.time()
        self.offset = 0.0

    def __call__(self) -> float:
        return self.base + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Settable time source wired into ``netbox_mcp.oauth.tokens.now``."""
    c = Clock()
    monkeypatch.setattr("netbox_mcp.oauth.tokens.now", c)
    return c


@pytest.fixture
def store(oauth_config: OAuthConfig) -> Iterator[StateStore]:
    StateStore.create(oauth_config.state_path, oauth_config.state_key)
    opened = StateStore.open(oauth_config.state_path, oauth_config.state_key)
    yield opened
    opened.close()


@pytest.fixture
def fake_idp() -> FakeIdP:
    """In-process OIDC provider matching ``oauth_config`` (client ID and secret)."""
    return FakeIdP(
        client_id=OAUTH_ENV["OIDC_CLIENT_ID"],
        client_secret=OAUTH_ENV["OIDC_CLIENT_SECRET"],
    )


@pytest.fixture
def fake_netbox_tokens() -> FakeNetBoxTokens:
    """Stateful NetBox users/tokens API; its service token is the broker token."""
    return FakeNetBoxTokens(service_token=OAUTH_ENV["NETBOX_TOKEN_BROKER_TOKEN"])
