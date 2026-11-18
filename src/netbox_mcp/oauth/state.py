"""Persistent state of the OAuth authorization server (pydantic schema).

All timestamps are epoch seconds (``float``). Dicts are keyed by the ID named
in each model's docstring.
"""

from pydantic import BaseModel
from pydantic import Field


class Client(BaseModel):
    """Registered OAuth client, keyed by ``client_id``."""

    client_id: str
    client_name: str
    redirect_uris: list[str]
    created_at: float
    last_used_at: float


class Grant(BaseModel):
    """Consent grant, keyed by ``f"{user_key}|{client_id}"``."""

    user_key: str
    client_id: str
    created_at: float


class Flow(BaseModel):
    """Login flow, keyed by ``flow_id``."""

    flow_id: str
    client_id: str
    redirect_uri: str
    state: str | None = None
    code_challenge: str
    resource: str | None = None
    idp_state: str
    idp_nonce: str
    idp_verifier: str
    created_at: float
    claimed: bool = False
    user_key: str | None = None
    idp_refresh_token: str | None = None


class Link(BaseModel):
    """Identity link, keyed by ``user_key`` (``f"{iss}|{sub}"``)."""

    user_key: str
    iss: str
    sub: str
    netbox_user_id: int
    netbox_username: str
    created_at: float


class Replay(BaseModel):
    """Replay slot of the last refresh rotation."""

    hash: str
    rotated_at: float
    response: dict


class Session(BaseModel):
    """Session, keyed by ``sid``."""

    sid: str
    user_key: str
    client_id: str
    netbox_user_id: int
    created_at: float
    code_hash: str | None = None
    code_expires_at: float | None = None
    code_redeemed: bool = False
    refresh_hash: str | None = None
    spent_hashes: list[str] = Field(default_factory=list)
    replay: Replay | None = None
    refresh_deadline: float
    idp_refresh_token: str | None = None
    # Set before an IdP refresh starts; a leftover value after a crash means the
    # refresh outcome is unknown, so the session fails closed.
    idp_refresh_started_at: float | None = None
    last_idp_check_at: float
    netbox_token: str
    netbox_token_id: int
    netbox_token_expires_at: float | None = None
    token_version: int = 1


class PendingCreate(BaseModel):
    """Marker for a NetBox token being created, keyed by ``nonce``."""

    nonce: str
    netbox_user_id: int
    sid: str
    created_at: float


class CleanupEntry(BaseModel):
    """NetBox token awaiting deletion, keyed by ``entry_id``."""

    entry_id: str
    netbox_token_id: int
    netbox_user_id: int
    reason: str
    created_at: float
    last_attempt_at: float | None = None
    warned_at: float | None = None


class OAuthState(BaseModel):
    """Complete persisted state."""

    version: int = 1
    clients: dict[str, Client] = Field(default_factory=dict)
    grants: dict[str, Grant] = Field(default_factory=dict)
    flows: dict[str, Flow] = Field(default_factory=dict)
    links: dict[str, Link] = Field(default_factory=dict)
    sessions: dict[str, Session] = Field(default_factory=dict)
    pending: dict[str, PendingCreate] = Field(default_factory=dict)
    cleanup: dict[str, CleanupEntry] = Field(default_factory=dict)
