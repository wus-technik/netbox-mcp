"""Secret fields stay out of ``repr`` (and so out of accidental log lines)."""

from netbox_mcp.oauth.idp import IdpLogin
from netbox_mcp.oauth.idp import IdpTokens
from netbox_mcp.oauth.state import Flow
from netbox_mcp.oauth.state import OAuthState
from netbox_mcp.oauth.state import PendingCreate
from netbox_mcp.oauth.state import Replay
from netbox_mcp.oauth.state import Session


def _replay() -> Replay:
    return Replay(
        hash="secret-replay-hash",
        rotated_at=1.0,
        response={
            "access_token": "secret-replay-access",
            "refresh_token": "secret-replay-refresh",
        },
    )


def test_flow_repr_hides_secrets() -> None:
    flow = Flow(
        flow_id="f1",
        client_id="c1",
        redirect_uri="http://localhost/cb",
        state="secret-client-state",
        code_challenge="challenge",
        idp_state="secret-idp-state",
        idp_nonce="secret-idp-nonce",
        idp_verifier="secret-idp-verifier",
        created_at=1.0,
        idp_refresh_token="secret-idp-refresh",
    )
    assert "f1" in repr(flow)
    assert "secret-" not in repr(flow)


def test_session_repr_hides_secrets() -> None:
    session = Session(
        sid="s1",
        user_key="iss|sub",
        client_id="c1",
        netbox_user_id=1,
        created_at=1.0,
        code_hash="secret-code-hash",
        refresh_hash="secret-refresh-hash",
        spent_hashes=["secret-spent-hash"],
        replay=_replay(),
        refresh_deadline=2.0,
        idp_refresh_token="secret-idp-refresh",
        last_idp_check_at=1.0,
        netbox_token="secret-netbox-token",
        netbox_token_id=7,
    )
    shown = repr(session)
    assert "s1" in shown
    assert "secret-" not in shown
    state = OAuthState(sessions={"s1": session})
    assert "secret-" not in repr(state)


def test_replay_and_pending_repr_hide_secrets() -> None:
    assert "secret-" not in repr(_replay())
    pending = PendingCreate(
        nonce="secret-nonce", netbox_user_id=1, sid="s1", created_at=1.0
    )
    assert "secret-" not in repr(pending)


def test_idp_results_repr_hide_tokens() -> None:
    login = IdpLogin("sub-a", "alice", ["g"], "secret-idp-refresh")
    tokens = IdpTokens("secret-idp-access", "secret-idp-refresh")
    assert "alice" in repr(login)
    assert "secret-" not in repr(login)
    assert "secret-" not in repr(tokens)
