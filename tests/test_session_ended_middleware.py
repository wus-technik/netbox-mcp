"""The ended-session middleware rejects every tool call, but only on the claim."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken

from netbox_mcp.netbox_client import SESSION_ENDED_CLAIM
from netbox_mcp.netbox_client import SESSION_ENDED_MESSAGE
from netbox_mcp.tools.common import SessionEndedMiddleware


def _token(claims: dict) -> AccessToken:
    return AccessToken(token="", client_id="c", scopes=[], claims=claims)


async def _run(token):
    calls = []

    async def call_next(context):
        calls.append(context)
        return "result"

    ctx = SimpleNamespace(message=SimpleNamespace(name="netbox_create_branch"))
    with patch("netbox_mcp.tools.common.get_access_token", return_value=token):
        result = await SessionEndedMiddleware().on_call_tool(ctx, call_next)
    return result, calls


async def test_ended_claim_raises_tool_error():
    token = _token({"netbox_mcp_auth_mode": "oauth", SESSION_ENDED_CLAIM: True})
    with pytest.raises(ToolError, match="reconnect") as exc:
        await _run(token)
    assert str(exc.value) == SESSION_ENDED_MESSAGE


@pytest.mark.parametrize(
    "token",
    [None, _token({}), _token({"netbox_mcp_auth_mode": "oauth", "sid": "s"})],
)
async def test_no_claim_is_a_no_op(token):
    result, calls = await _run(token)
    assert result == "result"
    assert len(calls) == 1
