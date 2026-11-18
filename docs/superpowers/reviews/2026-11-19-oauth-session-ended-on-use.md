# Review: fail the call once the session ended on use (F1 residual)

## Scope

Fix commit `55e60fb` ("fix(oauth): fail the call without NetBox once the session ended on use"),
diff against the merge commit `0281160`. It closes the residual F1 finding of the final review
(`2026-11-18-oauth-authorization-server-code.md`): when the on-use renewal check found the session's
NetBox token deleted or disabled, the session ended but the current tool call still went to NetBox
with that token.

Change: the verifier returns an `AccessToken` with an empty token and the claim
`netbox_mcp_session_ended`; `NetBoxClient._resolve_token` raises the spec §6.3 session-ended tool
error ("authorization expired, reconnect") before any HTTP client exists. Rate limiting keeps keying
on the OAuth user.

## Model / command

Codex CLI 0.170.0, model `gpt-6.1-terra`, read-only sandbox:
`codex exec --sandbox read-only --cd <repo> --model gpt-6.1-terra - < prompt.txt`.
Inputs: fix brief, implementer report, full diff, spec §5.4 and §6.3, origin finding.

## Results

| Question | Result |
|---|---|
| F1 closed for every tool that opens a `NetBoxClient` (incl. GraphQL, status, plugin discovery, 401/403 retry-once) | Yes: the error is raised while the client is opened, no request leaves (`src/netbox_mcp/netbox_client.py:269-272`, `289-290`) |
| Ended marker mistaken for a valid identity (rate limit, fingerprint caches, passthrough branch, per-request verification cache) | No path found |
| Tests | Endpoint test asserts no data request reaches NetBox and fails on the old code (`tests/oauth/test_mcp_endpoint.py:450-482`); two unit tests for the marker in `tests/test_auth.py` |

Full suite after the fix: 1157 passed, 1 skipped; ruff clean.

## Findings

| # | Severity | Location | Finding | Verdict | Action |
|---|---|---|---|---|---|
| 1 | Codex: MEDIUM, reviewer: Minor | `src/netbox_mcp/oauth/verifier.py:114-126`, `src/netbox_mcp/tools/objects.py:113-125`, `src/netbox_mcp/tools/branching.py:121-124` | The ended state is enforced only inside `NetBoxClient`. Tools that finish without NetBox (`netbox_list_object_types` with plugin discovery off, `netbox_create_branch` dry run) still succeed on that one call instead of returning the reconnect error. NetBox is never contacted; output is the built-in type list or the caller's own dry-run payload; the next request gets 401. | Valid | Open, optional follow-up: check the claim centrally in a tool-call middleware plus an endpoint test |

**Verdict:** APPROVED (Codex: CHANGES_REQUESTED for finding 1). F1 as raised is closed.
