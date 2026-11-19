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
| 1 | Codex: MEDIUM, reviewer: Minor | `src/netbox_mcp/oauth/verifier.py:114-126`, `src/netbox_mcp/tools/objects.py:113-125`, `src/netbox_mcp/tools/branching.py:121-124` | The ended state is enforced only inside `NetBoxClient`. Tools that finish without NetBox (`netbox_list_object_types` with plugin discovery off, `netbox_create_branch` dry run) still succeed on that one call instead of returning the reconnect error. NetBox is never contacted; output is the built-in type list or the caller's own dry-run payload; the next request gets 401. | Valid | Fixed in `93592a4` (see follow-up below) |

**Verdict:** APPROVED (Codex: CHANGES_REQUESTED for finding 1). F1 as raised is closed.

## Follow-up: central check (`93592a4`)

Commit `93592a4` ("fix(oauth): reject every tool call once the session ended on use") adds
`SessionEndedMiddleware` (`src/netbox_mcp/tools/common.py:155-167`, registered in
`src/netbox_mcp/tools/__init__.py:30`): a tool call whose access token carries the ended claim gets the
reconnect tool error before rate limiting, tool lookup or execution. The `NetBoxClient` check stays as
defence in depth. Full suite: 1162 passed, 1 skipped; ruff clean.

Reviewed with the same model and command (diff `c1ba81e..93592a4`).

| Question | Result |
|---|---|
| Every tool call returns the reconnect error once the claim is set, incl. tools without NetBox | Yes; the middleware runs outermost of the call path |
| No-op for stdio, passthrough, static bearer and normal OAuth calls; resources/prompts/list_tools | Yes; only `on_call_tool` is affected |
| Tests | Endpoint test with `netbox_list_object_types` (no NetBox request, 401 next); middleware unit tests cover the tool-independent guard, incl. the `netbox_create_branch` dry run |

| # | Severity | Location | Finding | Verdict | Action |
|---|---|---|---|---|---|
| 2 | Codex: LOW, reviewer: Minor | `src/netbox_mcp/tools/__init__.py:29-30`, `src/netbox_mcp/tools/common.py:163-166` | On the request where the session ends, an unknown or disabled tool name gets the reconnect result instead of the JSON-RPC -32602 of spec §7.6, because the guard runs before the tool lookup. One request only; the next request gets 401. | Valid | Accepted: an ended session takes precedence; the spec does not order §6.3 against §7.6 |

**Verdict:** APPROVED (Codex: CHANGES_REQUESTED for finding 2, LOW).
