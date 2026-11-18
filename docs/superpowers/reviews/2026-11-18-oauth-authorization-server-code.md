# Code review: OAuth authorization server (branch oauth-plan-generic)

Scope: implementation range 889ad95..86f0468 (final whole-branch review) and the fix wave 86f0468..dcb2360 (scoped re-review). Per-task Codex reviews ran after every task during execution; this file records the final review.

Reviewer: Codex CLI 0.170.0, model gpt-6.1-sol, reasoning effort high, read-only sandbox, wrapped by a Claude review agent that verified each finding against the code.

## Outcome

- Final review: Fix first (F1–F9). All nine fixed in 7 commits (a6c8c5c..dcb2360); F3 documented as a known limit.
- Scoped re-review: all addressed except F1 residual (MEDIUM): when the on-use check finds the NetBox token deleted/disabled, the session ends but the current call is still sent with that token; if the token is re-enabled in that moment, one call succeeds on an ended session. Status: open — decision with the maintainer.

---

# Final whole-branch review: OAuth authorization server

## Verdict
**Fix first.** Codex: VERDICT: CHANGES_REQUESTED. My assessment after checking each finding: the two IdP-issuer defects (F4 slashless issuer, F2 http issuer) and the renewal-path revocation gap (F1) are cheap and should be fixed before merge. The rest is LOW or can wait.

## Scope
- Branch oauth-plan-generic, range 889ad95..86f0468 (38 commits), HEAD 86f0468.
- Authority: spec docs/superpowers/specs/2026-11-18-oauth-authorization-server-design.md (incl. §5.4/§8/§9 amendment), plan docs/superpowers/plans/2026-11-18-oauth-authorization-server.md (Global Constraints, Review Focus 1-5), ledger progress.md (Rulings, deferred minors).
- Extra lead from interrupted run 1: check each refresh write boundary against the recovery test.
- Codex read code and tests by path itself (official install with a working shell). It was not given the 590 KB diff package or the partial transcript. It ran in-memory probes with python -B; it did not run pytest. Checkout stayed clean.

## Model / command
codex exec --sandbox read-only --cd REPO --model gpt-6.1-sol -c model_reasoning_effort=high -c features.shell_snapshot=false -c shell_environment_policy.experimental_use_profile=false PROMPT, stdin from /dev/null (codex-cli 0.170.0). Single run, exit 0, about 206k tokens. No split needed.

## Findings

| # | Codex sev | My sev | Location | Description | Why it is real (verified) | Fix |
|---|---|---|---|---|---|---|
| F4 | MEDIUM | **HIGH** | src/netbox_mcp/oauth/idp.py:152 | Discovery URL is built as issuer + ".well-known/openid-configuration", which only works when the issuer ends with a slash. | No normalisation in config.py:104. .env.example:98 documents https://idp.example.com/realm, which yields .../realm.well-known/... The exact issuer check at idp.py:158 means the operator cannot add a slash either, because many IdPs publish a slashless issuer (realm- or tenant-path issuers). Result: startup refuses, so OAuth mode does not work with those IdPs. Tests only use a trailing-slash issuer (tests/oauth/conftest.py, fakes.py:212). | Build issuer.rstrip("/") + "/.well-known/openid-configuration"; keep the configured issuer for exact compares; test slashless root and path issuers. |
| F2 | HIGH | MEDIUM | src/netbox_mcp/oauth/config.py:104, idp.py:150 | OIDC_ISSUER is not validated as https; only the advertised endpoints are (idp.py:162-172). | Spec §5.1: "The IdP issuer and every endpoint it advertises must be https". An http issuer is fetched in the clear, so a network attacker can substitute the discovery document (token endpoint, JWKS). It needs operator misconfiguration, so MEDIUM. | Validate the issuer in config as an absolute https URL without userinfo, query or fragment, like _check_public_url; add a test. |
| F1 | HIGH | MEDIUM | src/netbox_mcp/oauth/verifier.py:94-99 -> sessions.py:395 renew_if_due_locked | When renewal is due (under 2 days left), the bearer-verification path renews without checking that the current NetBox token still exists and is enabled. | The refresh path (sessions.py:913-920) and the daily check (sessions.py:1183-1190) call get_token and end the session on missing/disabled before renewing; the verifier path does not. A token the user deletes in NetBox during its last 2 days is silently replaced on the next tool call, so revocation by deleting the token (spec §6.3, Review Focus 5) fails in that window. The window is narrow because the hourly refresh also renews, which keeps this at MEDIUM. | Before renewing, call get_token under the session lock: missing/disabled -> end the session; unavailable -> keep the current token. Test: deleted token with renewal due -> 401. |
| F3 | HIGH | LOW | src/netbox_mcp/oauth/store.py:164-167, 296-301; sessions.py:847 | If the directory fsync fails after os.replace, the store raises _CommitUncertainError -> 503 and is marked failed. Reopen loads the new state (old refresh token spent), so a client retry after 30 s counts as reuse and ends the session. | Code path confirmed. This is the documented uncertain-commit class (test_dir_fsync_failure_marks_store_failed). It needs a dir-fsync I/O error on POSIX (skipped on Windows). The previous-token guarantee does not hold here, but the outcome fails closed (re-login), not open. | Accept and document as a known limit, or keep the replay entry valid past 30 s after an uncertain write. Not merge-blocking in my view. |
| F5 | MEDIUM | LOW | src/netbox_mcp/netbox_client.py:458-465 (pre-existing), reached via oauth/broker.py _call | The one-time redirect warning logs full URLs; broker GETs carry username=, user_id= and description__ic=(nonce/marker) query strings. | _check_redirect logs history[0].request.url and the final URL; _redirect_warned is a ClassVar, so it fires once per process per base URL, and only when NETBOX_URL redirects. No credentials, but it breaks the "no query strings in logs" constraint. | Drop the query from that warning (log scheme://host/path only). |
| F6 | MEDIUM | LOW | src/netbox_mcp/oauth/routes.py:217-251, 763-766 | A malformed token request (non-string JSON value, duplicate form field) returns 400 from _oauth_params before burn_code, so the code survives a malformed first attempt. | The parse error returns before the missing-field branch that burns. Security impact is small: the code still needs a valid PKCE verifier and redirect binding. Partial gap against ruling line 118. | On parse failure, extract code if it is one unambiguous string and burn it before answering 400; add tests. |
| F7 | MEDIUM | LOW | src/netbox_mcp/oauth/state.py (Flow, Session, Replay), idp.py:55/63 (IdpLogin, IdpTokens) | Default repr includes NetBox tokens, IdP tokens and replay responses. | No repr=False or SecretStr. I found no current path that logs these objects (repr-format uses in oauth/ are on usernames and paths; store load catches ValidationError without echoing it). Hardening only. | repr=False on the secret fields. |
| F8 | MEDIUM | LOW | src/netbox_mcp/tools/common.py:109-127 rename_content_keys | A dict with both content and content_value loses one value in structuredContent. | Codex probe returned only the content_value entry. All auth modes, but it needs a NetBox object with both keys, and I know of none; the text content stays intact. Same as deferred minor line 25. | Skip renaming when the target key exists (or use a collision-safe suffix); add a test. Can wait. |
| F9 | MEDIUM | MEDIUM (tests) | tests/oauth/test_token_endpoint.py, test_sessions.py | Run-1 lead confirmed: test_refresh_write_failure_keeps_previous_token injects failure only at the final MCP rotation without renewal. Renewal marker (sessions.py:414), renewal swap (435), marker clear after IdP unavailable (925), code burn (652) and code redemption (721) have no failure/restart tests. | The Codex per-boundary analysis below found no wrong behaviour at those boundaries before publication; only coverage is missing. | Add at least: renewal-due refresh with failing swap write -> previous refresh token works after reopen, marker recovered; failing redemption write -> code still usable. |

### Refresh write-boundary audit (Codex, spot-checked)
A refresh with renewal makes 5 writes: IdP-refresh mark (sessions.py:877), IdP persist + mark clear (925), renewal marker (414), renewal swap + marker removal + old-token enqueue (435), MCP rotation (847). A failure before publication at any of them leaves the previous MCP refresh token valid, with one exception by design: a failure at the IdP-persist write leaves the mark set, so the next refresh fails closed (spec §6.4/F8, covered by test_crash_between_idp_refresh_and_write_fails_closed). A failure after publication (uncertain commit) matters only at 847 (F3). Coverage: only 877, 925 (success branch) and 847 (no renewal, before publication).

## Review Focus 1-5
1. Concurrent refresh retry: **holds**. Session lock plus re-check; the waiter gets the replay (sessions.py:814); the named test asserts the same pair and one IdP call.
2. Write failure + restart: **holds for failures before publication** (named test, final rotation). It does not hold for an uncertain commit after rename (F3, LOW). Coverage gaps: F9.
3. Superseded token retries once: **holds** (version compare under the session lock, single retry; the named test checks old and new headers).
4. Ambiguous create: **holds** (marker kept, no session, recovery deletes on nonce match, 10-min guard re-checked under the user lock).
5. Deleted token: **holds for the tested case**, fails when renewal is due (F1).

Other cross-task checks (Codex; no counter-evidence found): no auth bypass to the MCP endpoint, no lock-order cycle; store mutate bodies do not await network I/O; the hash index is updated after successful writes and rebuilt from the store on load (covers offline CLI edits + restart); Windows replace retry is bounded and dir fsync is skipped on Windows; non-OAuth mode selection unchanged (only F8 touches all modes).

## Deferred-minor triage
| Ledger line | Item | Codex | Mine |
|---|---|---|---|
| 25 | rename_content_keys collision | FIX-BEFORE-MERGE | CAN-WAIT (no known NetBox object has both keys; text copy intact) |
| 26 | UnknownToolIsInvalidParams wraps whole call_next | CAN-WAIT | CAN-WAIT |
| 27 | deprecated outputSchema / missing tests | FIX-BEFORE-MERGE (collision test only) | CAN-WAIT (follows line 25) |
| 28 | deep copy per result | CAN-WAIT | CAN-WAIT |
| 39 | pytest-asyncio loop-scope warning (Linux) | not triaged | CAN-WAIT |
| 44 | metacharacter state filename test | CAN-WAIT | CAN-WAIT (re.escape used) |
| 65 | explicit azp null | CAN-WAIT | CAN-WAIT |
| 66 | discovery invalid port | CAN-WAIT | CAN-WAIT; fold into the F2 issuer validation |
| 76 | broker reaches into _http | CAN-WAIT | CAN-WAIT |
| 110 | Windows sleep backoff / tmp leftover / test asserts | CAN-WAIT | CAN-WAIT |
| 119 | IdP timeout clears marker | CAN-WAIT (README documents it) | CAN-WAIT |
| 143 | same-user renewal serialization | CAN-WAIT | CAN-WAIT |
| 156 | e2e stops at 302; README /mcp aliases; loopback placeholder | CAN-WAIT | CAN-WAIT |

## Ruling opinions
Codex AGREES with every ruling (lines 5, 6, 31, 32, 41, 47, 55, 56, 64, 72, 93, 94, 95, 98, 99 x2, 102, 108, 113, 114, 118, 125, 127, 131, 132 x2, 138, 145, 152). Notes: line 118 is only partly implemented (F6); line 64 was re-probed against the installed PyJWT and holds. I see no reason to disagree with any ruling.

## What was done
Review only; nothing fixed. Recommended before merge: F4, F2, F1 (with tests), ideally F5 (one line). F3, F6, F7, F8 and the F9 tests can follow.


---

# Scoped re-review of the fix wave

# Final re-review of the fix wave (86f0468..dcb2360)

Model: gpt-6.1-sol, reasoning high, read-only. Raw output: codex-out-final-rr.txt. Full pytest not rerun; Codex ran in-memory probes.

## Verdicts
| Item | Verdict | Sev | file:line |
|---|---|---|---|
| F1 | NOT ADDRESSED (renewal bypass fixed, current call still goes out) | MEDIUM | src/netbox_mcp/oauth/verifier.py:102-107 |
| F2 | ADDRESSED | MEDIUM | src/netbox_mcp/oauth/config.py:119 |
| F3 | ADDRESSED (documented, behavior unchanged) | LOW | README.md:727 |
| F4 | ADDRESSED, discovered issuer still compared exactly | HIGH | src/netbox_mcp/oauth/idp.py:156,162 |
| F5 | ADDRESSED | LOW | src/netbox_mcp/netbox_client.py:452,464 |
| F6 | ADDRESSED | LOW | src/netbox_mcp/oauth/routes.py:774 |
| F7 | ADDRESSED | LOW | oauth/state.py:59,78,105; oauth/idp.py:60 |
| F8 | ADDRESSED | LOW | src/netbox_mcp/tools/common.py:122 |
| F9 | ADDRESSED | MEDIUM | tests/oauth/test_token_endpoint.py:1129,1178 |
| output_schema | ADDRESSED | LOW | tests/test_tool_results.py:72 |
| azp:null | ADDRESSED | LOW | oauth/idp.py:333 |
| discovery invalid port | ADDRESSED | LOW | oauth/idp.py:176 |
| README placeholders | ADDRESSED | LOW | README.md:683,685 |

## F1 named risk
Codex: the call should fail immediately with the section 6.3 reconnect tool error once the session is ended, before any NetBox call. Codex's probe: session ended, NetBox token re-enabled, current call SUCCEEDS on an ended session (next request is rejected). A NetBox outage at that moment would also replace the reconnect error with an unrelated failure. I confirmed the code: verifier.py:102-107 still returns the bearer after `ended` is true (comment says the call goes ahead). Agree; severity MEDIUM (narrow window, requires re-enabled token, bounded to one call), but it contradicts the stated "ended = no access" contract. Smallest fix: when `ended` is true return None from verify (401) or mark the AccessToken so tool dispatch raises the 6.3 error without calling NetBox. Codex rated this the only new Important item; I rate it MEDIUM, not blocking if the owner accepts the one-call window.

## Other questions
- F2: the test fake issuer is HTTPS (tests/oauth/fakes.py:25); literal-loopback HTTP issuers are accepted, consistent with the MCP_PUBLIC_URL rule. A wholly HTTP dev IdP stays unsupported because advertised endpoints are HTTPS-only (idp.py:174), a pre-existing restriction.
- F4: exact comparison retained (idp.py:162).
- No other new Critical/Important breakage found.

VERDICT: CHANGES_REQUESTED (F1 only; MEDIUM)
