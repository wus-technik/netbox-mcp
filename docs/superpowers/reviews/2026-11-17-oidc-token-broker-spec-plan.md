# Review: OIDC token broker - spec and plan

- **Date:** 2026-11-17
- **Scope:** `docs/superpowers/specs/2026-11-17-oidc-token-broker-design.md`,
  `docs/superpowers/plans/2026-11-17-oidc-token-broker.md` (branch `oauth-plan-generic`),
  checked against `src/`, `tests/`, `pyproject.toml`/`uv.lock`, Dockerfile, README
- **Model/command:** Codex CLI 0.169.0, `gpt-6.1-sol`,
  `codex exec --sandbox read-only --model gpt-6.1-sol -`; triage and additional findings by Claude
- **Overall verdict:** Implementable after corrections. The architecture stands, but guarantees and plan tasks are missing.

Status: all findings were incorporated into the spec and plan on the same day (see "Actions").

## Findings

| # | Severity | Location | Finding | Fix | Verdict |
|---|---|---|---|---|---|
| 1 | high | Spec §3 (~l. 114); Plan Task 8 | On first login, `preferred_username` is mapped to a NetBox user. That proves uniqueness only, not ownership. The claim is not stable, and there is no unique rule on `netbox_user_id`, so two `(iss, sub)` pairs can point to the same user. | Admin-controlled username namespace or a pre-provisioned mapping. UNIQUE on `netbox_user_id` among active identities. Tests for collision and rename. | valid |
| 2 | high | Spec §3 l. 93-99; Plan Tasks 1, 12 | The IdP does not enforce PKCE S256 by configuration: it offers `plain` and `S256` and accepts requests without a challenge. The discovery requirement `["S256"]` cannot be met as written. | Expression policy for a mandatory S256 challenge. Change the requirement to "contains `S256`" and base it on the negative probes. | probably valid (source not checked by me) |
| 3 | high | Plan Task 9; `src/netbox_mcp/server.py:105-110` | `FastMCP` and the auth provider are created at import, and `fastmcp run` does not call `main()`. No task defines where the store lock, recovery, background loops and shutdown run. | New task with `FastMCP(lifespan=...)`. Test that the import takes no lock, and a test for shutdown while leases are held. | valid (verified) |
| 4 | medium | Plan Task 8; `src/netbox_mcp/retry.py:94-96` | The retry transport layer repeats non-idempotent POSTs on 429. This contradicts "one POST per journal entry". Branching would also send a branch lookup and the header with the broker token. | Broker client with `retry=False` and `use_branch=False`. Tests: exactly one POST on 429, no branch header. | valid (verified) |
| 5 | medium | Spec §4 (~l. 212); Plan Task 6 | JWKS discovery via the issuer has no task. The IdP uses a path issuer with a slash and only the appended form `/.well-known/openid-configuration`. The clients' AS metadata discovery (order per MCP 2025-11-25) is not checked. | Discovery step with exact URL construction and exact issuer comparison. Include AS discovery per client in the phase A probes. | valid |
| 6 | medium | Plan Tasks 6, 9; `src/netbox_mcp/auth.py:51-69, 143-158` | A single `JwtRejected` does not allow `403 insufficient_scope`. The 503 handler hangs off `NetBoxTokenVerifier.get_middleware()` and is lost when wrapped in an outer provider. | Typed errors (scope -> 403, broker rejection -> 403, outage -> 503). `on_error` on the outermost provider. Regression test for 503. | valid (FastMCP internals not checked locally) |
| 7 | medium | Spec §4, §8; Plan Tasks 6, 9 | The structure of `AccessToken` is unclear: where does `netbox_mcp_auth_mode` live (presumably `claims`)? `Identity` loses `exp`, so `expires_at` is missing. The leeway policy is inconsistent between SDK and spec. | Marker in `claims`, set by the server. `exp` -> `expires_at`. One leeway rule, tested with an injected clock. | probably valid |
| 8 | medium | Plan Task 5; `tests/test_settings_documented.py:11-14` | The documentation test scans only `netbox_client.py` and `utils.py`. New variables in `oidc/config.py` would not be checked. | Use the existing pattern or extend `SOURCES`. Settle `.env.example`, README and `server.json`/`REGISTRY_EXCLUDED` explicitly. | valid (verified) |
| 9 | medium (Codex: high) | Spec §1 l. ~27-29, §4 | NetBox token passthrough on the same endpoint violates the MCP rule "no token passthrough". The behavior already exists and is intentional, so it is not a new risk. | Document as a compatibility exception, optionally make it switchable off when OIDC is active. Do not emit `AccessToken.resource` as resource binding. | valid |
| 10 | medium | Spec §4 | "ID token must fail, even with a matching audience" - without a distinguishing criterion. For the analyzed IdP the claims are very similar. | Define a criterion (e.g. mandatory `scope` claim or `typ=at+jwt`) and confirm it in phase A with real tokens. | valid (Claude) |
| 11 | low | Plan l. 173 | An IdP-specific verifier class name contradicts spec §9 (no vendor-specific names in package code). | Rename to `OidcJwtVerifier`. | valid (verified) |
| 12 | low | Spec §4, §9 | `NETBOX_TOKEN_PASSTHROUGH=true` is missing from the mandatory list. SSE status is unclear. `TOKEN_STORE_PATH` is optional without a default although the store is mandatory. Dockerfile has no volume and runs as UID 10001. | Make the store path mandatory or give it a default. Define a transport rule. Tests in Task 5. | valid (Claude) |
| 13 | low | Plan (deps) | PyJWT is added next to joserfc/authlib (FastMCP) - two JOSE libraries. | Justify the choice or unify. | judgment call |
| 14 | low | Spec §3 | `codex mcp add --oauth-client-secret` ends up in the shell history. | Prescribe a way that avoids the command line. | valid (Claude) |
| 15 | low | Plan (tests) | `tests/oidc/test_config.py` collides with `tests/test_config.py`. | Create `tests/oidc/__init__.py`. | uncertain |
| 16 | info | Plan Task 4 (gate) | The IdP sets `aud = client_id` and presumably does not support RFC 8707. The gate would likely stop phase A. | Name the fallback up front (different IdP, token exchange). | note |
| 17 | info | Spec §6-§8 | The generation/lease/journal mechanics are extensive. | Check whether a simpler lifecycle meets the goals. | note |

## Compatibility (confirmed)

- Pre-registered credentials are the first registration path under MCP 2025-11-25. Dropping DCR and CIMD is therefore legitimate.
- PRM paths, `resource` value and scope challenge are consistent with RFC 9728.
- Codex CLI 0.169.0 knows `--oauth-client-id`/`--oauth-client-secret`.
- The callback URLs of claude.ai and ChatGPT were not verified again.

## Actions

| # | Implementation |
|---|---|
| 1 | Spec §3: admin-controlled username namespace as a deployment prerequisite, one active identity per NetBox user, no automatic relinking. Spec §6: partial unique index. Plan Tasks 1, 7, 8, 12: check and regression tests. |
| 2 | Spec §3: discovery "contains S256". IdP expression policy, whose feasibility phase A must prove. Plan Tasks 1, 12. |
| 3 | Spec §8: section "Server lifecycle". Plan: new Task 9a (lifespan, loops, shutdown, import without side effects). |
| 4 | Spec §5: broker client with `retry=False`/`use_branch=False`. Plan Task 8: tests for 429 and branching. |
| 5 | Spec §3/§4: AS discovery forms and JWKS discovery with exact issuer comparison. Plan Tasks 2, 6. |
| 6 | Spec §4: table of typed rejections, handler on the outermost provider. Plan Tasks 6, 9. |
| 7 | Spec §4: `AccessToken` with `expires_at` and `claims` marker, uniform 60 s leeway. Plan Tasks 6, 9. |
| 8 | Spec §9 and Plan Task 5: settings in `netbox_client.py`/`models.py`, `.env.example`, README, `REGISTRY_EXCLUDED`. |
| 9 | Spec §1: compliance exception documented, `OIDC_ACCEPT_NETBOX_TOKENS` (default `true`). |
| 10 | Spec §4: distinguishing rule (`typ`, `scope`, `nonce`/`at_hash`). Plan Task 2: confirm with real tokens. |
| 11 | Plan Task 6: `OidcJwtVerifier`. |
| 12 | Spec §4/§9: `MCP_TRANSPORT=http` and `NETBOX_TOKEN_PASSTHROUGH=true` are mandatory, `TOKEN_STORE_PATH` is mandatory, volume for UID 10001. |
| 13 | Spec §4: rationale for choosing PyJWT. |
| 14 | Spec §3 (client table), Plan Task 1: do not set the secret via the command line. |
| 15 | Plan Task 5: `tests/oidc/__init__.py`, test file renamed to `test_oidc_config.py`. |
| 16 | Spec §3: fallbacks defined, upstream status of the IdP documented (RFC 8707 and mandatory PKCE not released there). Token exchange and `aud` via scope mapping explicitly excluded. Plan Task 4. |
| 17 | Spec §6: simpler lifecycle described as an alternative, decision at the gate in Task 4. |

## Addendum: decision on the provider gate (2026-11-17)

Decision: wait for native support in a **released** IdP version.
This replaces the actions for finding 2 (expression policy) and 16 (fallback order).

- Spec, new section "Provider prerequisite": every implementation requires an IdP release that natively
  contains RFC 8707 and mandatory PKCE with S256 only. Merge, `main`, RC, beta, nightly and milestone do
  not count. For each feature it must be demonstrated that it is contained in the release: release notes,
  docs, merge commit in the release tag. That release becomes the minimum version.
- Excluded: token exchange, `aud` via scope mapping, expression policy, proxy, patched build, and a
  change of IdP without a new decision.
- Plan: new Task 0 (release check with a results table) blocks all phases.
  Tasks 1, 12 and 13 check the provider version. Task 4 stops if the behavior does not match.
