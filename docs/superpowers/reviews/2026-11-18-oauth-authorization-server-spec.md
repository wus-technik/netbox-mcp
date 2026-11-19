# Review: Spec "OAuth authorization server with per-session NetBox tokens"

- **Date:** 2026-11-18
- **Scope:** `docs/superpowers/specs/2026-11-18-oauth-authorization-server-design.md` (branch
  `oauth-plan-generic`, before the first commit), checked against `src/`, `tests/`, `fastmcp.json`, `.venv`
  (FastMCP 4.1.6, MCP SDK 2.3.0)
- **Part 1 - Codex review:** `codex-reviewer` agent, Codex CLI 0.170.0, model `gpt-6.1-terra`, read-only;
  triage and additional findings (Z1-Z4) by Claude
- **Part 2 - comparison with the reference implementation:** Claude agent, read-only, against the internal
  reference implementation (its hosted branch and an unmerged fix branch for ChatGPT tool-protocol handling)
- **Overall verdict:** Changes needed, architecture confirmed. Nothing critical.
- **Status:** All findings were incorporated into the spec on the same day, including the maintainer decision
  on how often the IdP is checked (spec §6.4).

## Part 1: Codex review

| # | Severity (triaged) | Location | Finding | Verdict | Action |
|---|---|---|---|---|---|
| 1 | high | §5.3, §6.4 | Userinfo `sub` is not checked against the ID-token `sub` or the stored link | valid (OIDC Core 5.3.2) | §5.3 step 3, §6.4 |
| 2 | medium | §6.1 | A unique username does not prove ownership; a local NetBox account with the same name would be linked | probably valid | §6.1: local accounts must go on the deny list (mandatory deployment step), superusers rejected |
| 3 | medium | §5.4, §8 | (a) The replay window hands the successor to any holder of the old token; (b) only one old hash is stored, so reusing an older token does not end the session | (b) valid, (a) valid, narrow | §5.4: all consumed hashes kept until the session ends; (a) documented as residual risk |
| 4 | medium | §5.3, §6.4 | Window between the IdP response and the write; reconciliation and login can overtake each other | probably valid | §6.4: IdP refresh serialized per session, unknown outcome fails closed |
| 5 | high | §6.2, §6.3 | Renewal without a marker, old token not atomically added to the cleanup list; renewal vs. session end | valid | §6.2: marker also on renewal, one write for swap + cleanup entry, session lock |
| 6 | high | §8 | "Missing file -> empty state" contradicts the anti-goal "no silent fresh start" | valid | §8: missing file -> start refused, `netbox-mcp oauth init` |
| 7 | high | §8 | A restore brings revoked sessions back | valid | §8: `oauth restore-reset` ends all restored sessions |
| 8 | low | §5.2, §5.3 | DCR client names are unverified, consent is remembered | overstated (the redirect allowlist limits abuse) | §5.2/§5.3: name shown as "unverified" |
| 9 | medium | §5.4, §5.5 | Refresh and revoke do not check `client_id` | valid | §5.4, §5.5 |
| 10 | medium | §2, §6.3, §6.4 | "at most one day" vs. "unreachable -> keep"; outcome of the detecting tool call is open | valid | §6.4: IdP check on every refresh limits access to about 1 h; §6.3 tool error, then 401 |
| 11 | medium | §5.1, §9 | `MCP_PUBLIC_URL` and IdP URLs are not validated | valid | §5.1 startup check |
| 12 | low | §7.2, §7.5 | "no `content` key" is ambiguous; "negotiating down" only applies to `initialize` | probably valid | §7.2, §7.6 reworded |
| 13 | high | §4, `server.py`, `fastmcp.json` | The outer app needs `lifespan=mcp_app.lifespan`; the rejection of `fastmcp run` in `main()` never fires | valid (verified, `fastmcp/server/http.py:104-106`) | §4: lifespan composition, marker check in the FastMCP lifespan, tests for both start paths |
| 14 | medium | `auth.py:319-330` | Rate limit keyed by DCR `client_id` instead of by user | valid (verified) | §4: key `claims["sub"]` |
| 15 | low | `tests/test_settings_documented.py:11-14` | The documentation test does not scan new modules | valid (verified) | §9 |
| Z1 | medium | §3, §1 | A personal name and first-person voice in a public repo | valid | worded neutrally ("maintainer decision") |
| Z2 | low | §3, §10 | The spec refers to uncommitted spike files | valid | Appendix A, mock-IdP requirements in §10 |
| Z3 | info | §4 | `JWTIssuer` covers the claims (`jwt_issuer.py:105-160`) | - | fixed in §4 |
| Z4 | info | §7.3 | FastMCP has its own host/origin protection (`mixins/transport.py:367-405`) | - | §4: configure consistently, the outer layer is authoritative |

## Part 2: Comparison with the reference implementation

Classes: (a) deliberate/justified, (b) gap, (c) contradiction that can break a client.

| # | Area | Reference | Class | Action in the spec |
|---|---|---|---|---|
| 1 | Scopes | one resource scope, no `openid` | (c) | §5.1: scope `netbox`; the earlier statement "as in the reference" was based on an outdated local branch |
| 2 | `resource` | optional, one trailing `/` tolerated | (c) | §5.3, §5.4 |
| 3 | Root aliases `/register`, `/authorize`, `/token`, `/revoke` | real handlers (Claude Code) | (b) | §5.1 |
| 4 | Renewal vs. running tool call | `tokenVersion`, retry once with the current token | (b)/(c) | §6.2, §6.3 |
| 5 | Orphaned sessions (code never redeemed) | end after 10 min | (b) | §6.3 |
| 6 | Replay window | one slot, strictly < 30 s, body not compared, lock | (b) | §5.4 described exactly (stricter for old hashes) |
| 7 | Transport | stateless, GET/DELETE 405, notifications 202 | (b) | §4, §7.5 |
| 8 | `/mcp/` | is served | (c) | §7.4 |
| 9 | DCR auth method | never reject, always `none` | (b) | §5.2 |
| 10 | Redirect validation in detail | limits, characters, patterns | (b) | §5.2 |
| 11 | Query strings in the log | path only | (b) | §4, §9: access log off |
| 12 | pending-create | atomic removal, 10-min protection, also on renewal | (b) | §6.2 |
| 13 | IdP on every refresh | yes, block about 1 h | (a) | adopted (maintainer decision), §5.4, §6.4 |
| 14 | Code reuse | `invalid_grant`, session stays; TTL 5 min | (a)/(c) | §5.4, §5.3: as in the reference |
| 15 | Error routing | validation errors as HTML page; IdP `error` -> `access_denied` | (a) | §5.3 |
| 16 | 401 header | `realm`, `/mcp/.well-known/...`, `error` only with a token | (b) | §7.1 |
| 17 | Protocol versions | real date, > newest, <= 2 years; `initialize` -> newest | (b) | §7.2 |
| 18 | Tool results | `structuredContent` as object, lists wrapped; not verified live | (b) | §7.6 |
| 19 | Flow cookie and headers | path, 10 min, Lax, no-store, no-referrer, anti-framing | (b) | §5.3 |
| 20 | Revoke details | 200 for unknown tokens, expired ones revocable | (b) | §5.5 |
| 21 | IdP/NetBox classification | userinfo 401, missing groups, no redirect following, HTML = unreachable | (b) | §6.4 |
| 22 | Access-token check | `client_id` = session client | (b) | §5.4 |
| 23 | Root `openid-configuration` | not served | (a) | removed in §5.1 |
| 24 | Storage format | sealed field by field, empty file written immediately | (a) | §8 deviation marked; start without a file refused |
| 25-28 | Cleanup cadence, registration flow, CORS, PKCE to the IdP | - | (a)/(b) | §6.3, §5.2 (30 days), §2 (no CORS), §5.3 |

Fixes in the reference after client failures that the first draft did not cover and that are now included: root
aliases (Claude Code), notification 202 (Codex CLI), tolerant `resource` with slash, object wrapping for
`structuredContent`, exact version rule.

## Decision

Spec §6.4: IdP check on every client refresh (as in the reference, block about 1 h, an IdP outage blocks the
refresh) instead of daily. Maintainer decision 2026-11-18. The 48-h staleness rule from Codex finding 10 is
therefore dropped; the daily run now only checks the NetBox side.
