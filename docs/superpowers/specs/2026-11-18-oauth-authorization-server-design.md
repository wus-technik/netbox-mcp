# OAuth authorization server with per-session NetBox tokens

Status: proposed design, not yet implemented. Revised after the Codex review
and the comparison with the reference implementation
([review](../reviews/2026-11-18-oauth-authorization-server-spec.md)).
Supersedes: [OIDC token broker](2026-11-17-oidc-token-broker-design.md).
Code baseline: upstream `v0.3.0`, FastMCP 4.1.6, MCP Python SDK 2.3.0, NetBox 4.7.x.

All URLs, account names, group names and paths in this document are
placeholders. The repository is public: no real usernames, provider IDs,
internal hostnames or secrets in code, fixtures, tests, examples or reviews.

## 1. Intent

Remote MCP clients (claude.ai, the Claude desktop app, Claude Code, Codex CLI,
ChatGPT) should connect to netbox-mcp with a normal OAuth login, and every
NetBox operation must run **as the human user** with that user's NetBox
permissions and change attribution. Users never copy a NetBox token into a
client.

The previous broker design made the identity provider (IdP) the OAuth
authorization server for the MCP clients. It is blocked until the IdP ships
RFC 8707 resource indicators and mandatory PKCE S256 in a release. This design
removes that dependency: **netbox-mcp is itself the OAuth authorization server
(AS) for its MCP clients**, and the IdP is only used to log the user in, as an
ordinary OIDC relying-party login. The same pattern runs in production for a
sibling MCP server and works with all five clients listed above.

**Reference implementation:** `wus-technik/xwiki-mcp-server`, branch
`origin/hosted` (Node.js; the unmerged branch `fix/chatgpt-tools-protocol`
for tool results and version tolerance): `src/oauth.js`, `src/sessions.js`,
`src/store.js`, `src/crypto-box.js`, `src/authentik.js`, `src/redirects.js`,
`src/metadata.js`, `src/auth-middleware.js`, `src/app.js`, its plan
`docs/superpowers/plans/2026-11-17-global-oauth.md` and reviews under
`docs/superpowers/reviews/2026-11-18-*`. Read it for behaviour, do not port
line by line. **This spec wins** where the two differ; where this spec is
silent, follow the reference. Deliberate deviations are marked *(deviation)*.

Pilot lessons referred to below: 1 = 401 before the version check (§7);
2 = ChatGPT redirect URIs and `iss` (§5.2, §5.3); 3 = ChatGPT tool-result
shape (§7.6); 4 = request order and non-canonical paths (§7.4);
5 = reserved redirect parameters (§5.2); 6 = persist the rotated IdP refresh
token first (§6.4); 7 = atomic takeover of concurrent login completions
(§5.3); 8 = no real names or hosts in the public repo.

## 2. Goals, non-goals, anti-goals

Goals:

- MCP-spec-conformant AS and protected resource at one base URL, usable by the
  five clients without per-client pre-registration (Dynamic Client
  Registration).
- One personal NetBox API token per MCP session, created, renewed and deleted
  by the server; all tool calls of that session use it.
- Access ends when the user loses eligibility (IdP account or group removed,
  NetBox user inactive, token deleted in NetBox): IdP-side changes within
  about one hour (§6.4), NetBox-side changes on the next tool call or daily
  check (§6.3).
- Tool results that ChatGPT displays correctly (§7.6).
- Package code stays generic (OIDC and OAuth terms only, no product names of a
  specific IdP), so the fork can still be offered upstream.

Non-goals:

- Creating NetBox user accounts. Accounts come from NetBox's own SSO login.
- Multiple server processes or replicas. One process owns the state.
- Supporting the old NetBox-token passthrough together with OAuth (§9).
- OAuth for stdio or SSE transports.
- CORS. Clients call the server from their backends or native apps; no
  preflight handling.

Anti-goals (would make this a failure even if it "works"):

- Any path where a client obtains a NetBox token, the IdP's tokens or another
  user's session.
- Silent loss of state that leaves orphaned, valid NetBox tokens behind, or a
  silent fresh start after a key, path or file problem.
- Plaintext tokens, codes, cookies, refresh tokens or OAuth query strings in
  any log, including the HTTP server's access log.
- Overriding private FastMCP methods (the reason approach A was dropped, §3).

## 3. Approaches considered

| Approach | Trade-off | Decision |
| --- | --- | --- |
| **A.** Extend FastMCP's `OIDCProxy` | Provides DCR, consent, PKCE, RFC 9207 `iss`, JWT signing and metadata. A spike (2026-11-18, FastMCP 4.1.6) showed that login policy can only be added by overriding the private `_handle_idp_callback`; that the stock grant lifecycle contacts the IdP on every refresh and hands the IdP token to tools; that a replayed refresh token does not end the session; that its file store has no transactions or locking and its default store silently starts empty on a key change; and seven checklist failures (Appendix A). The security core would be our own code anyway, behind a private interface. | Rejected |
| **B.** Own AS as Starlette routes next to FastMCP, modelled on the proven sibling implementation, using stable public FastMCP/SDK pieces as libraries | More own code (est. +3–5 days over A), but no private overrides, full control over every pilot lesson, and FastMCP upgrades stop being a risk to auth. | **Chosen** (maintainer decision, 2026-11-18) |
| **C.** Rewrite the whole server (e.g. in Node to reuse the sibling's code) | Throws away ~4,750 lines of tested NetBox tooling (302 tests) to save the AS port; tools touch auth in one place only (`netbox_client.py:218-224`). | Rejected |
| **D.** Keep the IdP as AS (previous broker spec) | Blocked on IdP releases with RFC 8707 and mandatory PKCE. | Superseded |

## 4. Architecture

```text
MCP client ──DCR / authorize / token / revoke──▶ netbox-mcp AS routes
                                                   │  browser login
                                                   ▼
                                      IdP (OIDC confidential client,
                                      code + PKCE, offline_access)
                                                   │ identity + groups
                                                   ▼
                                  session store (encrypted JSON file)
                                                   │
                     NetBox service credential ──▶ NetBox: create / renew /
                                                   delete personal token
MCP client ──Bearer (own HS256 JWT)──▶ /mcp ──▶ session lookup ──▶ AccessToken
                                                 .token = session's NetBox token
                                                   │
                                     tools ──▶ NetBox API as the human user
```

Integration into the existing server:

- A new `TokenVerifier` subclass verifies the server's own access JWT, loads
  the session and returns `AccessToken(token=<current session NetBox token>,
  client_id=<DCR client id>, claims={"netbox_mcp_auth_mode": "oauth", "sub":
  <internal user key>, "sid": ...})`. The claims are built by the server, never
  copied from the JWT.
- `NetBoxClient._resolve_token` (`netbox_client.py:200-230`) reads the token
  from the verified `AccessToken` in OAuth mode too (today only in passthrough
  mode). No tool code changes for auth.
- `rate_limit_client_id` (`auth.py:319-330`) keys on the internal user key
  (`claims["sub"]`) in OAuth mode, not on `client_id`, so one user with several
  client registrations shares one window.
- AS routes, metadata routes and the login flow are plain Starlette routes
  mounted outside FastMCP's bearer middleware.
- **Outer app and launcher** *(maintainer-side decision)*: OAuth mode runs only
  through the package entry point (`netbox-mcp` / `main()`). `main()` builds an
  own Starlette app, mounts `mcp.http_app(stateless_http=True,
  json_response=True)` plus the AS routes, adds the outer ASGI layer of §7.4,
  and **must pass `lifespan=mcp_app.lifespan`** (FastMCP warns about this,
  `fastmcp/server/http.py:104-106`); store, background jobs and IdP discovery
  are started inside that combined lifespan. The outer app sets a marker; the
  FastMCP lifespan fails startup in OAuth mode when the marker is missing. That
  is how `fastmcp run` / `fastmcp.json` (which import `server.py:mcp` and never
  call `main()`) are refused with a clear message. Existing modes keep working
  with `fastmcp run`. Contract tests cover both launch paths.
- Importing `server.py` must have no side effects on the store: no lock, no
  recovery, no tasks (broker review, finding 3).
- **Stateless MCP transport** *(as in the reference)*: no `Mcp-Session-Id`, so a
  server restart never yields "unknown session" 404s for live clients.
  `GET` and `DELETE /mcp` answer 405 with `Allow: POST`; notifications answer
  202 with an empty body (Codex CLI closed the transport on 200). Verify that
  FastMCP's stateless mode produces exactly this; otherwise the outer layer
  enforces it.
- Library pieces (public API, pinned by contract tests): FastMCP `JWTIssuer`
  (`jwt_issuer.py:105-160`; `issue_access_token(subject=..., extra_claims=...)`
  covers the claims of §5.4, `verify_token` additionally checks `token_use`),
  the loopback helpers in `fastmcp.server.auth.redirect_validation`, and the
  MCP SDK's metadata models. Anything that would require private overrides is
  written ourselves.
- FastMCP's own `host_origin_protection` / `allowed_origins`
  (`fastmcp/server/mixins/transport.py:367-405`) is configured to agree with
  the allowlist of §7.3, so it neither rejects the proxied `Host` nor
  contradicts the outer check; the outer layer stays authoritative because it
  must run before authentication.
- uvicorn's access log is disabled in OAuth mode (it prints request lines with
  `code` and `state`); the server logs its own events (§9).

## 5. Authorization server

### 5.1 Identifiers, endpoints and metadata

- `MCP_PUBLIC_URL` (e.g. `https://inventory.example.com/mcp`) is issuer **and**
  resource. Startup validation: `https` scheme (plain `http` only for a
  loopback host in development), no query, fragment or userinfo, no trailing
  slash. The IdP issuer and every endpoint it advertises must be `https` too.
- Endpoints advertised in AS metadata: `<base>/oauth/register`,
  `<base>/oauth/authorize`, `<base>/oauth/token`, `<base>/oauth/revoke`.
  **Root aliases with real handlers** (not redirects): `/register`,
  `/authorize`, `/token`, `/revoke`, `/oauth/revoke` on the origin root,
  because Claude Code built `origin + /path` while ignoring the base path. The
  IdP callback, login completion and consent stay under `<base>/oauth/` (the
  flow-cookie path).
- Discovery paths, all serving the same document per kind, with issuer =
  resource = `MCP_PUBLIC_URL`:
  - Protected-resource metadata (RFC 9728): `/.well-known/oauth-protected-resource`,
    `/.well-known/oauth-protected-resource/mcp`,
    `/mcp/.well-known/oauth-protected-resource`.
  - AS metadata (RFC 8414 and OIDC aliases):
    `/.well-known/oauth-authorization-server`,
    `/.well-known/oauth-authorization-server/mcp`,
    `/mcp/.well-known/oauth-authorization-server`,
    `/.well-known/openid-configuration/mcp`,
    `/mcp/.well-known/openid-configuration`.
  - **No** root `/.well-known/openid-configuration` *(as in the reference)*:
    if NetBox shares the host, a root OIDC document would mislead other
    software.
  - A test enumerates every path above (and the root aliases) and compares
    the documents.
- **Scope** *(as in the reference)*: one resource scope `netbox`.
  `scopes_supported: ["netbox"]` in both metadata documents; the 401
  challenge uses `scope="netbox"`; the token response and the access token
  carry `scope: "netbox"`. `/authorize` ignores the requested `scope`; unknown
  scopes are never an error. OIDC scopes are not advertised: an AS that
  advertises `openid` invites clients to expect an ID token. Scopes do not
  gate tools; NetBox permissions do.
- AS metadata also advertises `code_challenge_methods_supported: ["S256"]`,
  `response_types_supported: ["code"]`, grant types `authorization_code` and
  `refresh_token`, `token_endpoint_auth_methods_supported: ["none"]`, and
  `authorization_response_iss_parameter_supported: true`.

### 5.2 Dynamic Client Registration

- Public clients only. A registration is **never rejected because of the
  requested auth method, grant types or response types**: the server registers
  `token_endpoint_auth_method=none` with the fixed grant/response sets and
  echoes those. `/token` and `/revoke` ignore any `client_secret` or Basic
  credentials.
- Client name: stored and shown on the consent page labelled as
  *unverified*, next to the redirect host.
- Redirect URI allowlist:
  - `http://localhost:<port>/<path>` and `http://127.0.0.1:<port>/<path>`
    (RFC 8252 loopback; literal lowercase hosts, no `[::1]`; only the port may
    differ from the registered URI).
  - `https://claude.ai/api/mcp/auth_callback`, `https://claude.com/api/mcp/auth_callback`.
  - `https://chatgpt.com/connector_platform_oauth_redirect` and
    `https://chatgpt.com/connector/oauth/<id>` with `<id>` matching
    `[A-Za-z0-9_-]{1,128}`.
  - Exact entries from `EXTRA_REDIRECT_URIS` (comma-separated).
- Redirect URI validation (as in the reference, `redirects.js`): at most 20
  URIs per client, each ≤ 2048 chars; reject whitespace, `\`, control
  characters, userinfo or `@` in the authority, raw or encoded dot segments,
  fragments, non-http(s) schemes, and the reserved query parameters `iss`,
  `code`, `state` and `error*` (case-insensitive). Errors:
  `invalid_redirect_uri`; malformed JSON: `invalid_client_metadata`.
- At `/authorize`, the redirect URI must match one of **that client's**
  registered URIs (loopback port excepted), not merely the global allowlist.
- DCR has a per-IP rate limit and a cap on stored registrations.
- Registrations unused for 30 days and without sessions expire; their consent
  grants go with them.

### 5.3 Authorization request and login

1. `/authorize` requires `response_type=code`, a registered `client_id` and
   redirect URI, `state`, and `code_challenge` with method `S256` (absent
   method or `plain` → error). `resource` is **optional** *(as in the
   reference; clients differ)*; if sent it must equal `MCP_PUBLIC_URL` after
   stripping one trailing `/`, else `invalid_target`. Validation errors are
   shown as an HTML error page *(as in the reference)*, never redirected.
2. The server stores a login flow (random flow ID) and sets the flow cookie:
   `HttpOnly; Secure; SameSite=Lax; Path=<base path>/oauth`, 10 minutes.
   **Never `SameSite=Strict`**: the cookie must survive the cross-site return
   from the IdP. It redirects to the IdP as an OIDC confidential client:
   authorization code + PKCE S256 + `state` + `nonce`, scopes `openid profile
   email offline_access` plus configured extras. *(deviation: the reference
   uses no PKCE toward the IdP; keep it if the IdP accepts it.)*
3. IdP callback: an IdP `error` → `access_denied` redirect to the client with
   `state` and `iss`. Otherwise exchange the code (no redirect following),
   require both `access_token` and `refresh_token` (missing refresh token =
   `offline_access` not granted → deny), validate the ID token (RS256, issuer,
   audience = our IdP client ID, `nonce`, `exp`, `sub`, username claim), fetch
   userinfo and **require userinfo `sub` == ID token `sub`** (OIDC Core 5.3.2).
   Groups come from the configured userinfo claim; no group array → deny.
4. Eligibility (§6.1). A denial redirects to the client with
   `error=access_denied`, `state` and `iss`, and creates no session and no
   NetBox token. An IdP or NetBox outage during login shows an error page and
   creates nothing.
5. Consent **once per user and client registration** *(as in the reference)*:
   page shows the unverified client name and the redirect host; CSRF value =
   HMAC of the flow ID, plus the flow-cookie match. "Deny" → `access_denied`
   redirect with `iss`. The grant is remembered; it is dropped when the
   registration expires, the identity is relinked, or eligibility is lost.
   Revoking a session keeps the grant. The IdP login itself happens on every
   authorization (the IdP may answer from its own SSO session).
6. All flow pages send `Cache-Control: no-store`, `Referrer-Policy:
   no-referrer`, `X-Frame-Options: DENY` and a CSP with
   `frame-ancestors 'none'`.
7. On approval: create the session and the NetBox token (§6.2), then issue a
   single-use authorization code (≥ 256 bit, **5 minutes**, stored as hash) and
   redirect with `code`, `state` and `iss` (RFC 9207). Every redirect to the
   client carries `iss`.
8. Concurrent completions of the same login flow are taken over atomically
   (claim before the first await): exactly one creates the session and token,
   the others get an error page.

### 5.4 Token endpoint

- `authorization_code`: verify code hash, `client_id`, redirect URI,
  `code_verifier` (S256) and `resource` (optional, same rule as §5.3). The
  code is burned on the first attempt, even a failed one; a second use returns
  `invalid_grant` and does **not** end the session *(as in the reference: a
  client retrying after a timeout must not lose its session; the code is
  256-bit and single-use)*.
- Access token: HS256 JWT via `JWTIssuer`, 3600 s, claims `iss` = `aud` =
  `MCP_PUBLIC_URL`, `sub` (internal user key), `sid`, `client_id`, `scope`,
  `jti`. Verification requires `alg=HS256`, `iss`, `aud`, `exp`, `sid` of a
  live session, and `client_id` equal to the session's client. The Bearer
  scheme is matched case-insensitively.
- Refresh token: ≥ 256 bit random, base64url, stored only as SHA-256 hash.
  Rotated on every use. Sliding lifetime 30 days from the last client refresh;
  background jobs never extend it. `client_id` is optional on refresh
  (RFC 6749 §6) but must match the session's client if sent. `resource`, if
  sent, follows the §5.3 rule.
- **Absolute session cap** (maintainer decision 2026-11-18): spent hashes are
  kept for the session's whole lifetime, so a session also ends
  `OAUTH_MAX_SESSION_DAYS` (default 365, at least 1) after its creation; the
  next refresh gets `invalid_grant` and the user logs in again. Token and code
  lookups use an in-memory hash → session index, built from the store at first
  use and updated only after a successful write; every hit is re-checked
  against the session under its lock.
- Every refresh first runs the IdP eligibility check of §6.4; only an
  eligible result rotates the tokens.
- **Replay window (exact rule, as in the reference):** the session keeps one
  slot holding the hash of the token it just rotated away and the sealed
  response it returned. A presentation of exactly that token within **30 s**
  (strict `<`) of the rotation returns the stored response; the rest of the
  body is not compared (only `client_id`, if sent, must match). The lookup is
  revalidated under the per-session lock, so a concurrent duplicate waits and
  gets the replay. **Every** other presentation of a rotated token of the
  family, at any age, ends the session and enqueues its NetBox token *(stricter
  than the reference, which keeps 50 spent hashes and treats older ones as
  unknown)*: the session stores all spent hashes until it ends. Accepted
  residual risk: whoever holds the just-rotated token within 30 s gets the
  successor.
- A token or rotation only counts as done once the store write succeeded; the
  HTTP response is sent after that. A failed write answers 503 and leaves the
  previous state valid.

### 5.5 Revocation

RFC 7009 endpoint, form or JSON body. 400 only for a missing `token`; **200
for unknown or invalid tokens**. Expired but genuine access tokens still
revoke. Spent or replay-slot refresh tokens map to their session. If
`client_id` is sent it must match the token's client; otherwise 200 without
effect. Revoking ends the session and enqueues its NetBox token (§6.3). A
failed store write answers 503. Public clients need no `client_secret` field
(the SDK's handler requires one, so it is not used).

## 6. Identity, NetBox tokens and lifecycle

### 6.1 Eligibility and user mapping

Precondition (deployment): NetBox accounts are created by NetBox's own SSO
login against the same IdP, and users cannot change their own username in the
IdP. Code cannot verify either; the operations documentation states both.

- Required: the user is in at least one group from `OIDC_ALLOWED_GROUPS`.
- Mapping: the configured username claim (`OIDC_USERNAME_CLAIM`, default
  `preferred_username`; must be the claim NetBox's SSO uses as username) must
  resolve to **exactly one active** NetBox user, looked up with the service
  credential. None yet → deny with a hint to log in to NetBox via SSO once.
- Superusers are denied. Every local (non-SSO) NetBox account must be listed
  in `NETBOX_USER_DENYLIST`; the documentation states this as a required
  deployment step, because a local account whose name collides with an IdP
  username would otherwise be linked. *(The NetBox API does not expose a
  user's auth backend; if a later NetBox version does, check it instead.)*
- One IdP identity `(iss, sub)` per NetBox user ID. The first successful login
  records the link. A later login whose username resolves to a NetBox user
  already linked to a different `sub` is denied and logged, never relinked
  automatically.
- Relinking: offline admin command `netbox-mcp oauth unlink <netbox-user>`,
  only while the server is stopped (takes the exclusive store lock, refuses
  otherwise). It removes the link, ends that identity's sessions and enqueues
  their NetBox tokens; the server processes the queue at next start. No admin
  HTTP endpoint.

### 6.2 Per-session NetBox token

- Created with the NetBox service credential (`NETBOX_TOKEN_BROKER_TOKEN`) via
  `POST /api/users/tokens/` for the mapped user: `write_enabled=true` (the
  user's NetBox permissions are the limit), expiry **7 days**, description
  `NetBox MCP (OAuth) <client_name> <session-id-prefix> <nonce>`. The service
  client uses `retry=False` and `use_branch=False` (broker review, finding 4);
  the POST is never retried automatically.
- Store the full v2 bearer value (`nbt_<key>.<token>`) encrypted in the
  session, with a `tokenVersion` counter; it never leaves the server.
- **pending-create marker** (creation and renewal alike): written before the
  POST, holding nonce, NetBox user ID and session ID. It is removed **in the
  same store write** that stores the token in the session. It is dropped
  without a search only when the response proves no token was created.
  Recovery (at startup and in the hourly cleanup run, serialized per user)
  lists the user's tokens, matches the nonce and deletes any match; it never
  touches a marker younger than 10 minutes (its POST may still be in flight).
- **Renewal** when less than 2 days remain (checked on use and by the daily
  job), under the per-session lock: marker → POST → **one write** that swaps
  in the new token, increments `tokenVersion`, removes the marker and enqueues
  the old token for deletion. If the session ended meanwhile, the new token
  goes to the cleanup queue instead.
- Required NetBox permissions for the service user: `users.token` `add` and
  `grant` (optionally constrained by NetBox group), `view` and `delete`
  unconstrained (cleanup and sweep), `users.user` `view`. See broker spec §5
  for the `grant` action naming pitfall.

### 6.3 Session end, NetBox rejections and cleanup

A session ends on: revoke, refresh-token reuse, 30 days without client
refresh, eligibility loss (§6.4), an unredeemed code (**orphan**: no code
exchange within 10 minutes of session creation), or NetBox rejecting the
session's **current** token. Ending a session removes it from the store and
enqueues deletion of its NetBox token, in one write; the per-session lock is
held across renew and end.

When a tool call gets 401/403 from NetBox *(as in the reference)*: take the
session lock and compare the token used with the session's current token.

- Different (renewed meanwhile): retry the call **once** with the current
  token. Never end a session over a superseded token.
- Same: check it with the service credential. Missing or disabled → end the
  session; the current tool call returns an MCP tool error ("authorization
  expired, reconnect"), the next HTTP request gets 401 with the challenge.
  Exists and enabled → the 403 is an ordinary permission error and is passed
  through. Expired → renew, retry once.
- The service check itself failing (timeout, 5xx, non-JSON or HTML answer) is
  "unavailable": no session change, tool error, retry later.

Cleanup queue *(as in the reference)*: entries persist; a single-flight run
tries each entry once, hourly, after every session end and daily; 404 counts
as deleted; an entry older than 7 days logs a warning once per 24 h.

### 6.4 Eligibility check

**IdP check on every client refresh** (maintainer decision 2026-11-18, as in
the reference). Each refresh-token grant refreshes the session's IdP token and
reads the groups before rotating. Rejected → the session ends and the client
gets `invalid_grant`; unavailable → 503 `temporarily_unavailable`, the
previous refresh token stays valid and the client retries. Because access
tokens live 3600 s, IdP-side revocation takes effect within about one hour.
Accepted trade-off: during an IdP outage clients lose access once their
access token expires (new logins would fail anyway).

A **daily job** additionally checks every session for the NetBox side (user
still active, token still exists, renewal due) and processes the cleanup
queue. It does not contact the IdP and does not extend any deadline.

Rules:

- Per session, IdP refreshes are serialized. The rotated IdP refresh token is
  persisted **first**, in its own write, before any further check. A response
  without a new `refresh_token` keeps the old one. An unknown outcome (crash
  between IdP response and write) fails closed: the next refresh gets
  `invalid_grant` and the session ends.
- Userinfo `sub` must equal the stored link's `sub`.
- Also checked: NetBox user still active, session token still exists.
- **Rejected** (end session): IdP refresh 400/401 or response without
  `access_token`; userinfo 401; no group array or required group missing;
  userinfo `sub` mismatch; NetBox user missing/inactive; token missing or
  disabled.
- **Unavailable** (keep session, retry): IdP 403, 429, 3xx, 5xx, timeouts,
  unreadable JSON, JWKS failure; NetBox 5xx, timeouts, HTML or non-JSON 200.
  Redirects are never followed.
- No separate staleness limit is needed: without a successful IdP check no
  new access token is issued, so access ends at most one access-token
  lifetime after the last successful check. "Unavailable" on the daily
  NetBox check keeps the session and retries on the next run.

## 7. MCP endpoint behaviour

1. Without a valid token, always answer 401 with one header, independent of
   `MCP-Protocol-Version` (pilot lesson 1):
   `WWW-Authenticate: Bearer realm="<MCP_PUBLIC_URL>", resource_metadata="<MCP_PUBLIC_URL>/.well-known/oauth-protected-resource", scope="netbox"`,
   values quoted and escaped. With a presented but invalid token add
   `error="invalid_token"`; without credentials no error code (RFC 6750).
2. Protocol versions (rule from `fix/chatgpt-tools-protocol`): supported are
   the versions of the locked SDK. A header with a real calendar date newer than
   the newest supported and at most two years ahead is tolerated (claude.ai and
   ChatGPT send `2026-07-28`); anything else is 400. `initialize` is never
   rejected for its header; an unknown requested version is answered with the
   **latest** supported version. Later requests carry the negotiated version.
3. Origin allowlist, checked on all methods when an `Origin` header is
   present: `https://claude.ai`, `https://claude.com`, `https://chatgpt.com`,
   the origin of `MCP_PUBLIC_URL`, plus `EXTRA_ORIGINS`.
4. Order on `/mcp`: Origin → authentication → body parsing → version check →
   dispatch. `/mcp` and `/mcp/` are both served *(as in the reference)*;
   `//mcp`, `/mcp//` and case variants (`/MCP`) get 404, never a redirect.
5. Stateless transport and status codes as in §4.
6. Tool results for ChatGPT (pilot lesson 3; part of this design and its plan,
   maintainer decision 2026-11-18): the MCP result envelope keeps its normal
   `content` array; the rule concerns the **tool's data object**:
   - No key named `content` anywhere a client renders as the result object;
     NetBox payloads are checked for nested `content` keys and such keys are
     renamed consistently (documented mapping).
   - `structuredContent` must be a JSON **object**: list and paginated results
     are wrapped (e.g. `{"results": [...], ...}`), while the text content
     keeps the unchanged data.
   - `outputSchema` for tools with structured output; text-only tools have
     none. `title` and `annotations` on every tool; errors as `isError`;
     unknown tool → JSON-RPC -32602 with its message.
   - Existing clients must keep receiving the same data.
   - The root cause is a community report, not verified against a live
     ChatGPT connector; acceptance (§10) verifies it. At rollout the ChatGPT
     connector must be re-added to pick up the new tool list.
   - Plan it as an early, separately testable phase that works in every auth
     mode, so it can ship before the OAuth parts.

## 8. State store

- One encrypted JSON file at `OAUTH_STATE_PATH` (no default; parent directory
  must exist and be writable). AES-256-GCM with key `OAUTH_STATE_KEY`
  (32 bytes, base64), fresh nonce per write. *(deviation: the reference seals
  per field; whole-file encryption is simpler here and equally fail-closed.)*
- Atomic write: temp file in the same directory, fsync, rename, fsync of the
  directory. Writes are serialized in-process; an exclusive OS file lock
  refuses a second process.
- **Missing file → refuse to start.** A new store is created only by the
  offline command `netbox-mcp oauth init`, which writes an empty encrypted
  file and logs it loudly. This catches a wrong path or a lost volume.
- Unreadable, undecryptable or schema-invalid file → refuse to start. No
  automatic fresh start, ever.
- Contents: client registrations and consent grants, login flows, identity
  links, sessions (current refresh hash, all spent hashes, replay slot with
  sealed response, deadlines, last successful eligibility check, IdP refresh
  token, NetBox token with ID, expiry and `tokenVersion`), pending-create
  markers, cleanup queue.
- Expected scale (tens of users, a few sessions each) makes a whole-file
  rewrite per change acceptable. A session's spent refresh hashes stay until
  it ends; the absolute cap `OAUTH_MAX_SESSION_DAYS` (§5.4) bounds that list.
  The hash lookup index lives only in memory and is rebuilt from the file.
- Backup: the file plus the key, stored separately.
- **Restore** (offline commands, documented procedure):
  1. `netbox-mcp oauth restore-reset`: ends **all** restored sessions and
     enqueues their NetBox tokens (sessions revoked after the backup must not
     come back); users authorize again. Links and consent grants stay.
  2. `netbox-mcp oauth sweep`: lists every NetBox token with the description
     prefix and deletes those the store does not track. Dry run by default,
     `--apply` to delete. Never automatic.

## 9. Configuration, modes and logging

OAuth mode is on when `OIDC_ISSUER` is set. Then required:
`MCP_TRANSPORT=http`, `MCP_PUBLIC_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
`OIDC_ALLOWED_GROUPS`, `NETBOX_TOKEN_BROKER_TOKEN`, `OAUTH_SIGNING_KEY`
(≥ 32 bytes), `OAUTH_STATE_KEY`, `OAUTH_STATE_PATH`. Optional:
`OIDC_USERNAME_CLAIM`, `OIDC_GROUPS_CLAIM` (default `groups`),
`OIDC_EXTRA_SCOPES`, `EXTRA_REDIRECT_URIS`, `EXTRA_ORIGINS`,
`NETBOX_USER_DENYLIST`, `OAUTH_MAX_SESSION_DAYS`, `AUTH_DEBUG`. Missing or invalid values → startup
fails.

OAuth mode is mutually exclusive with `NETBOX_TOKEN_PASSTHROUGH` and
`MCP_HTTP_BEARER_TOKEN`; the combination fails at startup (maintainer
decision, 2026-11-18). `NETBOX_TOKEN` is ignored with a warning. Without
`OIDC_ISSUER` all existing modes behave as today.

New settings are read in `netbox_client.py` / `models.py` like the existing
ones, or `SOURCES` in `tests/test_settings_documented.py` is extended in the
same change. All are documented in `.env.example` and README and listed in
`REGISTRY_EXCLUDED`, not in `server.json`.

Logging: event names (e.g. `login_denied`, `token_refreshed`,
`refresh_rejected` with a reason code, `tool_call`, `session_ended`), user,
client name, session ID truncated to 8 chars, request path without query.
`AUTH_DEBUG` adds detail but never secrets. HTTP access logging is off in
OAuth mode (§4).

## 10. Verification

- Unit and integration tests against an in-process mock IdP and mock NetBox;
  no network in CI. The mock IdP needs: path issuer with trailing slash,
  discovery, authorize, token with refresh rotation, userinfo with groups,
  JWKS, RS256 tokens whose `aud` is the client ID.
- Required cases (from the reference's review focus, adapted): concurrent
  refresh of one session by a retrying client; NetBox answering token creation
  with an error or a login page; NetBox restart during a session; store write
  failure followed by restart (client and server agree on the valid refresh
  token); user deletes the token in NetBox (next call 401, session ended, no
  cleanup loop); renewal racing an in-flight tool call; orphan session after
  an unredeemed code; crash between token POST and store write.
- Every item of Appendix A gets an explicit test, plus: all discovery paths
  and root aliases; `GET`/`DELETE /mcp` → 405; notification → 202; `/mcp/`
  served; access log free of query strings; both launch paths.
- Acceptance before release: each of the five clients completes login, tool
  discovery, a read, a disposable write attributed to the human user, a
  refresh without interaction, a reconnect after server restart, and loses
  access after group removal (by its next refresh, ≤ 1 h) and after revoke.
  ChatGPT additionally shows tool results correctly. Records with client
  versions go to private pilot notes, not the repo.

## 11. Left to the builder

- Module layout under `src/netbox_mcp/` and the exact store schema.
- Consent page markup (minimal, server-rendered, headers per §5.3.6).
- DCR rate-limit values and registration cap.
- The documented `content` key mapping (§7.6) after surveying NetBox payloads.

## 12. References

- Previous design and its review: `2026-11-17-oidc-token-broker-design.md`,
  `../reviews/2026-11-17-oidc-token-broker-spec-plan.md` (NetBox permission
  naming, broker client, lifecycle and settings findings still apply).
- MCP authorization 2025-11-25; RFC 6749, 6750, 7009, 7591, 8252, 8414, 8707,
  9207, 9728; OpenID Connect Core 1.0 §5.3.2.
- ChatGPT redirect behaviour: https://developers.openai.com/apps-sdk/build/auth

## Appendix A. Spike checklist failures of approach A

Recorded on FastMCP 4.1.6 (spike files are not committed); each becomes a
required test for this implementation:

1. Only one of six AS/OIDC discovery aliases served AS metadata.
2. `POST /mcp//` answered 307 instead of 404.
3. DCR accepted redirect URIs with `?iss=` and with `?code=`.
4. `/authorize` without `state` reached consent.
5. `/authorize` without `resource` reached consent (this design: allowed, §5.3).
6. A foreign `resource` at the refresh endpoint was accepted.
7. Replaying an old refresh token left its successor usable.
8. Public-client revocation required an empty `client_secret` field.
9. With a changed encryption key the default store started empty.
