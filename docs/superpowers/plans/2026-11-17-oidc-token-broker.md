# OIDC token broker implementation plan

**Superseded** on 2026-11-18 by
[OAuth authorization server implementation plan](2026-11-18-oauth-authorization-server.md).
Do not execute.

Status: proposed work, not an implemented or verified feature. **Blocked** until
Task 0 passes: every task below requires a released Authentik version that
provides RFC 8707 resource indicators and required PKCE S256 natively (design,
"Provider prerequisite").

Design: [OIDC authentication with personal NetBox tokens](../specs/2026-11-17-oidc-token-broker-design.md).
Start implementation from upstream `v0.3.0`. Reference API versions and all
security/lifecycle contracts are defined in the design. Keep operational values
and measured integration results in private deployment records.

This plan covers client validation, package implementation, container release,
deployment, recovery and optional permission hardening. It does not depend on
a particular reverse proxy, container manager, DNS service or organization.
The required client surfaces are claude.ai, direct Claude Code, chatgpt.com and
direct Codex CLI, all using Streamable HTTP. Passing one client does not establish
support for the others. Use the setup matrix in design section 3 and record
actual client versions/hosted test dates privately.

## Working rules

- Use the repository's existing style, supported Python range and locked
  dependencies. Do not upgrade unrelated packages to implement authentication.
- Write focused regression tests for the failure cases below. Unit tests mock
  NetBox/JWKS with `httpx2.MockTransport`; use generated test-only signing keys.
- Use events/barriers and injected clocks for races and expiry tests, not sleeps.
- Never log bearer values, OAuth client secrets, encryption keys or JWTs.
- Separate read-only planning, snapshots, apply, verification and rollback in
  deployment automation. Follow the deployment owner's change authorization.
- Protect actual operational configuration outside the public repository.
- Snapshot before changing an external system. Give snapshots timestamped names
  and identify the exact restore point; preserve secrets through the secret store.
- Commit coherent steps with conventional messages. Verify publication content
  and reachable commit history before pushing a public branch or tag.

## Phase 0: provider release prerequisite

### Task 0: verify the Authentik release

No task of Phase A, B, C or D may start before this task is complete. This
includes experiments, prototypes, implementation branches, image builds and
provider configuration.

- [ ] Identify the first **published** Authentik release (tagged, with release
  notes) that contains both:
  - RFC 8707 resource indicators with `aud` set to the resource, from
    issue #27645 / PR #27855;
  - required PKCE with `plain` disallowed, from issue #25520 / PR #27884.

  A merged PR, `main`, a release candidate, a beta, a nightly image or a
  milestone does not count.
- [ ] For each feature, verify presence in that release:
  - the release notes entry;
  - the provider settings in that version's documentation;
  - the merged PR commit being contained in the release tag
    (`gh api repos/goauthentik/authentik/compare/<merge-commit>...version/<release> --jq .status`
    returns `ahead` or `identical`).

  Record links and results here, without deployment data.
- [ ] If either feature is missing, stop. Recheck at the next Authentik
  release. Do not substitute token exchange, scope-mapping `aud`, expression
  policies, a proxy or a patched build.
- [ ] Record the release as the **minimum provider version**. Update the design:
  the reference version, the "Upstream status" table and the source links in
  section 10.
- [ ] Recheck the ID-token criterion and the claims the design expects (design
  section 4) against the minimum release's documentation before Phase A.

Result record:

| Feature | Release | Release notes | Docs | Commit in tag | Checked on |
| --- | --- | --- | --- | --- | --- |
| RFC 8707 resource indicators | Pending | Pending | Pending | Pending | Pending |
| Required PKCE, S256 only | Pending | Pending | Pending | Pending | Pending |

## Phase A: prove client/provider compatibility

All Phase A experiments run against the minimum provider version from Task 0 or
a later release, never against an older version, a pre-release or a patched
build.

### Task 1: isolated discovery and identity probe

- [ ] Confirm the test provider instance reports the Task 0 minimum version or
  later, and record the version.
- [ ] Provision a temporary provider/application and dedicated test group with
  two disposable users. Do not reuse a production application for experiments.
- [ ] Create a minimal FastMCP server with remote authentication and a `whoami`
  tool returning selected identity/policy claims, never the bearer token.
- [ ] Require the test group and the intended scope. Configure the scope mapping
  to emit `groups` under the same required scope; verify claim inclusion settings.
- [ ] Configure authorization-code and refresh grants with PKCE S256. Disable
  unused grants and advertise the actual token-endpoint auth methods. Verify
  discovery includes `code_challenge_methods_supported` with `S256` and all
  requested scopes, including `offline_access`.
- [ ] Enforce S256 with the provider's native PKCE setting: required for all
  clients, `plain` disallowed. The Task 2 negative probes are the evidence. Do
  not use an expression policy.
- [ ] Configure the MCP resource URI as the provider's allowed resource for
  RFC 8707.
- [ ] Verify the username namespace precondition (design section 3): users cannot
  change their own username claim, and no enrollment flow lets them pick one.
  Record the provider settings that guarantee this.
- [ ] Enforce the exact MCP resource audience separately from the registration's
  client ID/authorized party. Exercise real authorization and token requests with
  `resource`; do not assume the reference provider supports this contract.
- [ ] Expose the temporary MCP route and protected-resource metadata through
  narrowly scoped host **and** path rules. Choose a deployment-specific available
  listener rather than embedding an infrastructure address in the repository.
- [ ] Record exact client callback URLs and register strict redirect matches.
- [ ] Configure all four clients using pre-registered credentials. For claude.ai,
  select the own-client option; for ChatGPT, copy the connection's displayed
  callback and verify workspace/tool permissions. For Claude Code and Codex CLI,
  configure their direct HTTP connections and effective loopback listener ports.
  Follow the version/issuer-dependent callback rules in design section 3.
- [ ] Set the requested scopes to `openid profile email offline_access netbox-mcp`
  through client configuration or discovery/challenge metadata and inspect the
  resulting request. Keep credentials outside shared project configuration.
  For Codex CLI, do not pass `--oauth-client-secret` on the command line; record
  the private method used to set the secret.
- [ ] Verify unauthenticated 401 challenge, public metadata, issuer discovery,
  ordinary application paths and unrelated-host routing, through both internal
  routing and any external edge. Record the pre-change baseline for rollback.

### Task 2: client, protocol and denial matrix

- [ ] For each of the four required clients, prove initial login, tool discovery,
  a successful `whoami` call, refresh after real access-token expiry without an
  interactive login, and reconnect/restart using the stored credentials.
- [ ] For each client, record which authorization-server metadata URL it fetched
  (path-inserted OAuth/OIDC forms versus the appended OIDC form, design section 3),
  whether it accepted the metadata, and that the returned `issuer` matched exactly,
  including the trailing slash.
- [ ] Record discovery URLs, issuer matching, `aud`, `azp`, `scope`, `groups`,
  `sub`, callbacks, client versions/test dates, token-endpoint auth method and
  `resource` handling privately. Record redacted evidence, never bearer values,
  authorization codes, refresh tokens or secrets.
- [ ] Verify PKCE S256 is sent and enforced. Negative protocol probes must deny
  missing/non-S256 challenges, missing/wrong verifiers, mismatched redirects and
  invalid client credentials.
  Check advertised response-issuer support against actual `iss` responses;
  issuer-bound clients must reject missing or mismatched response issuers.
- [ ] Prove the correct resource produces the expected MCP audience, including
  after refresh. A wrong resource must fail issuance or yield a token rejected
  by MCP; a client-ID-only audience must also be rejected. No negative case may
  mint a personal NetBox token. Confirm refresh cannot broaden scopes.
- [ ] Check actual ID-token rejection separately from access-token acceptance.
  Record the JOSE header `typ` and the presence of `scope`, `nonce` and `at_hash`
  in real access and ID tokens, including after refresh, and confirm the
  criterion in design section 4 separates them. Update the design if it does not.
- [ ] Measure account deactivation, group removal and application-binding denial
  independently, starting each case with a working test identity.
- [ ] For binding denial, snapshot bindings and mode; set `policy_engine_mode=all`
  and add a negated test-user binding while keeping group membership unchanged.
  Prove a **new authorization** is denied and a control user remains allowed.
  Only then interpret refresh/call results measured from the denial timestamp.
- [ ] Restore mode, bindings, membership and account state after each case;
  prove successful authorization and a working call again.
- [ ] Reject rollout if access persists beyond the agreed token lifetime plus
  clock tolerance. Evaluate online policy checks or a different architecture
  based on evidence rather than assuming refresh or UserInfo semantics.

Keep an acceptance table in the private pilot record with these four rows.
All cells begin as pending; do not fill them from documentation or unit tests.
Phase A fills login/discovery, refresh, reconnect and identity-provider denial.
Task 15 fills the final workload tests and repeats the earlier checks.

| Client | Version/date, callback, scopes and auth method | Login/discovery | Read/write and attribution | Refresh | Reconnect/restart | IdP denial | NetBox revocation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| claude.ai | Pending | Pending | Pending | Pending | Pending | Pending | Pending |
| Claude Code (direct HTTP) | Pending | Pending | Pending | Pending | Pending | Pending | Pending |
| chatgpt.com | Pending | Pending | Pending | Pending | Pending | Pending | Pending |
| Codex CLI (direct HTTP) | Pending | Pending | Pending | Pending | Pending | Pending | Pending |

Attach protocol-probe evidence for PKCE, issuer validation, resource binding,
ID-token rejection and token-endpoint authentication to this record. The shared
provider tests supplement, rather than replace, the per-client flow checks.

### Task 3: tear down the experiment

- [ ] Remove temporary routing, edge exceptions, workload, clients and provider
  objects in dependency order. Retain test identities only if later tests need
  them and keep their access disabled between experiments.
- [ ] Verify restored routing and the unchanged existing MCP service.
- [ ] Store results and the completed cleanup record privately.

### Task 4: architecture gate

- [ ] Confirm the fixed-client design works in all target clients and denial
  times meet the stated policy. Record an explicit deployment-owner decision.
- [ ] Require all four Phase A acceptance rows and the protocol probes to pass.
  Resource binding, PKCE S256, refresh and exact callbacks are blocking criteria.
  If the provider cannot issue resource-bound access tokens, stop and revise
  the integration or architecture before package implementation. Do not accept
  client-ID-only audiences as a compatibility exception or add a proxy silently.
- [ ] Confirm Task 0 is complete and Phase A ran against the recorded minimum
  provider version or later.
- [ ] If the release fails the behaviour check despite its release notes, stop.
  Report the deviation upstream if appropriate, and wait for a release that
  passes. The decision in design section 3 is to wait for native support. A
  different provider, a proxy or a workaround requires a new decision and a
  revised design.
- [ ] Decide whether to keep the full lease/generation lifecycle or the simpler
  lifecycle described in design section 6, and record the decision.
- [ ] If provider behavior changes the design, update this design and plan before
  implementing. Do not proceed with mocks that contradict measured behavior.

## Phase B: package implementation

### Task 5: configuration and dependencies

Files: `pyproject.toml`, `uv.lock`, `src/netbox_mcp/models.py` (`OidcConfig`),
`src/netbox_mcp/netbox_client.py` (`get_oidc_config_from_env()`),
`src/netbox_mcp/oidc/__init__.py`, `tests/oidc/__init__.py`,
`tests/oidc/test_oidc_config.py`, `.env.example`, `README.md`,
`tests/test_settings_documented.py` (`REGISTRY_EXCLUDED`).

- [ ] Declare PyJWT with crypto support and cryptography directly (both are
  already locked transitively); regenerate the lockfile. Ensure the container's
  locked dependency installation succeeds. Record the library choice as stated
  in design section 4.
- [ ] Implement immutable configuration with the required/optional environment
  variables in the design, read in `netbox_client.py` like the existing settings
  so `tests/test_settings_documented.py` finds them. Validate URLs, key format and
  incompatible auth modes.
- [ ] Document every new variable in `.env.example` and `README.md`; add all OIDC
  variables to `REGISTRY_EXCLUDED`, not to `server.json`. The settings test must
  pass unchanged apart from that set.
- [ ] Require `MCP_TRANSPORT=http`, `NETBOX_TOKEN_PASSTHROUGH=true` and a
  `TOKEN_STORE_PATH` whose parent directory exists and is writable. Test stdio,
  SSE, static bearer token, passthrough off, missing store path and an unwritable
  store directory as startup failures. Test `OIDC_ACCEPT_NETBOX_TOKENS` parsing.
- [ ] Require a separate nonempty `OIDC_CLIENT_ID` for `azp` validation and require
  `OIDC_AUDIENCE == MCP_PUBLIC_URL`. Test mismatched resource configuration and
  prevent a client-ID audience from being substituted for the MCP resource.
- [ ] Test issuer-unset behavior, missing required settings, defaults, issuer URL
  handling, empty required policy values and invalid encryption keys.
- [ ] Keep no-OIDC behavior unchanged. Reject OIDC with static shared bearer
  authentication or unsupported transports rather than silently ignoring it.

### Task 6: JWT verification and bounded JWKS trust

Files: `src/netbox_mcp/oidc/jwt.py`, `tests/oidc/test_jwt.py`,
`tests/oidc/conftest.py`.

Interfaces:

```python
class Identity:
    iss: str
    sub: str
    username: str
    azp: str
    groups: tuple[str, ...]
    exp: int

def looks_like_jwt(token: str) -> bool: ...

class JwtRejected(AuthenticationError): ...        # 401 + metadata challenge
class InsufficientScope(AuthenticationError): ...  # 403 insufficient_scope
class AccessDenied(AuthenticationError): ...       # 403 (group, broker denial)
class JwksUnavailable(AuthenticationError): ...    # 503 + Retry-After

class OidcJwtVerifier:
    async def verify(self, token: str) -> Identity: ...
```

- [ ] Implement RS256-only validation with required claims, issuer/audience,
  temporal checks, group, scope, subject/username types and authorized party.
  Accept `aud` as the exact MCP resource string or a string array containing it;
  compare `azp` separately with `OIDC_CLIENT_ID`. Reject malformed audience types.
- [ ] Apply one 60-second leeway to `exp`, `nbf` and `iat`; carry `exp` in
  `Identity` for `expires_at`.
- [ ] Implement the access-token/ID-token criterion from design section 4
  (`typ`, `scope`, `nonce`/`at_hash`). Raise the typed errors from the table in
  design section 4: missing scope is `InsufficientScope`, missing group is
  `AccessDenied`, everything else in the token is `JwtRejected`.
- [ ] Implement JWKS location: `OIDC_JWKS_URL`, or discovery from
  `OIDC_ISSUER` + `.well-known/openid-configuration` with exact `issuer` match
  (trailing slash kept). Test URL joining with and without a trailing slash,
  an issuer mismatch, a missing `jwks_uri` and discovery failure at startup.
- [ ] Inject wall and monotonic clocks independently. Implement a 300-second
  JWKS maximum age, full key-set replacement, shared concurrent refresh and
  60-second throttling of unknown-key/failed-fetch attempts.
- [ ] Return `JwksUnavailable` when no fresh trusted key set can be obtained;
  never extend cache freshness on failures or accept stale verified JWTs.
- [ ] Cover valid access tokens, ID tokens, missing/malformed claims, expiry,
  future `nbf`, wrong issuer/audience/party/group/scope, HS256/none, foreign
  signature with the same `kid`, and v1/v2 passthrough classification.
- [ ] Include tokens with only the client-ID audience, tokens for another MCP
  resource and valid resource tokens from the wrong authorized party. Each must
  fail before broker access. Test real-provider-shaped access/ID-token fixtures
  with generated test keys, based on the Phase A contract rather than assumptions.
- [ ] Cover known-key expiry, removed keys, full replacement versus merge,
  fetch outage at/after 300 seconds, unknown-key throttling and concurrent
  refresh. Removed known keys must fail without restarting the process.

### Task 7: durable encrypted state

Files: `src/netbox_mcp/oidc/store.py`, `tests/oidc/test_store.py`.

- [ ] Implement identity, generation, issuance-attempt and audit tables with the
  fields and uniqueness constraints in design section 6, including the partial
  unique index on `netbox_user_id` among non-retired identities. Test that a
  second subject cannot link to an already linked user ID.
- [ ] Bind Fernet ciphertext to `(iss, sub, netbox_user_id, token_id)` and reject
  swapped/corrupt records. Fail startup if the configured key cannot read state.
- [ ] Implement transactional `begin_issue`, `complete_issue`,
  `mark_issue_uncertain`, `remember_issue_tokens`, `resolve_issue`, `lock`,
  `unlock`, `drop_token`, `retire_for_cleanup`, `done_delete` and usage updates.
- [ ] Never overwrite an open attempt. Preserve attempt resolution evidence,
  generation fingerprints and deletion reason/timestamp after completion.
- [ ] Persist rotation/expiry/cleanup intent before each corresponding DELETE.
  Retiring the current token and clearing its fields must be atomic.
- [ ] Test roundtrip, wrong key, copied ciphertext, transaction boundaries,
  crash recovery of attempts/deletion intent, lock persistence, and absence of
  token plaintext in database/WAL files and audit logs.
- [ ] Enforce exclusive process ownership and reject a second store owner.

### Task 8: broker and leases

Files: `src/netbox_mcp/oidc/broker.py`, `tests/oidc/test_broker.py`.

Interfaces:

```python
class TokenLease:
    lease_id: str
    netbox_user_id: int
    token_id: int
    plaintext: str

class TokenBroker:
    async def token_for(self, ident: Identity) -> TokenLease: ...
    async def lease_for_authenticated_token(self, plaintext: str) -> TokenLease: ...
    async def release(self, lease: TokenLease) -> None: ...
    async def handle_rejection(self, plaintext: str, status: int) -> str: ...
    async def startup_cleanup(self) -> None: ...
    async def reconcile_issues(self) -> None: ...
    async def daily_cleanup(self) -> None: ...
```

- [ ] Use the service credential only for user/token management, through a
  dedicated `NetBoxClient(..., token=<broker>, retry=False)` with
  `use_branch=False` on every call (design section 5). Never reuse the default
  client factory for broker calls.
- [ ] Resolve exactly one active user on first login; subsequent requests follow
  the stored user ID. Deny and audit a first login whose username resolves to a
  user ID already linked to another subject; never relink automatically.
- [ ] Issue the full v2 bearer value, with a 90-day personal token lifetime and
  renewal at 14 days. Check existence and enabled state before expiry decisions.
- [ ] Serialize selection, lease registration, rotation, rejection handling and
  cleanup with one identity lock; do not hold it across the inventory operation.
- [ ] Implement the durable issuance protocol: journal before one POST, complete
  atomically, or preserve uncertainty and return 503. Reconcile exact nonce/user
  matches with pagination; empty searches never authorize another POST.
- [ ] For each discovered orphan, persist the ID before DELETE. Resolve only
  after confirmed cleanup or definitive non-creation evidence.
- [ ] Classify 401 and 403 using the exact generation. Protect the current
  generation from late errors of retired tokens. Never retry the inventory call.
- [ ] Retain each generation until all its leases end. Retry pending deletions
  after release, at startup and during scheduled cleanup.
- [ ] Before idle cleanup of a current generation, inspect token existence and
  enabled state. Persist a new revocation lock if it was already removed/disabled.
  Otherwise persist cleanup intent before deletion; block new issuance until
  that cleanup completes. Failed lookups leave state unchanged.

Required regression scenarios:

| Scenario | Required result |
| --- | --- |
| Two concurrent first logins | One token POST |
| Unknown/inactive/ambiguous user | Denial, no token POST |
| Same subject, renamed account | Same stored NetBox user ID |
| Two subjects claim the same NetBox user | Second link denied and audited, no token POST |
| Username reused after rename by another subject | Denied; first identity keeps its link |
| 429 on the issuance POST | Exactly one POST sent; attempt resolved as not created |
| Branching enabled | No branch lookup and no `X-NetBox-Branch` header on broker calls |
| Deleted or disabled token, including expired | Persistent lock, no replacement |
| Enabled expired token | Controlled replacement on a later request |
| Ordinary permission 403 | Original error, no identity lock |
| Broker lookup failure | Temporary failure, no guessed revocation |
| Late failure of old generation | Current generation unchanged |
| Rotation while a lease is held | No DELETE until final release |
| POST timeout, initial search empty, late commit | No second POST until orphan resolved |
| Crash between POST and storage | Exact nonce recovery |
| Failed orphan DELETE | Attempt stays unresolved |
| Revocation before idle cleanup | Remains locked after cleanup/restart/login |
| Cleanup DELETE committed, response lost | Recorded intent allows recovery from 404 |
| Login while cleanup pending | No premature replacement |
| Duplicate release or canceled release | No negative count or leaked ownership |
| Old authenticated token, client opens after rotation | Select current generation safely |

### Task 9a: server lifespan and background work

Files: `src/netbox_mcp/server.py`, `src/netbox_mcp/oidc/lifecycle.py`,
`tests/oidc/test_lifecycle.py`.

- [ ] Keep module import free of store side effects: building the verifier at
  import time must not open the store, take the lock or start tasks.
- [ ] Pass a `lifespan` to `FastMCP(...)` that, on entry, opens the store, takes
  exclusive ownership, runs startup recovery and reconciliation, attaches the
  broker to the verifier and starts the 60-second reconciliation and daily
  cleanup loops (design section 8, "Server lifecycle").
- [ ] Until the broker is attached, OIDC requests receive 503 with `Retry-After`.
- [ ] On exit, stop new OIDC authentications, cancel and await the loops,
  release outstanding leases within a bounded timeout (audited), then close the
  store and release ownership. Background-loop errors are logged visibly and do
  not stop later scheduled attempts.
- [ ] Verify the lifespan also runs under `fastmcp run` with `fastmcp.json`, not
  only through `main()`.
- [ ] Tests: importing `netbox_mcp.server` does not take the store lock; a second
  lifespan against the same store fails; shutdown while a lease is held waits and
  then releases; a failing loop iteration is followed by the next one; no-OIDC
  configuration starts no broker and no loops.

### Task 9: integrate HTTP authentication and actual client lifetimes

Files: `src/netbox_mcp/oidc/composite.py`, `src/netbox_mcp/oidc/leases.py`,
`src/netbox_mcp/auth.py`, `src/netbox_mcp/netbox_client.py`,
`src/netbox_mcp/server.py`, OIDC integration tests and `tests/test_auth.py`.

- [ ] Build the composite verifier and metadata/challenge responses. Reject bad
  JWTs without passthrough fallback. Preserve NetBox passthrough and its 503 errors.
  With `OIDC_ACCEPT_NETBOX_TOKENS=false`, reject non-JWT bearer values with 401.
- [ ] Install the error handler on the outermost provider's
  `AuthenticationMiddleware` and map the typed errors from Task 6 to 401, 403
  (including `error="insufficient_scope"` in `WWW-Authenticate`) and 503.
  Confirm against the locked FastMCP version which provider's `get_middleware()`
  is used when providers are composed.
- [ ] Use one canonical MCP URL for the metadata resource, configured audience
  and middleware resource. Advertise the design's complete login/refresh scope
  set in initial challenges and resource metadata; enforce the API scope in JWTs.
- [ ] Populate the verified access token as specified in design section 4:
  personal token, stable NetBox user client ID, `expires_at = exp + leeway` and
  the server-owned `netbox_mcp_auth_mode` marker in `claims`, built from verified
  values only. Include any resource field required by the selected auth
  middleware without breaking passthrough.
- [ ] Add an outer ASGI authentication-lease context with cleanup on every exit.
  Treat it as authentication ownership only, not ownership of the SDK tool task.
- [ ] In every OIDC `NetBoxClient.__aenter__`, acquire a separate lease for the
  current generation **before** constructing headers and cache keys. Keep it
  through `__aexit__`. Clean up partial entry and cancellation safely.
- [ ] Distinguish passthrough and explicit broker API clients to avoid recursive
  acquisition. Never let an incoming JWT inject the internal mode marker.
- [ ] Route 401/403 through generation-aware rejection handling using the token
  actually sent. Return useful MCP tool errors without replaying writes.
- [ ] Return HTTP 403 for locked/denied broker identities and 503 with retry
  guidance for dependency/JWKS failures. JWKS failures must not call the broker.
- [ ] Wire the broker from the Task 9a lifespan into the composite verifier and
  the `NetBoxClient` lease path; do not start background work here.
- [ ] Add generic README configuration, privilege/trust-boundary, recovery and
  persistent-volume (runtime UID 10001) documentation, and document NetBox-token
  passthrough as an explicit exception to the MCP no-passthrough rule. No
  concrete deployment inventory belongs in the package.

Integration tests must use the fully wired ASGI application and actual SDK
dispatch, with mocked NetBox/JWKS only:

- [ ] Both metadata routes, 401 challenge, invalid JWT, missing required group
  (403), missing required scope (403 with `insufficient_scope`), ID token (401),
  no-OIDC compatibility and passthrough outage/permission behavior, including
  the passthrough 503 after composition.
- [ ] Token expiry within and beyond the 60-second leeway through the real SDK
  bearer middleware, with an injected clock.
- [ ] A JWT carrying `netbox_mcp_auth_mode` in its claims does not change the
  server-set marker.
- [ ] Accept the correct resource and authorized party. Reject wrong resource,
  client-ID-only audience and wrong `azp` with HTTP 401 and metadata challenge;
  no personal-token issuance on rejection.
  Check exact resource and requested scopes in both metadata and initial challenge.
- [ ] Deletion/deactivation discovered on the first tool call: tool error first,
  HTTP 403 on the next request; exactly one inventory request was sent.
- [ ] Object-permission denial followed by a permitted operation still works.
- [ ] JWKS maximum age exceeded during outage: HTTP 503, no broker call.
- [ ] Rotation while a tool holds a client lease: old token remains usable until
  that client exits. Check the actual NetBox Authorization headers.
- [ ] Real ASGI `http.disconnect` during a stateful tool: HTTP auth lease ends,
  SDK task continues, rotation occurs, subsequent NetBox call still succeeds.
- [ ] Disconnect before the tool opens its client: rotate/delete the old token,
  then open the delayed client and verify it sends the current token.
- [ ] Client entry failure, cancellation, duplicate cleanup and shutdown release
  ownership correctly. Use events to prove the intended interleaving.

Run the existing suite and applicable repository checks: `uv run pytest`,
`uv run ruff check .`, `uv run ruff format --check .`, `uv run ty check .`.

### Task 10: review and publish a container

- [ ] Review the complete implementation diff against the baseline. Resolve
  high-impact findings before publishing a deployable tag.
- [ ] Add a narrowly triggered image workflow that tests before building. Use
  supported action versions pinned to immutable commits and least permissions.
- [ ] Derive the image repository from the repository/workflow configuration;
  avoid embedding a deployment organization in reusable source.
- [ ] Use an explicit pre-release tag convention and deploy immutable digests.
  Disable inherited upstream-only release/package publication workflows in a fork.
- [ ] Scan the public tree, commit history, image context and logs for secrets
  and internal data. Verify intended package visibility and pull behavior.

## Phase C: deployment and operational acceptance

### Task 11: provision the broker credential

- [ ] Implement private deployment automation with plan/snapshot/apply/verify/
  rollback and idempotent resource lookup. Existing valid credentials are reused.
- [ ] Create the service account and exact `add`/`grant`, `view`/`delete` and user
  lookup permissions described in design section 5. Check effective permissions.
- [ ] Generate and inject the broker token directly into the deployment secret
  store; do not print it, commit it or include it in configuration snapshots.
- [ ] From the workload network, prove user lookup succeeds, inventory writes
  fail, and a token for an eligible disposable user can be created and deleted.
  Prove issuance for an ineligible user and use outside allowed source addresses
  fail. Verify the source address NetBox actually observes.
- [ ] Define recovery for credential creation followed by failed secret-store
  persistence, avoiding repeated creation of unmanaged service credentials.

### Task 12: provision the permanent identity provider

- [ ] Apply the measured provider settings: dedicated client, strict callbacks,
  stable subject, signing key, lifetimes, group binding and mapped claims.
- [ ] Before any change, verify the permanent provider runs the Task 0 minimum
  version or later. If it does not, upgrade the provider first as a separate
  change; do not configure the application on an older version.
- [ ] Apply the proven resource binding, native PKCE S256 enforcement, grant
  restrictions and token-endpoint auth methods.
- [ ] Apply and verify the username namespace precondition: no self-service
  username change and no user-chosen names in enrollment. Register the four measured callbacks, including
  the CLI port/path details; verify supported response-issuer behavior.
- [ ] Verify discovery, exact issuer, JWKS and required scopes, including
  advertised `offline_access` and actual refresh-token issuance.
- [ ] Verify actual access tokens contain the expected group/scope/party and
  MCP resource audience, that refresh preserves that contract, and that an ID
  token does not pass the API-token contract.
- [ ] Keep the client secret in approved client/provider configuration only;
  document its rotation process in the private runbook.

### Task 13: deploy the workload

- [ ] Re-verify that the provider still runs the minimum version or later.
- [ ] Snapshot the current workload configuration without disclosing secrets.
- [ ] Configure a persistent store volume writable by the image's runtime UID
  (10001; the image declares no volume), set `TOKEN_STORE_PATH` inside it, inject
  OIDC configuration and secrets, and use the tested digest.
- [ ] Create the encryption key only for a genuinely new store. Preserve it on
  every redeploy and back it up separately through the secret-management process.
- [ ] Enforce one worker/replica and exclusive store ownership. A replacement
  starts after the old owner has stopped; test accidental second-owner refusal.
- [ ] Verify health, existing passthrough tool access, OIDC challenge and audit
  delivery. Keep any delete-tool restrictions until the rights rollout is proven.
- [ ] Document and rehearse image/config rollback while preserving the database,
  encryption key, revocation locks and unresolved issuance records.

### Task 14: expose metadata safely

- [ ] Add only the intended MCP and metadata paths to the existing proxy/edge
  policy. Combine host and path restrictions, including on shared frontends.
- [ ] Verify both metadata routes through internal and external paths; check
  that unrelated paths and unrelated hosts retain their previous behavior.
- [ ] Verify the MCP endpoint on HTTPS port 443 from claude.ai and chatgpt.com,
  and from both direct CLI environments. Verify provider discovery, authorization,
  token and JWKS reachability from their respective consumers; workstation VPN
  reachability alone is insufficient evidence for hosted clients.
- [ ] Roll back exactly the changed routing conditions from the snapshot rather
  than deleting shared rules or DNS records.

### Task 15: pilot and recovery acceptance

- [ ] Complete all four rows of the Task 2 acceptance matrix against the deployed
  workload. For each client, prove tool discovery, read access, a permitted write
  to a disposable object and correct human-user attribution. No client may pass
  using another client's connector or a manually injected personal NetBox token.
- [ ] Repeat login, refresh after access-token expiry without interactive login,
  reconnect/restart and all three IdP-denial cases in each client. Verify the
  actual token-endpoint auth method, resource/audience and scope behavior.
- [ ] Test token deletion, token deactivation and deactivation within the renewal
  window in each client; keep test expiry consistent in NetBox and the broker's
  test record. Verify denial persists after reconnect/refresh and no replacement
  token bypasses the lock. Restore each disposable test identity between cases.
- [ ] In every client, test genuine object denial followed by a permitted
  operation. Capture only safe status/error metadata, never credentials.
- [ ] Verify controlled unlock/retirement and distinguish it from unresolved
  issuance recovery. An unlock must not erase an open issuance attempt.
- [ ] Provide a private runbook for emergency shutdown, broker-token rotation,
  encryption-key rotation, snapshots, restore/reconciliation and pending-issue
  resolution. Include a separate administrator path when the broker is disabled.
- [ ] Exercise SQLite backup/restore using the Python backup API or an explicitly
  provisioned tool. Do not assume a `sqlite3` executable exists in the image.
- [ ] Exercise recovery with a token issued after the backup and a preserved
  revocation lock. Alert on unresolved attempts and repeatedly failing deletions.
- [ ] Confirm the measured identity-provider denial window before broad rollout.

### Task 16: client rollout

- [ ] Have authorized client administrators publish the connector to the intended
  audience after pilot acceptance.
- [ ] Publish user guidance for connecting, first-login prerequisites, permission
  errors, revocation support, personal attribution and existing passthrough use.
- [ ] Include separate setup instructions for claude.ai, Claude Code, chatgpt.com
  and Codex CLI, with tested versions/dates, generic scope/callback examples and
  private secret-storage guidance. Explain the shared registration's rotation
  impact and client-secret limitations on local machines.
- [ ] Record deployment version, validation and ownership in the organization's
  private change/service records, without copying those records into this repository.

## Phase D: optional permissions and endpoint cleanup

### Task 17: separate inventory access from administrative/deletion rights

- [ ] Inventory effective direct and inherited permissions in private records;
  define ordinary and maintainer roles based on the deployment's policy.
- [ ] Prevent ordinary users from modifying users, groups or permissions to
  self-escalate. Review additional actions such as token grants separately from
  basic CRUD. Keep needed read access to audit/change records.
- [ ] Snapshot, apply, synchronize memberships as required by the actual SSO
  integration, and read back effective NetBox permissions.
- [ ] With a non-maintainer test account, deny deletion, self-promotion and
  granting another person's token while preserving permitted reads and personal
  token management. Prove intended maintainer operations on disposable objects.
- [ ] Only then remove the optional MCP delete-tool restriction and verify the
  resulting tool list. Roll back roles and tool exposure together if tests fail.
- [ ] Remove temporary memberships and deactivate disposable test users.

### Task 18: retire obsolete endpoints

- [ ] Confirm clients no longer use an old endpoint before removing its private
  proxy/DNS configuration. Keep this independent of authentication rollout.
- [ ] Snapshot and remove only the obsolete endpoint's resources, then verify
  the permanent endpoint and unrelated applications still work.

## Completion criteria

The work is complete only when package and integration tests pass, all four
named clients pass every pilot acceptance column and the PKCE/resource/issuer
protocol probes pass, revocation/renewal/cleanup races are covered, recovery
has been exercised, and operators have the required private runbooks. Publishing
this plan or building an image alone does not establish production readiness.
