# OIDC token broker implementation plan

Status: proposed work, not an implemented or verified feature.

Design: [OIDC authentication with personal NetBox tokens](../design/oidc-token-broker.md).
Start implementation from upstream `v0.3.0`. Reference API versions and all
security/lifecycle contracts are defined in the design. Keep operational values
and measured integration results in private deployment records.

This plan covers client validation, package implementation, container release,
deployment, recovery and optional permission hardening. It does not depend on
a particular reverse proxy, container manager, DNS service or organization.

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

## Phase A: prove client/provider compatibility

### Task 1: isolated discovery and identity probe

- [ ] Provision a temporary provider/application and dedicated test group with
  two disposable users. Do not reuse a production application for experiments.
- [ ] Create a minimal FastMCP server with remote authentication and a `whoami`
  tool returning selected identity/policy claims, never the bearer token.
- [ ] Require the test group and the intended scope. Configure the scope mapping
  to emit `groups` under the same required scope; verify claim inclusion settings.
- [ ] Expose the temporary MCP route and protected-resource metadata through
  narrowly scoped host **and** path rules. Choose a deployment-specific available
  listener rather than embedding an infrastructure address in the repository.
- [ ] Record exact client callback URLs and register strict redirect matches.
- [ ] Verify unauthenticated 401 challenge, public metadata, issuer discovery,
  ordinary application paths and unrelated-host routing, through both internal
  routing and any external edge. Record the pre-change baseline for rollback.

### Task 2: client and denial matrix

- [ ] For every intended client, connect using its supported fixed-client OAuth
  configuration and prove a successful `whoami` call and refresh after expiry.
- [ ] Record discovery URLs, issuer matching, `aud`, `azp`, `scope`, `groups`,
  `sub`, callback URLs and the handling of the `resource` parameter privately.
- [ ] Check actual ID-token rejection separately from access-token acceptance.
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

### Task 3: tear down the experiment

- [ ] Remove temporary routing, edge exceptions, workload, clients and provider
  objects in dependency order. Retain test identities only if later tests need
  them and keep their access disabled between experiments.
- [ ] Verify restored routing and the unchanged existing MCP service.
- [ ] Store results and the completed cleanup record privately.

### Task 4: architecture gate

- [ ] Confirm the fixed-client design works in all target clients and denial
  times meet the stated policy. Record an explicit deployment-owner decision.
- [ ] If provider behavior changes the design, update this design and plan before
  implementing. Do not proceed with mocks that contradict measured behavior.

## Phase B: package implementation

### Task 5: configuration and dependencies

Files: `pyproject.toml`, `uv.lock`, `src/netbox_mcp/oidc/config.py`,
`src/netbox_mcp/oidc/__init__.py`, `tests/oidc/test_config.py`.

- [ ] Add PyJWT with crypto support and cryptography; regenerate the lockfile.
  Ensure the container's locked dependency installation succeeds.
- [ ] Implement immutable configuration with the required/optional environment
  variables in the design. Validate URLs, key format and incompatible auth modes.
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

def looks_like_jwt(token: str) -> bool: ...

class JwtRejected(Exception): ...
class JwksUnavailable(AuthenticationError): ...

class AuthentikJwtVerifier:
    async def verify(self, token: str) -> Identity: ...
```

- [ ] Implement RS256-only validation with required claims, issuer/audience,
  temporal checks, group, scope, subject/username types and authorized party.
- [ ] Inject wall and monotonic clocks independently. Implement a 300-second
  JWKS maximum age, full key-set replacement, shared concurrent refresh and
  60-second throttling of unknown-key/failed-fetch attempts.
- [ ] Return `JwksUnavailable` when no fresh trusted key set can be obtained;
  never extend cache freshness on failures or accept stale verified JWTs.
- [ ] Cover valid access tokens, ID tokens, missing/malformed claims, expiry,
  future `nbf`, wrong issuer/audience/party/group/scope, HS256/none, foreign
  signature with the same `kid`, and v1/v2 passthrough classification.
- [ ] Cover known-key expiry, removed keys, full replacement versus merge,
  fetch outage at/after 300 seconds, unknown-key throttling and concurrent
  refresh. Removed known keys must fail without restarting the process.

### Task 7: durable encrypted state

Files: `src/netbox_mcp/oidc/store.py`, `tests/oidc/test_store.py`.

- [ ] Implement identity, generation, issuance-attempt and audit tables with the
  fields and uniqueness constraints in design section 6.
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

- [ ] Use the service credential only for user/token management. Resolve exactly
  one active user on first login; subsequent requests follow the stored user ID.
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

### Task 9: integrate HTTP authentication and actual client lifetimes

Files: `src/netbox_mcp/oidc/composite.py`, `src/netbox_mcp/oidc/leases.py`,
`src/netbox_mcp/auth.py`, `src/netbox_mcp/netbox_client.py`,
`src/netbox_mcp/server.py`, OIDC integration tests and `tests/test_auth.py`.

- [ ] Build the composite verifier and metadata/challenge responses. Reject bad
  JWTs without passthrough fallback. Preserve NetBox passthrough and its 503 errors.
- [ ] Populate the verified access token with a personal token, stable NetBox
  user client ID and a server-owned OIDC-mode marker. Include any resource field
  required by the selected auth middleware without breaking passthrough.
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
- [ ] Run startup recovery, reconciliation every 60 seconds and daily cleanup.
  Handle background-loop errors visibly and continue later scheduled attempts.
  Stop/await background work before closing the store and releasing its lock.
- [ ] Add generic README configuration, privilege/trust-boundary and recovery
  documentation; no concrete deployment inventory belongs in the package.

Integration tests must use the fully wired ASGI application and actual SDK
dispatch, with mocked NetBox/JWKS only:

- [ ] Both metadata routes, 401 challenge, invalid JWT, missing required group,
  no-OIDC compatibility and passthrough outage/permission behavior.
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
- [ ] Verify discovery, exact issuer, JWKS and required scopes.
- [ ] Verify actual access tokens contain the expected group/scope/party and
  that an ID token does not pass the API-token contract.
- [ ] Keep the client secret in approved client/provider configuration only;
  document its rotation process in the private runbook.

### Task 13: deploy the workload

- [ ] Snapshot the current workload configuration without disclosing secrets.
- [ ] Configure a persistent store volume with permissions for the image's
  runtime UID, inject OIDC configuration and secrets, and use the tested digest.
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
- [ ] Roll back exactly the changed routing conditions from the snapshot rather
  than deleting shared rules or DNS records.

### Task 15: pilot and recovery acceptance

- [ ] Connect a limited pilot user in each supported client. Prove read access,
  a permitted write to a disposable object, and correct user attribution.
- [ ] Test token deletion, token deactivation and deactivation within the renewal
  window; keep test expiry consistent in NetBox and the broker's test record.
- [ ] Test genuine object denial followed by a permitted operation. Capture only
  safe status/error metadata, never credentials.
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

The work is complete only when package and integration tests pass, each target
client passes the pilot, revocation/renewal/cleanup races are covered, recovery
has been exercised, and operators have the required private runbooks. Publishing
this plan or building an image alone does not establish production readiness.
