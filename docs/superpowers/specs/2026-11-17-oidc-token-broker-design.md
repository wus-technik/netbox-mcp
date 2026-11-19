# OIDC authentication with personal NetBox tokens

Status: **superseded** on 2026-11-18 by
[OAuth authorization server with per-session NetBox tokens](2026-11-18-oauth-authorization-server-design.md).
Kept for its NetBox permission, broker-client and lifecycle analysis.

Former status: proposed design; implementation and integration tests are outstanding.
**Blocked** until a released IdP version provides the features listed under
"Provider prerequisite" below.

Implementation plan: [OIDC token broker implementation](../plans/2026-11-17-oidc-token-broker.md).
Code baseline: upstream `v0.3.0`. The repository lockfile selects FastMCP 4.1.6
and MCP Python SDK 2.3.0. NetBox 4.7.3 is the reference version for the API
contracts below, not an inventory of any deployment. The IdP version the
current behaviour was analysed on does **not** meet the provider prerequisite
and is not a supported target.

All service URLs, account names, group names and deployment paths in examples
are placeholders. No particular organization, infrastructure platform or
existing permission configuration is assumed.

## Provider prerequisite: a released IdP version

**Every implementation step of this design requires a released IdP version
that natively provides both of the following features.** This applies
to the Phase A experiments, the package implementation (Phase B) and every
deployment (Phase C):

1. **Resource indicators (RFC 8707):** the provider accepts `resource` on the
   authorization and token requests, restricts it to configured allowed
   resources, issues the access token with `aud` set to the MCP resource URI, and
   preserves (or only narrows) it on refresh.
2. **Required PKCE with S256 only:** a provider setting that rejects
   authorization requests without a code challenge, for confidential clients as
   well, and disallows `plain`.

Rules:

- **Only a published release counts:** a tagged version with release notes. A
  merged pull request, the `main` branch, a release candidate, a beta or a
  nightly image does not satisfy the prerequisite, and neither does a planned
  milestone (as of 2026-11-17 neither feature was merged in the IdP's upstream).
- **Check before starting work:** before any implementation work begins, check
  that the release contains each feature. Read its release notes and the provider
  settings in its documentation, and confirm the merged pull requests are in
  that release's tag. Record the version and the evidence in the plan.
- **Test the release itself:** Phase A tests must then show that the release
  behaves as required. The release notes alone are not proof.
- **Minimum version:** that release becomes the minimum supported provider
  version. Replace the reference IdP version in this document with it.
- **Every deployment:** check that the production provider runs at least the
  minimum version before deploying, and again before each provider upgrade or
  downgrade.
- **No workarounds:** the following do not replace the native features: token
  exchange, `aud` from a scope mapping, expression policies, a proxy or a patched
  provider build. If a release ships only one of the two features, the
  prerequisite is not met.

## 1. Purpose and boundaries

Allow remote MCP clients to authenticate through an identity provider while
executing every NetBox operation as the corresponding human user. The server
creates and maintains a personal NetBox API token; users do not copy it into
their MCP clients. NetBox permissions and change attribution remain authoritative.

The required clients are **claude.ai, Claude Code, chatgpt.com and Codex CLI**,
using Streamable HTTP at the same HTTPS MCP endpoint. Each uses a pre-registered
OAuth client for the initial integration. Current client capabilities support
this approach; successful operation with the selected provider is still an
integration gate, not an implemented or tested compatibility claim.

Existing NetBox-token passthrough remains available on the same MCP endpoint.
Passthrough is authorized by NetBox, independently of the OIDC application.
Revoking OIDC access does not revoke separately issued NetBox API tokens.

**Compliance exception:** the MCP authorization specification (2025-06-18 and
2025-11-25) forbids accepting and forwarding tokens that were not issued for the
MCP server. NetBox-token passthrough does exactly that. It is an existing,
intentional compatibility mode, not part of the OIDC contract. Document it as an
explicit exception and let operators turn it off while OIDC is enabled
(`OIDC_ACCEPT_NETBOX_TOKENS=false`, default `true`). Never describe a filled
`AccessToken.resource` on a passthrough request as resource binding.

Excluded from the initial implementation:

- Dynamic client registration and an OAuth authorization proxy.
- Automatic creation of NetBox user accounts.
- A browser page for users to submit existing NetBox tokens.
- A shared service token used for ordinary inventory operations.
- Automatic retries of operations with an ambiguous write outcome.

## 2. Architecture

```text
MCP client -- OAuth authorization --> identity provider
MCP client -- Bearer access JWT ---> composite verifier
                                      | validate identity and access policy
                                      v
                                  token broker <--> encrypted SQLite store
                                      | obtain personal token
                                      v
                                  NetBox API (human user's permissions)

MCP client -- Bearer NetBox token --> existing passthrough verifier --> NetBox API
```

The broker has a separate NetBox service credential for user lookup and token
administration. It cannot modify ordinary inventory objects with that credential.

**Trust boundary:** possession of the broker credential allows creating tokens
for the permitted users and therefore acting with their privileges. Encrypting
the token store does not remove this capability. Limit eligible users, restrict
the broker's source address as supported by the deployment, and protect both
the broker credential and encryption key through the deployment's secret store.
Unconstrained token deletion also allows disruption of unrelated credentials;
this is an explicit tradeoff of the proposed cleanup permission.

## 3. Identity provider contract

Example values:

| Setting | Example or initial policy |
| --- | --- |
| Public MCP URL | `https://inventory.example.com/mcp` |
| Issuer | `https://identity.example.com/application/o/inventory-mcp/` |
| Required scope | `netbox-mcp` |
| Required group | `MCPUsers` |
| Signing algorithm | RS256 |
| Access-token lifetime | 10 minutes |
| Refresh-token lifetime | 30 days |

Use a dedicated confidential OAuth/OIDC client. Register exact callback URLs
obtained from each client; do not use wildcard callback matching. Initially one
provider can serve multiple clients, with the operational consequence that a
client-secret rotation affects all of them. Separate providers require an
explicit multi-issuer design and separate identity mappings.

This shared registration is an initial deployment constraint, not client
isolation. CLI users can access a locally stored client secret; possession of
that secret must never authorize a user or replace PKCE, group and token checks.
Enable authorization-code and refresh grants for this registration, and disable
client-credentials, implicit and other unused grants. Splitting registrations
requires an explicit issuer/client allowlist design before deployment; do not
silently broaden the verifier to accept arbitrary clients.

Require authorization-code flow with **PKCE S256**, including for confidential
clients. Discovery must advertise `code_challenge_methods_supported` **including**
`S256`, and the supported `token_endpoint_auth_methods_supported`. With `plain`
disallowed in the native provider setting, discovery is expected to list only
`S256`; record what the minimum release actually advertises. Enforcement is
proven by the negative probes below, not by discovery.

The IdP version analysed for this design advertises `plain` and `S256`,
accepts an authorization request without a challenge, and checks the verifier
only when a challenge was recorded. It cannot meet this requirement. Use the
native PKCE setting of the minimum provider release (see "Provider
prerequisite"), set to require PKCE for all clients with `plain` disallowed. An
expression policy is not an accepted substitute. Record and test the
actual method selected by each client (for example `client_secret_basic` or
`client_secret_post`), both at code exchange and refresh. Reject authorization
without an S256 challenge, an absent or incorrect PKCE verifier, and a code
exchange with a mismatched redirect URI.
Only advertise `authorization_response_iss_parameter_supported: true` when
every authorization response includes the correct issuer; test client rejection
of missing/mismatched response `iss` when this support is advertised.

Assign an application binding for the required group. Configure the
`netbox-mcp` scope mapping to return the `groups` claim itself, so requesting
that scope requests the authorization data. Enable inclusion of mapped claims
in access tokens for the reference provider. The initial requested scope set is
`openid profile email offline_access netbox-mcp`. Advertise these scopes in
discovery and resource metadata, enable refresh-token issuance and verify the
actual scope set requested by every client. Verify actual access and ID tokens;
synthetic claims alone are not an interoperability test.

Use a stable subject mode based on an immutable provider user identifier.
Identity is `(iss, sub)`. At first login, resolve `preferred_username` to exactly
one active NetBox user, then persist the NetBox user ID. Subsequent logins follow
that ID, including after a username change. Missing or ambiguous mappings deny
access; a deleted user must not be reassigned through a reused username.

A unique match proves uniqueness in NetBox, not that the OIDC subject owns the
account. OIDC makes no stability or uniqueness promise for `preferred_username`.
First-login linking is therefore only safe under these preconditions:

- **Operator-controlled namespace (deployment precondition):** only
  administrators can set or change the username claim in the provider. Users must
  not be able to edit their own username (in the IdP: no self-service username
  change in the user settings flow, and no enrollment flow that lets users choose
  a name matching an existing NetBox account). The provider's username and the
  NetBox username must come from the same administered source, for example the
  same directory. Document this as a required deployment setting and verify it in
  Phase A.
- **One identity per NetBox user:** at most one active `(iss, sub)` may link to a
  given NetBox user ID (a store uniqueness constraint, see section 6). A first
  login whose username resolves to a NetBox user already linked to a different
  subject is denied and audited. It is never relinked automatically. Relinking
  (for example after a provider account was recreated) is an explicit
  administrative action that retires the old identity and its tokens first.

The canonical resource identifier is the exact `MCP_PUBLIC_URL`, initially
`https://inventory.example.com/mcp`. Require `OIDC_AUDIENCE` to equal that value;
the access token's `aud` must be that string or a string array containing it.
Validate `azp` separately against `OIDC_CLIENT_ID`, the dedicated registration.
The OAuth client ID is not a substitute for the MCP resource audience.

Verify that authorization and token requests carry the intended `resource` and
that the provider binds the issued access token to it. A different resource must
be rejected or receive a token unusable at this MCP endpoint. Refresh must
preserve the audience and authorized party without broadening scopes. Reject
tokens containing only the client-ID audience, even if their signature, group
and scope are otherwise valid. ID tokens remain intended for the OAuth client
and must not be accepted as MCP access tokens. Section 4 defines the criterion
that tells them apart; Phase A must confirm it with real tokens.

**Authorization-server metadata discovery.** The reference issuer has a path and
a trailing slash. RFC 8414 places metadata at the path-inserted form
`https://identity.example.com/.well-known/oauth-authorization-server/application/o/inventory-mcp/`,
while the analysed IdP serves only the appended OIDC form
`https://identity.example.com/application/o/inventory-mcp/.well-known/openid-configuration`.
Under MCP 2025-11-25, clients try the path-inserted OAuth and OIDC forms first
and the appended OIDC form last. Phase A must record, per client, which URL it
fetched, that it accepted the metadata, and that the returned `issuer` matched
the configured issuer exactly, including the trailing slash.

**Provider gate:** the gate has two stages, and both must pass before the
broker is implemented.

1. **Release check.** Confirm the "Provider prerequisite" (top of this document)
   against a published IdP release.
2. **Behaviour check.** Prove the resource contract and PKCE enforcement with
   real authorization, code-exchange and refresh requests against that release.

A successful login with a client-ID-only audience does not pass this gate.

**Decision (2026-11-17): wait for native support in a released IdP
version.** The released IdP versions available at the time fail the gate, and
neither feature was merged upstream (see "Upstream status" below).
No phase of this plan starts before such a release exists and has passed both
stages.

The following are explicitly not pursued while waiting:

- Switching to a different identity provider.
- Adding an OAuth proxy.
- Building a patched IdP.

Changing that requires a new decision and a revised design.

Also not acceptable as workarounds:

- **IdP token exchange (RFC 8693).** In the analysed IdP its `audience`
  parameter accepts only a target provider's client ID or application UUID, so
  the issued `aud` is a client ID, not the MCP resource URI; `resource` is
  rejected with `invalid_target`.
- **Returning `aud` from a scope mapping.** The same claims feed the ID token, so
  the mapping also overwrites the ID token's `aud` (a confirmed upstream bug in
  the analysed IdP). The
  documented workaround `["<resource>", client_id]` puts the resource into the ID
  token's audience as well, which removes the separation this design relies on.
- **An expression policy enforcing PKCE.** It would emulate the missing provider
  setting without the token-endpoint enforcement and discovery change of the
  native feature.

### Upstream status (analysed IdP, checked 2026-11-17)

At the time of checking, no released version of the analysed IdP contained any
of the items below. This table is a snapshot. It does not prove anything about
a release: the release check in the provider gate decides. Recheck it whenever
a new IdP release appears.

| Topic | Status |
| --- | --- |
| RFC 8707 resource indicators, access-token `aud` = resource | Requested upstream, not released. A proposed change adds `resource` on authorize/token, per-provider allowed resources, `aud` from the grant, and refresh that can only narrow. |
| MCP client support (CIMD, public MCP clients) | Requested upstream, not released; resource indicators are a sub-item. |
| Require PKCE / S256 only | Requested upstream, not released. A draft change adds a PKCE mode (optional / public clients / all) and an option to allow `plain`; discovery would then advertise only S256. |
| RFC 9068 access tokens (`typ: at+jwt`, resource `aud`, `client_id`) | Requested upstream, no change in progress. Access tokens carry no `typ` header today. |
| Scope-mapping `aud` overwrites ID-token `aud` | Confirmed upstream bug, not fixed. |
| Audience for resource-server protection | Closed upstream in favour of the RFC 9068 request; maintainers point to token exchange in the meantime. |

Consequences for this design: no released IdP version meets the
provider prerequisite yet, so implementation is blocked. Of the analysed IdP's
tokens, only the access token carries a `scope` claim, which matches rule 2 of
the ID-token criterion in section 4. Recheck this against the minimum release,
because RFC 8707 support changes the access token's `aud`.

Measure removal from the application binding, removal from the required group,
and account deactivation separately. Acceptance requires denial of newly issued
credentials after the policy change and expiry of existing access within the
access-token lifetime plus the explicit clock tolerance (initially 60 seconds).
If refresh does not enforce this, redesign the access check before rollout;
do not assume UserInfo alone will fix every policy case.

For a binding-denial experiment in the IdP, save the original bindings and
policy mode, use `policy_engine_mode=all`, and add a negated test-user binding
alongside the group binding. In default `any` mode the group could still permit
access. Prove a new authorization fails for the denied test user and succeeds
for a control user before interpreting refresh results. Restore the original
mode and bindings afterward.

### Client setup and acceptance

The following setup requirements were checked against the official client
documentation on 2026-11-17. Recheck them for the versions and workspace policies
used in the pilot. Use each product's direct remote MCP setup; do not count an
imported claude.ai connector in Claude Code as a test of its own OAuth client.

| Client | Registration and connection | Callback requirements |
| --- | --- | --- |
| claude.ai | Custom remote connector; choose the existing/own OAuth client and supply its ID and secret. Allow connections from the hosted service to HTTPS port 443. | Register `https://claude.ai/api/mcp/auth_callback`. |
| Claude Code | Direct HTTP MCP server with `--client-id`, masked `--client-secret` input and `--callback-port`; authenticate with `claude mcp login` or `/mcp`. | Register the exact loopback URI sent by the tested version, normally `http://localhost:PORT/callback`; match the configured listener port. Version 2.1.229 used `127.0.0.1`; 2.1.231 restored `localhost`. |
| chatgpt.com | Custom MCP app/plugin with a predefined OAuth client in an account/workspace that permits the required read and write tools. | Copy the exact redirect from its management page. Depending on issuer support and connection history, it can be `https://chatgpt.com/connector/oauth/{callback_id}` or `https://chatgpt.com/connector_platform_oauth_redirect`. |
| Codex CLI | Direct Streamable HTTP server with `--oauth-client-id` and the pre-registered secret configured privately; authenticate with `codex mcp login`. CLI 0.169.0 exposes the required flags; this is not a tested minimum version. Do not pass the secret with `--oauth-client-secret` on a command line, where it reaches shell history and process listings; set it through a private configuration file or a prompt and record the method used. | Register the callback displayed by `codex mcp add`. Preserve any server-specific callback suffix; configure the listener port separately from the callback URL. |

For Claude Code, choose an available fixed callback port before registering the
URI. For Codex CLI, use `mcp_servers.<name>.oauth.callback_port` (or the global
`mcp_oauth_callback_port`) and the matching saved `oauth.callback_url`; verify
the effective URI after discovery. If choosing variable loopback ports instead,
prove RFC 8252 port handling with the provider while keeping host/path matching
strict. Never solve a callback mismatch with a broad redirect wildcard.

For Codex CLI, persist the requested scopes in `mcp_servers.<name>.scopes`;
`codex mcp login <name> --scopes openid,profile,email,offline_access,netbox-mcp`
can override them for one login. For each other client, record the effective
requested scopes and verify that metadata/configuration yields the same required
authorization and refresh capabilities. Keep secrets in private client storage,
never in checked-in examples, shell transcripts or shared project settings.

Hosted clients need a reachable MCP endpoint and provider discovery/token/JWKS
endpoints; the user's workstation having VPN access is not sufficient. Test from
the actual hosted client and the actual CLI environment, including applicable
workspace permissions, firewall/proxy rules and certificate validation. The
common deployment path is externally reachable HTTPS; provider-specific tunnels
are a separate deployment option and do not establish cross-client reachability.

Each of the four clients must pass its own initial login, tool discovery, read,
permitted disposable write with human attribution, access-token refresh without
interactive login, reconnect/restart, and policy/token-revocation tests. Record
client version or hosted test date, exact callback, scopes, token-endpoint auth
method, resource/audience results and safe evidence in private pilot records.
No client is marked supported until its entire acceptance row passes.

## 4. JWT and HTTP authentication

Enable OIDC only with `MCP_TRANSPORT=http` (Streamable HTTP),
`NETBOX_TOKEN_PASSTHROUGH=true` and complete OIDC configuration. stdio and SSE
are unsupported with OIDC. Reject conflicting static bearer authentication
(`MCP_HTTP_BEARER_TOKEN`) or another transport at startup rather than silently
changing authentication mode.

Exactly three nonempty base64url segments select the JWT path. All other
tokens use existing NetBox passthrough, including legacy alphanumeric tokens
and v2 `nbt_<key>.<token>` values. A rejected JWT never falls back to passthrough.
With `OIDC_ACCEPT_NETBOX_TOKENS=false`, non-JWT bearer values are rejected with
401 instead of being passed through.

Validate RS256, signature, exact issuer, MCP resource audience, expiration,
optional `nbf`, required scope, `azp` equal to `OIDC_CLIENT_ID`, required group
and a nonempty subject/username. Require `exp`, `iss`, `aud` and `sub`; check
claim types before using them.

**Clock tolerance:** one leeway of 60 seconds applies to `exp`, `nbf` and `iat`
in the JWT verifier and to the `expires_at` derived from `exp`. The SDK's bearer
middleware compares `expires_at` without leeway, so set
`expires_at = exp + leeway`. Test both checks with injected clocks through the
real SDK dispatch.

**Access token versus ID token.** An ID token must fail the access-token contract
even when its audience matches. Criterion, in this order:

1. If the JOSE header `typ` is `at+jwt` (RFC 9068), the token is an access token.
   If `typ` is present with any other value except `JWT`, reject it.
2. Otherwise require a `scope` claim (space-separated string) containing the
   required API scope. ID tokens carry no `scope` claim.
3. Reject any token carrying `nonce` or `at_hash`, which are ID-token claims.

Phase A must confirm with real provider tokens that this rule accepts every
access token and rejects every ID token. If the provider's tokens cannot be told
apart this way, update the rule before implementation.

**Typed rejection:**

| Failure | HTTP response |
| --- | --- |
| Malformed, bad signature, wrong issuer/audience/party, expired, ID token, unknown `kid` in a fresh key set | 401 with metadata challenge |
| Valid token without the required scope | 403 with `WWW-Authenticate: Bearer error="insufficient_scope", scope="...", resource_metadata="..."` |
| Valid token, required group missing | 403 |
| Broker denial (locked identity, unknown or conflicting mapping, inactive user) | 403 |
| JWKS beyond maximum age, broker or NetBox dependency outage | 503 with `Retry-After` |

The error handler that renders these responses (today `auth_error_response`,
installed by `NetBoxTokenVerifier.get_middleware()`) must be installed on the
**outermost** provider's `AuthenticationMiddleware`. If the composite verifier
is wrapped in another FastMCP provider, that provider's middleware is the one
used. A regression test must prove the existing passthrough 503 still works
after composition.

**JWKS location.** Fetch JWKS from configured `OIDC_JWKS_URL`. If unset, fetch
the provider configuration from `OIDC_ISSUER` with
`.well-known/openid-configuration` appended (issuer with trailing slash kept,
joined without a double slash). Require the returned `issuer` to equal
`OIDC_ISSUER` exactly, including the trailing slash, and take `jwks_uri` from it.
Discovery failure at startup is fatal; later failures follow the JWKS cache rules
below. Cache keys for at most **300 seconds**, measured with a
monotonic clock. Check age even for a known `kid`. On expiry, wait for a shared
refresh before accepting more tokens. Replace key sets completely; do not
merge removed keys back into the cache.

An unknown `kid` may trigger an extra fetch at most once per 60 seconds. Fetch
failure must not reset cache age. Known keys remain usable only until the
original 300-second limit; beyond it return HTTP 503 with `Retry-After: 60`.
Retry failed fetches at most every 60 seconds. An absent key in a fresh valid
key set is a 401. No verified-JWT cache may outlive the key-cache decision.

Publish protected-resource metadata at both:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-protected-resource/mcp`

Set `resource` to the configured public MCP URL, `authorization_servers` to the
issuer, `bearer_methods_supported` to `["header"]`, and advertise the configured
scopes. Authentication 401 responses include the corresponding
`WWW-Authenticate: Bearer resource_metadata="...",
scope="openid profile email offline_access netbox-mcp"` challenge (one header);
advertise the same requested scope set in resource metadata. Keep the required
API scope separate from OIDC scopes used for login and refresh. Explicit client
scope configuration must include `offline_access` for the refresh acceptance test.

The verified request carries:

```python
AccessToken(
    token=<personal NetBox token>,
    client_id="user:<NetBox user ID>",
    scopes=[],
    expires_at=<JWT exp + leeway>,
    claims={"netbox_mcp_auth_mode": "oidc", "iss": ..., "sub": ...},
)
```

`claims` is built by the server from verified values only; the input JWT's claims
are never copied into it wholesale, so a JWT cannot inject the mode marker.
Passthrough requests carry `netbox_mcp_auth_mode="passthrough"`. If the selected
auth provider enforces a resource field, populate it consistently for both
accepted modes. Confirm the field names against the locked FastMCP version
before implementation. Metadata scopes do not replace the explicit JWT checks.

**JWT library.** Use PyJWT (with `cryptography`), which is already locked as a
transitive dependency of the MCP SDK; declare both directly. FastMCP's own JWT
verifier (joserfc/authlib) is not used because the verifier needs the bounded
JWKS cache, the ID-token rule and typed errors above, which its built-in verifier
does not offer. Two JOSE libraries in the image are an accepted cost; revisit if
FastMCP's verifier gains these hooks.

## 5. NetBox service permissions

Create a dedicated active service user with no administrative role or inherited
inventory permissions. For the example eligible group `MCPUsers`, grant:

| Object type | Actions | Constraint |
| --- | --- | --- |
| `users.token` | `add`, `grant` | `{"user__groups__name": "MCPUsers"}` |
| `users.token` | `view`, `delete` | Unconstrained, for cleanup after group removal |
| `users.user` | `view` | As needed for identity and active-state lookup |

`grant` is the ObjectPermission action; NetBox forms `users.grant_token` from
the action and model. Using `grant_token` as the action would form the wrong
permission. Check effective permissions as well as positive and negative API
probes. Never broaden privileges merely to make a failing probe pass.

The broker token is write-enabled and source-restricted to the deployment's
actual egress address. Determine the address NetBox sees through the deployed
proxy chain. Define its rotation/expiry policy in private deployment settings.
Generated personal tokens use `write_enabled=true`, a 90-day lifetime, and a
description containing the generic prefix `NetBox MCP (OAuth)` plus a unique
issuance nonce. Assemble the full v2 bearer value from the creation response;
store only its encrypted form.

**Broker API client.** Broker calls use a dedicated `NetBoxClient` built with
the broker token and `retry=False`, and every call passes `use_branch=False`.
The default client retries non-idempotent requests on 429
(`src/netbox_mcp/retry.py`), which would send a token-create POST more than once
and break the one-POST-per-journal-entry rule. With branching enabled, the
default would also look up the branch and send `X-NetBox-Branch` with the broker
credential, which lacks those permissions. A 429 on the issuance POST leaves the
attempt in the state its response proves: a 429 response is definitive
non-creation and resolves the attempt without a token.

## 6. Store and issuance state machine

Use SQLite in a persistent volume, WAL mode, transactions, and one process
owning an exclusive store lock. Run one worker/replica. Stop the old owner
before starting its replacement. Missing or invalid encryption keys, corrupt
records, or an already-owned store must fail startup.

The store contains:

- Identity records: issuer, subject, NetBox user ID, observed username, current
  token ID/ciphertext/expiry, creation and last-use times, lock and open attempt.
  `(iss, sub)` is unique. `netbox_user_id` is unique among non-retired identities
  (a partial unique index); a conflicting first-time link fails the transaction
  and is denied, as described in section 3.
- Generations: token ID, identity, fingerprint, current/pending-delete/deleted
  state, deletion reason and intent timestamp.
- Issuance attempts: unique nonce, identity, user ID, start time, state,
  discovered token IDs and resolution evidence.
- Audit events without token plaintext, JWTs or secrets.

Encrypt a JSON envelope with Fernet containing issuer, subject, NetBox user ID,
token ID and full bearer token. Check every identifier against its row when
decrypting. Keep the encryption key outside the database and preserve it on
redeploy. Generation fingerprints and attempt records contain no bearer values.

Serialize operations per `(iss, sub)` with an async lock. At most one open
issuance attempt exists per identity. Persist its nonce **before** the POST;
never overwrite an unresolved attempt or retry that POST automatically.

After a confirmed successful POST, atomically store the new generation and
encrypted token, mark the attempt complete, and retire the old generation with
a recorded rotation deletion intent. Delete retired tokens after their leases
have ended; retain unsuccessful deletions for retry.

A timeout, cancellation after possible send, malformed success response or
5xx leaves issuance unresolved. Return 503 plus `Retry-After` for affected
requests. Reconcile at startup, on the next access, and every 60 seconds by
paging through the target user's tokens and matching the exact recorded nonce
and user ID. Persist discovered IDs before deletion. Empty search results do
not prove that the original POST cannot still commit.

Resolve only after all discovered tokens are confirmed removed, or there is
definitive evidence that no token was created. Keep unresolved attempts across
restarts; neither elapsed time nor an unlock clears them. Manual resolution
requires proof the original server request can no longer commit and a final
search/cleanup. Preserve resolved attempt history for audit and recovery.

**Considered simplification.** The generation, lease and journal machinery in
sections 6–8 exists because tokens rotate while requests may still use them and
because issuance must never duplicate a credential. A simpler lifecycle (never
rotate a token while any request uses it, accept 90-day tokens without renewal,
re-issue only after expiry) would remove most of the lease logic but leaves the
issuance journal necessary. Keep the full design unless the Task 4 gate decides
otherwise; record that decision in the plan before Phase B.

## 7. Revocation, renewal and cleanup

Renew at 14 days remaining. Before replacing an existing token, inspect it
using the broker credential. A missing token or `enabled=false` is revocation,
even when also expired: lock the identity before any expiry handling. Only an
existing enabled token is eligible for automatic renewal/replacement.

NetBox may return **403** for invalid authentication as well as missing object
permissions. For 401/403 on a personal broker-issued token, map its fingerprint
to the exact generation. A failure of an old generation must not lock or drop
the current one. For the current generation:

| Broker lookup result | Behavior |
| --- | --- |
| 404 or disabled | Lock identity; report revocation; no new token |
| Exists, enabled, expired | Retire token; allow replacement on next attempt |
| Exists, enabled, unexpired | Preserve original object/access error; no mutation |
| Lookup failed, including broker 401/403 | Temporary failure; no lock or issuance |

Never repeat the failed inventory operation. When revocation is discovered
inside a tool, return an MCP tool error; subsequent HTTP authentication returns
403. When discovered during authentication/renewal, return 403 immediately.
Passthrough errors retain their existing behavior.

Daily cleanup considers tokens idle for 30 days and users that became inactive.
Under the identity lock, recheck usage, leases and the current token's state.
An already missing or disabled current token without a prior broker deletion
intent is revocation, including when the user made no request after revocation.
A lookup failure leaves the record unchanged.

For an eligible existing enabled token, atomically record cleanup intent and
reason, move it to pending deletion, and clear the current token fields before
DELETE. After timeout/restart, 404 confirms deletion only for a generation
already marked as the broker's own deletion. Login waits for this cleanup to
finish before issuing a replacement. Cleanup must preserve locked identities.

## 8. Token leases and request lifetime

An authentication lease protects the token while an HTTP request authenticates.
An outer ASGI context releases only that lease on completion/disconnect. HTTP
completion is not a guarantee that a stateful MCP tool has finished running.

Every OIDC `NetBoxClient` context therefore acquires its own lease before
building outgoing headers. The verifier sets a server-owned marker
`netbox_mcp_auth_mode="oidc"` in the verified `AccessToken.claims` (section 4);
never copy that marker from an input JWT. The client uses the SDK's request
context to obtain it.

Resolve the authenticated token fingerprint, including retired generations,
to the identity. Recheck the lock, active user and unresolved work; select and
pin the **current** usable generation under the same identity lock. Unknown
mapping denies access. Use the selected token for headers, client cache keys
and rejection handling. This also handles a delayed tool that opens its client
after the HTTP connection ended and an old token was removed by rotation.

Release a client lease only when its actual context exits. Clean up if context
entry fails after acquisition; make release idempotent and cancellation-safe.
The HTTP middleware must not release client leases. Background tasks require
their own client context. Stop/await them before releasing the store lock at
shutdown. Passthrough and explicit internal broker API clients do not acquire
OIDC client leases, avoiding recursive broker acquisition.

**Server lifecycle.** `server.py` builds the auth provider and `FastMCP` at
import time, and `fastmcp run` (via `fastmcp.json`) imports the module without
calling `main()`. Importing the module must therefore have no side effects on the
store: no lock, no recovery, no background tasks. All of that happens in a
`FastMCP(lifespan=...)` context:

1. On entry: open the store and take exclusive ownership, run startup recovery
   and reconciliation, attach the broker to the already constructed verifier,
   start the reconciliation (60 s) and daily cleanup loops, then yield.
2. Until the broker is attached, OIDC requests receive 503.
3. On exit: stop accepting new OIDC authentications, cancel and await the
   background loops, wait for or release outstanding leases (bounded by a
   timeout and audited), then close the store and release ownership.

## 9. Configuration and operational responsibilities

Keep existing behavior when `OIDC_ISSUER` is unset. When configured, require
`OIDC_AUDIENCE`, `OIDC_CLIENT_ID`, `OIDC_REQUIRED_GROUP`, `MCP_PUBLIC_URL`,
`NETBOX_TOKEN_BROKER_TOKEN`, `TOKEN_ENCRYPTION_KEY` and `TOKEN_STORE_PATH`
(example `/data/tokens.db`), plus `MCP_TRANSPORT=http` and
`NETBOX_TOKEN_PASSTHROUGH=true`.
Fail startup unless `OIDC_AUDIENCE` equals the canonical `MCP_PUBLIC_URL` and
`OIDC_CLIENT_ID` is nonempty. Keep the client identity and resource settings
distinct; changing an identifier requires coordinated provider/client rollout.
The store path has no default, so the store never lands silently on ephemeral
container storage. Its parent directory must exist and be writable by the
runtime user; fail startup otherwise.

Optional settings are `OIDC_REQUIRED_SCOPE` (default `netbox-mcp`),
`OIDC_USERNAME_CLAIM` (default `preferred_username`), `OIDC_JWKS_URL` and
`OIDC_ACCEPT_NETBOX_TOKENS` (default `true`). Use generic defaults and no
organization-specific names in package code, class names or published examples.

Settings are read in `netbox_client.py` like the existing ones (an
`OidcConfig` model and `get_oidc_config_from_env()`), so that
`tests/test_settings_documented.py` covers them. Every new variable is documented
in `.env.example` and `README.md`. All OIDC variables are added to
`REGISTRY_EXCLUDED` and not to `server.json`, because the registry manifest
configures a local stdio install.

The image runs as UID 10001 and declares no volume. The deployment must mount a
persistent volume for the store directory, owned by or writable for that UID.

Deployment-specific URLs, object IDs, host addresses, operator identities,
credentials, session links and actual permission inventories belong in private
deployment configuration and operational records.

The deployment must provide durable storage, secret injection, audit collection,
backup/restore, controlled unlock/recovery, key rotation and image rollback.
Protect routing with both host and path conditions. Verify unrelated hosts with
the same paths continue to reach their own applications. Keep metadata public
without exposing unrelated NetBox web/API paths unintentionally.

Backup SQLite through its backup API, including issuance and generation state;
copying a live database file alone is insufficient in WAL mode. Store the
encryption key separately and test recovery in an isolated environment.
Account for tokens issued after the backup: do not restore an old store into
live service without reconciliation and an inventory of affected credentials.

Emergency response stops OIDC entry, disables the broker credential, and
settles any already-running issuance requests. A separate administrative
credential removes all recorded generations and exact nonce matches. Revoking
the broker credential alone does not revoke existing personal tokens.

An optional permission-hardening rollout can separate ordinary inventory users
from maintainers with deletion/admin rights. Audit effective permissions and
prevent self-escalation through user/group/permission administration. Validate
with disposable accounts before removing any MCP delete-tool restriction.

## 10. Reference contracts

- [Claude remote connector setup and network requirements](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
- [Claude Code OAuth credentials and callbacks](https://code.claude.com/docs/en/mcp#use-pre-configured-oauth-credentials)
- [ChatGPT MCP authentication, resource binding and PKCE](https://developers.openai.com/plugins/build/auth)
- [Codex CLI MCP registration, callbacks and scopes](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [ChatGPT custom MCP setup and workspace requirements](https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt)
- [NetBox token model](https://github.com/netbox-community/netbox/blob/v4.7.3/netbox/users/models/tokens.py)
- [NetBox token serializer](https://github.com/netbox-community/netbox/blob/v4.7.3/netbox/users/api/serializers_/tokens.py)
- [NetBox grant constraint evaluation](https://github.com/netbox-community/netbox/blob/v4.7.3/netbox/users/utils.py)
- [NetBox permission naming](https://github.com/netbox-community/netbox/blob/v4.7.3/netbox/netbox/authentication/__init__.py)
- [NetBox authentication settings](https://github.com/netbox-community/netbox/blob/v4.7.3/netbox/netbox/settings.py)
- [DRF 401/403 behavior](https://www.django-rest-framework.org/api-guide/authentication/#unauthorized-and-forbidden-responses)
- [MCP session lifetime](https://github.com/modelcontextprotocol/python-sdk/blob/v2.3.0/src/mcp/server/streamable_http_manager.py)
- [MCP HTTP transport](https://github.com/modelcontextprotocol/python-sdk/blob/v2.3.0/src/mcp/server/streamable_http.py)
