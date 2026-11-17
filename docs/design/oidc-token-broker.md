# OIDC authentication with personal NetBox tokens

Status: proposed design; implementation and integration tests are outstanding.

Implementation plan: [OIDC token broker implementation](../plans/oidc-token-broker.md).
Code baseline: upstream `v0.3.0`. The repository lockfile selects FastMCP 4.1.6
and MCP Python SDK 2.3.0. NetBox 4.7.3 and Authentik 2026.8.5 are reference
versions for the API contracts below, not an inventory of any deployment.

All service URLs, account names, group names and deployment paths in examples
are placeholders. No particular organization, infrastructure platform or
existing permission configuration is assumed.

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
clients. Discovery must advertise `code_challenge_methods_supported: ["S256"]`
and the supported `token_endpoint_auth_methods_supported`. Record and test the
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
and must not be accepted as MCP access tokens.

**Provider gate:** do not assume the reference Authentik version can implement
this resource contract. Prove it with real authorization, exchange and refresh
requests before implementing the broker. If it cannot, stop Phase A and revise
the provider integration or architecture. An OAuth proxy remains outside the
initial scope; introducing one requires a revised design. A successful login
with a client-ID-only audience does not pass this gate.

Measure removal from the application binding, removal from the required group,
and account deactivation separately. Acceptance requires denial of newly issued
credentials after the policy change and expiry of existing access within the
access-token lifetime plus the explicit clock tolerance (initially 60 seconds).
If refresh does not enforce this, redesign the access check before rollout;
do not assume UserInfo alone will fix every policy case.

For a binding-denial experiment in Authentik, save the original bindings and
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
| Codex CLI | Direct Streamable HTTP server with `--oauth-client-id` and the pre-registered secret configured privately; authenticate with `codex mcp login`. CLI 0.169.0 exposes the required flags; this is not a tested minimum version. | Register the callback displayed by `codex mcp add`. Preserve any server-specific callback suffix; configure the listener port separately from the callback URL. |

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

Enable OIDC only with HTTP token passthrough and complete OIDC configuration.
Reject conflicting static bearer authentication or unsupported transports at
startup rather than silently changing authentication mode.

Exactly three nonempty base64url segments select the JWT path. All other
tokens use existing NetBox passthrough, including legacy alphanumeric tokens
and v2 `nbt_<key>.<token>` values. A rejected JWT never falls back to passthrough.

Validate RS256, signature, exact issuer, MCP resource audience, expiration,
optional `nbf`, required scope, `azp` equal to `OIDC_CLIENT_ID`, required group
and a nonempty subject/username. Require `exp`, `iss`, `aud` and `sub`; check
claim types before using them. An ID token
must fail the access-token contract even when its audience matches.

Fetch JWKS from configured `OIDC_JWKS_URL`, or discover `jwks_uri` through the
configured issuer. Cache keys for at most **300 seconds**, measured with a
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

The verified request carries `AccessToken(token=<personal NetBox token>,
client_id="user:<NetBox user ID>", scopes=[])`. If the selected auth provider
enforces a resource field, populate it consistently for both accepted modes.
Metadata scopes do not replace the explicit JWT checks. Preserve existing
passthrough availability errors and ensure the chosen FastMCP middleware can
return 403 for broker denials and 503 for dependency outages.

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

## 6. Store and issuance state machine

Use SQLite in a persistent volume, WAL mode, transactions, and one process
owning an exclusive store lock. Run one worker/replica. Stop the old owner
before starting its replacement. Missing or invalid encryption keys, corrupt
records, or an already-owned store must fail startup.

The store contains:

- Identity records: issuer, subject, NetBox user ID, observed username, current
  token ID/ciphertext/expiry, creation and last-use times, lock and open attempt.
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
`netbox_mcp_auth_mode="oidc"` on the verified `AccessToken`; never copy that marker
from an input JWT. The client uses the SDK's request context to obtain it.

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

## 9. Configuration and operational responsibilities

Keep existing behavior when `OIDC_ISSUER` is unset. When configured, require
`OIDC_AUDIENCE`, `OIDC_CLIENT_ID`, `OIDC_REQUIRED_GROUP`, `MCP_PUBLIC_URL`,
`NETBOX_TOKEN_BROKER_TOKEN` and `TOKEN_ENCRYPTION_KEY`.
Fail startup unless `OIDC_AUDIENCE` equals the canonical `MCP_PUBLIC_URL` and
`OIDC_CLIENT_ID` is nonempty. Keep the client identity and resource settings
distinct; changing an identifier requires coordinated provider/client rollout.

Optional settings are `OIDC_REQUIRED_SCOPE` (default `netbox-mcp`),
`OIDC_USERNAME_CLAIM` (default `preferred_username`), `OIDC_JWKS_URL`, and
`TOKEN_STORE_PATH` (example `/data/tokens.db`). Use generic defaults and no
organization-specific names in package code or published examples.

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
- [Authentik scope mapping evaluation](https://github.com/goauthentik/authentik/blob/version/2026.8.5/authentik/providers/oauth2/views/userinfo.py)
- [Authentik policy modes](https://github.com/goauthentik/authentik/blob/version/2026.8.5/authentik/policies/models.py)
- [Authentik policy evaluation](https://github.com/goauthentik/authentik/blob/version/2026.8.5/authentik/policies/engine.py)
- [MCP session lifetime](https://github.com/modelcontextprotocol/python-sdk/blob/v2.3.0/src/mcp/server/streamable_http_manager.py)
- [MCP HTTP transport](https://github.com/modelcontextprotocol/python-sdk/blob/v2.3.0/src/mcp/server/streamable_http.py)
