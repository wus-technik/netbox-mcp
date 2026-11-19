# OAuth Authorization Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** netbox-mcp becomes its own OAuth authorization server for remote MCP clients, logs users in through an OIDC IdP, and runs every tool call with a personal per-session NetBox token. Tool results are made ChatGPT-compatible first.

**Architecture:** Own Starlette routes (AS, metadata, login flow) mounted next to `mcp.http_app()` in an outer app built by `main()`. A `TokenVerifier` maps the server's HS256 access JWT to a session in an encrypted single-file store and hands the session's NetBox token to the unchanged tools. A broker client with a NetBox service credential creates, renews and deletes the personal tokens; background jobs handle cleanup, recovery and the daily NetBox check.

**Tech Stack:** Python 3.11+, FastMCP 4.1.6 (`JWTIssuer`, `TokenVerifier`, `http_app`), MCP SDK 2.3.0, Starlette, httpx2, `cryptography` (AES-GCM), PyJWT for IdP ID tokens (already locked), pytest + pytest-asyncio.

**Spec:** [`docs/superpowers/specs/2026-11-18-oauth-authorization-server-design.md`](../specs/2026-11-18-oauth-authorization-server-design.md). The spec is authoritative; section references (§) point there. Behaviour the spec leaves open follows the reference implementation named in spec §1.

## Global Constraints

- `MCP_PUBLIC_URL` is issuer and resource on every metadata path; https only (http only for a loopback host), no query/fragment/userinfo/trailing slash.
- Single resource scope `netbox`; `/authorize` ignores requested scopes; no root `/.well-known/openid-configuration`.
- Access token: HS256 via `JWTIssuer`, 3600 s, claims `iss`=`aud`=`MCP_PUBLIC_URL`, `sub`, `sid`, `client_id`, `scope`, `jti`.
- Refresh token: ≥ 256 bit random, base64url, stored only as SHA-256; rotated on every use; sliding 30 days; replay slot 30 s strict `<`; any other reuse of a spent token ends the session.
- Authorization code: ≥ 256 bit, 5 minutes, hash only, burned on first attempt; reuse → `invalid_grant`, session stays.
- Flow cookie: `HttpOnly; Secure; SameSite=Lax; Path=<base path>/oauth`, 10 minutes. Never `Strict`.
- NetBox personal token: `write_enabled=true`, 7 days, renew below 2 days, description `NetBox MCP (OAuth) <client_name> <sid[:8]> <nonce>`; service client `retry=False`, `use_branch=False`; token POST never retried.
- pending-create marker: removed in the same write that stores the token; recovery never touches a marker younger than 10 minutes.
- Orphan session (code not exchanged): ends after 10 minutes. Registrations unused 30 days without sessions expire.
- IdP check on **every** refresh; rejected → `invalid_grant` + session end; unavailable → 503 `temporarily_unavailable`, previous refresh token stays valid.
- Store: one AES-256-GCM file at `OAUTH_STATE_PATH`; tmp + fsync + rename + dir fsync; exclusive OS lock; missing/unreadable/undecryptable → refuse to start; created only by `netbox-mcp oauth init`.
- A response that depends on a state change is sent only after the store write succeeded; failed write → 503.
- No plaintext tokens, codes, cookies, refresh tokens or query strings in logs; uvicorn access log off in OAuth mode.
- OAuth mode (`OIDC_ISSUER` set) requires `MCP_TRANSPORT=http` and excludes `NETBOX_TOKEN_PASSTHROUGH` and `MCP_HTTP_BEARER_TOKEN`; only via `netbox-mcp` entry point, `fastmcp run` refused.
- Generic code: no IdP product names in package code, names or examples. Public repo: no real names, hosts or IDs in fixtures, tests or docs.
- Commit messages in English, conventional prefix (`feat(oauth): …`), no AI co-author trailer, author `foellmann@wus-technik.com`.

## Review Focus

1. **A client retries a refresh after a network timeout while the first request is still running** → both get the same token pair; the session survives (Task 11 test `test_refresh_concurrent_duplicate_gets_replay`).
2. **The store write fails mid-refresh (disk full, permission) and the server restarts** → the client's previous refresh token still works; nothing half-written (Task 11 test `test_refresh_write_failure_keeps_previous_token`).
3. **NetBox renews the session token while a long tool call is in flight and the old token is deleted** → the call retries once with the new token, the session lives (Task 12 test `test_superseded_token_retries_once`).
4. **NetBox answers the token POST with a login page or times out** → login ends with an error page, no session, the marker is recovered later and any created token deleted (Task 9 test `test_create_token_ambiguous_keeps_marker`, Task 13 test `test_recovery_deletes_matching_token`).
5. **The user deletes the MCP token in their NetBox profile** → next tool call returns a tool error, next HTTP request 401 with the challenge, no cleanup loop (Task 12 test `test_deleted_token_ends_session`).

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/netbox_mcp/tools/common.py` | (modify) result shaping helpers for structured output |
| `src/netbox_mcp/tools/*.py` | (modify) return annotations / wrapping per tool |
| `src/netbox_mcp/oauth/__init__.py` | package marker, `OAUTH_AUTH_MODE = "oauth"` |
| `src/netbox_mcp/oauth/config.py` | `OAuthConfig`, `get_oauth_config_from_env()`, validation |
| `src/netbox_mcp/oauth/state.py` | pydantic state schema |
| `src/netbox_mcp/oauth/store.py` | encrypted file store, lock, `mutate()` |
| `src/netbox_mcp/oauth/redirects.py` | redirect URI validation and matching |
| `src/netbox_mcp/oauth/tokens.py` | access JWT issue/verify, random secrets, hashing |
| `src/netbox_mcp/oauth/metadata.py` | metadata documents, discovery routes, 401 challenge |
| `src/netbox_mcp/oauth/idp.py` | OIDC login client: discovery, code exchange, ID token, userinfo, refresh, classification |
| `src/netbox_mcp/oauth/broker.py` | NetBox service-credential client: user lookup, token create/get/list/delete |
| `src/netbox_mcp/oauth/sessions.py` | `SessionManager`: links, sessions, codes, renewal, end, cleanup, recovery, locks |
| `src/netbox_mcp/oauth/routes.py` | Starlette handlers: register, authorize, callback, consent, token, revoke |
| `src/netbox_mcp/oauth/verifier.py` | `OAuthTokenVerifier(TokenVerifier)` |
| `src/netbox_mcp/oauth/app.py` | outer app, lifespan composition, request-order middleware |
| `src/netbox_mcp/oauth/jobs.py` | background loops (cleanup hourly, daily NetBox check) |
| `src/netbox_mcp/oauth/cli.py` | `netbox-mcp oauth init|unlink|restore-reset|sweep` |
| `tests/oauth/__init__.py`, `tests/oauth/fakes.py` | `FakeIdP`, store/clock helpers; reuse `FakeNetBox` from `tests/conftest.py` |

Test command throughout: `uv run pytest <path> -v`. Before each commit also `uv run ruff check src tests && uv run ruff format --check src tests`.

---

## Phase 1 – ChatGPT-compatible tool results (spec §7.6)

### Task 1: Structured output for every tool

**Files:**
- Modify: `src/netbox_mcp/tools/common.py` (add `as_object`, `CONTENT_KEY_RENAME`)
- Modify: every tool in `src/netbox_mcp/tools/{objects,writes,extras,capacity,branching,actions}.py` without `-> dict`
- Test: `tests/test_tool_results.py`

**Interfaces:**
- Produces: `as_object(value: Any, *, key: str = "results") -> dict` — returns dicts unchanged, wraps lists/scalars as `{key: value}`; `rename_content_keys(value: Any) -> Any` — recursively renames dict keys `content` → `CONTENT_KEY_RENAME` (`"content_value"`, final name chosen after the survey in Step 1 and documented in README).

- [ ] **Step 1: Survey NetBox payloads for `content` keys** — grep the NetBox 4.7 OpenAPI schema (or fixtures in `tests/`) for properties named `content`; record the affected object types in the README section "Tool results" (draft) and pick the rename target.
- [ ] **Step 2: Write the failing tests**

```python
@pytest.mark.parametrize("tool", ALL_TOOL_NAMES)  # from mcp.list_tools()
async def test_every_tool_has_object_output_schema_or_none(tool): ...
    # schema is None (text-only) or schema["type"] == "object"; title and annotations set

async def test_list_tool_structured_content_is_object(client, fake_netbox):
    result = await client.call_tool("netbox_list_object_types", {})
    assert isinstance(result.structured_content, dict)
    assert json.loads(result.content[0].text) == <unchanged previous data>

async def test_no_content_key_in_structured_content(client, fake_netbox):
    # fake object containing {"content": "x"} in a nested field
    assert "content" not in json.dumps(result.structured_content)  # key-level check helper

async def test_tool_error_is_is_error(client, fake_netbox): ...  # result.is_error is True
async def test_unknown_tool_is_invalid_params(client): ...       # McpError code -32602
```

- [ ] **Step 3: Run tests, expect FAIL** (`uv run pytest tests/test_tool_results.py -v`).
- [ ] **Step 4: Implement** — annotate every tool `-> dict`, wrap list/Any returns with `as_object`, apply `rename_content_keys` where NetBox objects are returned; text content keeps the unchanged data (FastMCP serialises the dict; if the text must stay a bare list for list tools, return `ToolResult(content=..., structured_content=...)`). Verify unknown tool → -32602 with FastMCP's behaviour; add handling only if it differs.
- [ ] **Step 5: Run the full suite** `uv run pytest -v`, expect all 302+ tests PASS (update assertions only where the envelope legitimately changed, never weaken them).
- [ ] **Step 6: Commit** `feat(tools): return structured object results compatible with ChatGPT`

---

## Phase 2 – OAuth foundations

### Task 2: OAuth configuration and startup rules

**Files:**
- Create: `src/netbox_mcp/oauth/__init__.py`, `src/netbox_mcp/oauth/config.py`
- Modify: `src/netbox_mcp/auth.py:333-371` (`build_auth_provider` rejects combinations), `.env.example`, `README.md`, `tests/test_settings_documented.py` (`SOURCES` += `oauth/config.py`, `REGISTRY_EXCLUDED` += all new vars)
- Test: `tests/oauth/test_config.py`

**Interfaces:**
- Produces: `class OAuthConfig(BaseModel)` with fields `public_url: str`, `issuer_url: str`, `client_id: str`, `client_secret: SecretStr`, `allowed_groups: list[str]`, `username_claim: str = "preferred_username"`, `groups_claim: str = "groups"`, `extra_scopes: list[str] = []`, `broker_token: SecretStr`, `signing_key: SecretStr`, `state_key: bytes` (32), `state_path: Path`, `extra_redirect_uris: list[str] = []`, `extra_origins: list[str] = []`, `user_denylist: set[str] = set()`, `auth_debug: bool = False`; property `base_path: str` (path of `public_url`, e.g. `/mcp`).
- Produces: `get_oauth_config_from_env() -> OAuthConfig | None` (None when `OIDC_ISSUER` unset; raises `ValueError` with the variable name on missing/invalid values).
- Env names exactly: `OIDC_ISSUER`, `MCP_PUBLIC_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ALLOWED_GROUPS`, `OIDC_USERNAME_CLAIM`, `OIDC_GROUPS_CLAIM`, `OIDC_EXTRA_SCOPES`, `NETBOX_TOKEN_BROKER_TOKEN`, `OAUTH_SIGNING_KEY`, `OAUTH_STATE_KEY`, `OAUTH_STATE_PATH`, `EXTRA_REDIRECT_URIS`, `EXTRA_ORIGINS`, `NETBOX_USER_DENYLIST`, `AUTH_DEBUG`.

- [ ] **Step 1: Write failing tests**: `test_unset_issuer_returns_none`; `test_missing_required_var_names_it` (parametrized over the 9 required); `test_public_url_rules` (rejects `http://example.com/mcp`, `…/mcp/`, `…?a=1`, `…#x`, `https://u@host/mcp`; accepts `http://127.0.0.1:8000/mcp`); `test_signing_key_min_32_bytes`; `test_state_key_must_be_32_bytes_base64`; `test_state_path_parent_must_exist`; `test_oauth_excludes_passthrough_and_static_bearer` (ValueError from `build_auth_provider`); `test_oauth_requires_http_transport`.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** using the existing `env_*` helpers from `utils.py`; IdP https check happens later at discovery (Task 6).
- [ ] **Step 4: Run** `tests/oauth/test_config.py tests/test_settings_documented.py`, expect PASS.
- [ ] **Step 5: Commit** `feat(oauth): add OAuth configuration and mode rules`

### Task 3: Encrypted state store

**Files:**
- Create: `src/netbox_mcp/oauth/state.py`, `src/netbox_mcp/oauth/store.py`
- Test: `tests/oauth/test_store.py`

**Interfaces:**
- Produces (`state.py`, pydantic models, all timestamps `float` epoch seconds):
  - `Client(client_id, client_name, redirect_uris: list[str], created_at, last_used_at)`
  - `Grant(user_key, client_id, created_at)` keyed `f"{user_key}|{client_id}"`
  - `Flow(flow_id, client_id, redirect_uri, state, code_challenge, resource, idp_state, idp_nonce, idp_verifier, created_at, claimed: bool, user_key|None, idp_refresh_token|None, …)`
  - `Link(user_key, iss, sub, netbox_user_id, netbox_username, created_at)` — `user_key = f"{iss}|{sub}"`
  - `Session(sid, user_key, client_id, netbox_user_id, created_at, code_hash|None, code_expires_at|None, code_redeemed: bool, refresh_hash|None, spent_hashes: list[str], replay: Replay|None, refresh_deadline, idp_refresh_token, last_idp_check_at, netbox_token: str, netbox_token_id: int, netbox_token_expires_at, token_version: int)`
  - `Replay(hash, rotated_at, response: dict)`
  - `PendingCreate(nonce, netbox_user_id, sid, created_at)`
  - `CleanupEntry(entry_id, netbox_token_id, netbox_user_id, reason, created_at, last_attempt_at|None, warned_at|None)`
  - `OAuthState(version: int = 1, clients, grants, flows, links, sessions, pending, cleanup)` — dicts keyed by ID.
- Produces (`store.py`): `class StateStore` with `StateStore.open(path: Path, key: bytes) -> StateStore` (takes OS lock, loads, raises `StoreError` on missing/unreadable/undecryptable/schema-invalid/locked), `StateStore.create(path, key) -> None` (writes empty state; refuses if file exists), `snapshot() -> OAuthState` (deep copy), `async mutate() -> AsyncContextManager[OAuthState]` (serialized; on clean exit encrypts and writes atomically, on exception or write error discards changes and raises `StoreWriteError`), `close()`.
- File format: `b"NBMCPOA1" + nonce(12) + AESGCM(key).encrypt(nonce, json, aad=b"netbox-mcp-oauth-state-v1")`. Lock: `fcntl.flock`/`msvcrt.locking` on `<path>.lock`.

- [ ] **Step 1: Failing tests**: `test_create_then_open_roundtrip`; `test_open_missing_file_raises`; `test_create_refuses_existing`; `test_wrong_key_raises`; `test_corrupt_file_raises`; `test_schema_invalid_raises`; `test_second_open_is_locked`; `test_mutate_exception_discards`; `test_write_failure_raises_and_keeps_old_file` (monkeypatch `os.replace` to raise; on-disk content and in-memory state stay the previous version); `test_write_is_atomic_tmp_in_same_dir` (assert tmp path parent == state parent, fsync called on file and dir via monkeypatch spies).
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** Directory fsync is skipped on Windows (no-op), tested only on POSIX (`pytest.mark.skipif`).
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat(oauth): add encrypted single-file state store`

### Task 4: Redirect URIs, tokens and metadata

**Files:**
- Create: `src/netbox_mcp/oauth/redirects.py`, `src/netbox_mcp/oauth/tokens.py`, `src/netbox_mcp/oauth/metadata.py`
- Test: `tests/oauth/test_redirects.py`, `tests/oauth/test_tokens.py`, `tests/oauth/test_metadata.py`

**Interfaces:**
- `validate_registered_uri(uri: str, extra: list[str]) -> str | None` — returns an error message or None; rules of spec §5.2 (≤ 2048 chars, loopback literal `localhost`/`127.0.0.1`, claude.ai/claude.com callback, chatgpt `connector_platform_oauth_redirect` and `connector/oauth/[A-Za-z0-9_-]{1,128}`, exact extras; rejects whitespace, `\`, control chars, userinfo/`@`, raw or `%2e` dot segments, fragments, non-http(s), reserved params `iss|code|state|error*` case-insensitive).
- `matches_registered(uri: str, registered: list[str]) -> bool` — exact, loopback port may differ.
- `new_secret() -> str` (32 random bytes base64url), `hash_secret(value: str) -> str` (SHA-256 hex).
- `class AccessTokens` with `__init__(config: OAuthConfig)`, `issue(sid: str, user_key: str, client_id: str) -> tuple[str, int]` (token, expires_in=3600), `verify(token: str) -> dict` (raises `InvalidToken`; requires HS256, iss, aud, exp, sid, client_id; uses `JWTIssuer.verify_token`).
- `protected_resource_metadata(config) -> dict`, `authorization_server_metadata(config) -> dict`, `challenge_header(config, *, invalid_token: bool) -> str`, `metadata_routes(config) -> list[Route]` (exact paths of spec §5.1, no root `openid-configuration`), `ROOT_ALIAS_PATHS = ("/register", "/authorize", "/token", "/revoke", "/oauth/revoke")`.

- [ ] **Step 1: Failing tests**:
  - `test_allowlist_accepts` (parametrized: `http://localhost:53111/callback`, `http://127.0.0.1:1/cb`, `https://claude.ai/api/mcp/auth_callback`, `https://claude.com/api/mcp/auth_callback`, `https://chatgpt.com/connector_platform_oauth_redirect`, `https://chatgpt.com/connector/oauth/abc_123-X`).
  - `test_allowlist_rejects` (parametrized: `http://[::1]:5/cb`, `http://LOCALHOST:5/cb`, `https://chatgpt.com/connector/oauth/a/b`, `https://evil.example/cb`, `…?iss=x`, `…?Code=x`, `…?error_description=x`, `…#f`, `http://u@localhost:5/cb`, `http://localhost:5/a/%2e%2e/b`, `javascript:x`, a 2049-char URI).
  - `test_loopback_port_may_differ_only_port`.
  - `test_access_token_claims` (decode: iss, aud, sub, sid, client_id, scope == "netbox", exp − iat == 3600).
  - `test_verify_rejects_wrong_aud_alg_none_expired_missing_sid`.
  - `test_all_discovery_paths_identical` (TestClient over `metadata_routes`; the 3 PRM paths return one document, the 5 AS paths another; `/.well-known/openid-configuration` → 404).
  - `test_as_metadata_values` (issuer == resource == public_url; endpoints `<base>/oauth/{register,authorize,token,revoke}`; `scopes_supported == ["netbox"]`; `code_challenge_methods_supported == ["S256"]`; `token_endpoint_auth_methods_supported == ["none"]`; `authorization_response_iss_parameter_supported is True`).
  - `test_challenge_header_exact`: `'Bearer realm="https://inventory.example.com/mcp", resource_metadata="https://inventory.example.com/mcp/.well-known/oauth-protected-resource", scope="netbox"'`; with `invalid_token=True` additionally `error="invalid_token"`.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** Reuse `fastmcp.server.auth.redirect_validation.is_loopback_host` only for literal hosts check if it fits; otherwise own code.
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat(oauth): add redirect validation, access tokens and metadata`

### Task 5: Test fakes

**Files:**
- Create: `tests/oauth/__init__.py`, `tests/oauth/fakes.py`, `tests/oauth/conftest.py`
- Test: `tests/oauth/test_fakes.py`

**Interfaces:**
- Produces `FakeIdP` (Starlette app + `httpx2.MockTransport`): issuer `https://idp.example.com/application/o/test/` (path, trailing slash), discovery, authorize (auto-approve configured user), token (code + refresh with rotation; settable responses per status: 400, 401, 403, 429, 503, timeout, HTML 200, missing refresh_token), userinfo (`sub`, `preferred_username`, `groups`; settable 401 / no groups / other `sub`), JWKS, RS256 ID token with `aud` = client ID. Users `alice` (group `netbox-users`), `bob` (no group), `carol` (group, no NetBox account).
- Produces fixtures: `oauth_config` (`OAuthConfig` with example values, `state_path` in `tmp_path`), `store` (created + opened), `clock` (patchable `now()` used via `netbox_mcp.oauth.tokens.now`), `fake_idp`, `fake_netbox` (existing `FakeNetBox`, extended with `/api/users/users/`, `/api/users/tokens/` CRUD including v2 `nbt_` key/token in create response).

- [ ] **Step 1: Write `test_fake_idp_code_and_refresh_rotation` and `test_fake_netbox_token_crud`.**
- [ ] **Step 2–4: Implement fakes until both pass.**
- [ ] **Step 5: Commit** `test(oauth): add fake IdP and NetBox token API`

### Task 6: OIDC login client

**Files:**
- Create: `src/netbox_mcp/oauth/idp.py`
- Test: `tests/oauth/test_idp.py`

**Interfaces:**
- Consumes: `OAuthConfig`, `FakeIdP`.
- Produces: `class IdpClient` with `__init__(config, transport: httpx2.AsyncBaseTransport | None = None)`, `async discover() -> None` (fetch `<issuer>.well-known/openid-configuration`, issuer must match exactly incl. trailing slash, all endpoints https; failure raises `IdpUnavailable` at startup), `authorization_url(state: str, nonce: str, verifier: str, redirect_uri: str) -> str` (PKCE S256, scopes `openid profile email offline_access` + extras), `async exchange_code(code, verifier, redirect_uri, nonce) -> IdpLogin` (`IdpLogin(sub, username, groups: list[str], refresh_token)`; validates ID token RS256/iss/aud/nonce/exp/sub/username claim, requires access and refresh token, userinfo `sub` == ID-token `sub`, groups list required), `async check(refresh_token: str, expected_sub: str) -> IdpCheck` (`IdpCheck(refresh_token, groups)`; rotated refresh token returned or old kept), exceptions `IdpRejected(reason: str)` and `IdpUnavailable(reason: str)`. No redirect following.
- Classification exactly per spec §6.4: refresh 400/401 or no `access_token` → rejected; userinfo 401, no group array, `sub` mismatch → rejected; 3xx/403/429/5xx/timeout/non-JSON/JWKS failure → unavailable.

- [ ] **Step 1: Failing tests**: `test_discovery_issuer_exact_trailing_slash`; `test_discovery_rejects_http_endpoint`; `test_exchange_code_happy`; `test_exchange_requires_refresh_token`; `test_id_token_wrong_nonce_rejected`; `test_userinfo_sub_mismatch_rejected`; `test_check_classification` (parametrized over the fake's status settings → `IdpRejected` / `IdpUnavailable`); `test_check_keeps_old_refresh_token_when_none_returned`; `test_no_redirect_following` (fake returns 302 → `IdpUnavailable`).
- [ ] **Step 2–4: Run FAIL, implement with PyJWT `PyJWKClient`-equivalent over httpx2 (cache keys 300 s), run PASS.**
- [ ] **Step 5: Commit** `feat(oauth): add OIDC login client with check classification`

### Task 7: NetBox broker client

**Files:**
- Create: `src/netbox_mcp/oauth/broker.py`
- Test: `tests/oauth/test_broker.py`

**Interfaces:**
- Consumes: `NetBoxClient(config, token=broker_token, retry=False)`; every call with `use_branch=False`.
- Produces: `class NetBoxBroker` with `async find_user(username: str) -> NetBoxUser | None` (`NetBoxUser(id, username, is_active, is_superuser)`; raises `BrokerConflict` if more than one), `async get_user(user_id: int) -> NetBoxUser | None`, `async create_token(user_id: int, description: str, expires_at: float) -> CreatedToken` (`CreatedToken(token_id, bearer, expires_at)`; full v2 bearer `nbt_<key>.<token>`), `async get_token(token_id: int) -> TokenInfo | None` (`TokenInfo(id, enabled, expires_at, user_id)`), `async list_tokens(user_id: int | None, description_contains: str) -> list[TokenInfo]` (paginates), `async delete_token(token_id: int) -> bool` (404 → True). Errors: `BrokerUnavailable` (timeout, 5xx, 429, HTML or non-JSON 200), `BrokerAmbiguous` (create: timeout/5xx/malformed success — outcome unknown), `BrokerDefinite` (create: 4xx, proves no token).

- [ ] **Step 1: Failing tests**: `test_find_user_unique_inactive_superuser_fields`; `test_find_user_conflict`; `test_create_token_payload` (assert POST body `write_enabled is True`, `user == id`, ISO `expires`, description passed; exactly one POST even on 429 → `BrokerDefinite`); `test_create_token_ambiguous_on_timeout_and_5xx`; `test_html_200_is_unavailable`; `test_no_branch_header` (with branching configured, no `X-NetBox-Branch` sent); `test_delete_404_counts_as_deleted`; `test_list_tokens_paginates`.
- [ ] **Step 2–4: FAIL, implement, PASS.**
- [ ] **Step 5: Commit** `feat(oauth): add NetBox broker client for personal tokens`

---

## Phase 3 – Sessions and flows

### Task 8: Identity mapping and links

**Files:**
- Create: `src/netbox_mcp/oauth/sessions.py` (first part)
- Test: `tests/oauth/test_mapping.py`

**Interfaces:**
- Produces: `class SessionManager` with `__init__(config, store: StateStore, broker: NetBoxBroker, idp: IdpClient, tokens: AccessTokens)`; per-session `asyncio.Lock` registry `lock_for(sid) -> asyncio.Lock`; per-user lock `user_lock(user_key)`.
- Produces: `async resolve_identity(iss: str, login: IdpLogin) -> Link` raising `LoginDenied(reason_code: str, message: str)` with reason codes `no_group`, `no_netbox_user`, `ambiguous_user`, `inactive_user`, `superuser`, `denylisted`, `linked_elsewhere`; `BrokerUnavailable` propagates.

- [ ] **Step 1: Failing tests**: `test_first_login_creates_link`; `test_second_login_same_sub_reuses_link`; `test_other_sub_for_linked_user_denied` (`linked_elsewhere`, no link change); `test_group_missing_denied`; `test_no_netbox_user_denied`; `test_superuser_denied`; `test_denylisted_denied`; `test_inactive_denied`; `test_username_change_in_netbox_follows_link_id` (link by `netbox_user_id`; renamed user still matched by ID, username claim must still resolve to same ID or deny).
- [ ] **Step 2–4: FAIL, implement, PASS.**
- [ ] **Step 5: Commit** `feat(oauth): map IdP identities to NetBox users`

### Task 9: Session creation, NetBox token, renewal and end

**Files:**
- Modify: `src/netbox_mcp/oauth/sessions.py`
- Test: `tests/oauth/test_sessions.py`

**Interfaces:**
- Produces on `SessionManager`:
  - `async create_session(link: Link, client: Client, idp_refresh_token: str) -> tuple[Session, str]` — writes `PendingCreate` → `broker.create_token` → one write storing the session (token, `token_version=1`) and removing the marker; returns session and plaintext authorization code (5 min). `BrokerAmbiguous` keeps the marker and raises `LoginFailed`; `BrokerDefinite` removes it.
  - `async renew_if_due(sid: str) -> None` — below 2 days: marker → create → one write swapping token, `token_version += 1`, removing marker, enqueuing old token; if the session vanished meanwhile, enqueue the new token.
  - `async end_session(sid: str, reason: str) -> None` — one write removing the session and enqueuing its token; idempotent.
  - `current_token(sid) -> tuple[str, int] | None` (bearer, token_version).

- [ ] **Step 1: Failing tests**: `test_create_session_marker_removed_in_same_write` (spy on store writes: exactly one write after the POST, containing session and no marker); `test_create_token_ambiguous_keeps_marker`; `test_create_token_definite_drops_marker`; `test_renew_swaps_and_enqueues_old` (clock at expiry − 2 days + 1 s → no renewal; − 1 s → renewal); `test_renew_after_session_end_enqueues_new`; `test_end_session_idempotent`; `test_description_format` (`NetBox MCP (OAuth) <client_name> <sid[:8]> <nonce>`).
- [ ] **Step 2–4: FAIL, implement, PASS.**
- [ ] **Step 5: Commit** `feat(oauth): manage sessions and per-session NetBox tokens`

### Task 10: Registration, authorize, IdP callback and consent routes

**Files:**
- Create: `src/netbox_mcp/oauth/routes.py`
- Test: `tests/oauth/test_flow.py`

**Interfaces:**
- Consumes: Tasks 3, 4, 6, 8, 9.
- Produces: `oauth_routes(config, manager: SessionManager) -> list[Route]` with handlers mounted at `<base>/oauth/register`, `<base>/oauth/authorize`, `<base>/oauth/callback`, `<base>/oauth/consent` plus root aliases `/register`, `/authorize` (same handler objects). Token and revoke handlers come in Task 11.
- Behaviour: spec §5.2 (DCR echoes `none`, never rejects for auth method; per-IP rate limit 10/min and cap 1,000 registrations → 429/`invalid_client_metadata`), §5.3 steps 1–8 (HTML error page for validation errors; flow cookie; IdP error → `access_denied` redirect with `state` and `iss`; denial → `access_denied` redirect; outage → error page; consent once per user+client with CSRF = HMAC(signing key, `consent:<flow_id>`); security headers on every flow page; claim-before-await for concurrent completions).

- [ ] **Step 1: Failing tests** (Starlette `TestClient` with `fake_idp` and `fake_netbox`):
  - `test_dcr_echoes_none_for_client_secret_post` (request `client_secret_post` → 201, response `token_endpoint_auth_method == "none"`).
  - `test_dcr_rejects_reserved_params` (`?iss=` and `?code=` → 400 `invalid_redirect_uri`).
  - `test_authorize_requires_state_and_s256` (missing `state`, `plain`, missing challenge → HTML 400 page, no redirect).
  - `test_authorize_resource_optional_trailing_slash` (absent → ok; `…/mcp/` → ok; `https://other.example/mcp` → `invalid_target` page).
  - `test_authorize_redirect_must_match_client_registration`.
  - `test_full_login_success_redirect_has_code_state_iss`.
  - `test_flow_cookie_attributes` (`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/mcp/oauth`, `Max-Age=600`).
  - `test_flow_pages_security_headers` (`no-store`, `no-referrer`, `DENY`, CSP contains `frame-ancestors 'none'`).
  - `test_bob_without_group_access_denied_redirect` and `test_carol_without_account_access_denied_redirect` (302 with `error=access_denied`, original `state`, `iss`; no session, no NetBox token).
  - `test_idp_error_maps_to_access_denied`.
  - `test_consent_shown_once_per_user_and_client` and `test_consent_csrf_mismatch_rejected`.
  - `test_concurrent_callbacks_create_one_session` (two parallel completions of one flow → exactly one session and one NetBox token).
  - `test_idp_refresh_token_persisted_before_group_check` (store spy: write containing the IdP refresh token precedes eligibility evaluation).
- [ ] **Step 2–4: FAIL, implement, PASS.**
- [ ] **Step 5: Commit** `feat(oauth): add registration, authorization and login flow`

### Task 11: Token and revocation endpoints

**Files:**
- Modify: `src/netbox_mcp/oauth/routes.py`, `src/netbox_mcp/oauth/sessions.py`
- Test: `tests/oauth/test_token_endpoint.py`

**Interfaces:**
- Produces on `SessionManager`: `async redeem_code(code: str, client_id: str, redirect_uri: str, verifier: str, resource: str | None) -> dict` (token response), `async refresh(refresh_token: str, client_id: str | None, resource: str | None) -> dict`, `async revoke(token: str, client_id: str | None) -> None`.
- Token response: `{"access_token", "token_type": "Bearer", "expires_in": 3600, "refresh_token", "scope": "netbox"}`.
- Routes `<base>/oauth/token`, `/token`, `<base>/oauth/revoke`, `/revoke`, `/oauth/revoke`; form or JSON bodies; `client_secret`/Basic ignored.

- [ ] **Step 1: Failing tests**:
  - `test_code_exchange_happy` and `test_code_exchange_wrong_verifier_burns_code`.
  - `test_code_reuse_invalid_grant_session_survives`.
  - `test_code_expires_after_5_minutes` (clock + 301 s).
  - `test_refresh_rotates_and_checks_idp` (fake IdP saw one refresh + userinfo per client refresh).
  - `test_refresh_concurrent_duplicate_gets_replay` (two concurrent refreshes with the same token → identical responses; session alive).
  - `test_replay_window_strict_30s` (rotation at t; presentation at t + 29.9 → replay; at t + 30.0 → session ended).
  - `test_older_spent_token_ends_session` (A→B→C, present A → `invalid_grant`, session gone, NetBox token enqueued).
  - `test_refresh_client_id_mismatch_rejected`; `test_refresh_foreign_resource_invalid_target`.
  - `test_refresh_idp_rejected_ends_session`; `test_refresh_idp_unavailable_503_keeps_token` (then a retry with the same refresh token succeeds after the fake recovers).
  - `test_refresh_write_failure_keeps_previous_token` (store write raises → 503; reopen store; old refresh token works).
  - `test_sliding_deadline_30_days`.
  - `test_revoke_rules` (missing token → 400; unknown → 200; expired genuine access token revokes; spent refresh token maps to session; client_id mismatch → 200 no effect; no `client_secret` field needed).
  - `test_root_aliases_token_and_revoke`.
- [ ] **Step 2–4: FAIL, implement, PASS.**
- [ ] **Step 5: Commit** `feat(oauth): add token endpoint with rotation, replay window and revocation`

---

## Phase 4 – MCP integration and operations

### Task 12: Token verifier, outer app and MCP endpoint rules

**Files:**
- Create: `src/netbox_mcp/oauth/verifier.py`, `src/netbox_mcp/oauth/app.py`
- Modify: `src/netbox_mcp/netbox_client.py:202-225` (`_resolve_token` reads the verified token when `claims["netbox_mcp_auth_mode"] == "oauth"`; on 401/403 call a hook), `src/netbox_mcp/auth.py:319-330` (rate-limit key `claims["sub"]` in OAuth mode), `src/netbox_mcp/server.py` (`main()` builds the outer app in OAuth mode and runs uvicorn with `access_log=False`; FastMCP lifespan refusal)
- Test: `tests/oauth/test_mcp_endpoint.py`, `tests/oauth/test_launch.py`

**Interfaces:**
- Produces: `class OAuthTokenVerifier(TokenVerifier)` with `verify_token(token) -> AccessToken | None` returning `AccessToken(token=<bearer>, client_id=<client_id>, scopes=["netbox"], expires_at=<exp>, claims={"netbox_mcp_auth_mode": "oauth", "sub": user_key, "sid": sid, "token_version": n})`.
- Produces: `async SessionManager.handle_netbox_rejection(sid: str, used_version: int) -> Literal["retry", "ended", "permission", "unavailable"]` (spec §6.3) and the client hook in `netbox_client.py` that retries once on `"retry"` and raises a tool error on `"ended"`/`"unavailable"`.
- Produces: `build_oauth_app(mcp: FastMCP, config: OAuthConfig) -> Starlette` — mounts `mcp.http_app(path=<base>, stateless_http=True, json_response=True)` with `lifespan` composed from `mcp_app.lifespan` and the OAuth lifespan (open store, discover IdP, start jobs; close in reverse); outer middleware order Origin → canonical path → auth (FastMCP) → body → version; sets `app.state.netbox_mcp_outer = True`. FastMCP lifespan in OAuth mode raises `RuntimeError("OAuth mode must be started with the netbox-mcp entry point")` when the marker is absent.
- Version rule: supported = SDK's `SUPPORTED_PROTOCOL_VERSIONS`; tolerate a real calendar date > newest and ≤ 2 years ahead; else 400; `initialize` never rejected, unknown version answered with the latest supported.

- [ ] **Step 1: Failing tests**:
  - `test_unauthenticated_initialize_with_2026_07_28_is_401_challenge` (exact header from Task 4).
  - `test_invalid_token_challenge_has_error_invalid_token`.
  - `test_tool_call_uses_session_netbox_token` (FakeNetBox records `Authorization: Bearer nbt_…` of the session).
  - `test_superseded_token_retries_once`; `test_deleted_token_ends_session` (tool error now, next request 401, cleanup queue has one entry, no loop); `test_permission_403_passes_through`.
  - `test_get_and_delete_mcp_405_allow_post`; `test_notification_202_empty_body`; `test_no_mcp_session_id_header`.
  - `test_mcp_and_trailing_slash_served`; `test_noncanonical_paths_404` (`//mcp`, `/mcp//`, `/MCP`, no redirect).
  - `test_origin_allowlist_all_methods` (`https://evil.example` → 403 on POST/GET; allowed origins pass; no `Origin` passes).
  - `test_version_rules` (`2026-07-28` ok; `2099-01-01` → 400; `2026-02-30` → 400; garbage → 400; `initialize` with `2099-01-01` → latest supported).
  - `test_rate_limit_keyed_by_user_not_client`.
  - `test_access_log_has_no_query_strings` (caplog over a full login: no `code=`/`state=` anywhere).
  - `test_fastmcp_run_refused_in_oauth_mode` (start `mcp.http_app()` lifespan directly with OAuth env → RuntimeError); `test_main_builds_outer_app` (outer app lifespan starts and stops store and jobs).
  - `test_import_has_no_side_effects` (import `netbox_mcp.server` with OAuth env and a missing state file → no exception, no lock file).
- [ ] **Step 2–4: FAIL, implement, PASS.** Configure FastMCP `host_origin_protection`/`allowed_origins` consistent with the allowlist (spec §4). Emit the log events of spec §9 (`login_denied`, `token_refreshed`, `refresh_rejected` + reason code, `tool_call`, `session_ended`; sid truncated to 8 chars, path without query); `test_log_events_contain_no_secrets` asserts no bearer, code, cookie or refresh token appears in caplog across the e2e flow.
- [ ] **Step 5: Run full suite** `uv run pytest -v`, expect PASS (existing passthrough/static-bearer tests unchanged).
- [ ] **Step 6: Commit** `feat(oauth): serve MCP with OAuth sessions behind the outer app`

### Task 13: Background jobs

**Files:**
- Create: `src/netbox_mcp/oauth/jobs.py`
- Modify: `src/netbox_mcp/oauth/sessions.py`
- Test: `tests/oauth/test_jobs.py`

**Interfaces:**
- Produces on `SessionManager`: `async run_cleanup() -> None` (single-flight; each entry once; 404 = done; warn once per 24 h for entries > 7 days), `async recover_pending() -> None` (markers ≥ 10 min old: list tokens of the user matching the nonce, delete, drop marker; serialized per user), `async end_orphans() -> None` (sessions with `code_redeemed=False` older than 10 min), `async end_expired() -> None` (sessions past `refresh_deadline`, i.e. 30 days without client refresh), `async expire_clients() -> None` (30 days unused, no sessions; drops grants), `async daily_netbox_check() -> None` (per session: user active, token exists/enabled, `renew_if_due`; unavailable keeps session).
- Produces: `class Jobs` with `start()`/`async stop()`; schedule: cleanup + recovery + orphans hourly and after every `end_session`; daily check and client expiry every 24 h; first run at startup.

- [ ] **Step 1: Failing tests**: `test_session_ends_30_days_without_refresh`; `test_cleanup_404_counts_deleted`; `test_cleanup_failure_retries_next_run`; `test_cleanup_warns_once_per_day_after_7_days`; `test_recovery_skips_young_marker`; `test_recovery_deletes_matching_token`; `test_orphan_session_ended_after_10_minutes`; `test_client_expiry_30_days_drops_grants`; `test_daily_check_inactive_user_ends_session`; `test_daily_check_unavailable_keeps_session`; `test_daily_check_renews_due_token`; `test_jobs_stop_awaits_tasks`.
- [ ] **Step 2–4: FAIL, implement, PASS.**
- [ ] **Step 5: Commit** `feat(oauth): add cleanup, recovery and daily NetBox check jobs`

### Task 14: Admin commands

**Files:**
- Create: `src/netbox_mcp/oauth/cli.py`
- Modify: `src/netbox_mcp/server.py` (`main()` dispatches `netbox-mcp oauth <cmd>` before starting the server)
- Test: `tests/oauth/test_cli.py`

**Interfaces:**
- Produces: `oauth_cli(argv: list[str]) -> int` with subcommands `init`, `unlink <netbox-username>`, `restore-reset`, `sweep [--apply]`. All take the exclusive store lock (fail with exit 2 and a clear message when the server holds it). `sweep` lists tokens whose description starts with `NetBox MCP (OAuth) ` and deletes (with `--apply`) those not tracked by any session, marker or cleanup entry; prints counts only, never token values.

- [ ] **Step 1: Failing tests**: `test_init_creates_file_and_refuses_existing`; `test_commands_refuse_when_locked`; `test_unlink_removes_link_ends_sessions_enqueues_tokens`; `test_restore_reset_ends_all_sessions_keeps_links_and_grants`; `test_sweep_dry_run_deletes_nothing`; `test_sweep_apply_deletes_only_untracked`.
- [ ] **Step 2–4: FAIL, implement, PASS.**
- [ ] **Step 5: Commit** `feat(oauth): add offline admin commands`

### Task 15: End-to-end flow, documentation and deployment notes

**Files:**
- Create: `tests/oauth/test_e2e.py`
- Modify: `README.md` (OAuth mode: setup, IdP client settings incl. `offline_access` and the groups claim, NetBox service user permissions from spec §6.2, local-account denylist as required step, username-change precondition, `oauth init`, backup and restore procedure, ChatGPT connector re-add note, tool-result changes), `.env.example`, `Dockerfile` (document volume for the state directory, UID 10001), `CHANGELOG` via release-please (no manual edit)
- Test: `tests/oauth/test_e2e.py`

**Interfaces:**
- Consumes everything above; no new production interfaces.

- [ ] **Step 1: Write `test_e2e_full_lifecycle`**: metadata discovery over every path → DCR (loopback) → authorize → fake IdP → consent → code → token → MCP `initialize` + `tools/call netbox_get_objects` (NetBox sees the session bearer) → refresh → server restart (new app, same state file) → tool call works without login → group removal at the fake IdP → next refresh `invalid_grant` → NetBox token deleted by cleanup.
- [ ] **Step 2: Write `test_spike_checklist`**: one assertion per spec Appendix A item (1–9) against the built app.
- [ ] **Step 3: Run, fix gaps, run** `uv run pytest -v` → all PASS; `uv run ruff check src tests`; `uv run ty check` if configured.
- [ ] **Step 4: Update docs; check** `tests/test_settings_documented.py` passes and no IdP product name appears in `src`.
- [ ] **Step 5: Commit** `docs(oauth): document OAuth mode and add end-to-end test`

### Task 16: Review and acceptance

- [ ] **Step 1: Codex review** of the whole branch diff against `main` via the `codex-reviewer` agent (focus: spec §5, §6, the Review Focus list above). Store the result in `docs/superpowers/reviews/YYYY-MM-DD-oauth-authorization-server-code.md` (scope, model, findings with severity, file:line, verdict, action), without personal names. Fix agreed findings, re-run tests, commit.
- [ ] **Step 2: Acceptance with real clients** (needs the maintainer: test IdP application, public test instance, NetBox service user): for claude.ai, Claude desktop, Claude Code, Codex CLI and ChatGPT run login, tool discovery, read, disposable write attributed to the human user, refresh without interaction, reconnect after server restart, loss of access after group removal (≤ 1 h) and after revoke; ChatGPT shows tool results correctly. Record client versions in private pilot notes only.
- [ ] **Step 3: PR** against `main` with summary, test evidence and link to spec and reviews.
