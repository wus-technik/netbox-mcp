<div align="center">

# NetBox MCP Server

**Give AI agents structured access to NetBox, your network source of truth**

[![PyPI](https://img.shields.io/pypi/v/netbox-mcp?logo=pypi&logoColor=white)](https://pypi.org/project/netbox-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/netbox-mcp?logo=python&logoColor=white)](https://pypi.org/project/netbox-mcp/)
[![License](https://img.shields.io/github/license/mhajder/netbox-mcp)](https://github.com/mhajder/netbox-mcp/blob/main/LICENSE)

[![Pre-commit Checks](https://github.com/mhajder/netbox-mcp/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/mhajder/netbox-mcp/actions/workflows/pre-commit.yml)
[![Docker](https://img.shields.io/badge/ghcr.io-netbox--mcp-2496ED?logo=docker&logoColor=white)](https://github.com/mhajder/netbox-mcp/pkgs/container/netbox-mcp)
[![MCP Registry](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fregistry.modelcontextprotocol.io%2Fv0.1%2Fservers%2Fio.github.mhajder%252Fnetbox-mcp%2Fversions%2Flatest&query=%24.server.version&label=MCP%20Registry&color=6E56CF)](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.mhajder%2Fnetbox-mcp/versions/latest)

[Installation](https://github.com/mhajder/netbox-mcp#-installation) · [Tools](https://github.com/mhajder/netbox-mcp#-available-tools) · [Configuration](https://github.com/mhajder/netbox-mcp#-configuration) · [Security](https://github.com/mhajder/netbox-mcp#-security--safety-features)

</div>

<!-- mcp-name: io.github.mhajder/netbox-mcp -->

NetBox MCP Server is a Python-based Model Context Protocol (MCP) server that gives AI assistants structured access to [NetBox](https://netbox.dev) - the source of truth for network infrastructure (DCIM and IPAM). A small set of generic tools covers all 139 core object types of NetBox 4.7 (and plugin types, if enabled), plus specialised tools for search, change logs, GraphQL, free IP/prefix/VLAN allocation, prefix utilization, free rack space, cable tracing and connecting, config rendering, custom scripts and (optionally) netbox-branching. Writes can be hidden entirely (read-only mode) or simulated (dry-run mode).

## ✨ Features

### Core Features

- Query any NetBox object type with filtering, ordering and pagination through one tool
- Keep responses small with `fields`, `omit` and `brief` - the tools steer the model to use them
- Search many object types at once, with explicit reporting of failed and truncated types
- Read the change log (who changed what, when) and NetBox status/version/plugins
- Run read-only GraphQL queries for nested data in one round trip
- List free IPs, prefixes, VLANs and ASNs; trace cable paths; render device configs
- Compute prefix utilization (as the NetBox UI shows it) and find racks with room for a device

### Management Operations

- Create, update and delete any object type, singly or in bulk (NetBox runs a bulk write as one transaction)
- Allocate the next free IP, prefix, VLAN or ASN atomically
- Connect ports with a cable, naming them by device and port name
- Run NetBox custom scripts (changes rolled back unless `commit` is set)
- Optionally stage changes in a netbox-branching branch instead of main
- Describe an object type's writable fields and choices before writing

### Advanced Capabilities

- Read-only mode hides every write tool; dry-run mode turns every write into a preview
- NetBox v2 (`Bearer nbt_...`) and legacy v1 (`Token ...`) API tokens
- Plugin object type discovery (e.g. `netbox_dns.zone`)
- Filter validation that rejects filters NetBox would silently ignore (`__in`, multi-hop lookups)
- Retries on 429/5xx without ever replaying a create after a server error
- Tag-based tool filtering, optional tool-search transform, rate limiting and response size limit
- Bearer token authentication for HTTP transport
- Multiple transport options (STDIO, SSE, HTTP)
- Optional Sentry integration for error tracking

## 🚀 Installation

### Prerequisites

- Python 3.11 to 3.15
- A NetBox instance, version 4.2 or newer. Features added later (`omit`, v2
  tokens, `/api/authentication-check/`) are used when the server detects them
- A NetBox API token with the permissions you want the assistant to have. The
  token is the real security boundary: a read-only token cannot write, whatever
  this server's settings are

### Quick Install from PyPI

The easiest way to get started is to install from PyPI:

```sh
# Using UV (recommended)
uvx netbox-mcp

# Or using pip
pip install netbox-mcp
```

Remember to configure the environment variables for your NetBox instance before running the server:

```sh
# Create environment configuration
export NETBOX_URL=https://netbox.example.com
export NETBOX_TOKEN=nbt_your-key.your-token
```

### Install from Source

1. Clone the repository:

```sh
git clone https://github.com/mhajder/netbox-mcp.git
cd netbox-mcp
```

2. Install dependencies:

```sh
# Using UV (recommended)
uv sync

# Or using pip
pip install -e .
```

3. Configure environment variables:

```sh
cp .env.example .env
# Edit .env with your NetBox URL and API token
```

4. Run the server:

```sh
# Using UV (recommended)
uv run netbox-mcp

# Or using the installed command directly
netbox-mcp
```

### Using Docker

A Docker image is available on GitHub Packages for easy deployment.

```sh
docker pull ghcr.io/mhajder/netbox-mcp:latest
```

### Development Setup

For development with additional tools:

```sh
# Clone and install with development dependencies
git clone https://github.com/mhajder/netbox-mcp.git
cd netbox-mcp
uv sync --group dev

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/

# Run linting and formatting
uv run ruff check .
uv run ruff format .

# Run type checking
uv run ty check .

# Setup prek hooks
uv run prek install
```


## 🔧 Configuration

### Environment Variables

```env
# NetBox MCP Server Environment Configuration

# NetBox Connection Details
NETBOX_URL=https://netbox.example.com

# API Token - v2 tokens (nbt_<key>.<token>, NetBox 4.5+) are sent as "Bearer",
# legacy v1 tokens as "Token"
NETBOX_TOKEN=nbt_your-key.your-token

# SSL Configuration
NETBOX_VERIFY_SSL=true
# Total time allowed for one NetBox request, retries included (seconds)
NETBOX_TIMEOUT=30

# Branching (requires the netbox-branching plugin)
# Set NETBOX_BRANCHING_ENABLED true to add the branch tools and the 'branch'
# argument to every tool. Off by default - leave it off on a NetBox without the plugin
NETBOX_BRANCHING_ENABLED=false
# Default branch (name or schema ID) used by every call; empty = main.
# Requires NETBOX_BRANCHING_ENABLED=true
NETBOX_BRANCH=

# Plugin Discovery
# Set NETBOX_PLUGIN_DISCOVERY true to expose plugin models (e.g. netbox_dns.zone)
NETBOX_PLUGIN_DISCOVERY=false

# Read-Only Mode
# Set READ_ONLY_MODE true to hide all write tools (create, update, delete)
READ_ONLY_MODE=false

# Dry-Run Mode
# Set DRY_RUN_MODE true to make every write tool only simulate the change:
# it returns the request it would send and never modifies NetBox
DRY_RUN_MODE=false

# Disabled Tags
# Comma-separated list of tags to disable tools for (empty by default)
# Example: DISABLED_TAGS=delete,graphql,branching
DISABLED_TAGS=

# Logging Configuration
LOG_LEVEL=INFO

# Response Size Limit
# Maximum tool response size in bytes; larger responses are truncated (empty = unlimited)
RESPONSE_MAX_SIZE=

# Rate Limiting
# Set RATE_LIMIT_ENABLED true to enable rate limiting
RATE_LIMIT_ENABLED=false
RATE_LIMIT_MAX_REQUESTS=60
RATE_LIMIT_WINDOW_MINUTES=1

# Tool Search Transform (Optional)
# Set TOOL_SEARCH_ENABLED true to replace full tool listings with search_tools + call_tool
TOOL_SEARCH_ENABLED=false
# Search strategy: bm25 (natural language) or regex (pattern match)
TOOL_SEARCH_STRATEGY=bm25
# Maximum number of tools returned by search_tools
TOOL_SEARCH_MAX_RESULTS=5

# Sentry Error Tracking (Optional)
# Set SENTRY_DSN to enable error tracking and performance monitoring
# SENTRY_DSN=https://your-key@o12345.ingest.us.sentry.io/6789
# Optional Sentry configuration
# SENTRY_TRACES_SAMPLE_RATE=1.0
# SENTRY_SEND_DEFAULT_PII=false
# SENTRY_ENVIRONMENT=production
# SENTRY_RELEASE=1.2.3
# SENTRY_PROFILE_SESSION_SAMPLE_RATE=1.0
# SENTRY_PROFILE_LIFECYCLE=trace
# SENTRY_ENABLE_LOGS=true

# MCP Transport Configuration
# Transport type: 'stdio' (default), 'sse' (Server-Sent Events), or 'http' (HTTP Streamable)
# 'streamable-http' is accepted as an alias for 'http'. Any other value stops
# the server at startup.
# MCP_TRANSPORT=stdio

# HTTP Transport Settings (used when MCP_TRANSPORT=sse or MCP_TRANSPORT=http)
# Host to bind the HTTP server (default: 127.0.0.1)
# MCP_HTTP_HOST=127.0.0.1
# Port to bind the HTTP server (default: 8000)
# MCP_HTTP_PORT=8000
# Optional bearer token for authentication (leave empty for no auth)
# MCP_HTTP_BEARER_TOKEN=
# Set NETBOX_TOKEN_PASSTHROUGH true to make every client authenticate with its own
# NetBox API token (Authorization: Bearer <token>); NetBox then applies that user's
# permissions. NETBOX_TOKEN is ignored. Cannot be combined with MCP_HTTP_BEARER_TOKEN
# NETBOX_TOKEN_PASSTHROUGH=false
```

## 🧰 Available Tools

Object types are named `app.model`, as NetBox itself names them (`dcim.device`, `ipam.prefix`, `virtualization.virtualmachine`). API paths such as `dcim/devices` are accepted too. With branching enabled, every tool that reads or writes objects also takes an optional `branch` argument.

### Objects (read)

| Tool | Description |
|---|---|
| `netbox_list_object_types` | List supported object types and their endpoints (core and discovered plugin types) |
| `netbox_get_objects` | List objects of a type with `filters`, `fields`, `omit`, `brief`, `ordering`, `limit`, `offset` |
| `netbox_get_object` | Get one object by ID |
| `netbox_search_objects` | Free-text search (`q`) across several object types at once |
| `netbox_describe_object_type` | Writable fields of a type: data type, required, choices |
| `netbox_get_changelogs` | Change log entries, newest first |

### Specialised (read)

| Tool | Description |
|---|---|
| `netbox_get_status` | NetBox version, plugins, workers, authenticated user and this server's modes |
| `netbox_graphql_query` | Read-only GraphQL query (mutations are rejected) |
| `netbox_get_available` | Free IPs / prefixes in a prefix or IP range, VLANs in a VLAN group, ASNs in an ASN range |
| `netbox_trace_cable` | Full cable path from an interface, front/rear/console/power port or circuit termination |
| `netbox_render_config` | Render a device's or VM's configuration from its config template |
| `netbox_get_prefix_utilization` | Utilization of up to 25 prefixes, computed as NetBox's UI does (child prefixes for containers, IPs and utilized ranges otherwise) |
| `netbox_find_rack_space` | Racks in a site, location or list with room for a device of a given height (counts both faces for full-depth devices, and reservations) |
| `netbox_list_branches` | List netbox-branching branches (only with `NETBOX_BRANCHING_ENABLED=true`) |

### Write

| Tool | Description |
|---|---|
| `netbox_create_object` | Create one object |
| `netbox_update_object` | Partially update one object (PATCH) |
| `netbox_bulk_create_objects` | Create up to 500 objects in one transaction |
| `netbox_bulk_update_objects` | Update up to 500 objects in one transaction |
| `netbox_allocate_available` | Allocate the next free IP, prefix, VLAN or ASN |
| `netbox_connect_cable` | Cable ports together, given by ID or by device and port name; refuses ports that are already cabled |
| `netbox_run_script` | Run a custom script and wait for its log and output; `commit` defaults to false (`destructiveHint`) |
| `netbox_create_branch` | Create a netbox-branching branch (only with `NETBOX_BRANCHING_ENABLED=true`) |
| `netbox_delete_object` | Delete one object (`destructiveHint`) |
| `netbox_bulk_delete_objects` | Delete up to 500 objects in one transaction (`destructiveHint`) |

### Tool Tags

Every tool is tagged `netbox` plus a group tag, which `DISABLED_TAGS` can switch off: `objects`, `search`, `changelog`, `status`, `graphql`, `ipam`, `dcim`, `config`, `branching`, `scripts`, `write` and `delete`. Read tools also carry `read-only`.

## Tool results

Every tool has a human-readable `title`, annotations, and returns a JSON object as its structured result (list results are wrapped, e.g. `{"results": [...], "count": ...}`). Failures are returned as results with `isError` set; a call to an unknown or disabled tool is a JSON-RPC `-32602` (invalid params) error.

ChatGPT cannot render a result whose data object has a key named `content`. In the structured result every `content` key, at any depth, is therefore renamed to `content_value`. This affects `netbox_render_config` (NetBox answers `{"content": "<rendered config>"}`) and any NetBox object that carries such a key in a nested field. The text content of the result keeps the NetBox data unchanged.

After upgrading to a version with this change, remove and re-add an existing ChatGPT connector so ChatGPT picks up the new tool list.

## 🔒 Security & Safety Features

### Read-Only Mode

Read-only mode hides every write tool - the client only sees the 13 read tools (14 with branching enabled):

```env
READ_ONLY_MODE=true
```

### Dry-Run Mode

Dry-run mode keeps the write tools visible, but none of them changes NetBox. Each one resolves and validates its target, then returns the request it would have sent, flagged `"dry_run": true`. Updates and deletes also fetch the current object, so the preview shows the values that would change and exactly what would be deleted:

```env
DRY_RUN_MODE=true
```

`READ_ONLY_MODE` takes precedence: when both are set, write tools are hidden.

### NetBox Branching

With the [netbox-branching](https://github.com/netboxlabs/netbox-branching) plugin, changes can be staged in a branch and reviewed before they are merged into main. Branching support is **off by default**, so a NetBox without the plugin gets no branch tools and no `branch` argument. Enable it with:

```env
NETBOX_BRANCHING_ENABLED=true
```

This adds `netbox_list_branches` and `netbox_create_branch`, and a `branch` argument (a branch name or its schema ID) to every other tool. To send every call to one branch by default:

```env
NETBOX_BRANCH=assistant-changes
```

Setting `NETBOX_BRANCH` without `NETBOX_BRANCHING_ENABLED=true` is a configuration error: the server refuses to start rather than silently writing to main.

Branch names are resolved to the schema ID that the `X-NetBox-Branch` header needs. Merging, syncing and reverting are deliberately not exposed as tools - they belong in a human review step.

### Plugin Discovery

```env
NETBOX_PLUGIN_DISCOVERY=true
```

The first time a call names an unknown type (or `netbox_list_object_types` runs), the server reads `/api/core/object-types/` and adds every plugin model with a REST endpoint (for example `netbox_dns.zone`). Plugin types never shadow core types. If discovery fails, the core types keep working.

### Tag-Based Tool Filtering

You can disable specific categories of tools by setting disabled tags. For example, allow creates and updates but never deletes:

```env
DISABLED_TAGS=delete
```

### Response Size Limit

Large NetBox objects add up quickly. `RESPONSE_MAX_SIZE` truncates any tool response above the given number of bytes:

```env
RESPONSE_MAX_SIZE=200000
```

### Tool Search for Large Toolsets

FastMCP tool search can reduce prompt size for servers with many tools.
When enabled, `list_tools` returns two synthetic tools:

- `search_tools`: Finds matching tools and returns their full schemas
- `call_tool`: Executes any discovered tool by name

Enable it with:

```env
TOOL_SEARCH_ENABLED=true
TOOL_SEARCH_STRATEGY=bm25      # bm25 or regex
TOOL_SEARCH_MAX_RESULTS=8      # optional, default is 5
```

`bm25` supports natural language queries, while `regex` uses a regex
`pattern` input for deterministic matching.

Tool search respects existing visibility controls (read-only mode and
disabled tags).

### Rate Limiting

The server supports rate limiting to control API usage and prevent abuse. If enabled, requests are limited per client using a sliding window algorithm.

Enable rate limiting by setting the following environment variables in your `.env` file:

```env
RATE_LIMIT_ENABLED=true
RATE_LIMIT_MAX_REQUESTS=60    # Maximum requests allowed per window (default: 60)
RATE_LIMIT_WINDOW_MINUTES=1   # Window size in minutes
```

If `RATE_LIMIT_ENABLED` is set to `true`, the server will apply rate limiting middleware. Adjust `RATE_LIMIT_MAX_REQUESTS` and `RATE_LIMIT_WINDOW_MINUTES` as needed for your environment.

### Sentry Error Tracking & Monitoring (Optional)

The server optionally supports **Sentry** for error tracking, performance monitoring, and debugging. Sentry integration is completely optional and only initialized if configured.

#### Installation

To enable Sentry monitoring, install the optional dependency:

```sh
# Using UV (recommended)
uv sync --extra sentry
```

#### Configuration

Enable Sentry by setting the `SENTRY_DSN` environment variable in your `.env` file:

```env
# Required: Sentry DSN for your project
SENTRY_DSN=https://your-key@o12345.ingest.us.sentry.io/6789

# Optional: Performance monitoring sample rate (0.0-1.0, default: 1.0)
SENTRY_TRACES_SAMPLE_RATE=1.0

# Optional: Include personally identifiable information (default: false).
# When true, tool inputs and outputs (NetBox inventory data) are sent to Sentry.
SENTRY_SEND_DEFAULT_PII=false

# Optional: Environment name (e.g., "production", "staging")
SENTRY_ENVIRONMENT=production

# Optional: Release version (auto-detected from package if not set)
SENTRY_RELEASE=1.2.3

# Optional: Profiling - continuous profiling sample rate (0.0-1.0, default: 1.0)
SENTRY_PROFILE_SESSION_SAMPLE_RATE=1.0

# Optional: Profiling - lifecycle mode for profiling (default: "trace")
# Options: "all", "continuation", "trace"
SENTRY_PROFILE_LIFECYCLE=trace

# Optional: Enable log capture as breadcrumbs and events (default: true)
SENTRY_ENABLE_LOGS=true
```

#### Features

When enabled, Sentry automatically captures:

- **Exceptions & Errors**: All unhandled exceptions with full context
- **Performance Metrics**: Request/response times and traces
- **MCP Integration**: Detailed MCP server activity and interactions
- **Logs & Breadcrumbs**: Application logs and event trails for debugging
- **Context Data**: Environment, client info, and request parameters

#### Getting a Sentry DSN

1. Create a free account at [sentry.io](https://sentry.io)
2. Create a new Python project
3. Copy your DSN from the project settings
4. Set it in your `.env` file

#### Disabling Sentry

Sentry is completely optional. If you don't set `SENTRY_DSN`, the server will run normally without any Sentry integration, and no monitoring data will be collected.

### SSL/TLS Configuration

The server supports SSL certificate verification and custom timeout settings:

```env
NETBOX_VERIFY_SSL=true    # Enable SSL certificate verification
NETBOX_TIMEOUT=30         # Total time per request, retries included (seconds)
```

Certificates are verified against the operating system trust store, so a NetBox behind an internal CA works as soon as that CA is trusted by the OS. `SSL_CERT_FILE` or `SSL_CERT_DIR` take precedence when set.

### Transport Configuration

The server supports multiple transport mechanisms for the MCP protocol:

#### STDIO Transport (Default)

The default transport uses standard input/output for communication. This is ideal for local usage and integration with tools that communicate via stdin/stdout:

```env
MCP_TRANSPORT=stdio
```

#### HTTP SSE Transport (Server-Sent Events)

For network-based deployments, you can use HTTP with Server-Sent Events. This allows the MCP server to be accessed over HTTP with real-time streaming:

```env
MCP_TRANSPORT=sse
MCP_HTTP_HOST=127.0.0.1        # Localhost
MCP_HTTP_PORT=8000           # Port to listen on
MCP_HTTP_BEARER_TOKEN=your-secret-token  # Optional authentication token
```

When using SSE transport with a bearer token, clients must include the token in their requests:

```bash
curl -H "Authorization: Bearer your-secret-token" http://localhost:8000/sse
```

#### HTTP Streamable Transport

The HTTP Streamable transport provides HTTP-based communication with request/response streaming. This is ideal for web integrations and tools that need HTTP endpoints:

```env
MCP_TRANSPORT=http
MCP_HTTP_HOST=127.0.0.1        # Localhost
MCP_HTTP_PORT=8000           # Port to listen on
MCP_HTTP_BEARER_TOKEN=your-secret-token  # Optional authentication token
```

When using streamable transport with a bearer token:

```sh
curl -H "Authorization: Bearer your-secret-token" \
     -H "Accept: application/json, text/event-stream" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
     http://localhost:8000/mcp
```

#### Per-user NetBox tokens

By default every client shares the server's `NETBOX_TOKEN`, so NetBox sees one user. With `NETBOX_TOKEN_PASSTHROUGH=true`, each client sends its own NetBox API token instead. NetBox applies that user's permissions and the changelog records the real user:

```env
MCP_TRANSPORT=http
MCP_HTTP_HOST=0.0.0.0
NETBOX_TOKEN_PASSTHROUGH=true
```

```sh
claude mcp add --transport http netbox https://netbox-mcp.example.com/mcp \
  --header "Authorization: Bearer nbt_your-key.your-token"
```

- Requests without a token, or with a token NetBox rejects, get HTTP 401. If NetBox cannot be reached to check a token within 10 seconds (or `NETBOX_TIMEOUT`, if lower), the request gets HTTP 503 with `Retry-After`, so clients retry instead of logging in again. The 503 passes on NetBox's own `Retry-After` when NetBox sends one. Accepted tokens are cached for 60 seconds. After that, the token is still accepted right away for up to 10 minutes while the server re-checks it with NetBox in the background, so a known user never waits on a check, even during a NetBox outage. A revoked token is dropped once its re-check comes back; until then it only reaches tools that don't call NetBox (such as the tool list), because NetBox refuses the token on every call that does. Rejected tokens are cached for 30 seconds, so a token just created in NetBox may be refused for up to 30 seconds if it was tried before it existed. At most 8 token checks reach NetBox at once; requests with a token the server hasn't seen yet wait for a free slot, and get HTTP 503 if the wait exceeds the check timeout.
- v2 (`nbt_...`) and legacy v1 tokens both work; the server sends each to NetBox with the right scheme.
- `NETBOX_TOKEN` is ignored. Only the `http` and `sse` transports are supported, and the server refuses to start if `MCP_HTTP_BEARER_TOKEN` is set too, since both use the `Authorization` header.
- With `RATE_LIMIT_ENABLED=true`, each NetBox user gets their own rate-limit window (each token on NetBox before 4.5), so the limit no longer caps the server's total load on NetBox.
- With `NETBOX_PLUGIN_DISCOVERY=true`, plugin types found with any user's token are added to one shared list. `rediscover` replaces that list with what the calling user can see, which drops uninstalled plugins; another user's call that names a type only they can see rediscovers it with their token.
- Clients send their NetBox tokens to this server, so put it behind HTTPS.

#### OAuth login

With `OIDC_ISSUER` set, the server signs users in through an OpenID Connect identity provider, acts as its own OAuth authorization server for the MCP clients and calls NetBox with a personal token per session. See [OAuth mode](#oauth-mode) for setup and operation.

**Note**: The HTTP transport requires proper JSON-RPC formatting with `jsonrpc` and `id` fields. The server may also require session initialization for some operations.

#### Health Endpoint

Both HTTP transports (`sse` and `http`) serve `GET /health`, which answers `200 ok`
when the server is handling requests. It needs no bearer token and does not
contact NetBox, so a NetBox outage does not mark the MCP server unhealthy.
The Docker image's `HEALTHCHECK` uses it:

```sh
curl http://localhost:8000/health
```

For more information on FastMCP transports, see the [FastMCP documentation](https://gofastmcp.com/deployment/running-server#transport-protocols).

## OAuth mode

In OAuth mode remote MCP clients (claude.ai, the Claude desktop app, Claude Code, Codex CLI, ChatGPT) connect with a normal OAuth login, and every NetBox call runs **as the signed-in user**, with that user's NetBox permissions and changelog attribution. Users never copy a NetBox token into a client.

The server is its own OAuth authorization server for the MCP clients (with Dynamic Client Registration, so no per-client setup) and signs users in through an OpenID Connect identity provider (IdP) as an ordinary confidential client. For each MCP session it creates a personal NetBox API token for the user through a NetBox service account, renews it, and deletes it when the session ends. The token never leaves the server.

```text
MCP client ──register / authorize / token / revoke──▶ netbox-mcp
                                                        │ browser login
                                                        ▼
                                           OIDC IdP (code + PKCE, offline_access)
                                                        │ identity + groups
                                                        ▼
                                    encrypted state file (sessions, tokens)
                                                        │ service account
                                                        ▼
                                    NetBox: create / renew / delete the user's token
MCP client ──Bearer (server-issued access token)──▶ /mcp ──▶ tools ──▶ NetBox as the user
```

### Deployment preconditions

The server cannot check these; the deployment must guarantee them:

- **NetBox accounts come from NetBox's own SSO login against the same IdP.** The server never creates NetBox users. A user who has never logged in to NetBox via SSO is denied with a hint to do that once.
- **Users cannot change their own username at the IdP.** The username claim is mapped to the NetBox username; a self-chosen username could take over another NetBox account.
- **Every local (non-SSO) NetBox account and every superuser is listed in `NETBOX_USER_DENYLIST`.** This is a required step, not an option. The NetBox REST API does not tell how an account authenticates, so a local account whose name matches an IdP username would otherwise be linked. The server also refuses superusers, but only if NetBox reports `is_superuser` in its users API, which current NetBox versions do not; until then the denylist is the only superuser guard. Names are compared case-insensitively.
- **One server process.** The state file is locked by the running process; replicas are not supported.
- **HTTPS in front of the server.** `MCP_PUBLIC_URL` must be `https` (plain `http` only on a loopback host for development). The reverse proxy passes requests through to the server's port.

### Identity provider client

Register a **confidential** OIDC client at the IdP:

- Redirect URI: `<MCP_PUBLIC_URL>/oauth/callback`, e.g. `https://mcp.example.com/mcp/oauth/callback`.
- Grant types: authorization code and refresh token. The server uses PKCE (S256), `state` and `nonce`.
- Scopes: `openid profile email offline_access` (plus `OIDC_EXTRA_SCOPES`). **`offline_access` must be granted**: a login whose token response has no refresh token is denied, because every client refresh re-checks the user at the IdP.
- ID tokens signed with RS256, audience = the client ID. The issuer and every endpoint in its discovery document must be `https`.
- Userinfo must return the **groups claim** (`OIDC_GROUPS_CLAIM`, default `groups`) as a list. A user without the claim, or without a group from `OIDC_ALLOWED_GROUPS`, is denied.
- The username claim (`OIDC_USERNAME_CLAIM`, default `preferred_username`) must be the claim NetBox's SSO uses as the NetBox username.

### NetBox service account

Create a dedicated, active NetBox user without administrative roles or inventory permissions, create a write-enabled token for it (`NETBOX_TOKEN_BROKER_TOKEN`), and grant exactly these object permissions:

| Object type | Actions | Constraint |
| --- | --- | --- |
| `users.token` | `add`, `grant` | Optional, e.g. `{"user__groups__name": "<NetBox group of MCP users>"}` |
| `users.token` | `view`, `delete` | None (cleanup and `sweep` must reach every token the server created) |
| `users.user` | `view` | None |

`grant` is the ObjectPermission action; NetBox forms the permission `users.grant_token` from it. Entering `grant_token` as the action forms the wrong permission. Restrict the service token to the server's egress address where possible.

The per-session tokens are created with `write_enabled=true` (the user's own NetBox permissions are the limit), a lifetime of 7 days (renewed when less than 2 days remain), and the description `NetBox MCP (OAuth) <client name> <session prefix> <nonce>`.

### Configuration

Setting `OIDC_ISSUER` turns OAuth mode on. A missing or invalid value stops startup and names the variable.

| Variable | Required | Meaning |
| --- | --- | --- |
| `OIDC_ISSUER` | yes | Issuer URL of the identity provider; turns OAuth mode on |
| `MCP_PUBLIC_URL` | yes | Public URL of the MCP endpoint, e.g. `https://mcp.example.com/mcp`; issuer and resource of this server. https (http only on loopback), no trailing slash, query or credentials |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | yes | Confidential client registered at the identity provider |
| `OIDC_ALLOWED_GROUPS` | yes | Comma-separated groups whose members may sign in |
| `NETBOX_TOKEN_BROKER_TOKEN` | yes | NetBox token of the service account that creates per-session user tokens |
| `OAUTH_SIGNING_KEY` | yes | Base64 key that signs access tokens, at least 32 bytes decoded (`openssl rand -base64 32`) |
| `OAUTH_STATE_KEY` | yes | Base64 key, exactly 32 bytes decoded, that encrypts the state file (`openssl rand -base64 32`) |
| `OAUTH_STATE_PATH` | yes | Path of the encrypted state file; its directory must exist and be writable |
| `OIDC_USERNAME_CLAIM` | no | Claim holding the username (default `preferred_username`) |
| `OIDC_GROUPS_CLAIM` | no | Claim holding the groups (default `groups`) |
| `OIDC_EXTRA_SCOPES` | no | Extra scopes to request, comma-separated |
| `EXTRA_REDIRECT_URIS`, `EXTRA_ORIGINS` | no | Extra allowed client redirect URIs (exact match) and web origins, comma-separated |
| `NETBOX_USER_DENYLIST` | no in the parser, **required in practice** | NetBox usernames that may never sign in, comma-separated, case-insensitive: every local account and every superuser |
| `OAUTH_MAX_SESSION_DAYS` | no | Maximum age of a session in days, independent of the 30-day refresh window; afterwards the user signs in again (default `365`, at least `1`) |
| `AUTH_DEBUG` | no | Log more detail about sign-ins, never secrets (default `false`) |

OAuth mode needs `MCP_TRANSPORT=http` and cannot be combined with `NETBOX_TOKEN_PASSTHROUGH` or `MCP_HTTP_BEARER_TOKEN`. `NETBOX_URL` is still required; `NETBOX_TOKEN` is ignored with a warning, because every call uses the session's own token.

### First start

1. Create the empty state file once, with the same `OAUTH_STATE_PATH` and `OAUTH_STATE_KEY` the server will use:

   ```sh
   netbox-mcp oauth init
   ```

   The server never creates the file itself: a missing, unreadable or undecryptable file (wrong path, lost volume, changed key) stops startup instead of silently starting empty.
2. Start the server with `netbox-mcp` (the package entry point). OAuth mode cannot be started with `fastmcp run` or `fastmcp.json`; that refuses to start with a message.
3. At startup the server opens the state file and fetches the IdP's discovery document. **If the IdP is unreachable at startup, the server does not start** (existing sessions are unavailable until it can); restart it once the IdP is back.
4. Add the server to a client with the URL `MCP_PUBLIC_URL`, e.g. `claude mcp add --transport http netbox https://mcp.example.com/mcp`. The client registers itself, opens the browser for the IdP login and a one-time consent page per client registration, and then works without further interaction.

**ChatGPT:** the tool results changed for ChatGPT (see [Tool results](#tool-results)); an existing ChatGPT connector must be removed and added again to pick up the new tool list.

### Sessions and tokens

- Access tokens are valid for 1 hour. Refresh tokens rotate on every use; a refresh window of 30 days slides with each client refresh, and a session ends at the latest `OAUTH_MAX_SESSION_DAYS` after its login.
- **Every client refresh re-checks the user**: it refreshes the session's IdP token, reads the groups from userinfo, and checks that the NetBox user is active and the session's NetBox token still exists. Removing a user from the allowed groups at the IdP therefore ends access within about an hour (the next refresh gets `invalid_grant`).
- Unavailable is not rejected: an IdP or NetBox that times out, answers 5xx/429 or HTML makes the refresh answer 503 `temporarily_unavailable`; the session and the previous refresh token stay valid and the client retries. One exception: if the IdP had already rotated its refresh token when the answer was lost, the next refresh fails closed (`invalid_grant`, the user logs in again). During an IdP outage clients lose access once their access token expires.
- A refresh token presented again after it was rotated ends the session (a retry of the same refresh within 30 seconds gets the same answer instead).
- A session also ends on revocation by the client, after 30 days without a refresh, when the NetBox user becomes inactive or is deleted, and when NetBox rejects the session's current token (for example because the user deleted it in NetBox). The tool call then returns a tool error asking to reconnect the client, and the next request gets 401, so the client logs in again. A 403 for a token that still exists is an ordinary NetBox permission error.
- NetBox briefly unavailable during a session: the tool call returns a tool error, nothing ends, and the same session works again once NetBox is back.
- Background jobs: hourly (and right after every session end) the server deletes the NetBox tokens of ended sessions and recovers tokens whose creation was interrupted; once a day it checks every session against NetBox, renews tokens due for renewal and removes client registrations unused for 30 days. A token that cannot be deleted for 7 days is logged as a warning once a day.

### Endpoints and request rules

- Discovery: protected-resource metadata at `/.well-known/oauth-protected-resource`, `/.well-known/oauth-protected-resource/mcp` and `<base>/.well-known/oauth-protected-resource`; authorization-server metadata at `/.well-known/oauth-authorization-server[/mcp]`, `<base>/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration/mcp` and `<base>/.well-known/openid-configuration`. There is deliberately no root `/.well-known/openid-configuration`, so a NetBox on the same host is not shadowed.
- OAuth endpoints under `<base>/oauth/` (`register`, `authorize`, `token`, `revoke`, plus the IdP `callback` and the consent page), with root aliases `/register`, `/authorize`, `/token`, `/revoke` and `/oauth/revoke` for clients that ignore the base path. The only scope is `netbox`.
- Redirect URIs a client may register: loopback `http://localhost:<port>/…` and `http://127.0.0.1:<port>/…`, the claude.ai/claude.com and ChatGPT callbacks, and `EXTRA_REDIRECT_URIS`.
- Registration is rate-limited to 10 per minute per client address, with at most 1,000 stored registrations. The limit lives in memory, per process, and is keyed by the address of the TCP peer: **behind a reverse proxy all clients share one limit**.
- `/mcp`: without a valid token every request gets 401 with a `WWW-Authenticate` challenge pointing at the metadata. Requests with an `Origin` header are only accepted from `https://claude.ai`, `https://claude.com`, `https://chatgpt.com`, the origin of `MCP_PUBLIC_URL` and `EXTRA_ORIGINS` (403 otherwise). FastMCP's own Host/Origin protection is switched off in OAuth mode; this allowlist is the only Origin check, and the `Host` header is not checked (set it at the reverse proxy). Only `POST` is served (`GET`/`DELETE` → 405); the transport is stateless.
- `GET /health` answers without a token, as in the other HTTP modes.

### Admin commands

Offline commands that work on the state file directly. Each takes the file's lock, so they refuse to run while the server is running (exit code 2). Exit codes: `0` success, `1` error (usage, configuration, state file or NetBox failure), `2` state file locked. No command prints tokens, keys or state content.

| Command | Purpose | Environment |
| --- | --- | --- |
| `netbox-mcp oauth init` | Create the empty encrypted state file; refuses an existing file. Works before the rest of the server configuration exists. | `OAUTH_STATE_PATH`, `OAUTH_STATE_KEY` |
| `netbox-mcp oauth unlink <netbox-username>` | Remove the identity link of a NetBox user (e.g. after the IdP account was replaced). Also ends that user's sessions, queues their NetBox tokens for deletion and drops the user's consent grants and open logins. The tokens are deleted by the server's cleanup at its next start. | `OAUTH_STATE_PATH`, `OAUTH_STATE_KEY` |
| `netbox-mcp oauth restore-reset` | End all sessions and queue their NetBox tokens (after a restore). Identity links, consent grants and client registrations stay. | `OAUTH_STATE_PATH`, `OAUTH_STATE_KEY` |
| `netbox-mcp oauth sweep [--apply]` | List NetBox tokens with the description prefix `NetBox MCP (OAuth) ` that the state file does not track; dry run by default, `--apply` deletes them. Prints counts only. | as above plus `NETBOX_URL`, `NETBOX_TOKEN_BROKER_TOKEN` (optional `NETBOX_VERIFY_SSL`, `NETBOX_TIMEOUT`) |

The first login of an IdP identity links it to the NetBox user ID. A later login of a different identity with the same username is denied and logged; it is never relinked automatically. Use `unlink` while the server is stopped to allow it.

### Backup and restore

Back up the state file and `OAUTH_STATE_KEY`, **stored separately**; the file is useless without the key, and the key must not travel with the file. The file contains client registrations, consent grants, identity links, sessions (with encrypted NetBox tokens and IdP refresh tokens) and the cleanup queue.

To restore:

1. Stop the server and put the backed-up file at `OAUTH_STATE_PATH` (same key).
2. `netbox-mcp oauth restore-reset`: ends every restored session, so sessions revoked after the backup cannot come back. Users authorize again; links and consent grants stay.
3. `netbox-mcp oauth sweep`, check the counts, then `netbox-mcp oauth sweep --apply`: deletes NetBox tokens created after the backup that the restored file does not know about.
4. Start the server; its cleanup deletes the tokens queued in step 2.

### Docker

The image runs as UID/GID `10001` and creates `/data` owned by that user. Mount a persistent volume there and point `OAUTH_STATE_PATH` into it; with a bind mount, make the host directory writable for UID 10001:

```sh
docker run --rm -v netbox-mcp-state:/data --env-file .env ghcr.io/mhajder/netbox-mcp oauth init
docker run -d -p 8000:8000 -v netbox-mcp-state:/data --env-file .env ghcr.io/mhajder/netbox-mcp
```

with `OAUTH_STATE_PATH=/data/oauth-state.json`. The image's entry point is `netbox-mcp`, so the admin commands are passed as arguments the same way (`oauth unlink <user>`, `oauth sweep`), while the server container is stopped.

### Logging

The HTTP access log is off in OAuth mode (request lines would contain `code` and `state`), and the HTTP client libraries log at WARNING only. The server logs its own events instead, e.g. `login_denied`, `token_refreshed`, `refresh_rejected` with a reason, `tool_call` and `session_ended`, with the NetBox username, client name, the first 8 characters of the session ID and the request path without query string. No tokens, codes, cookies or secrets are logged, also not with `AUTH_DEBUG=true`.

## 🤝 Contributing

Contributions are welcome. See [CONTRIBUTING.md](https://github.com/mhajder/netbox-mcp/blob/main/CONTRIBUTING.md) for the dev setup, checks and commit message format, and use the [issue templates](https://github.com/mhajder/netbox-mcp/issues/new/choose) for bugs and feature requests.

Found a security problem? Please report it privately as described in [SECURITY.md](https://github.com/mhajder/netbox-mcp/blob/main/SECURITY.md).

## 📜 License

MIT License - see [LICENSE](https://github.com/mhajder/netbox-mcp/blob/main/LICENSE) for details.
