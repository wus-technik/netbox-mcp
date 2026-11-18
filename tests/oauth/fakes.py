"""In-process fakes for the OAuth tests: an OIDC identity provider and a stateful
NetBox users/tokens API. Both expose an ``httpx2.MockTransport`` (``.transport``),
record every request and let a test program failures. Example hosts only.
"""

import base64
import calendar
import hashlib
import json
import secrets
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import ClassVar
from urllib.parse import parse_qs
from urllib.parse import urlencode

import httpx2
from joserfc import jwt
from joserfc.jwk import RSAKey

HTML_LOGIN = "<html><body><form action='/login'>Sign in</form></body></html>"
_RSA_KEY: RSAKey | None = None


def _rsa_key() -> RSAKey:
    """One RSA key per test process; generating it per test would be slow."""
    global _RSA_KEY
    if _RSA_KEY is None:
        _RSA_KEY = RSAKey.generate_key(
            2048, parameters={"kid": "test-key", "use": "sig"}
        )
    return _RSA_KEY


def _html() -> httpx2.Response:
    return httpx2.Response(200, text=HTML_LOGIN, headers={"content-type": "text/html"})


def _malformed() -> httpx2.Response:
    return httpx2.Response(
        200, content=b'{"truncated": ', headers={"content-type": "application/json"}
    )


def _bearer(request: httpx2.Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    return value if scheme.lower() in ("bearer", "token") and value else None


# --------------------------------------------------------------------------- IdP


@dataclass
class IdPRequest:
    endpoint: str
    method: str
    path: str
    query: dict[str, str]
    form: dict[str, str]
    headers: httpx2.Headers


class FakeIdP:
    """OpenID provider with authorize, token (code + rotating refresh), userinfo, JWKS.

    Outcome knobs (``code_outcome``, ``refresh_outcome``, ``userinfo_outcome``,
    ``jwks_outcome``, ``discovery_outcome``) take ``"ok"`` or one of: an HTTP
    status int (400, 401, 403, 429, 503, ...), ``"timeout"`` (raises
    ``httpx2.ReadTimeout``), ``"html"`` (200 login page), ``"malformed"`` (200,
    broken JSON), ``"redirect"`` (302 to a login page), and for the token
    endpoint ``"no_refresh_token"`` (success without ``refresh_token``) or
    ``"no_access_token"``. A failing outcome never consumes the presented code
    or refresh token. ``*_outcome`` persists until reset; ``fail_next(endpoint,
    outcome, times)`` queues one-shot outcomes ahead of it.
    """

    issuer = "https://idp.example.com/application/o/test/"
    USERS: ClassVar[dict[str, dict[str, Any]]] = {
        "alice": {"sub": "sub-alice", "groups": ["netbox-users"]},
        "bob": {"sub": "sub-bob", "groups": []},
        "carol": {"sub": "sub-carol", "groups": ["netbox-users"]},
    }

    def __init__(
        self,
        client_id: str = "netbox-mcp",
        client_secret: str = "client-secret",
        *,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.now = now
        self.login_user = "alice"
        self.access_ttl = 3600
        self.users = {
            k: {**v, "groups": list(v["groups"])} for k, v in self.USERS.items()
        }
        self.code_outcome: Any = "ok"
        self.refresh_outcome: Any = "ok"
        self.userinfo_outcome: Any = "ok"
        self.jwks_outcome: Any = "ok"
        self.discovery_outcome: Any = "ok"
        self.authorize_outcome: Any = "ok"
        self.userinfo_omit_groups = False
        self.userinfo_sub: str | None = None
        self.userinfo_groups: list[str] | None = None
        self.calls: Counter[str] = Counter()
        self.requests: list[IdPRequest] = []
        self.codes: dict[str, dict[str, Any]] = {}
        self.refresh_tokens: dict[str, str] = {}
        self.access_tokens: dict[str, str] = {}
        self._queued: dict[str, list[Any]] = {}
        self.transport = httpx2.MockTransport(self.handle)

    # -- configuration helpers
    def fail_next(self, endpoint: str, outcome: Any, times: int = 1) -> None:
        """Queue ``times`` one-shot outcomes for ``endpoint`` (token, refresh, ...)."""
        self._queued.setdefault(endpoint, []).extend([outcome] * times)

    def revoke_access_tokens(self) -> None:
        self.access_tokens.clear()

    def revoke_refresh_tokens(self) -> None:
        self.refresh_tokens.clear()

    def requests_to(self, endpoint: str) -> list[IdPRequest]:
        return [r for r in self.requests if r.endpoint == endpoint]

    @property
    def jwks(self) -> dict[str, Any]:
        return {"keys": [_rsa_key().as_dict(private=False)]}

    # -- helpers
    def _outcome(self, endpoint: str, default: Any) -> Any:
        queue = self._queued.get(endpoint)
        return queue.pop(0) if queue else default

    def _failure(self, outcome: Any, request: httpx2.Request) -> httpx2.Response | None:
        if outcome in ("ok", "no_refresh_token", "no_access_token", None):
            return None
        if outcome == "timeout":
            raise httpx2.ReadTimeout("fake IdP timeout", request=request)
        if outcome == "html":
            return _html()
        if outcome == "malformed":
            return _malformed()
        if outcome == "redirect":
            return httpx2.Response(
                302, headers={"location": "https://idp.example.com/login/"}
            )
        status = int(outcome)
        headers = {"retry-after": "1"} if status == 429 else {}
        error = {400: "invalid_grant", 401: "invalid_client"}.get(
            status, "server_error"
        )
        return httpx2.Response(status, json={"error": error}, headers=headers)

    def _id_token(self, username: str, nonce: str | None) -> str:
        now = int(self.now())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": self.users[username]["sub"],
            "preferred_username": username,
            "iat": now,
            "exp": now + self.access_ttl,
        }
        if nonce:
            claims["nonce"] = nonce
        return jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, _rsa_key())

    def _client_ok(self, request: httpx2.Request, form: dict[str, str]) -> bool:
        cid, secret = form.get("client_id"), form.get("client_secret")
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            raw = base64.b64decode(auth[6:]).decode()
            cid, _, secret = raw.partition(":")
        return cid == self.client_id and secret == self.client_secret

    def _issue(
        self, username: str, nonce: str | None, *, with_refresh: bool, with_access: bool
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "token_type": "Bearer",
            "expires_in": self.access_ttl,
            "scope": "openid profile groups offline_access",
            "id_token": self._id_token(username, nonce),
        }
        if with_access:
            access = secrets.token_urlsafe(24)
            self.access_tokens[access] = username
            body["access_token"] = access
        if with_refresh:
            refresh = secrets.token_urlsafe(24)
            self.refresh_tokens[refresh] = username
            body["refresh_token"] = refresh
        return body

    # -- request handling
    def handle(self, request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        base = httpx2.URL(self.issuer).path
        route = path[len(base) :] if path.startswith(base) else None
        names = {
            ".well-known/openid-configuration": "discovery",
            "authorize": "authorize",
            "token": "token",
            "userinfo": "userinfo",
            "jwks": "jwks",
        }
        endpoint = names.get(route.rstrip("/") if route else "")
        form = {
            k: v[0]
            for k, v in parse_qs(
                request.content.decode() if request.content else ""
            ).items()
        }
        self.requests.append(
            IdPRequest(
                endpoint or "unknown",
                request.method,
                path,
                dict(request.url.params),
                form,
                request.headers,
            )
        )
        if endpoint is None:
            return httpx2.Response(404, json={"error": "not_found"})
        self.calls[endpoint] += 1
        if endpoint == "token":
            return self._token(request, form)
        return getattr(self, f"_{endpoint}")(request)

    def _discovery(self, request: httpx2.Request) -> httpx2.Response:
        if failed := self._failure(
            self._outcome("discovery", self.discovery_outcome), request
        ):
            return failed
        i = self.issuer
        return httpx2.Response(
            200,
            json={
                "issuer": i,
                "authorization_endpoint": f"{i}authorize/",
                "token_endpoint": f"{i}token/",
                "userinfo_endpoint": f"{i}userinfo/",
                "jwks_uri": f"{i}jwks/",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "subject_types_supported": ["public"],
                "code_challenge_methods_supported": ["S256"],
            },
        )

    def _jwks(self, request: httpx2.Request) -> httpx2.Response:
        if failed := self._failure(self._outcome("jwks", self.jwks_outcome), request):
            return failed
        return httpx2.Response(200, json=self.jwks)

    def _authorize(self, request: httpx2.Request) -> httpx2.Response:
        if failed := self._failure(
            self._outcome("authorize", self.authorize_outcome), request
        ):
            return failed
        q = dict(request.url.params)
        if q.get("client_id") != self.client_id or not q.get("redirect_uri"):
            return httpx2.Response(400, json={"error": "invalid_request"})
        code = secrets.token_urlsafe(16)
        self.codes[code] = {
            "user": self.login_user,
            "nonce": q.get("nonce"),
            "redirect_uri": q["redirect_uri"],
            "challenge": q.get("code_challenge"),
        }
        params = {"code": code}
        if "state" in q:
            params["state"] = q["state"]
        sep = "&" if "?" in q["redirect_uri"] else "?"
        return httpx2.Response(
            302, headers={"location": f"{q['redirect_uri']}{sep}{urlencode(params)}"}
        )

    def _token(self, request: httpx2.Request, form: dict[str, str]) -> httpx2.Response:
        if not self._client_ok(request, form):
            return httpx2.Response(401, json={"error": "invalid_client"})
        grant = form.get("grant_type")
        if grant == "authorization_code":
            return self._code_grant(request, form)
        if grant == "refresh_token":
            return self._refresh_grant(request, form)
        return httpx2.Response(400, json={"error": "unsupported_grant_type"})

    def _code_grant(
        self, request: httpx2.Request, form: dict[str, str]
    ) -> httpx2.Response:
        outcome = self._outcome("token", self.code_outcome)
        if failed := self._failure(outcome, request):
            return failed
        entry = self.codes.pop(form.get("code", ""), None)
        if entry is None or entry["redirect_uri"] != form.get("redirect_uri"):
            return httpx2.Response(400, json={"error": "invalid_grant"})
        if entry["challenge"]:
            digest = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
            if (
                base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                != entry["challenge"]
            ):
                return httpx2.Response(400, json={"error": "invalid_grant"})
        body = self._issue(
            entry["user"],
            entry["nonce"],
            with_refresh=outcome != "no_refresh_token",
            with_access=outcome != "no_access_token",
        )
        return httpx2.Response(200, json=body)

    def _refresh_grant(
        self, request: httpx2.Request, form: dict[str, str]
    ) -> httpx2.Response:
        outcome = self._outcome("refresh", self.refresh_outcome)
        if failed := self._failure(outcome, request):
            return failed
        username = self.refresh_tokens.pop(form.get("refresh_token", ""), None)
        if username is None:
            return httpx2.Response(400, json={"error": "invalid_grant"})
        body = self._issue(
            username,
            None,
            with_refresh=outcome != "no_refresh_token",
            with_access=outcome != "no_access_token",
        )
        if outcome == "no_refresh_token":
            # The IdP did not rotate: the presented token stays usable.
            self.refresh_tokens[form["refresh_token"]] = username
        return httpx2.Response(200, json=body)

    def _userinfo(self, request: httpx2.Request) -> httpx2.Response:
        if failed := self._failure(
            self._outcome("userinfo", self.userinfo_outcome), request
        ):
            return failed
        username = self.access_tokens.get(_bearer(request) or "")
        if username is None:
            return httpx2.Response(401, json={"error": "invalid_token"})
        user = self.users[username]
        body: dict[str, Any] = {
            "sub": self.userinfo_sub or user["sub"],
            "preferred_username": username,
        }
        if not self.userinfo_omit_groups:
            body["groups"] = (
                user["groups"] if self.userinfo_groups is None else self.userinfo_groups
            )
        return httpx2.Response(200, json=body)


# ----------------------------------------------------------------------- NetBox


@dataclass
class NetBoxRequest:
    method: str
    path: str
    query: list[tuple[str, str]]
    headers: httpx2.Headers
    json: Any
    endpoint: str = ""
    authenticated_as: str | None = None  # username, "service" or None
    status: int | None = None
    bearer: str | None = None

    @property
    def branch(self) -> str | None:
        return self.headers.get("x-netbox-branch")


@dataclass
class _Failure:
    mode: Any
    remaining: int | None
    status: int | None = None


@dataclass
class _User:
    id: int
    username: str
    is_active: bool = True
    is_superuser: bool = False
    groups: list[str] = field(default_factory=list)


class FakeNetBoxTokens:
    """Stateful NetBox 4.x users and v2 tokens API (``/api/users/users|tokens/``).

    Issued tokens authenticate later requests (``Authorization: Bearer
    nbt_<key>.<token>``); the broker credential ``service_token`` always does.
    Any other ``/api/...`` path answers a small canned object for authenticated
    callers, which is enough to test "the tool call used the session token".
    Endpoint names for ``fail``: ``users.list``, ``users.get``, ``tokens.list``,
    ``tokens.create``, ``tokens.get``, ``tokens.update``, ``tokens.delete``,
    ``other``.
    """

    base_url = "https://netbox.example.com"

    def __init__(
        self,
        service_token: str = "nbt_broker.secret",
        *,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.service_token = service_token
        self.now = now
        self.page_size = 50
        self.invalid_token_status = 403
        self.users: dict[int, _User] = {}
        self.tokens: dict[int, dict[str, Any]] = {}
        self._next_token_id = 1
        self.requests: list[NetBoxRequest] = []
        self.failures: dict[str, list[_Failure]] = {}
        self.transport = httpx2.MockTransport(self.handle)
        self.add_user("alice")
        self.add_user("bob")
        self.add_user("admin", is_superuser=True)
        self.add_user("dave", is_active=False)
        # carol has an IdP identity but deliberately no NetBox account.

    # -- state helpers
    def add_user(self, username: str, **kwargs: Any) -> _User:
        user = _User(id=len(self.users) + 1, username=username, **kwargs)
        self.users[user.id] = user
        return user

    def user_id(self, username: str) -> int:
        return next(u.id for u in self.users.values() if u.username == username)

    @property
    def usernames(self) -> list[str]:
        return [u.username for u in self.users.values()]

    def add_token(
        self,
        username: str,
        *,
        description: str = "",
        write_enabled: bool = True,
        expires: str | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Create a token directly (no request recorded); returns the record,
        including ``bearer`` (``nbt_<key>.<token>``)."""
        tid = self._next_token_id
        self._next_token_id += 1
        key = secrets.token_hex(6)
        secret = secrets.token_hex(20)
        record = {
            "id": tid,
            "user": self.user_id(username),
            "key": key,
            "token": secret,
            "description": description,
            "write_enabled": write_enabled,
            "enabled": enabled,
            "expires": expires,
            "created": self._iso(self.now()),
        }
        self.tokens[tid] = record
        return record

    @staticmethod
    def bearer_for(record: dict[str, Any]) -> str:
        return f"nbt_{record['key']}.{record['token']}"

    @staticmethod
    def _iso(ts: float) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))

    def delete_token(self, token_id: int) -> None:
        self.tokens.pop(token_id, None)

    def disable_token(self, token_id: int) -> None:
        self.tokens[token_id]["enabled"] = False

    def expire_token(self, token_id: int) -> None:
        self.tokens[token_id]["expires"] = self._iso(self.now() - 60)

    def sent(self, method: str, endpoint: str | None = None) -> list[NetBoxRequest]:
        return [
            r
            for r in self.requests
            if r.method == method and (endpoint is None or r.endpoint == endpoint)
        ]

    def fail(self, endpoint: str, mode: Any, *, times: int | None = None) -> None:
        """Make ``endpoint`` fail ``times`` times (``None``: until ``clear_failures``).

        ``mode``: ``"timeout"``, an HTTP status int (5xx, 429 with Retry-After,
        4xx), ``"html"`` (200 login page), ``"malformed"`` (200, broken JSON) or
        ``"commit_then_timeout"`` (create/delete takes effect, then the client
        sees a timeout).
        """
        self.failures.setdefault(endpoint, []).append(_Failure(mode, times))

    def clear_failures(self) -> None:
        self.failures.clear()

    def _take_failure(self, endpoint: str) -> Any:
        queue = self.failures.get(endpoint)
        if not queue:
            return None
        failure = queue[0]
        if failure.remaining is not None:
            failure.remaining -= 1
            if failure.remaining <= 0:
                queue.pop(0)
        return failure.mode

    # -- auth
    def _authenticate(self, request: httpx2.Request) -> str | None:
        value = _bearer(request)
        if value is None:
            return None
        if value == self.service_token:
            return "service"
        if not value.startswith("nbt_") or "." not in value:
            return None
        key, _, secret = value[4:].partition(".")
        for record in self.tokens.values():
            if record["key"] == key and secrets.compare_digest(record["token"], secret):
                if not record["enabled"] or self._is_expired(record):
                    return None
                user = self.users[record["user"]]
                return user.username if user.is_active else None
        return None

    def _is_expired(self, record: dict[str, Any]) -> bool:
        exp = record["expires"]
        if not exp:
            return False
        parsed = calendar.timegm(time.strptime(exp[:19], "%Y-%m-%dT%H:%M:%S"))
        return parsed <= self.now()

    # -- routing
    def _classify(self, method: str, path: str) -> tuple[str, int | None]:
        parts = [p for p in path.split("/") if p]
        if parts[:2] == ["api", "users"] and len(parts) in (3, 4):
            kind = {"users": "users", "tokens": "tokens"}.get(parts[2])
            if kind:
                pk = int(parts[3]) if len(parts) == 4 and parts[3].isdigit() else None
                if len(parts) == 3:
                    return f"{kind}.{'create' if method == 'POST' else 'list'}", None
                if pk is not None:
                    verb = {
                        "GET": "get",
                        "PATCH": "update",
                        "PUT": "update",
                        "DELETE": "delete",
                    }
                    return f"{kind}.{verb.get(method, 'get')}", pk
        return "other", None

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        endpoint, pk = self._classify(request.method, request.url.path)
        body = json.loads(request.content) if request.content else None
        record = NetBoxRequest(
            request.method,
            request.url.path,
            list(request.url.params.multi_items()),
            request.headers,
            body,
            endpoint=endpoint,
            bearer=_bearer(request),
        )
        self.requests.append(record)
        mode = self._take_failure(endpoint)
        if mode is not None and mode != "commit_then_timeout":
            response = self._failing(mode, request)
        else:
            response = self._serve(request, record, endpoint, pk, body)
            if mode == "commit_then_timeout":
                record.status = None
                raise httpx2.ReadTimeout("fake NetBox timeout", request=request)
        record.status = response.status_code
        return response

    def _failing(self, mode: Any, request: httpx2.Request) -> httpx2.Response:
        if mode == "timeout":
            raise httpx2.ReadTimeout("fake NetBox timeout", request=request)
        if mode == "html":
            return _html()
        if mode == "malformed":
            return _malformed()
        status = int(mode)
        headers = {"retry-after": "1"} if status == 429 else {}
        return httpx2.Response(
            status, json={"detail": f"fake {status}"}, headers=headers
        )

    def _serve(
        self,
        request: httpx2.Request,
        record: NetBoxRequest,
        endpoint: str,
        pk: int | None,
        body: Any,
    ) -> httpx2.Response:
        who = self._authenticate(request)
        record.authenticated_as = who
        if who is None:
            status = 401 if _bearer(request) is None else self.invalid_token_status
            detail = (
                "Authentication credentials were not provided."
                if status == 401 and _bearer(request) is None
                else "Invalid v2 token"
            )
            return httpx2.Response(status, json={"detail": detail})
        if endpoint == "other":
            return httpx2.Response(200, json={"count": 0, "next": None, "results": []})
        params = dict(request.url.params.multi_items())
        if endpoint == "users.list":
            return self._page(
                request, [self._user_json(u) for u in self._filter_users(params)]
            )
        if endpoint == "users.get":
            user = self.users.get(pk or 0)
            return self._one(self._user_json(user) if user else None)
        if endpoint == "tokens.list":
            return self._page(
                request, [self._token_json(t) for t in self._filter_tokens(params)]
            )
        if endpoint == "tokens.create":
            return self._create_token(body)
        token = self.tokens.get(pk or 0)
        if endpoint == "tokens.get":
            return self._one(self._token_json(token) if token else None)
        if token is None:
            return httpx2.Response(404, json={"detail": "Not found."})
        if endpoint == "tokens.delete":
            del self.tokens[token["id"]]
            return httpx2.Response(204)
        for name in ("enabled", "description", "write_enabled", "expires"):
            if isinstance(body, dict) and name in body:
                token[name] = body[name]
        return httpx2.Response(200, json=self._token_json(token))

    @staticmethod
    def _one(payload: Any) -> httpx2.Response:
        if payload is None:
            return httpx2.Response(404, json={"detail": "Not found."})
        return httpx2.Response(200, json=payload)

    def _create_token(self, body: Any) -> httpx2.Response:
        if not isinstance(body, dict) or body.get("user") not in self.users:
            return httpx2.Response(
                400, json={"user": ["Invalid pk - object does not exist."]}
            )
        record = self.add_token(
            self.users[body["user"]].username,
            description=body.get("description", ""),
            write_enabled=body.get("write_enabled", True),
            expires=body.get("expires"),
            enabled=body.get("enabled", True),
        )
        # NetBox shows the plaintext secret only in the create response.
        return httpx2.Response(
            201, json={**self._token_json(record), "token": record["token"]}
        )

    def _user_json(self, user: _User) -> dict[str, Any]:
        return {
            "id": user.id,
            "username": user.username,
            "is_active": user.is_active,
            "is_superuser": user.is_superuser,
            "groups": [{"name": g} for g in user.groups],
            "display": user.username,
        }

    def _token_json(self, token: dict[str, Any]) -> dict[str, Any]:
        user = self.users[token["user"]]
        return {
            "id": token["id"],
            "url": f"{self.base_url}/api/users/tokens/{token['id']}/",
            "display": f"{token['key']}",
            "user": {"id": user.id, "username": user.username},
            "version": 2,
            "key": token["key"],
            "description": token["description"],
            "write_enabled": token["write_enabled"],
            "enabled": token["enabled"],
            "expires": token["expires"],
            "created": token["created"],
            "last_used": None,
        }

    def _filter_users(self, params: dict[str, str]) -> list[_User]:
        out = list(self.users.values())
        if "username" in params:
            out = [u for u in out if u.username == params["username"]]
        if "id" in params:
            out = [u for u in out if str(u.id) == params["id"]]
        if "is_active" in params:
            want = params["is_active"].lower() == "true"
            out = [u for u in out if u.is_active == want]
        if "q" in params:
            out = [u for u in out if params["q"].lower() in u.username.lower()]
        return out

    def _filter_tokens(self, params: dict[str, str]) -> list[dict[str, Any]]:
        out = list(self.tokens.values())
        if "user_id" in params:
            out = [t for t in out if str(t["user"]) == params["user_id"]]
        if "user" in params:
            out = [t for t in out if self.users[t["user"]].username == params["user"]]
        if "username" in params:
            out = [
                t for t in out if self.users[t["user"]].username == params["username"]
            ]
        if "description" in params:
            out = [t for t in out if t["description"] == params["description"]]
        if "description__ic" in params:
            needle = params["description__ic"].lower()
            out = [t for t in out if needle in t["description"].lower()]
        if "enabled" in params:
            want = params["enabled"].lower() == "true"
            out = [t for t in out if t["enabled"] == want]
        if "id" in params:
            out = [t for t in out if str(t["id"]) == params["id"]]
        return out

    def _page(
        self, request: httpx2.Request, items: list[dict[str, Any]]
    ) -> httpx2.Response:
        q = dict(request.url.params.multi_items())
        limit = int(q.get("limit", self.page_size))
        offset = int(q.get("offset", 0))
        chunk = items[offset : offset + limit]
        nxt = None
        if offset + limit < len(items):
            nq = {**q, "limit": limit, "offset": offset + limit}
            nxt = f"{self.base_url}{request.url.path}?{urlencode(nq)}"
        prev = None
        if offset > 0:
            pq = {**q, "limit": limit, "offset": max(offset - limit, 0)}
            prev = f"{self.base_url}{request.url.path}?{urlencode(pq)}"
        return httpx2.Response(
            200,
            json={"count": len(items), "next": nxt, "previous": prev, "results": chunk},
        )
