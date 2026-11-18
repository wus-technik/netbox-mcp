"""OIDC login client for the upstream identity provider.

Used for the login (authorization code + PKCE, ID token validation) and for
the per-refresh eligibility check of design spec section 6.4, which is split
into :meth:`IdpClient.refresh` and :meth:`IdpClient.userinfo` so the caller
can persist a rotated IdP refresh token between the two calls.

Outcomes are classified into two exceptions: :class:`IdpRejected` (the IdP
answered and the identity is not acceptable: end the session) and
:class:`IdpUnavailable` (no usable answer: keep the session and retry).
Redirects are never followed. Tokens and codes are never logged.
"""

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode
from urllib.parse import urlsplit

import httpx2
import jwt

from netbox_mcp.oauth import tokens
from netbox_mcp.oauth.config import OAuthConfig

BASE_SCOPES = ("openid", "profile", "email", "offline_access")
JWKS_TTL = 300
# Clock skew tolerated between this server and the IdP for exp/iat.
LEEWAY = 60
HTTP_TIMEOUT = httpx2.Timeout(10.0)


class IdpRejected(Exception):  # noqa: N818
    """The IdP answered and the identity or credential is not acceptable."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class IdpUnavailable(Exception):  # noqa: N818
    """The IdP gave no usable answer (outage, throttling, redirect, bad body)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class IdpLogin:
    sub: str
    username: str
    groups: list[str]
    refresh_token: str


@dataclass(frozen=True)
class IdpTokens:
    access_token: str
    # None when the IdP did not rotate; the caller keeps its old refresh token.
    refresh_token: str | None


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _nonempty_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


class IdpClient:
    """Talks to the configured OIDC provider; call :meth:`discover` first."""

    def __init__(
        self,
        config: OAuthConfig,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.transport = transport
        self._endpoints: dict[str, str] | None = None
        self._jwks: dict[str, Any] | None = None
        self._jwks_fetched = 0.0

    # -- HTTP plumbing

    async def _send(
        self,
        method: str,
        url: str,
        *,
        what: str,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx2.Response:
        """One request, never following redirects.

        Transport errors, timeouts, 3xx, 403, 429 and 5xx raise
        ``IdpUnavailable``; every other status is returned for the caller.
        """
        try:
            async with httpx2.AsyncClient(
                transport=self.transport,
                follow_redirects=False,
                timeout=HTTP_TIMEOUT,
            ) as http:
                resp = await http.request(method, url, data=data, headers=headers)
        except httpx2.HTTPError as exc:
            raise IdpUnavailable(f"{what}: {type(exc).__name__}") from None
        status = resp.status_code
        if 300 <= status < 400 or status in (403, 429) or status >= 500:
            raise IdpUnavailable(f"{what}: HTTP {status}")
        return resp

    @staticmethod
    def _json(resp: httpx2.Response, what: str) -> dict[str, Any]:
        try:
            body = resp.json()
        except ValueError:
            raise IdpUnavailable(f"{what}: response is not JSON") from None
        if not isinstance(body, dict):
            raise IdpUnavailable(f"{what}: response is not a JSON object")
        return body

    def _endpoint(self, name: str) -> str:
        if self._endpoints is None:
            raise RuntimeError("IdpClient.discover() has not run")
        return self._endpoints[name]

    # -- discovery

    async def discover(self) -> None:
        """Fetch and validate the provider metadata (startup)."""
        issuer = self.config.issuer_url
        resp = await self._send(
            "GET", f"{issuer}.well-known/openid-configuration", what="discovery"
        )
        if resp.status_code != 200:
            raise IdpUnavailable(f"discovery: HTTP {resp.status_code}")
        doc = self._json(resp, "discovery")
        if doc.get("issuer") != issuer:
            raise IdpUnavailable("discovery: issuer does not match configuration")
        found: dict[str, str] = {}
        for key in (
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
        ):
            value = _nonempty_str(doc.get(key))
            if value is None or urlsplit(value).scheme != "https":
                raise IdpUnavailable(f"discovery: {key} missing or not https")
            found[key] = value
        self._endpoints = found

    # -- login

    def authorization_url(
        self, state: str, nonce: str, verifier: str, redirect_uri: str
    ) -> str:
        scopes = [*BASE_SCOPES, *self.config.extra_scopes]
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.config.client_id,
                "redirect_uri": redirect_uri,
                "scope": " ".join(dict.fromkeys(scopes)),
                "state": state,
                "nonce": nonce,
                "code_challenge": pkce_challenge(verifier),
                "code_challenge_method": "S256",
            }
        )
        base = self._endpoint("authorization_endpoint")
        return f"{base}{'&' if '?' in base else '?'}{query}"

    def _client_form(self, **fields: str) -> dict[str, str]:
        return {
            **fields,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret.get_secret_value(),
        }

    async def _token_request(self, what: str, form: dict[str, str]) -> dict[str, Any]:
        resp = await self._send(
            "POST", self._endpoint("token_endpoint"), what=what, data=form
        )
        if resp.status_code in (400, 401):
            raise IdpRejected(f"{what}: HTTP {resp.status_code}")
        if resp.status_code != 200:
            raise IdpUnavailable(f"{what}: HTTP {resp.status_code}")
        body = self._json(resp, what)
        if not _nonempty_str(body.get("access_token")):
            raise IdpRejected(f"{what}: no access_token")
        return body

    async def exchange_code(
        self, code: str, verifier: str, redirect_uri: str, nonce: str
    ) -> IdpLogin:
        body = await self._token_request(
            "code exchange",
            self._client_form(
                grant_type="authorization_code",
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=verifier,
            ),
        )
        refresh_token = _nonempty_str(body.get("refresh_token"))
        if refresh_token is None:
            raise IdpRejected("no refresh_token (offline_access not granted)")
        id_token = _nonempty_str(body.get("id_token"))
        if id_token is None:
            raise IdpRejected("no id_token")
        claims = await self._validate_id_token(id_token, nonce)
        sub = _nonempty_str(claims.get("sub"))
        username = _nonempty_str(claims.get(self.config.username_claim))
        if sub is None:
            raise IdpRejected("id_token has no sub")
        if username is None:
            raise IdpRejected(f"id_token has no {self.config.username_claim} claim")
        groups = await self.userinfo(body["access_token"], sub)
        return IdpLogin(sub, username, groups, refresh_token)

    # -- ID token

    async def _jwks_keys(self, *, force: bool = False) -> dict[str, Any]:
        stale = tokens.now() - self._jwks_fetched >= JWKS_TTL
        if self._jwks is None or stale or force:
            resp = await self._send("GET", self._endpoint("jwks_uri"), what="jwks")
            if resp.status_code != 200:
                raise IdpUnavailable(f"jwks: HTTP {resp.status_code}")
            keys = self._json(resp, "jwks").get("keys")
            if not isinstance(keys, list):
                raise IdpUnavailable("jwks: no keys array")
            self._jwks = {
                k["kid"]: k
                for k in keys
                if isinstance(k, dict) and isinstance(k.get("kid"), str)
            }
            self._jwks_fetched = tokens.now()
        return self._jwks

    async def _signing_key(self, kid: str) -> Any:
        keys = await self._jwks_keys()
        if kid not in keys:
            keys = await self._jwks_keys(force=True)  # key rotation: refetch once
        jwk = keys.get(kid)
        if jwk is None:
            raise IdpRejected("id_token signed with an unknown key")
        try:
            return jwt.PyJWK(jwk).key
        except jwt.PyJWTError:
            raise IdpRejected("id_token key is unusable") from None

    async def _validate_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError:
            raise IdpRejected("id_token is malformed") from None
        kid = header.get("kid")
        if header.get("alg") != "RS256" or not isinstance(kid, str):
            raise IdpRejected("id_token must be RS256 with a kid")
        key = await self._signing_key(kid)
        try:
            # exp/iat are checked below against tokens.now() (patchable clock).
            claims = jwt.decode(
                id_token,
                key,
                algorithms=["RS256"],
                audience=self.config.client_id,
                issuer=self.config.issuer_url,
                options={
                    "require": ["exp", "iss", "aud", "sub"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.PyJWTError:
            raise IdpRejected("id_token validation failed") from None
        current = tokens.now()
        exp = claims["exp"]
        if isinstance(exp, bool) or not isinstance(exp, int | float):
            raise IdpRejected("id_token exp is not a number")
        if exp + LEEWAY <= current:
            raise IdpRejected("id_token expired")
        iat = claims.get("iat")
        if (
            isinstance(iat, int | float)
            and not isinstance(iat, bool)
            and iat - LEEWAY > current
        ):
            raise IdpRejected("id_token issued in the future")
        got = claims.get("nonce")
        if not isinstance(got, str) or not hmac.compare_digest(got, nonce):
            raise IdpRejected("id_token nonce mismatch")
        return claims

    # -- per-refresh eligibility check (spec 6.4)

    async def refresh(self, refresh_token: str) -> IdpTokens:
        """Refresh the IdP token. Rotation is reported, not persisted here."""
        body = await self._token_request(
            "token refresh",
            self._client_form(grant_type="refresh_token", refresh_token=refresh_token),
        )
        return IdpTokens(body["access_token"], _nonempty_str(body.get("refresh_token")))

    async def userinfo(self, access_token: str, expected_sub: str) -> list[str]:
        """Return the user's groups; reject on 401, bad groups or sub mismatch."""
        resp = await self._send(
            "GET",
            self._endpoint("userinfo_endpoint"),
            what="userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status_code == 401:
            raise IdpRejected("userinfo: HTTP 401")
        if resp.status_code != 200:
            raise IdpUnavailable(f"userinfo: HTTP {resp.status_code}")
        body = self._json(resp, "userinfo")
        sub = body.get("sub")
        if not isinstance(sub, str) or not hmac.compare_digest(sub, expected_sub):
            raise IdpRejected("userinfo sub does not match")
        groups = body.get(self.config.groups_claim)
        if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
            raise IdpRejected(f"userinfo has no {self.config.groups_claim} list")
        return list(groups)
