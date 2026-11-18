"""Access tokens (HS256 JWT) and secret helpers.

fastmcp's ``JWTIssuer`` stamps ``iat``/``exp`` from ``time.time()`` and its
``verify_token`` cannot check an expired token's other claims, so this module
signs and decodes with the same library (``joserfc``), key import and
algorithm, but takes its timestamps from :func:`now`. That makes expiry
testable and lets ``allow_expired`` verify everything except ``exp``.
"""

import base64
import hashlib
import secrets
import time
import uuid
from typing import Any

from joserfc import jwk
from joserfc import jwt
from joserfc.errors import JoseError

from netbox_mcp.oauth.config import OAuthConfig

ACCESS_TOKEN_TTL = 3600
SCOPE = "netbox"


def now() -> float:
    """Current time in seconds; all expiry logic in this package uses it."""
    return time.time()


def new_secret() -> str:
    """32 random bytes, base64url without padding."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def hash_secret(value: str) -> str:
    """SHA-256 hex digest of a secret."""
    return hashlib.sha256(value.encode()).hexdigest()


class InvalidToken(Exception):  # noqa: N818 - name fixed by the interface
    """The presented access token is not valid."""


class AccessTokens:
    def __init__(self, config: OAuthConfig) -> None:
        self._issuer = config.public_url
        key = base64.b64decode(config.signing_key.get_secret_value())
        self._key = jwk.import_key(key, "oct")

    def issue(self, sid: str, user_key: str, client_id: str) -> tuple[str, int]:
        """Return ``(token, expires_in)``."""
        issued = int(now())
        claims: dict[str, Any] = {
            "iss": self._issuer,
            "aud": self._issuer,
            "sub": user_key,
            "sid": sid,
            "client_id": client_id,
            "scope": SCOPE,
            "jti": uuid.uuid4().hex,
            "iat": issued,
            "exp": issued + ACCESS_TOKEN_TTL,
        }
        token = jwt.encode(
            {"alg": "HS256", "typ": "JWT"}, claims, self._key, algorithms=["HS256"]
        )
        return token, ACCESS_TOKEN_TTL

    def verify(self, token: str, *, allow_expired: bool = False) -> dict[str, Any]:
        """Verify signature, alg, iss, aud, sid, client_id and, unless
        ``allow_expired``, a present and future ``exp``.

        Raises:
            InvalidToken: On any failure.
        """
        try:
            decoded = jwt.decode(token, self._key, algorithms=["HS256"])
        except (JoseError, ValueError, TypeError) as exc:
            raise InvalidToken("token signature or format invalid") from exc
        if decoded.header.get("alg") != "HS256":
            raise InvalidToken("unexpected algorithm")
        claims: dict[str, Any] = decoded.claims
        if claims.get("iss") != self._issuer or claims.get("aud") != self._issuer:
            raise InvalidToken("wrong issuer or audience")
        for name in ("sid", "client_id"):
            value = claims.get(name)
            if not isinstance(value, str) or not value:
                raise InvalidToken(f"missing {name}")
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise InvalidToken("token without numeric exp")
        if not allow_expired and exp <= now():
            raise InvalidToken("token expired")
        return claims
