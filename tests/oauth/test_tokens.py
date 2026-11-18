import base64

import pytest
from joserfc import jwk
from joserfc import jwt

from netbox_mcp.oauth.tokens import AccessTokens
from netbox_mcp.oauth.tokens import InvalidToken
from netbox_mcp.oauth.tokens import hash_secret
from netbox_mcp.oauth.tokens import new_secret


def _key(config):
    return jwk.import_key(
        base64.b64decode(config.signing_key.get_secret_value()), "oct"
    )


def _sign(config, **overrides):
    claims = {
        "iss": config.public_url,
        "aud": config.public_url,
        "sid": "s1",
        "client_id": "c1",
        "exp": 1_900_000_000,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode({"alg": "HS256"}, claims, _key(config), algorithms=["HS256"])


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def test_secret_helpers():
    a, b = new_secret(), new_secret()
    assert a != b
    assert len(a) == 43
    assert len(hash_secret(a)) == 64
    assert hash_secret(a) == hash_secret(a)


def test_access_token_claims(oauth_config, clock):
    tokens = AccessTokens(oauth_config)
    token, expires_in = tokens.issue("s1", "user-1", "c1")
    assert expires_in == 3600
    claims = jwt.decode(token, _key(oauth_config), algorithms=["HS256"]).claims
    assert claims["iss"] == claims["aud"] == oauth_config.public_url
    assert claims["sub"] == "user-1"
    assert claims["sid"] == "s1"
    assert claims["client_id"] == "c1"
    assert claims["scope"] == "netbox"
    assert claims["exp"] - claims["iat"] == 3600
    assert abs(claims["iat"] - clock()) <= 2
    assert claims["jti"]
    assert tokens.verify(token)["sid"] == "s1"


@pytest.mark.usefixtures("clock")
def test_verify_rejects_wrong_aud_alg_none_expired_missing_sid(oauth_config):
    tokens = AccessTokens(oauth_config)
    assert tokens.verify(_sign(oauth_config))["sid"] == "s1"
    none_token = (
        _b64(b'{"alg":"none"}')
        + "."
        + _b64(
            b'{"iss":"https://mcp.example.com/mcp","aud":"https://mcp.example.com/mcp",'
            b'"sid":"s","client_id":"c","exp":1900000000}'
        )
        + "."
    )
    bad = [
        _sign(oauth_config, aud="https://other.example.com"),
        _sign(oauth_config, iss="https://other.example.com"),
        _sign(oauth_config, sid=None),
        _sign(oauth_config, client_id=None),
        _sign(oauth_config, exp=None),
        _sign(oauth_config, exp=1_700_000_000),
        none_token,
        "garbage",
    ]
    for token in bad:
        with pytest.raises(InvalidToken):
            tokens.verify(token)


def test_expiry_uses_clock_and_allow_expired(oauth_config, clock):
    tokens = AccessTokens(oauth_config)
    token, _ = tokens.issue("s1", "u", "c1")
    clock.advance(3599)
    tokens.verify(token)
    clock.advance(1)
    with pytest.raises(InvalidToken):
        tokens.verify(token)
    assert tokens.verify(token, allow_expired=True)["sid"] == "s1"


@pytest.mark.usefixtures("clock")
def test_allow_expired_never_bypasses_signature(oauth_config):
    tokens = AccessTokens(oauth_config)
    token, _ = tokens.issue("s1", "u", "c1")
    head, payload, sig = token.split(".")
    flipped = "A" if sig[-1] != "A" else "B"
    for forged in (f"{head}.{payload}.{sig[:-1]}{flipped}", f"{head}.{payload}."):
        with pytest.raises(InvalidToken):
            tokens.verify(forged, allow_expired=True)
    with pytest.raises(InvalidToken):
        tokens.verify(_sign(oauth_config, aud="x"), allow_expired=True)
    with pytest.raises(InvalidToken):
        tokens.verify(_sign(oauth_config, sid=None), allow_expired=True)


def test_allow_expired_still_requires_exp(oauth_config):
    tokens = AccessTokens(oauth_config)
    with pytest.raises(InvalidToken):
        tokens.verify(_sign(oauth_config, exp=None), allow_expired=True)
