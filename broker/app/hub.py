"""Hub JWT re-validation (design §3): never trust the gateway.

The broker independently verifies issuer, signature, expiry, and tier
audience on every inbound call. (Production also verifies cnf against the
caller's mTLS cert; the lab's callers are interactive workforce tokens,
which carry no cnf — see README substitutions.)
"""

import os

import jwt
from jwt import PyJWKClient

HUB_ISSUER = os.environ.get("HUB_ISSUER", "http://localhost:8080/realms/mcp-plane")
HUB_JWKS_URI = os.environ.get(
    "HUB_JWKS_URI", "http://keycloak:8080/realms/mcp-plane/protocol/openid-connect/certs"
)
TIER_AUDIENCE = os.environ.get("HUB_TIER_AUDIENCE", "mcp://tier/internal")

_jwks = PyJWKClient(HUB_JWKS_URI, cache_keys=True)


class HubAuthError(Exception):
    pass


def validate(authorization: str | None) -> dict:
    """Return verified claims of the Bearer hub JWT or raise HubAuthError.

    Algorithms are pinned to the claims-contract §2 set (PS256 primary,
    ES256 permitted; RS256 and all HMAC forbidden). Contract shape —
    mcp_contract 1.0 and exactly one tier audience — is enforced here so a
    malformed or cross-tier token never reaches the resolve path.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HubAuthError("missing bearer token")
    token = authorization.split(None, 1)[1]
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["PS256", "ES256"],
            issuer=HUB_ISSUER,
            audience=TIER_AUDIENCE,
            leeway=30,
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
    except Exception as exc:  # jwt raises many subclasses; all mean 401
        raise HubAuthError(str(exc)) from exc
    if claims.get("mcp_contract") != "1.0":
        raise HubAuthError("unsupported mcp_contract")
    aud = claims.get("aud", [])
    aud = [aud] if isinstance(aud, str) else aud
    if sum(a.startswith("mcp://tier/") for a in aud) != 1:
        raise HubAuthError("token must carry exactly one tier audience")
    return claims
