"""Hub JWT re-validation (design §3): never trust the gateway.

The broker independently verifies issuer, signature, expiry, and tier
audience on every inbound call. (Production also verifies cnf against the
caller's mTLS cert; the lab's callers are interactive workforce tokens,
which carry no cnf — see README substitutions.)
"""

from typing import Any

import jwt
from jwt import PyJWKClient

from .config import get_settings

_jwks: Any = None  # PyJWKClient, built on first use (tests inject a fake)


def set_jwks_client(client: Any) -> None:
    """Test seam: anything with get_signing_key_from_jwt(token) -> obj.key."""
    global _jwks
    _jwks = client


def _jwks_client() -> Any:
    global _jwks
    if _jwks is None:
        _jwks = PyJWKClient(get_settings().hub_jwks_uri, cache_keys=True)
    return _jwks


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
    settings = get_settings()
    try:
        key = _jwks_client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["PS256", "ES256"],
            issuer=settings.hub_issuer,
            audience=settings.hub_tier_audience,
            leeway=30,
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
    except Exception as exc:  # noqa: BLE001 — jwt raises many subclasses; all mean 401
        raise HubAuthError(str(exc)) from exc
    if claims.get("mcp_contract") != "1.0":
        raise HubAuthError("unsupported mcp_contract")
    aud = claims.get("aud", [])
    aud = [aud] if isinstance(aud, str) else aud
    if sum(isinstance(a, str) and a.startswith("mcp://tier/") for a in aud) != 1:
        raise HubAuthError("token must carry exactly one tier audience")
    return claims
