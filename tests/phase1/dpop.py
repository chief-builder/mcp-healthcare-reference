"""DPoP (RFC 9449) proof minting for the test harness.

Mints ES256 proofs with PyJWT[crypto] (already in requirements.txt) — no new
dependency. Every field is overridable so the phase-7 red-team probes can tamper
htm/htu/iat/ath/jti/typ/jwk independently. The RFC 7638 `jkt` computed here is
the same shape as tests/phase4/conftest.py's x5t#S256 (canonical JSON → SHA-256
→ base64url no padding).
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import ec


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _coord(value: int) -> str:
    # P-256 field elements are 32 bytes, big-endian, left-zero-padded.
    return _b64url(value.to_bytes(32, "big"))


def make_key() -> ec.EllipticCurvePrivateKey:
    """A fresh EC P-256 private key — one per simulated client."""
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    """The public JWK (the only members RFC 7638 uses for the thumbprint)."""
    numbers = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": _coord(numbers.x), "y": _coord(numbers.y)}


def jkt(key: ec.EllipticCurvePrivateKey) -> str:
    """RFC 7638 JWK thumbprint — the value Keycloak stamps into cnf.jkt."""
    j = public_jwk(key)
    canonical = json.dumps(
        {"crv": j["crv"], "kty": j["kty"], "x": j["x"], "y": j["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return _b64url(hashlib.sha256(canonical.encode()).digest())


def ath(access_token: str) -> str:
    """base64url(SHA-256(access token)) — binds a proof to one token."""
    return _b64url(hashlib.sha256(access_token.encode()).digest())


def proof(
    key: ec.EllipticCurvePrivateKey,
    htm: str,
    htu: str,
    *,
    access_token: str | None = None,
    ath_value: str | None = None,
    iat: int | None = None,
    jti: str | None = None,
    typ: str = "dpop+jwt",
    jwk_override: dict | None = None,
) -> str:
    """Mint a DPoP proof JWT. Pass access_token for a correct ath, or ath_value
    to force a wrong one; every header/claim is overridable for tampering."""
    payload: dict = {
        "htm": htm,
        "htu": htu,
        "iat": iat if iat is not None else int(time.time()),
        "jti": jti if jti is not None else uuid.uuid4().hex,
    }
    if ath_value is not None:
        payload["ath"] = ath_value
    elif access_token is not None:
        payload["ath"] = ath(access_token)

    headers = {"typ": typ, "jwk": jwk_override if jwk_override is not None else public_jwk(key)}
    return jwt.encode(payload, key, algorithm="ES256", headers=headers)
