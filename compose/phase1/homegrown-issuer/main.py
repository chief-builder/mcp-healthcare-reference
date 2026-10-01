"""Toy homegrown authorization server (prototype plan §2, claims contract §6.2).

Deliberately minimal: one static client, client_credentials only, RS256 JWTs.
It exists to exercise the RFC 8693 exchange leg at Keycloak — the "frozen,
sunsetting" migration story. No new features get added here by design.
"""

import base64
import os
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Header, HTTPException
from fastapi.responses import JSONResponse

ISSUER = os.environ.get("HOMEGROWN_ISSUER", "http://homegrown-issuer:7000")
AUDIENCE = os.environ.get("HOMEGROWN_AUDIENCE", "mcp-plane")
CLIENT_ID = os.environ.get("HOMEGROWN_CLIENT_ID", "svc-legacy-batch")
CLIENT_SECRET = os.environ["HOMEGROWN_CLIENT_SECRET"]
TOKEN_TTL_SECONDS = 300
KID = "homegrown-boot-key"

_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_numbers = _private_key.public_key().public_numbers()

app = FastAPI(title="homegrown-issuer")


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@app.get("/.well-known/openid-configuration")
def openid_configuration():
    return {
        "issuer": ISSUER,
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "authorization_endpoint": f"{ISSUER}/authorize",
        "response_types_supported": ["token"],
        "grant_types_supported": ["client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "subject_types_supported": ["public"],
    }


@app.get("/jwks")
def jwks():
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": _b64url_uint(_public_numbers.n),
                "e": _b64url_uint(_public_numbers.e),
            }
        ]
    }


@app.get("/userinfo")
@app.post("/userinfo")
def userinfo(authorization: str = Header(default="")):
    """Keycloak's external->internal exchange validates subject tokens here."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    try:
        claims = jwt.decode(
            authorization.removeprefix("Bearer "),
            _private_key.public_key(),
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"invalid token: {exc}")
    return {"sub": claims["sub"], "preferred_username": claims["sub"]}


@app.get("/authorize")
def authorize():
    raise HTTPException(
        status_code=501,
        detail="Interactive login was never built; this AS only mints service tokens.",
    )


@app.post("/token")
def token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: str = Form("legacy.batch"),
):
    if grant_type != "client_credentials":
        return JSONResponse(status_code=400, content={"error": "unsupported_grant_type"})
    if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
        return JSONResponse(status_code=401, content={"error": "invalid_client"})

    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": CLIENT_ID,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
        "jti": str(uuid.uuid4()),
        "scope": scope,
        "preferred_username": CLIENT_ID,
    }
    encoded = jwt.encode(
        claims,
        _private_key,
        algorithm="RS256",
        headers={"kid": KID},
    )
    return {
        "access_token": encoded,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECONDS,
        "scope": scope,
    }
