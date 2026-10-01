"""Hub JWT re-validation (design §3, claims contract §2/§3): positive and
negative cases against locally generated PS256/ES256 keys."""

import time

import jwt
import pytest

from app.hub import HubAuthError, validate
from tests.conftest import TIER_AUD


@pytest.mark.parametrize("alg", ["PS256", "ES256"])
def test_contract_algorithms_are_accepted(keys, alg):
    claims = validate(f"Bearer {keys.mint(alg=alg)}")
    assert claims["sub"] == "alice-sub"


def test_scheme_is_case_insensitive(keys):
    assert validate(f"bearer {keys.mint()}")["mcp_contract"] == "1.0"


@pytest.mark.parametrize("header", [None, "", "Basic abc", "DPoP xyz"])
def test_missing_or_non_bearer_header_is_rejected(keys, header):
    with pytest.raises(HubAuthError, match="missing bearer token"):
        validate(header)


def test_rs256_is_forbidden_even_with_a_trusted_key(keys):
    # Same trusted RSA key, forbidden algorithm (contract §2: RS256 is out).
    with pytest.raises(HubAuthError):
        validate(f"Bearer {keys.mint(alg='RS256', kid='ps')}")


def test_hmac_token_is_rejected(keys):
    token = jwt.encode(
        {"sub": "x", "mcp_contract": "1.0"}, "k" * 32, algorithm="HS256", headers={"kid": "ps"}
    )
    with pytest.raises(HubAuthError):
        validate(f"Bearer {token}")


def test_signature_from_an_untrusted_key_is_rejected(keys):
    other = keys.mint()
    head, payload, _ = other.split(".")
    forged = keys.mint(alg="ES256").split(".")[2]
    with pytest.raises(HubAuthError):
        validate(f"Bearer {head}.{payload}.{forged}")


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "http://evil.example/realms/mcp-plane"},
        {"aud": ["mcp://tier/external"]},  # cross-tier replay
        {"exp": int(time.time()) - 120},  # past the 30 s leeway
    ],
)
def test_wrong_issuer_tier_or_expired_is_rejected(keys, overrides):
    with pytest.raises(HubAuthError):
        validate(f"Bearer {keys.mint(**overrides)}")


def test_two_tier_audiences_are_rejected(keys):
    token = keys.mint(aud=[TIER_AUD, "mcp://tier/external"])
    with pytest.raises(HubAuthError, match="exactly one tier audience"):
        validate(f"Bearer {token}")


@pytest.mark.parametrize("value", [None, "2.0", 1.0])
def test_wrong_or_missing_contract_version_is_rejected(keys, value):
    token = keys.mint(drop=("mcp_contract",)) if value is None else keys.mint(mcp_contract=value)
    with pytest.raises(HubAuthError, match="mcp_contract"):
        validate(f"Bearer {token}")


@pytest.mark.parametrize("claim", ["jti", "sub", "iat", "exp"])
def test_required_claims_must_be_present(keys, claim):
    with pytest.raises(HubAuthError):
        validate(f"Bearer {keys.mint(drop=(claim,))}")
