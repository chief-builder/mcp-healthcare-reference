"""IDN-* — single issuer, algorithm pinning, token shape, no PII.

Portable equivalents of tests/phase1/test_contract.py, parameterized on the
descriptor. These inspect the token any declared internal identity carries;
they do not depend on which grant path minted it.
"""
import jwt
import pytest
import requests

pytestmark = pytest.mark.identity

PII_CLAIMS = ("email", "name", "given_name", "family_name",
              "preferred_username", "phone_number", "birthdate", "address")


@pytest.fixture(scope="module")
def a_token(identity):
    """Any declared workforce identity — the probes here are path-agnostic."""
    return identity("workforce_clinical")


def test_signature_alg_and_issuer(descriptor, a_token):
    """IDN-01/02: token verifies under the hub JWKS with a pinned algorithm."""
    raw = a_token.token
    header = jwt.get_unverified_header(raw)
    assert header["alg"] in ("PS256", "ES256"), f"IDN-02: {header['alg']} not pinned"
    jwks = requests.get(descriptor.jwks_uri, timeout=15).json()
    key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    verified = jwt.decode(
        raw, jwt.PyJWK(key).key, algorithms=["PS256", "ES256"],
        issuer=descriptor.issuer, options={"verify_aud": False},
    )
    assert verified["iss"] == descriptor.issuer, "IDN-01: iss is not the hub issuer"


def test_sub_stable_non_email(claims, a_token):
    c = claims(a_token.token)
    assert c.get("sub"), "IDN-07: sub missing"
    assert "@" not in c["sub"], "IDN-07: sub must never be an email"


def test_jti_present(claims, a_token):
    assert claims(a_token.token).get("jti"), "IDN-07: jti missing (audit joinability)"


def test_contract_version_pinned(claims, a_token):
    assert claims(a_token.token).get("mcp_contract"), "IDN-06: mcp_contract pin missing"


def test_lifetime_bounded(claims, a_token):
    c = claims(a_token.token)
    lifetime = c["exp"] - c["iat"]
    assert 0 < lifetime <= 600, f"IDN-03: lifetime {lifetime}s exceeds interactive ceiling"


def test_no_pii_claims(claims, a_token):
    leaked = [c for c in PII_CLAIMS if c in claims(a_token.token)]
    assert not leaked, f"IDN-04: access token carries PII claims {leaked}"


def test_groups_normalized(claims, a_token):
    groups = claims(a_token.token).get("groups")
    if groups is None:
        pytest.skip("token carries no groups claim")
    assert all(g.startswith("mcp-") for g in groups), \
        f"IDN-05: non-normalized group names present: {groups}"
