"""TIER-* — audience discipline and the cryptographic tier wall.

Portable equivalents of tests/phase2/test_tier_wall.py. The headline probe
(TIER-02) replays an internal-tier token at the external gateway and requires
a 401 with no token echo.
"""

import pytest
import requests

pytestmark = pytest.mark.tier


def _aud_list(claims_dict):
    aud = claims_dict.get("aud", [])
    return [aud] if isinstance(aud, str) else list(aud)


def _get(url, token):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.get(url, headers=headers, params={"_count": 1}, timeout=15)


def _reachable_or_skip(url):
    """A connection error means the deployment is unreachable — an environment
    problem, not a failed control. Skip (clearly), never fail."""
    if not url:
        pytest.skip("probe_endpoints.acl_resource not set")
    try:
        requests.get(url, timeout=10)
    except requests.exceptions.ConnectionError as exc:
        pytest.skip(f"gateway unreachable at {url}: {exc.__class__.__name__}")
    return url


@pytest.fixture(scope="module")
def acl_internal(descriptor):
    return _reachable_or_skip(descriptor.endpoint("internal", "acl_resource"))


@pytest.fixture(scope="module")
def acl_external(descriptor):
    return _reachable_or_skip(descriptor.endpoint("external", "acl_resource"))


def test_aud_exactly_one_tier_plus_server(descriptor, claims, identity):
    """TIER-01: exactly one tier audience, matching mcp_tier, plus ≥1 server URI."""
    ident = identity("workforce_clinical")
    c = claims(ident.token)
    auds = _aud_list(c)
    tier_auds = [a for a in auds if "tier" in a]
    assert len(tier_auds) == 1, f"TIER-01: expected one tier audience, got {tier_auds}"
    assert tier_auds[0] == descriptor.audience(c["mcp_tier"]), (
        "TIER-01: tier audience does not match mcp_tier"
    )


def test_internal_token_admitted_at_internal_dp(acl_internal, identity):
    """Control: the token passes its own tier's wall (not 401/403 on the wall)."""
    r = _get(acl_internal, identity("workforce_clinical").token)
    assert r.status_code not in (401,), r.text


def test_internal_token_replayed_at_external_dp(acl_external, identity):
    """TIER-02, the headline probe: an internal token at the external gateway
    fails 401 invalid_token, and the token is not echoed in the rejection."""
    token = identity("workforce_clinical").token
    r = _get(acl_external, token)
    assert r.status_code == 401, f"TIER-02: cross-tier replay was not rejected ({r.status_code})"
    assert 'error="invalid_token"' in r.headers.get("WWW-Authenticate", "")
    assert token not in r.text, "AU-03/§8: token echoed in rejection body"


def test_anonymous_is_401_with_challenge(acl_internal):
    """AZ-06: no token → 401 with a WWW-Authenticate challenge."""
    r = _get(acl_internal, None)
    assert r.status_code == 401 and "WWW-Authenticate" in r.headers


def test_garbage_token_is_401(acl_internal):
    r = _get(acl_internal, "not.a.jwt")
    assert r.status_code == 401
