"""Phase 2 acceptance: the two-level tier wall and route ACLs.

Gate (prototype plan §3): an internal-tier token replayed at the external DP
fails with 401 — the audiences are a cryptographic wall, not a convention.
"""
import requests

from conftest import EXTERNAL_GW, INTERNAL_GW


def _get(gateway: str, token: str | None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.get(f"{gateway}/fhir/Patient", headers=headers, params={"_count": 1})


def test_internal_token_at_internal_dp(alice_token):
    response = _get(INTERNAL_GW, alice_token)
    assert response.status_code == 200
    assert response.json()["resourceType"] == "Bundle"


def test_gate_internal_token_replayed_at_external_dp(alice_token):
    """THE phase 2 gate."""
    response = _get(EXTERNAL_GW, alice_token)
    assert response.status_code == 401
    challenge = response.headers.get("WWW-Authenticate", "")
    assert 'error="invalid_token"' in challenge
    assert alice_token not in response.text, "token echoed in rejection (contract §8)"


def test_m2m_internal_token_replayed_at_external_dp(smoke_token):
    response = _get(EXTERNAL_GW, smoke_token)
    assert response.status_code == 401


def test_customer_token_at_external_dp(customer_token):
    response = _get(EXTERNAL_GW, customer_token)
    assert response.status_code == 200


def test_customer_token_replayed_at_internal_dp(customer_token):
    response = _get(INTERNAL_GW, customer_token)
    assert response.status_code == 401
    assert 'error="invalid_token"' in response.headers.get("WWW-Authenticate", "")


def test_acl_wrong_group_is_403_not_401(bob_token):
    """bob-analyst is authenticated with a valid internal token but lacks
    mcp-clinical-tools — authorization failure, not authentication."""
    response = _get(INTERNAL_GW, bob_token)
    assert response.status_code == 403


def test_acl_no_groups_is_403(smoke_token):
    response = _get(INTERNAL_GW, smoke_token)
    assert response.status_code == 403


def test_anonymous_is_401_with_challenge():
    response = _get(INTERNAL_GW, None)
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


def test_garbage_token_is_401():
    response = _get(INTERNAL_GW, "not.a.jwt")
    assert response.status_code == 401
