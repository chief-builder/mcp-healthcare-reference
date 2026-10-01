"""AZ-* — tool-layer authorization: scope-is-not-authorization, compartment.

Portable equivalents of phase-2/3/7 authorization probes. The scope-vs-group
probe needs a 'workforce_nonclinical' identity; the compartment probe needs a
'patient' identity declaring expects_compartment.
"""

import pytest
import requests

pytestmark = pytest.mark.authorization


def _get(url, token):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.get(url, headers=headers, params={"_count": 1}, timeout=15)


def test_group_gate_is_authorization_not_authentication(descriptor, identity):
    """AZ-01: a valid token that lacks the required group is refused at the
    protected resource with 403 (authorization), not 401 (authentication) —
    the token being well-formed is not sufficient."""
    url = descriptor.endpoint("internal", "acl_resource")
    if not url:
        pytest.skip("probe_endpoints.acl_resource not set")
    ident = identity("workforce_nonclinical")
    r = _get(url, ident.token)
    assert r.status_code == 403, f"AZ-01: non-authorized identity got {r.status_code}, expected 403"


def test_customer_token_carries_compartment(descriptor, claims, identity):
    """AZ-04: a customer-path token carries a non-empty fhir_patient, and a
    workforce token must not."""
    patient = identity("patient")
    if not patient.expects_compartment:
        pytest.skip("patient identity does not declare expects_compartment")
    pc = claims(patient.token).get("fhir_patient")
    assert pc, "AZ-04: customer token missing the fhir_patient compartment"

    wf = identity("workforce_clinical")
    assert "fhir_patient" not in claims(wf.token), (
        "AZ-04 (forbidden direction): workforce token carries fhir_patient"
    )


def test_customer_token_rejected_at_internal_tier(descriptor, identity):
    """TIER-02/AZ: an external customer token replayed at the internal gateway
    fails 401 — the external population cannot reach the internal catalog."""
    patient = identity("patient")
    url = descriptor.endpoint("internal", "acl_resource")
    if not url:
        pytest.skip("probe_endpoints.acl_resource not set")
    r = _get(url, patient.token)
    assert r.status_code == 401, f"customer token admitted at internal tier ({r.status_code})"
