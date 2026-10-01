"""Phase 3 gate (3) — a patient-scoped token retrieves exactly its own
fhir_patient compartment (contract §6.5). Enforced by the FHIR server's
authz-hook; the patient reaches the server through the EXTERNAL tier.
"""

import mcp_http
from conftest import FHIR_MCP_EXTERNAL


def test_search_is_hard_scoped_to_the_token_patient(patient_token, seeded_patients):
    mine, other = seeded_patients[0], seeded_patients[1]
    # Ask for another patient's observations; the hook overrides `patient` to mine.
    r = mcp_http.call_tool(
        FHIR_MCP_EXTERNAL, patient_token, "searchObservation", {"patient": other, "_count": 20}
    )
    assert r.status_code == 200
    bundle = mcp_http.tool_result(r)
    subjects = {
        (e.get("resource", {}).get("subject", {}).get("reference") or "")
        for e in bundle.get("entry", [])
    }
    # Every returned Observation must reference the token's own patient.
    assert all(mine in s for s in subjects if s), f"cross-patient data leaked: {subjects}"


def test_cross_patient_read_is_blocked(patient_token, seeded_patients):
    other = seeded_patients[1]
    r = mcp_http.call_tool(FHIR_MCP_EXTERNAL, patient_token, "getPatient", {"id": other})
    # The hook rejects a by-id read of a patient other than the token's own.
    assert r.status_code != 200 or mcp_http._parse_sse(r.text).get("result", {}).get("isError")
