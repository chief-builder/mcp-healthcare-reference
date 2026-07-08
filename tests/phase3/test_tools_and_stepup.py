"""Phase 3 gate — tool visibility by role, and scope step-up.

Gate (1): a client lists only role-permitted tools.
Gate (2): an under-scoped call -> 403 insufficient_scope -> step-up -> success.
"""
from conftest import FHIR_MCP_INTERNAL

import mcp_http


def test_clinician_lists_clinical_tools(alice_floor):
    tools = mcp_http.list_tools(FHIR_MCP_INTERNAL, alice_floor)
    # floor read tools plus the clinical-only broad tool
    assert {"getPatient", "searchObservation", "searchCondition", "searchMedicationRequest"} <= set(tools)
    assert "patientEverything" in tools  # clinical group present


def test_non_clinical_role_does_not_see_clinical_only_tool(bob_analyst):
    tools = mcp_http.list_tools(FHIR_MCP_INTERNAL, bob_analyst)
    # patientEverything is x-mcp-group=mcp-clinical-tools; bob is analytics-only
    assert "patientEverything" not in tools, "role-gated tool leaked to a non-clinical role"


def test_under_scoped_call_triggers_insufficient_scope_challenge(alice_floor):
    r = mcp_http.call_tool(FHIR_MCP_INTERNAL, alice_floor, "patientEverything", {"id": "1"})
    assert r.status_code == 403
    challenge = r.headers.get("WWW-Authenticate", "")
    assert 'error="insufficient_scope"' in challenge
    assert 'scope="mcp:fhir-clinical:everything:read"' in challenge  # single-shot, names the scope


def test_step_up_token_is_accepted(alice_everything, seeded_patients):
    # Same tool, now with the stepped-up scope: no 403 (it dispatches to the server).
    r = mcp_http.call_tool(FHIR_MCP_INTERNAL, alice_everything, "patientEverything",
                           {"id": seeded_patients[0]})
    assert r.status_code != 403
    result = mcp_http.tool_result(r)
    assert result.get("resourceType") == "Bundle"
