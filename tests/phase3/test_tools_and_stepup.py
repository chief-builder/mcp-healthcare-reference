"""Phase 3 gate — tool visibility by role, and scope step-up.

Gate (1): a client lists only role-permitted tools.
Gate (2): an under-scoped call -> 403 insufficient_scope -> step-up -> success.
Plus the MCP 2026-07-28 wire contract through the gateway, legacy-client
compatibility, the batch-smuggling regression (S1), and MFA on clinical scopes.
"""

import base64
import json

import mcp_http
import requests
from conftest import FHIR_MCP_INTERNAL


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


def _claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def test_server_negotiates_2026_07_28_through_the_gateway(alice_floor):
    r = mcp_http.post(FHIR_MCP_INTERNAL, alice_floor, mcp_http.envelope("server/discover"))
    assert r.status_code == 200, r.text
    result = mcp_http._parse_sse(r.text)["result"]
    assert "2026-07-28" in result["supportedVersions"]
    assert result["resultType"] == "complete"


def test_2025_era_client_is_still_served(alice_floor):
    """Clients that have not migrated (no _meta envelope, initialize handshake)
    get the SDK's stateless 2025-11-25 fallback from the same server."""
    r = requests.post(
        FHIR_MCP_INTERNAL,
        headers={
            "Content-Type": "application/json",
            "Accept": mcp_http.ACCEPT,
            "Authorization": f"Bearer {alice_floor}",
        },
        json={
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "legacy", "version": "1"},
            },
        },
        timeout=30,
    )
    assert r.status_code == 200, r.text
    assert mcp_http._parse_sse(r.text)["result"]["protocolVersion"] == "2025-11-25"


def test_batch_cannot_smuggle_a_tool_call_past_step_up(alice_floor):
    """S1 regression: wrapping an under-scoped tools/call in a JSON-RPC batch
    used to skip the per-tool scope check. Batches are refused outright."""
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "patientEverything", "arguments": {"id": "1"}},
    }
    r = requests.post(
        FHIR_MCP_INTERNAL,
        headers={
            "Content-Type": "application/json",
            "Accept": mcp_http.ACCEPT,
            "Authorization": f"Bearer {alice_floor}",
        },
        json=[call],
        timeout=30,
    )
    assert r.status_code == 400, r.text
    assert "Bundle" not in r.text


def test_clinical_step_up_token_carries_the_mfa_mark(alice_everything):
    """The step-up scope is MFA-gated (MCP_MFA_SCOPES); the brokered workforce
    login stamps amr=mfa, which is why test_step_up_token_is_accepted passes.
    The no-mfa rejection (401 insufficient_user_authentication) is covered
    offline in servers/fhir-clinical/test (no lab user lacks the mark)."""
    claims = _claims(alice_everything)
    assert "mcp:fhir-clinical:everything:read" in claims["scope"].split()
    assert "mfa" in claims.get("amr", [])
