"""Phase 3 gate (4) — statelessness. Hold a slot on the scheduling server, then
drop a replica; the surviving replica confirms the hold using the explicit
slot_hold_id handle (state lives in Postgres, not server memory).
"""
import subprocess
from pathlib import Path

from conftest import SCHED_MCP_INTERNAL

import mcp_http

COMPOSE_DIR = Path(__file__).resolve().parents[2] / "compose" / "phase3"


def _compose(*args):
    subprocess.run(["docker", "compose", *args], cwd=COMPOSE_DIR, check=True, capture_output=True)


def test_hold_survives_replica_loss(alice_scheduling):
    slots = mcp_http.tool_result(
        mcp_http.call_tool(SCHED_MCP_INTERNAL, alice_scheduling, "find-slots", {}))
    slot_id = slots[0]["slot_id"]

    held = mcp_http.tool_result(
        mcp_http.call_tool(SCHED_MCP_INTERNAL, alice_scheduling, "hold-slot", {"slot_id": slot_id}))
    slot_hold_id = held["slot_hold_id"]
    assert slot_hold_id

    # Drop the scheduling service to a single replica (removes one container).
    _compose("up", "-d", "--no-recreate", "--scale", "scheduling=1")
    try:
        # The surviving replica has never seen this hold in memory — it must read
        # it from Postgres via the handle.
        r = mcp_http.call_tool(SCHED_MCP_INTERNAL, alice_scheduling, "confirm-hold",
                               {"slot_hold_id": slot_hold_id})
        assert r.status_code == 200
        result = mcp_http.tool_result(r)
        assert result.get("status") == "confirmed"
        assert result.get("slot_id") == slot_id
    finally:
        _compose("up", "-d", "--no-recreate", "--scale", "scheduling=2")


def test_hold_requires_step_up_scope(alice_floor):
    # A floor token cannot place a hold (execute scope required).
    r = mcp_http.call_tool(SCHED_MCP_INTERNAL, alice_floor, "hold-slot", {"slot_id": "slot-x"})
    assert r.status_code == 403
    assert 'scope="mcp:scheduling:hold-slot:execute"' in r.headers.get("WWW-Authenticate", "")
