"""AU-* — jti-joinable audit spine.

Portable equivalents of phase-6 audit probes. Require an 'audit' section with
a reachable backend. AU-01 walks a first-party tool call back to its audit
record by jti; AU-03 proves no token material lands on the spine.
"""

import pytest
from harness import mcp as mcp_lib

pytestmark = pytest.mark.audit


@pytest.fixture(scope="module")
def spine(audit):
    if not audit.available:
        pytest.skip("no audit backend declared (audit.backend = none / absent)")
    return audit


def test_tool_call_joins_on_jti(descriptor, spine, identity, claims):
    """AU-01: a first-party tool call produces an audit record joinable by the
    token's jti — the record carries the principal, keyed by jti."""
    url = descriptor.endpoint("internal", "scheduling_mcp")
    if not url:
        pytest.skip("probe_endpoints.scheduling_mcp not set")
    ident = identity("workforce_clinical")
    r = mcp_lib.list_tools(url, ident.token)  # any authorized call emits a record
    assert r, "tool call produced no result"

    c = claims(ident.token)
    lines = spine.query_by_jti(c["jti"])
    assert lines, f"AU-01: no audit record joined on jti {c['jti']}"
    assert any(c["sub"] in line for line in lines), (
        "AU-01: audit records for this jti do not carry the principal (sub)"
    )


def test_no_token_material_on_the_spine(descriptor, spine, identity):
    """AU-03: the token's signature segment appears in no shipped log line —
    the spine records ids, never secrets."""
    ident = identity("workforce_clinical")
    url = descriptor.endpoint("internal", "scheduling_mcp")
    if url:
        mcp_lib.list_tools(url, ident.token)  # ensure the token has crossed the plane
    signature = ident.token.split(".")[2]
    hits = spine.grep(signature)
    assert hits == 0, f"AU-03: token material leaked to the spine ({hits} lines)"
