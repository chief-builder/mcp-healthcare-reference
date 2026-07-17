"""ST-* — statelessness: any request hits any replica.

Portable check that a first-party MCP server holds no protocol session:
tools/list and tools/call both work on independent single POSTs with no
session negotiation. (The lab additionally kills a replica mid-conversation;
that needs orchestration control the descriptor does not model, so this probe
asserts the observable property — stateless per-request operation — that the
replica-kill test relies on.)
"""
import pytest

from harness import mcp as mcp_lib

pytestmark = pytest.mark.statelessness


@pytest.fixture(scope="module")
def sched(descriptor):
    url = descriptor.endpoint("internal", "scheduling_mcp")
    if not url:
        pytest.skip("probe_endpoints.scheduling_mcp not set")
    return url


def test_tools_list_needs_no_session(sched, identity):
    """ST-01: a bare POST returns the tool list with no prior initialize/session."""
    tools = mcp_lib.list_tools(sched, identity("workforce_clinical").token)
    assert tools, "no tools returned"


def test_independent_calls_share_no_session(sched, identity):
    """ST-01: two independent POSTs both succeed — continuity is not carried in
    an MCP session (any replica can serve either)."""
    token = identity("workforce_clinical").token
    first = mcp_lib.list_tools(sched, token)
    second = mcp_lib.list_tools(sched, token)
    assert first == second, "tool list is not stable across independent requests"
