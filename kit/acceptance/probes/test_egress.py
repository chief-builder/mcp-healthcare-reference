"""EG-* — governed egress: DLP screening, credential swap, broker no-issuance.

Portable equivalents of phase-5 egress probes. The DLP probes plant SYNTHETIC
samples (from the descriptor) and require a block; they never send a real
identifier. Broker probes require a 'broker' section. All require an 'egress'
section; absent it, the module skips.
"""

import pytest
import requests
from harness import mcp as mcp_lib

pytestmark = pytest.mark.egress


@pytest.fixture(scope="module")
def egress(descriptor):
    section = descriptor.section("egress")
    if not section:
        pytest.skip("descriptor has no 'egress' section")
    return section


def _consent_if_needed(route, token):
    """Drive the first-call consent dance to a live grant if the route asks for
    it. Returns True when the route is usable, False if consent can't complete
    headlessly (real vendor needing a browser)."""
    r = mcp_lib.call_tool(route, token, "noop-probe", {})
    if r.status_code == 401 and "authorize_uri" in r.text:
        page = requests.get(r.json()["authorize_uri"], timeout=20)
        return page.status_code == 200
    return True


def test_planted_sample_is_blocked_and_audited(egress, identity):
    """EG-01: each configured DLP pattern's synthetic sample, planted in a tool
    argument, is blocked (403) before leaving the boundary."""
    route = egress["route"]
    tool = egress["tool"]
    token = identity("workforce_clinical").token
    _consent_if_needed(route, token)

    for pattern in egress["dlp_patterns"]:
        r = mcp_lib.call_tool(
            route, token, tool, {"title": "probe", "body": f"contains {pattern['sample']}"}
        )
        assert r.status_code == 403, (
            f"EG-01: sample for {pattern['name']} was not blocked ({r.status_code})"
        )
        body = r.json()
        assert body.get("pattern") == pattern["name"], (
            f"EG-01: block reported pattern {body.get('pattern')}, expected {pattern['name']}"
        )


def test_clean_payload_passes(egress, identity):
    """EG-02: a payload with no identifiers passes DLP and reaches the vendor
    (the credential swap put the vendor's own token on the call)."""
    route, tool = egress["route"], egress["tool"]
    token = identity("workforce_clinical").token
    if not _consent_if_needed(route, token):
        pytest.skip("vendor consent cannot complete headlessly in this environment")
    r = mcp_lib.call_tool(route, token, tool, egress.get("clean_args", {"title": "clean"}))
    assert r.status_code == 200, (
        f"EG-02: clean payload was not forwarded ({r.status_code}): {r.text[:200]}"
    )


@pytest.mark.parametrize(
    "path",
    [
        "/oauth/token",
        "/token",
        "/keys",
        "/v1/tokens/issue",
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
    ],
)
def test_broker_exposes_no_issuance_endpoint(descriptor, path):
    """EG-04: the broker is a custodian, not an issuer — no token/JWKS surface."""
    broker = descriptor.section("broker")
    if not broker:
        pytest.skip("descriptor has no 'broker' section")
    configured = broker.get("issuance_paths_absent")
    if configured and path not in configured:
        pytest.skip(f"{path} not in this deployment's issuance_paths_absent")
    r = requests.get(f"{broker['url'].rstrip('/')}{path}", timeout=10)
    assert r.status_code == 404, f"EG-04: broker answered {r.status_code} at {path}, expected 404"


def test_broker_resolve_requires_valid_hub_token(descriptor, egress):
    """EG-05: resolve without a hub token is 401 — the broker independently
    authenticates the caller, never trusting the gateway."""
    broker = descriptor.section("broker")
    if not broker:
        pytest.skip("descriptor has no 'broker' section")
    r = requests.post(
        f"{broker['url'].rstrip('/')}/v1/tokens/resolve",
        json={"vendor": egress["vendor"], "min_ttl_s": 30},
        timeout=15,
    )
    assert r.status_code == 401, f"EG-05: unauthenticated resolve got {r.status_code}, expected 401"
