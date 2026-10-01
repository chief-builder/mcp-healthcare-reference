"""SC-* — DPoP sender-constraint (RFC 9449).

Portable equivalents of the phase-7 DPoP probe pack, run against the
descriptor's scheduling MCP endpoint through the internal gateway. All require
a 'workforce_dpop' identity (acquire: scripted, dpop: true); absent it, the
whole module skips. mTLS constraint (SC-01) needs a client certificate and is
left to a deployment-specific extension — see conformance-profile.md.
"""
import time

import pytest
import requests

from harness import dpop as dpop_lib
from harness import mcp as mcp_lib

pytestmark = pytest.mark.sender_constraint


@pytest.fixture(scope="module")
def dpop_endpoint(descriptor):
    url = descriptor.endpoint("internal", "scheduling_mcp")
    if not url:
        pytest.skip("probe_endpoints.scheduling_mcp not set")
    return url


@pytest.fixture(scope="module")
def bound(identity):
    """The DPoP-bound identity: (EC key, token)."""
    ident = identity("workforce_dpop")
    if ident.dpop_key is None:
        pytest.skip("workforce_dpop identity is not DPoP-bound (needs acquire: scripted, dpop: true)")
    return ident.dpop_key, ident.token


def _send(url, token, *, scheme="DPoP", proof=None):
    body = mcp_lib.envelope("tools/list")
    headers = {**mcp_lib.headers_for(body), "Authorization": f"{scheme} {token}"}
    if proof is not None:
        headers["DPoP"] = proof
    return requests.post(url, headers=headers, json=body, timeout=15)


def test_token_carries_cnf_jkt(claims, bound):
    key, token = bound
    assert claims(token).get("cnf", {}).get("jkt") == dpop_lib.jkt(key), \
        "SC-02: token is not bound to the client key"


def test_valid_proof_admitted(dpop_endpoint, bound):
    """Control: correct scheme + fresh proof is accepted."""
    key, token = bound
    proof = dpop_lib.proof(key, "POST", dpop_endpoint, access_token=token)
    assert _send(dpop_endpoint, token, proof=proof).status_code == 200


def test_bound_token_as_plain_bearer_rejected(dpop_endpoint, bound):
    """SC-02 headline: a jkt-bound token replayed as plain Bearer (lifted from
    the store, no proof) is refused."""
    _key, token = bound
    assert _send(dpop_endpoint, token, scheme="Bearer").status_code == 401


def test_missing_proof_rejected(dpop_endpoint, bound):
    _key, token = bound
    assert _send(dpop_endpoint, token, proof=None).status_code == 401


def test_wrong_htu_rejected(descriptor, dpop_endpoint, bound):
    key, token = bound
    other = descriptor.endpoint("external", "scheduling_mcp") or (dpop_endpoint + "/x")
    proof = dpop_lib.proof(key, "POST", other, access_token=token)
    assert _send(dpop_endpoint, token, proof=proof).status_code == 401


def test_wrong_htm_rejected(dpop_endpoint, bound):
    key, token = bound
    proof = dpop_lib.proof(key, "GET", dpop_endpoint, access_token=token)
    assert _send(dpop_endpoint, token, proof=proof).status_code == 401


def test_stale_iat_rejected(dpop_endpoint, bound):
    key, token = bound
    proof = dpop_lib.proof(key, "POST", dpop_endpoint, access_token=token,
                           iat=int(time.time()) - 600)
    assert _send(dpop_endpoint, token, proof=proof).status_code == 401


def test_wrong_ath_rejected(dpop_endpoint, bound):
    key, token = bound
    proof = dpop_lib.proof(key, "POST", dpop_endpoint, ath_value="not-this-token")
    assert _send(dpop_endpoint, token, proof=proof).status_code == 401


def test_thumbprint_mismatch_rejected(dpop_endpoint, bound):
    _key, token = bound
    attacker = dpop_lib.make_key()
    proof = dpop_lib.proof(attacker, "POST", dpop_endpoint, access_token=token)
    assert _send(dpop_endpoint, token, proof=proof).status_code == 401


def test_jti_replay_rejected(dpop_endpoint, bound):
    """SC-04: the same proof twice — first admitted, replay refused."""
    key, token = bound
    proof = dpop_lib.proof(key, "POST", dpop_endpoint, access_token=token)
    assert _send(dpop_endpoint, token, proof=proof).status_code == 200
    assert _send(dpop_endpoint, token, proof=proof).status_code == 401


def test_plain_bearer_identity_unaffected(dpop_endpoint, identity):
    """SC-03: a non-bound bearer identity is not subject to DPoP (not 401 at
    the gateway on the constraint)."""
    ident = identity("workforce_clinical")
    body = mcp_lib.envelope("tools/list")
    r = requests.post(dpop_endpoint,
                      headers={**mcp_lib.headers_for(body), "Authorization": f"Bearer {ident.token}"},
                      json=body, timeout=15)
    assert r.status_code != 401, r.text
