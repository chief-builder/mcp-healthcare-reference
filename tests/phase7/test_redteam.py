"""Phase 7 — red-team weekend (prototype-plan.md §3).

Runs the arch-doc §13 security assertions plus the named probes:
cross-tier replay, scope-ceiling, broker `state` replay, RFC 9207 `iss`
tampering/omission, STALE-storm, and a token-in-log grep; plus the CIMD
external-tier experiment and the broker no-issuance rule.

Passing test = defense held. The RFC 9207 iss-omission and mass-STALE probes
(GitHub #1, #2) were xfail(strict) gaps; both are now fixed and asserted as
real defenses. The remaining known gap is the external-tier CIMD control
(#3), which its probe asserts as the secure outcome the realm already gives.
"""

import json
import secrets
import subprocess
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import dpop as dpop_lib
import mcp_http
import pytest
import requests
from conftest import (
    BROKER,
    EXTERNAL,
    INTERNAL,
    KC_BASE,
    MOCK,
    REALM,
    broker_audit,
    claims_of,
    do_consent,
    grep_container_logs,
    grep_loki,
    login,
    mock_reset,
    mock_state,
    new_consent_state,
    resolve,
)

# ── P1. Cross-tier replay (arch §13 tier isolation; Appendix A.5) ─────────────


def _fhir_get(gateway: str, token: str | None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.get(
        f"{gateway}/fhir/Patient", headers=headers, params={"_count": 1}, timeout=15
    )


def test_internal_token_replayed_at_external_dp(alice):
    """Internal-tier token at the external DP → 401 invalid_token, no echo."""
    r = _fhir_get(EXTERNAL, alice)
    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers.get("WWW-Authenticate", "")
    assert alice not in r.text, "token echoed in rejection (contract §8)"


def test_internal_token_admitted_at_internal_dp(alice):
    """Control: the same token is admitted by its own tier's wall — the DP
    does not reject it on authn/authz. (A 5xx here only means the FHIR
    upstream is down; the tier wall runs before the upstream, so anything
    other than 401/403 proves the token passed the wall.)"""
    assert _fhir_get(INTERNAL, alice).status_code not in (401, 403)


def test_garbage_and_anonymous_rejected():
    assert _fhir_get(INTERNAL, None).status_code == 401
    assert _fhir_get(INTERNAL, "not.a.jwt").status_code == 401


# ── P2. Scope-ceiling probes (claims-contract §5; arch §5.2) ──────────────────


def test_wildcard_tool_scope_is_not_grantable(env):
    """`mcp:<server>:*:<verb>` needs platform-admin approval and is not a
    registerable scope for a workforce client — Keycloak must refuse it
    (authorization error, no code) or at least never mint it into a token."""
    try:
        tok = login(env, "dr-alice", "openid mcp:fhir-clinical:*:execute")
    except KeyError, AssertionError:
        return  # refused at the authorization endpoint — the secure outcome
    assert "mcp:fhir-clinical:*:execute" not in claims_of(tok).get("scope", "").split(), (
        "wildcard tool scope leaked into a token"
    )


def test_scope_string_alone_is_not_authorization(env):
    """Defense in depth: a non-clinical user CAN request the clinical scope
    string, but the DP group ACL still blocks the clinical route — the scope
    is not sufficient without the group (contract §5, §8)."""
    bob_clinical = login(env, "bob-analyst", "openid mcp:fhir-clinical:everything:read")
    assert "mcp:fhir-clinical:everything:read" in claims_of(bob_clinical)["scope"]
    assert "mcp-clinical-tools" not in claims_of(bob_clinical).get("groups", [])
    # …yet the clinical route is refused (group ACL), scope notwithstanding.
    assert _fhir_get(INTERNAL, bob_clinical).status_code == 403


def test_broker_never_requests_beyond_registry_ceiling(alice):
    """The authorize leg requests exactly the registry scope ceiling; the
    caller has no input that can widen it (design §4.2)."""
    r = resolve(alice)
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        do_consent(alice)  # already connected; nothing to inspect
        return
    redirect = requests.get(r.json()["authorize_uri"], allow_redirects=False, timeout=15)
    scope_param = (
        parse_qs(urlparse(redirect.headers["Location"]).query).get("scope", [""])[0].split()
    )
    ceiling = {"issues:read", "issues:write"}
    assert set(scope_param) <= ceiling, f"broker requested {scope_param} beyond ceiling {ceiling}"


# ── P3. Broker callback `state` replay (design §4.3/§10) ───────────────────────


def test_state_replay_is_a_security_event(alice):
    """A callback `state` that is unknown/consumed is a security event, not a
    plain 400 — replaying one must alert."""
    forged = secrets.token_urlsafe(32)
    r = requests.get(
        f"{BROKER}/v1/callback/mockhub",
        params={"state": forged, "code": "x"},
        allow_redirects=False,
        timeout=15,
    )
    assert r.status_code == 400
    events = broker_audit()
    assert any(
        e.get("audit") == "broker.consent.fail"
        and e.get("reason") == "state_invalid_or_replayed"
        and e.get("security_event") is True
        for e in events
    ), "state replay did not raise a security_event audit alert"


# ── P4. RFC 9207 iss on the broker callback (design §2; contract §8) ──────────


def test_iss_tampering_is_rejected_and_alerts(alice):
    """A callback whose `iss` mismatches the recorded issuer is rejected
    before code redemption, with a security_event alert (mix-up defense)."""
    state = new_consent_state(alice)
    r = requests.get(
        f"{BROKER}/v1/callback/mockhub",
        params={"state": state, "code": "forged", "iss": "https://evil.example"},
        allow_redirects=False,
        timeout=15,
    )
    assert r.status_code == 400 and "mismatch" in r.text.lower()
    assert any(
        e.get("audit") == "broker.consent.fail"
        and e.get("reason") == "iss_mismatch"
        and e.get("security_event") is True
        for e in broker_audit()
    ), "iss tampering did not raise a security_event"


def test_iss_omission_is_rejected_when_vendor_advertises_iss(alice):
    meta = requests.get(f"{MOCK}/.well-known/oauth-authorization-server", timeout=10).json()
    assert meta.get("authorization_response_iss_parameter_supported") is True
    state = new_consent_state(alice)
    # Assert on the RESPONSE (not shared logs, which the tamper probe also
    # writes to): a compliant broker rejects the missing iss the same way it
    # rejects a mismatched one — 400 with an issuer rejection, no redemption.
    r = requests.get(
        f"{BROKER}/v1/callback/mockhub",
        params={"state": state, "code": "forged-mixup-code"},
        allow_redirects=False,
        timeout=15,
    )
    assert r.status_code == 400 and "issuer" in r.text.lower(), (
        f"missing iss not rejected as a mix-up (got {r.status_code}: {r.text[:80]})"
    )


# ── P5. STALE-storm — org-app uninstall (design §8/§10; arch §9 anomaly) ──────


def test_stale_storm_marks_each_entry_and_audits(env):
    """Uninstall (revoke_family) → every affected entry goes STALE and each
    transition is audited joinably by sub (per-entry behavior holds)."""
    mock_reset()
    alice = login(env, "dr-alice")
    bob = login(env, "bob-analyst")
    do_consent(alice)
    do_consent(bob)
    assert len(mock_state()["families"]) >= 2
    requests.post(f"{MOCK}/_test/revoke_family", timeout=10)
    # Each resolve lands in the refresh buffer → refresh → invalid_grant → STALE.
    assert resolve(alice).status_code == 404
    assert resolve(bob).status_code == 404
    stale = [e for e in broker_audit() if e.get("audit") == "broker.stale"]
    subs = {e.get("sub") for e in stale}
    assert len(subs) >= 2, f"expected ≥2 distinct STALE subs, got {subs}"


def test_stale_storm_raises_mass_stale_signal(env):
    mock_reset()
    tokens = [login(env, u) for u in ("dr-alice", "bob-analyst")]
    for t in tokens:
        do_consent(t)
    requests.post(f"{MOCK}/_test/revoke_family", timeout=10)
    for t in tokens:
        resolve(t)
    events = broker_audit()
    # Desired: a distinct aggregate/paging event (not just per-entry stale).
    assert any(
        e.get("audit") in ("broker.stale.mass", "broker.page")
        or e.get("mass_stale")
        or e.get("page")
        for e in events
    ), "no mass-stale/page anomaly signal emitted"


# ── P6. Token-in-log grep (contract §8/§9; arch §13 compliance) ───────────────


def test_no_token_material_in_any_log(env):
    """A live hub token and a live vendor access token must appear nowhere in
    any container log or on the Loki spine (records carry ids, never secrets)."""
    alice = login(env, "dr-alice")
    do_consent(alice)
    r = resolve(alice)
    assert r.status_code == 200, r.text
    vendor_at = r.json()["access_token"]
    hub_sig = alice.rsplit(".", 1)[-1]  # the JWT signature segment

    for label, needle in (("vendor access_token", vendor_at), ("hub jwt signature", hub_sig)):
        container_hits = grep_container_logs(needle)
        assert not container_hits, f"{label} found in container logs: {container_hits}"
        loki_hits = grep_loki(needle)
        assert loki_hits == 0, f"{label} found {loki_hits}× on the Loki spine"


# ── P7. CIMD external-tier experiment (arch §5.1) ─────────────────────────────


def test_cimd_url_form_client_id_is_refused():
    """A URL-form client_id from a non-allowlisted origin must be refused, and
    must NOT redirect back to the attacker-controlled URL."""
    r = requests.get(
        f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/auth",
        params={
            "client_id": "https://evil.example/mcp-metadata.json",
            "redirect_uri": "https://evil.example/cb",
            "response_type": "code",
            "scope": "openid",
            "state": "x",
        },
        allow_redirects=False,
        timeout=15,
    )
    assert r.status_code >= 400, f"URL-form client_id was accepted ({r.status_code})"
    assert "evil.example" not in r.headers.get("Location", ""), (
        "authorization redirected to the non-allowlisted origin"
    )


# ── Arch §13 checklist — broker no-issuance rule (broker design §11) ──────────


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
def test_broker_exposes_no_issuance_endpoint(path):
    """The broker is a custodian, not an issuer: no token or JWKS surface."""
    assert requests.get(f"{BROKER}{path}", timeout=10).status_code == 404


def test_broker_resolve_requires_valid_hub_token():
    """resolve without a hub token is 401 — the JWT is authoritative."""
    r = requests.post(
        f"{BROKER}/v1/tokens/resolve", json={"vendor": "mockhub", "min_ttl_s": 30}, timeout=15
    )
    assert r.status_code == 401


# ── P8. DPoP sender-constraint (RFC 9449; contract §8, plugins/dpop-check) ────
#
# The DPoP client's access token is bound to a client-held key (cnf.jkt). A
# stolen token is useless without a fresh proof signed by that key. Enforced
# gateway-first (dpop-check plugin) and re-checked authoritatively at the server
# (requireDpop). Probes target the scheduling MCP endpoint through the internal
# DP; a passing test means the defense held.

DPOP_MCP = f"{INTERNAL}/scheduling/mcp"
LIST = mcp_http.envelope("tools/list")


def _send(token, *, scheme="DPoP", proof=None):
    """Raw tools/list with explicit auth scheme and optional DPoP header."""
    headers = {**mcp_http.headers_for(LIST), "Authorization": f"{scheme} {token}"}
    if proof is not None:
        headers["DPoP"] = proof
    return requests.post(DPOP_MCP, headers=headers, json=LIST, timeout=15)


def test_dpop_token_carries_cnf_jkt(alice_dpop):
    """Control: Keycloak bound the token to the client key (cnf.jkt == jkt)."""
    key, token = alice_dpop
    assert claims_of(token).get("cnf", {}).get("jkt") == dpop_lib.jkt(key)


def test_dpop_valid_proof_admitted(alice_dpop):
    """Control: a correct scheme + fresh proof is accepted (200)."""
    key, token = alice_dpop
    proof = dpop_lib.proof(key, "POST", DPOP_MCP, access_token=token)
    assert _send(token, proof=proof).status_code == 200


def test_dpop_token_replayed_as_plain_bearer_rejected(alice_dpop):
    """The headline probe: a jkt-bound token replayed as a plain Bearer with no
    proof (i.e. lifted from the credential store) is refused."""
    _key, token = alice_dpop
    assert _send(token, scheme="Bearer").status_code == 401


def test_dpop_missing_proof_rejected(alice_dpop):
    """DPoP scheme but no proof header → 401."""
    _key, token = alice_dpop
    assert _send(token, proof=None).status_code == 401


def test_dpop_wrong_htu_rejected(alice_dpop):
    """A proof signed for a different endpoint URL is refused."""
    key, token = alice_dpop
    proof = dpop_lib.proof(key, "POST", f"{EXTERNAL}/scheduling/mcp", access_token=token)
    assert _send(token, proof=proof).status_code == 401


def test_dpop_wrong_htm_rejected(alice_dpop):
    """A proof whose htm doesn't match the request method is refused."""
    key, token = alice_dpop
    proof = dpop_lib.proof(key, "GET", DPOP_MCP, access_token=token)
    assert _send(token, proof=proof).status_code == 401


def test_dpop_stale_iat_rejected(alice_dpop):
    """A proof minted outside the freshness window is refused."""
    key, token = alice_dpop
    proof = dpop_lib.proof(key, "POST", DPOP_MCP, access_token=token, iat=int(time.time()) - 600)
    assert _send(token, proof=proof).status_code == 401


def test_dpop_wrong_ath_rejected(alice_dpop):
    """A proof whose ath binds a different token is refused (proof lifted from
    another exchange cannot be reused with a stolen token)."""
    key, token = alice_dpop
    proof = dpop_lib.proof(key, "POST", DPOP_MCP, ath_value="not-this-token")
    assert _send(token, proof=proof).status_code == 401


def test_dpop_jti_replay_rejected(alice_dpop):
    """The same proof twice: first admitted, replay refused (DP shared-dict)."""
    key, token = alice_dpop
    proof = dpop_lib.proof(key, "POST", DPOP_MCP, access_token=token)
    first = _send(token, proof=proof)
    assert first.status_code == 200, first.text
    assert _send(token, proof=proof).status_code == 401


def test_dpop_thumbprint_mismatch_rejected(alice_dpop):
    """A proof signed by a different key (cnf.jkt != proof jwk) is refused."""
    _key, token = alice_dpop
    attacker = dpop_lib.make_key()
    proof = dpop_lib.proof(attacker, "POST", DPOP_MCP, access_token=token)
    assert _send(token, proof=proof).status_code == 401


def test_dpop_server_revalidates_without_gateway(alice_dpop):
    """Layered defense: bypass Kong and hit the scheduling container directly
    with the jkt token and no proof — the server's own requireDpop refuses it,
    proving the check does not depend on the gateway (contract §8). The image
    is a non-root Node build with no curl, so drive it with node's http like
    the container healthcheck does."""
    _key, token = alice_dpop
    node = (
        "const http=require('http');"
        f"const body={json.dumps(json.dumps(LIST))};"
        "const req=http.request('http://127.0.0.1:3000/mcp',"
        "{method:'POST',headers:{'Content-Type':'application/json',"
        "'MCP-Protocol-Version':'2026-07-28','Mcp-Method':'tools/list',"
        f"'Authorization':'Bearer {token}'}}}},"
        "res=>{process.stdout.write(String(res.statusCode));process.exit(0);}); "
        "req.on('error',()=>{process.stdout.write('ERR');process.exit(0);}); "
        "req.write(body);req.end();"
    )
    out = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(Path(__file__).resolve().parents[2] / "compose" / "phase5" / "docker-compose.yml"),
            "exec",
            "-T",
            "scheduling",
            "node",
            "-e",
            node,
        ],
        capture_output=True,
        text=True,
    )
    assert out.stdout.strip() == "401", (
        f"server admitted a proofless jkt token: {out.stdout!r} / {out.stderr!r}"
    )


def test_bearer_client_unaffected(alice):
    """Regression: the plain claude-code bearer token (no cnf.jkt) is not
    subject to DPoP and still reaches the server (not 401 at the DP)."""
    r = requests.post(
        DPOP_MCP,
        headers={**mcp_http.headers_for(LIST), "Authorization": f"Bearer {alice}"},
        json=LIST,
        timeout=15,
    )
    assert r.status_code != 401, r.text
