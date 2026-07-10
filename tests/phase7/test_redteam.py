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
import base64
import hashlib
import secrets
import time
from urllib.parse import parse_qs, urlparse

import pytest
import requests

import conftest as C
from conftest import (BROKER, EXTERNAL, INTERNAL, KC_BASE, MOCK, REALM,
                      broker_audit, claims_of, do_consent, grep_container_logs,
                      grep_loki, login, mock_reset, mock_state,
                      new_consent_state, resolve, wait_for)


# ── P1. Cross-tier replay (arch §13 tier isolation; Appendix A.5) ─────────────

def _fhir_get(gateway: str, token: str | None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.get(f"{gateway}/fhir/Patient", headers=headers,
                        params={"_count": 1}, timeout=15)


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
    except (KeyError, AssertionError):
        return  # refused at the authorization endpoint — the secure outcome
    assert "mcp:fhir-clinical:*:execute" not in claims_of(tok).get("scope", "").split(), \
        "wildcard tool scope leaked into a token"


def test_scope_string_alone_is_not_authorization(env):
    """Defense in depth: a non-clinical user CAN request the clinical scope
    string, but the DP group ACL still blocks the clinical route — the scope
    is not sufficient without the group (contract §5, §8)."""
    bob_clinical = login(env, "bob-analyst",
                         "openid mcp:fhir-clinical:everything:read")
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
    redirect = requests.get(r.json()["authorize_uri"], allow_redirects=False,
                            timeout=15)
    scope_param = parse_qs(urlparse(redirect.headers["Location"]).query).get(
        "scope", [""])[0].split()
    ceiling = {"issues:read", "issues:write"}
    assert set(scope_param) <= ceiling, \
        f"broker requested {scope_param} beyond ceiling {ceiling}"


# ── P3. Broker callback `state` replay (design §4.3/§10) ───────────────────────

def test_state_replay_is_a_security_event(alice):
    """A callback `state` that is unknown/consumed is a security event, not a
    plain 400 — replaying one must alert."""
    forged = secrets.token_urlsafe(32)
    r = requests.get(f"{BROKER}/v1/callback/mockhub",
                     params={"state": forged, "code": "x"},
                     allow_redirects=False, timeout=15)
    assert r.status_code == 400
    events = broker_audit()
    assert any(e.get("audit") == "broker.consent.fail"
               and e.get("reason") == "state_invalid_or_replayed"
               and e.get("security_event") is True for e in events), \
        "state replay did not raise a security_event audit alert"


# ── P4. RFC 9207 iss on the broker callback (design §2; contract §8) ──────────

def test_iss_tampering_is_rejected_and_alerts(alice):
    """A callback whose `iss` mismatches the recorded issuer is rejected
    before code redemption, with a security_event alert (mix-up defense)."""
    state = new_consent_state(alice)
    r = requests.get(f"{BROKER}/v1/callback/mockhub",
                     params={"state": state, "code": "forged",
                             "iss": "https://evil.example"},
                     allow_redirects=False, timeout=15)
    assert r.status_code == 400 and "mismatch" in r.text.lower()
    assert any(e.get("audit") == "broker.consent.fail"
               and e.get("reason") == "iss_mismatch"
               and e.get("security_event") is True for e in broker_audit()), \
        "iss tampering did not raise a security_event"


def test_iss_omission_is_rejected_when_vendor_advertises_iss(alice):
    meta = requests.get(
        f"{MOCK}/.well-known/oauth-authorization-server", timeout=10).json()
    assert meta.get("authorization_response_iss_parameter_supported") is True
    state = new_consent_state(alice)
    # Assert on the RESPONSE (not shared logs, which the tamper probe also
    # writes to): a compliant broker rejects the missing iss the same way it
    # rejects a mismatched one — 400 with an issuer rejection, no redemption.
    r = requests.get(f"{BROKER}/v1/callback/mockhub",
                     params={"state": state, "code": "forged-mixup-code"},
                     allow_redirects=False, timeout=15)
    assert r.status_code == 400 and "issuer" in r.text.lower(), \
        f"missing iss not rejected as a mix-up (got {r.status_code}: {r.text[:80]})"


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
    assert any(e.get("audit") in ("broker.stale.mass", "broker.page")
               or e.get("mass_stale") or e.get("page") for e in events), \
        "no mass-stale/page anomaly signal emitted"


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

    for label, needle in (("vendor access_token", vendor_at),
                          ("hub jwt signature", hub_sig)):
        container_hits = grep_container_logs(needle)
        assert not container_hits, f"{label} found in container logs: {container_hits}"
        loki_hits = grep_loki(needle)
        assert loki_hits == 0, f"{label} found {loki_hits}× on the Loki spine"


# ── P7. CIMD external-tier experiment (arch §5.1) ─────────────────────────────

def test_cimd_url_form_client_id_is_refused():
    """A URL-form client_id from a non-allowlisted origin must be refused, and
    must NOT redirect back to the attacker-controlled URL."""
    r = requests.get(f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/auth",
                     params={"client_id": "https://evil.example/mcp-metadata.json",
                             "redirect_uri": "https://evil.example/cb",
                             "response_type": "code", "scope": "openid",
                             "state": "x"},
                     allow_redirects=False, timeout=15)
    assert r.status_code >= 400, f"URL-form client_id was accepted ({r.status_code})"
    assert "evil.example" not in r.headers.get("Location", ""), \
        "authorization redirected to the non-allowlisted origin"


# ── Arch §13 checklist — broker no-issuance rule (broker design §11) ──────────

@pytest.mark.parametrize("path", [
    "/oauth/token", "/token", "/keys", "/v1/tokens/issue",
    "/.well-known/jwks.json", "/.well-known/openid-configuration",
])
def test_broker_exposes_no_issuance_endpoint(path):
    """The broker is a custodian, not an issuer: no token or JWKS surface."""
    assert requests.get(f"{BROKER}{path}", timeout=10).status_code == 404


def test_broker_resolve_requires_valid_hub_token():
    """resolve without a hub token is 401 — the JWT is authoritative."""
    r = requests.post(f"{BROKER}/v1/tokens/resolve",
                      json={"vendor": "mockhub", "min_ttl_s": 30}, timeout=15)
    assert r.status_code == 401
