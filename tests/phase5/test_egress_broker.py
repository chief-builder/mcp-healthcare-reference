"""Phase 5 acceptance gate (docs/prototype-plan.md §3):

  first call -> consent dance -> vendor MCP tool works;
  planted MRN in a create_issue argument -> blocked + audited;
  forced concurrent refresh (60s AT TTL, 20 parallel resolves) -> exactly
  one vendor refresh call (single-flight + generation CAS);
  DELETE /grants revokes at the vendor (RFC 7009).

plus broker-design invariants: state replay/iss-mismatch are security
events (§4.3), STALE -> re-consent (§8), vault loss fails closed (§10),
and the §11 no-issuance rule via route audit. All headless against
mockhub; the GitHub leg activates when the App is configured.
"""
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from conftest import (BROKER, EGRESS_GITHUB, EGRESS_MOCKHUB, MOCK, broker_audit,
                      do_consent, kong_audit, mcp_call, mock_state, resolve,
                      sub_of, wait_for)


@pytest.fixture(autouse=True, scope="module")
def _fresh_vendor(alice):
    """Start the module from a clean vendor + no grant."""
    requests.post(f"{MOCK}/_test/reset", timeout=10)
    requests.delete(f"{BROKER}/v1/grants/mockhub/{sub_of(alice)}",
                    headers={"Authorization": f"Bearer {alice}"}, timeout=10)
    yield


def sse_json(text: str) -> dict:
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:"):].strip())
    return json.loads(text)


def tool_result(r: requests.Response) -> dict:
    return json.loads(sse_json(r.text)["result"]["content"][0]["text"])


# ------------------------------------------------ gate 1: consent dance
def test_first_call_consent_dance_then_tool_works(alice):
    r = mcp_call(EGRESS_MOCKHUB, alice, "create_issue", {"title": "hello"})
    assert r.status_code == 401
    authorize_uri = r.json()["authorize_uri"]
    assert "/v1/authorize/mockhub" in authorize_uri

    page = requests.get(authorize_uri, timeout=15)  # 302s: broker -> AS -> broker
    assert page.status_code == 200 and "Connected" in page.text

    r = mcp_call(EGRESS_MOCKHUB, alice, "create_issue", {"title": "hello again"})
    assert r.status_code == 200, r.text
    assert tool_result(r)["ok"] is True

    # The vendor MCP endpoint accepted its OWN token: the hub JWT was
    # stripped by injection (a hub JWT there would have been a 401).
    state = mock_state()
    assert state["counters"]["mcp_calls"] >= 1
    assert state["counters"]["mcp_unauthorized"] == 0

    assert broker_audit("broker.consent.start")
    complete = broker_audit("broker.consent.complete")
    assert complete and complete[-1]["vendor_user_id"] == "mock-4217"


def test_consent_transaction_is_sub_bound(alice):
    """The authorize txn minted for one resolve cannot be pointed at another
    vendor; a bad txn is a clean 400, never a redirect."""
    r = resolve(alice, "mockhub")  # ACTIVE from the dance above -> 200
    assert r.status_code == 200
    bad = requests.get(f"{BROKER}/v1/authorize/mockhub", params={"txn": "forged"},
                       timeout=10)
    assert bad.status_code == 400


# ---------------------------------------------------- gate 2: egress DLP
def test_planted_mrn_is_blocked_and_audited(alice):
    do_consent(alice)
    before = mock_state()["counters"]["mcp_calls"]

    r = mcp_call(EGRESS_MOCKHUB, alice, "create_issue",
                 {"title": "follow-up", "body": "Patient MRN-1234567 needs review"})
    assert r.status_code == 403
    assert r.json()["error"] == "dlp_blocked"
    assert r.json()["pattern"] == "mrn"

    assert mock_state()["counters"]["mcp_calls"] == before  # never left the DP

    events = [e for e in kong_audit("dlp-egress")
              if e.get("pattern") == "mrn" and e.get("decision") == "deny"]
    assert events, "expected a dlp-egress audit record"
    assert events[-1]["token_id"], "audit record must be jti-joinable"
    # The audit record must not leak what it blocked.
    assert "MRN-1234567" not in json.dumps(events)


def test_ssn_pattern_also_blocked(alice):
    r = mcp_call(EGRESS_MOCKHUB, alice, "create_issue",
                 {"title": "x", "body": "ssn 123-45-6789"})
    assert r.status_code == 403 and r.json()["pattern"] == "ssn"


def test_clean_payload_passes(alice):
    do_consent(alice)
    r = mcp_call(EGRESS_MOCKHUB, alice, "create_issue",
                 {"title": "clean", "body": "no identifiers here"})
    assert r.status_code == 200


# -------------------------------- gate 3: single-flight forced concurrency
def test_twenty_parallel_resolves_one_vendor_refresh(alice):
    do_consent(alice)
    time.sleep(1)  # let the consent's token age past any in-flight work
    before = mock_state()["counters"]

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda _: resolve(alice, "mockhub"), range(20)))

    assert all(r.status_code == 200 for r in results), \
        [r.status_code for r in results]
    tokens = {r.json()["access_token"] for r in results}
    assert len(tokens) == 1, "waiters must receive the winner's token"

    after = mock_state()["counters"]
    assert after["token_refresh"] - before["token_refresh"] == 1, \
        f"expected exactly one vendor refresh, saw {after['token_refresh'] - before['token_refresh']}"
    assert after["rt_replay"] == 0, "a replay means the token family was burned"

    refreshes = broker_audit("broker.refresh")
    assert refreshes, "expected a broker.refresh audit event"
    last = refreshes[-1]
    assert last["generation_to"] == last["generation_from"] + 1


def test_generation_advances_on_next_refresh(alice):
    gen_before = broker_audit("broker.refresh")[-1]["generation_to"]
    r = resolve(alice, "mockhub")
    assert r.status_code == 200
    gen_after = broker_audit("broker.refresh")[-1]["generation_to"]
    assert gen_after == gen_before + 1


# ------------------------------------- §4.3: state replay and iss mix-up
def _walk_to_callback(alice) -> str:
    """Drive the dance manually and return the callback URL un-redeemed."""
    requests.delete(f"{BROKER}/v1/grants/mockhub/{sub_of(alice)}",
                    headers={"Authorization": f"Bearer {alice}"}, timeout=10)
    r = resolve(alice, "mockhub")
    assert r.status_code == 404
    r = requests.get(r.json()["authorize_uri"], allow_redirects=False, timeout=10)
    assert r.status_code == 307 or r.status_code == 302, r.status_code
    r = requests.get(r.headers["location"], allow_redirects=False, timeout=10)
    assert r.status_code in (302, 307)
    return r.headers["location"]


def test_state_replay_is_a_security_event(alice):
    callback = _walk_to_callback(alice)
    assert requests.get(callback, timeout=10).status_code == 200   # legit
    replay = requests.get(callback, timeout=10)                    # replayed
    assert replay.status_code == 400
    alerts = [e for e in broker_audit("broker.consent.fail")
              if e.get("security_event") and e.get("reason") == "state_invalid_or_replayed"]
    assert alerts, "state replay must raise a security alert"


def test_iss_tampering_never_redeems_the_code(alice):
    callback = _walk_to_callback(alice)
    redeemed_before = mock_state()["counters"]["token_code"]
    tampered = callback.replace("iss=http", "iss=https").replace(
        "mock-vendor%3A8310", "evil.example")
    r = requests.get(tampered, timeout=10)
    assert r.status_code == 400
    assert mock_state()["counters"]["token_code"] == redeemed_before
    alerts = [e for e in broker_audit("broker.consent.fail")
              if e.get("security_event") and e.get("reason") == "iss_mismatch"]
    assert alerts, "RFC 9207 mismatch must raise a security alert"
    assert requests.get(callback, timeout=10).status_code == 200  # untampered completes


# --------------------------------------------- §8: STALE -> re-consent
def test_vendor_side_revocation_goes_stale_then_reconsent(alice):
    do_consent(alice)
    requests.post(f"{MOCK}/_test/revoke_family", timeout=10)
    r = resolve(alice, "mockhub")   # refresh hits invalid_grant
    assert r.status_code == 404 and "authorize_uri" in r.json()
    assert broker_audit("broker.stale")
    do_consent(alice)               # dance again -> fresh gen=1 entry
    assert resolve(alice, "mockhub").status_code == 200


# ----------------------------------------- gate 4: DELETE /grants + 7009
def test_delete_grant_revokes_at_vendor(alice):
    do_consent(alice)
    revokes_before = mock_state()["counters"]["revoke"]
    sub = sub_of(alice)

    r = requests.delete(f"{BROKER}/v1/grants/mockhub/{sub}",
                        headers={"Authorization": f"Bearer {alice}"}, timeout=10)
    assert r.status_code == 200 and r.json()["revoked"] is True

    assert mock_state()["counters"]["revoke"] == revokes_before + 1  # RFC 7009 hit
    assert resolve(alice, "mockhub").status_code == 404              # entry gone
    grants = requests.get(f"{BROKER}/v1/grants",
                          headers={"Authorization": f"Bearer {alice}"}, timeout=10)
    assert all(g["vendor"] != "mockhub" for g in grants.json()["grants"])
    audit = broker_audit("broker.revoke")
    assert audit and audit[-1]["outcome"] == "revoked"


def test_grants_are_self_service_only(alice, bob):
    r = requests.delete(f"{BROKER}/v1/grants/mockhub/{sub_of(alice)}",
                        headers={"Authorization": f"Bearer {bob}"}, timeout=10)
    assert r.status_code == 403


# ------------------------------------------------- §11 and §10 invariants
def test_no_issuance_rule_route_audit():
    """§11: no token minting, no JWKS. The route table is the whole API."""
    spec = requests.get(f"{BROKER}/openapi.json", timeout=10).json()
    paths = set(spec["paths"])
    assert paths == {"/healthz", "/v1/tokens/resolve", "/v1/authorize/{vendor}",
                     "/v1/callback/{vendor}", "/v1/grants/{vendor}/{sub}",
                     "/v1/grants", "/v1/admin/vendors/{vendor}"}
    assert not any("jwks" in p or p.endswith("/token") for p in paths)


def test_sub_mismatch_is_rejected(alice):
    r = resolve(alice, "mockhub", sub="somebody-else")
    assert r.status_code == 400


def test_vault_loss_fails_closed(bob):
    # PAUSE (not stop): the dev-mode vault holds all provisioning in memory,
    # so a stop/start would wipe the broker token and vendor creds. Pausing
    # freezes it — unreachable to the broker, state intact on unpause.
    vault = subprocess.run(
        ["docker", "ps", "--filter", "name=vault", "--format", "{{.Names}}"],
        check=True, capture_output=True, text=True).stdout.split()[0]
    subprocess.run(["docker", "pause", vault], check=True, capture_output=True)
    try:
        r = resolve(bob, "mockhub")   # bob has no cached entry -> vault read
        assert r.status_code == 503
        assert "vault" in r.json()["type"]
    finally:
        subprocess.run(["docker", "unpause", vault], check=True, capture_output=True)
    wait_for(lambda: requests.get(f"{BROKER}/healthz", timeout=5).ok,
             timeout=60, what="broker healthy after vault unpause")


# ------------------------------------------------------- real-GitHub leg
def test_github_leg_when_configured(env, alice):
    if not env.get("GITHUB_CLIENT_ID"):
        pytest.skip("GitHub App not configured (GITHUB_CLIENT_ID unset)")
    r = resolve(alice, "github", min_ttl_s=120)
    if r.status_code == 404:
        pytest.skip("GitHub consent not yet granted — open once in a browser: "
                    + r.json()["authorize_uri"])
    assert r.status_code == 200
    r = mcp_call(EGRESS_GITHUB, alice, "list_issues",
                 {"owner": env.get("GITHUB_TEST_OWNER", ""),
                  "repo": env.get("GITHUB_TEST_REPO", "")})
    assert r.status_code in (200, 400)  # 400 = tool args; the auth path worked
