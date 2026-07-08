"""Phase 4 acceptance gate (docs/prototype-plan.md §3):

  - agent obtains tokens with zero secrets in its manifest
  - token presented without mTLS, or with a different cert -> 401 + audit event
  - cert rotation happens without pod restart

plus contract §6.3 claim validation for the m2m path and the positive
end-to-end path through the cnf-check plugin.
"""
import json
import subprocess
import time

import pytest

from conftest import (
    SCHED_MCP_HTTP,
    EXPECTED_ISS,
    agent_pod,
    call_find_slots,
    decode,
    kong_audit_events,
    kubectl,
    mint_token,
    pod_file,
    x5t_s256,
)


def sse_json(text: str) -> dict:
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:"):].strip())
    return json.loads(text)


def agent_log_events(tail: int = 50) -> list[dict]:
    out = kubectl("-n", "mcp-agents", "logs", "deploy/loop-agent", "-c", "agent",
                  f"--tail={tail}")
    events = []
    for line in out.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def wait_for(predicate, timeout: float, interval: float = 5.0, what: str = "condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    pytest.fail(f"timed out after {timeout}s waiting for {what}")


# ---------------------------------------------------------------- gate 1
def test_agent_manifest_contains_zero_secrets():
    """The workload's manifest carries identity by *reference* (namespace +
    service account); nothing secret-shaped may appear anywhere in it."""
    deploy = json.loads(kubectl("-n", "mcp-agents", "get", "deploy", "loop-agent", "-o", "json"))
    template = json.dumps(deploy["spec"]["template"]).lower()
    assert "secret" not in template  # no Secret volumes, secretKeyRef, envFrom, imagePullSecrets
    for container in deploy["spec"]["template"]["spec"]["containers"]:
        for env in container.get("env", []):
            assert "valueFrom" not in env, f"indirect env in {container['name']}: {env}"


def test_agent_is_obtaining_tokens_and_calling_tools():
    def looped_ok():
        events = [e for e in agent_log_events() if e.get("event") == "loop"]
        return events and events[-1]["ok"]
    wait_for(looped_ok, timeout=60, what="a successful agent loop iteration")


# ------------------------------------------------- contract §6.3 claims
def test_m2m_token_matches_claims_contract(svid):
    r = mint_token(svid)
    assert r.status_code == 200, r.text
    claims = decode(r.json()["access_token"])

    assert claims["iss"] == EXPECTED_ISS
    aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    assert "mcp://tier/internal" in aud and "mcp://srv/scheduling" in aud
    assert claims["mcp_tier"] == "internal"
    assert claims["mcp_contract"] == "1.0"
    assert claims["azp"] == "mcp-agents.loop-agent"
    assert claims["idp_origin"] == "athenz"
    assert claims["jti"]
    assert claims["cnf"]["x5t#S256"] == x5t_s256(svid[0])  # bound to the presenting cert
    for scope in ("mcp:scheduling:hold-slot:execute", "mcp:scheduling:confirm:execute"):
        assert scope in claims["scope"].split()
    for pii in ("email", "name", "preferred_username"):
        assert pii not in claims  # §3: no directory PII
    assert "fhir_patient" not in claims and "groups" not in claims  # §6.3: absent


def test_keycloak_refuses_client_without_certificate():
    r = mint_token(cert=None)
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_client"


# ------------------------------------------ gate 2: no mTLS / wrong cert
def test_token_replayed_without_client_cert_is_401_and_audited(svid):
    token = mint_token(svid).json()["access_token"]
    jti = decode(token)["jti"]

    r = call_find_slots(token, cert=None)
    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers.get("WWW-Authenticate", "")

    events = [e for e in kong_audit_events()
              if e.get("token_id") == jti and e.get("reason") == "no_client_certificate"]
    assert events, "expected a cnf-check audit record for the rejected replay"
    assert events[0]["decision"] == "deny"
    assert events[0]["client"] == "mcp-agents.loop-agent"


def test_token_replayed_on_plaintext_listener_is_401(svid):
    """§3 of the contract: a cnf the DP cannot verify is a rejection, not a
    no-op — the plaintext listener can never satisfy channel binding."""
    token = mint_token(svid).json()["access_token"]
    r = call_find_slots(token, cert=None, url=SCHED_MCP_HTTP)
    assert r.status_code == 401


def test_token_replayed_with_different_cert_is_401_and_audited(svid, tmp_path):
    token = mint_token(svid).json()["access_token"]
    jti = decode(token)["jti"]

    crt, key = str(tmp_path / "intruder.crt"), str(tmp_path / "intruder.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=intruder", "-keyout", key, "-out", crt],
        check=True, capture_output=True)

    r = call_find_slots(token, cert=(crt, key))
    assert r.status_code == 401

    events = [e for e in kong_audit_events()
              if e.get("token_id") == jti and e.get("reason") == "thumbprint_mismatch"]
    assert events, "expected a cnf-check audit record for the mismatched cert"


def test_matching_cert_succeeds_end_to_end(svid):
    token = mint_token(svid).json()["access_token"]
    r = call_find_slots(token, cert=svid)
    assert r.status_code == 200, r.text
    slots = json.loads(sse_json(r.text)["result"]["content"][0]["text"])
    assert slots and slots[0]["slot_id"]


# ------------------------------------------------- gate 3: rotation
def test_cert_rotation_happens_without_pod_restart(svid):
    """The SVID TTL is 180s (setup-phase4.sh), so SPIRE rotates at ~half-life.
    The gate: the presented cert changes while the same pod keeps running —
    no container restarts across the rotation window — and the loop keeps
    succeeding with the new cert."""
    pod_before = agent_pod()
    restarts_before = {s["name"]: s["restartCount"]
                       for s in pod_before["status"]["containerStatuses"]}
    old_x5t = x5t_s256(svid[0])

    def rotated():
        import base64 as b64, hashlib
        pem = pod_file("/svid/svid.pem")
        body = pem.split("-----BEGIN CERTIFICATE-----", 1)[1].split("-----END CERTIFICATE-----", 1)[0]
        der = b64.b64decode("".join(body.split()))
        new = b64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()
        return new if new != old_x5t else None

    new_x5t = wait_for(rotated, timeout=300, interval=10, what="SVID rotation")

    pod_after = agent_pod()
    assert pod_after["metadata"]["name"] == pod_before["metadata"]["name"]
    for status in pod_after["status"]["containerStatuses"]:
        assert status["restartCount"] == restarts_before[status["name"]], \
            f"{status['name']} restarted during rotation"

    def loop_ok_with_new_cert():
        events = [e for e in agent_log_events() if e.get("event") == "loop" and e.get("ok")]
        return any(e.get("x5t") == new_x5t for e in events)
    wait_for(loop_ok_with_new_cert, timeout=90,
             what="a successful loop iteration with the rotated cert")
