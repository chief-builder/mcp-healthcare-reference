"""Phase 4 fixtures: the loop agent's SVID (read out of the pod), cert-bound
tokens minted host-side with it, and helpers for Kong mTLS calls + audit log
inspection."""
import base64
import hashlib
import json
import subprocess
import time
from pathlib import Path

import pytest
import requests

KC_TOKEN_URL_TLS = "https://localhost:8443/realms/mcp-plane/protocol/openid-connect/token"
EXPECTED_ISS = "http://localhost:8080/realms/mcp-plane"
SCHED_MCP_TLS = "https://localhost:8143/scheduling/mcp"
SCHED_MCP_HTTP = "http://localhost:8100/scheduling/mcp"
CA = str(Path(__file__).resolve().parents[2] / "compose" / "phase4" / "certs" / "lab-ca.crt")
KONG_CONTAINER = "mcp-phase4-kong-internal-1"
CLIENT_ID = "mcp-agents.loop-agent"
SCOPE = "mcp:scheduling:hold-slot:execute mcp:scheduling:confirm:execute"
KCTL = ["kubectl", "--context", "k3d-mcp-lab"]
NS = "mcp-agents"
ACCEPT = "application/json, text/event-stream"


def kubectl(*args: str) -> str:
    for attempt in range(3):  # the k3d API server times out under load spikes
        proc = subprocess.run([*KCTL, *args], capture_output=True, text=True)
        if proc.returncode == 0:
            return proc.stdout
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"kubectl {' '.join(args)}: {proc.stderr}")


def pod_file(path: str) -> str:
    return kubectl("-n", NS, "exec", "deploy/loop-agent", "-c", "agent", "--", "cat", path)


def agent_pod() -> dict:
    pods = json.loads(kubectl("-n", NS, "get", "pods", "-l", "app=loop-agent", "-o", "json"))["items"]
    assert len(pods) == 1
    return pods[0]


def x5t_s256(cert_path: str) -> str:
    pem = Path(cert_path).read_text()
    body = pem.split("-----BEGIN CERTIFICATE-----", 1)[1].split("-----END CERTIFICATE-----", 1)[0]
    der = base64.b64decode("".join(body.split()))
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()


def decode(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


@pytest.fixture()
def svid(tmp_path) -> tuple[str, str]:
    """The loop agent's CURRENT SVID, copied out of the pod (lab-only move —
    in production the key never leaves the workload; here it lets the suite
    replay the exact cert/token combinations the gates require)."""
    cert = tmp_path / "svid.pem"
    key = tmp_path / "svid_key.pem"
    cert.write_text(pod_file("/svid/svid.pem"))
    key.write_text(pod_file("/svid/svid_key.pem"))
    return str(cert), str(key)


def mint_token(cert: tuple[str, str] | None, scope: str = SCOPE) -> requests.Response:
    return requests.post(
        KC_TOKEN_URL_TLS,
        data={"grant_type": "client_credentials", "client_id": CLIENT_ID, "scope": scope},
        cert=cert,
        verify=CA,
        timeout=10,
    )


def call_find_slots(token: str, cert: tuple[str, str] | None, url: str = SCHED_MCP_TLS) -> requests.Response:
    return requests.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": ACCEPT},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "find-slots", "arguments": {}}},
        cert=cert,
        verify=CA if url.startswith("https") else None,
        timeout=10,
    )


def kong_audit_events(since: str = "3m") -> list[dict]:
    """cnf-check emits one-line JSON audit records on the proxy log (contract
    §9 fields); until the Phase 6 audit spine ships they are read off the
    container log."""
    out = subprocess.run(
        ["docker", "logs", "--since", since, KONG_CONTAINER],
        capture_output=True, text=True, check=True,
    )
    events = []
    marker = "[cnf-check] "
    for line in (out.stdout + out.stderr).splitlines():
        idx = line.find(marker)
        if idx == -1:
            continue
        payload = line[idx + len(marker):]
        try:  # nginx appends ", client: ..." after the JSON; no braces in it
            events.append(json.loads(payload[payload.find("{"):payload.rfind("}") + 1]))
        except json.JSONDecodeError:
            continue
    return events
