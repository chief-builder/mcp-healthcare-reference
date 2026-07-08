"""Phase 5 fixtures: egress-scoped workforce tokens, the mockhub consent
dance, and audit-log helpers for the DP plugins and the broker."""
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase1"))
import oidc_flows  # noqa: E402

KC_BASE = "http://localhost:8080"
REALM = "mcp-plane"
INTERNAL = "http://localhost:8100"
EGRESS_MOCKHUB = f"{INTERNAL}/egress/mockhub"
EGRESS_GITHUB = f"{INTERNAL}/egress/github"
BROKER = "http://localhost:8300"
MOCK = "http://localhost:8310"
KONG_CONTAINER = "mcp-phase5-kong-internal-1"
BROKER_CONTAINER = "mcp-phase5-broker-1"
ENV_FILE = Path(__file__).resolve().parents[2] / "compose" / "phase5" / ".env"
EGRESS_SCOPES = "openid egress-github egress-mockhub"
ACCEPT = "application/json, text/event-stream"


def _env() -> dict[str, str]:
    env = {}
    for line in ENV_FILE.read_text().splitlines():
        m = re.match(r"^([A-Z0-9_]+)=(.*)$", line.strip())
        if m:
            env[m.group(1)] = m.group(2)
    return env


@pytest.fixture(scope="session")
def env() -> dict[str, str]:
    return _env()


def _login(env, user, scope=EGRESS_SCOPES) -> str:
    return oidc_flows.authorization_code_login(
        KC_BASE, REALM, "claude-code", "http://localhost:8765/callback",
        user, env["FAKE_PING_PASSWORD"], idp_hint="ping", scope=scope,
    )["access_token"]


@pytest.fixture(scope="session")
def alice(env) -> str:
    """Workforce clinician with both egress audiences."""
    return _login(env, "dr-alice")


@pytest.fixture(scope="session")
def bob(env) -> str:
    """A second workforce sub (fail-closed test needs an uncached entry)."""
    return _login(env, "bob-analyst")


def sub_of(token: str) -> str:
    import base64
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))["sub"]


def mcp_call(url: str, token: str, tool: str, args: dict) -> requests.Response:
    return requests.post(url, headers={"Authorization": f"Bearer {token}",
                                       "Accept": ACCEPT},
                         json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": tool, "arguments": args}},
                         timeout=15)


def resolve(token: str, vendor: str, min_ttl_s: int = 30, sub: str | None = None,
            ) -> requests.Response:
    body = {"vendor": vendor, "min_ttl_s": min_ttl_s}
    if sub is not None:
        body["sub"] = sub
    return requests.post(f"{BROKER}/v1/tokens/resolve", json=body,
                         headers={"Authorization": f"Bearer {token}"}, timeout=15)


def mock_state() -> dict:
    return requests.get(f"{MOCK}/_test/state", timeout=10).json()


def do_consent(token: str) -> None:
    """Run the full §6 dance headlessly: needs-consent -> authorize ->
    mock auto-approves -> broker callback -> connected."""
    r = resolve(token, "mockhub")
    if r.status_code == 200:
        return
    assert r.status_code == 404, r.text
    authorize_uri = r.json()["authorize_uri"]
    page = requests.get(authorize_uri, timeout=15)  # follows 302s across hosts
    assert page.status_code == 200 and "Connected" in page.text, page.text
    assert resolve(token, "mockhub").status_code == 200


def container_audit_events(container: str, marker: str, since: str = "5m") -> list[dict]:
    """One-line JSON audit records off a container log (pre-phase-6 spine)."""
    out = subprocess.run(["docker", "logs", "--since", since, container],
                         capture_output=True, text=True, check=True)
    events = []
    for line in (out.stdout + out.stderr).splitlines():
        idx = line.find(marker)
        if idx == -1:
            continue
        payload = line[idx:]
        start, end = payload.find("{"), payload.rfind("}")
        if start == -1:
            continue
        try:
            events.append(json.loads(payload[start:end + 1]))
        except json.JSONDecodeError:
            continue
    return events


def kong_audit(marker: str) -> list[dict]:
    return container_audit_events(KONG_CONTAINER, f"[{marker}] ")


def broker_audit(event: str) -> list[dict]:
    return [e for e in container_audit_events(BROKER_CONTAINER, '{"audit"')
            if e.get("audit") == event]


def wait_for(predicate, timeout: float, interval: float = 2.0, what: str = "condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    pytest.fail(f"timed out after {timeout}s waiting for {what}")
