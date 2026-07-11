"""Phase 7 red-team fixtures (prototype-plan.md §3, Phase 7).

Drives the running phase-5 stack + phase-6 audit spine. Reuses the phase-1
OIDC flow drivers and mirrors the phase-5/6 broker + audit helpers so the
red-team probes read the same way the acceptance gates do.

A passing test here means the defense held. The two former xfail(strict)
gaps (GitHub #1 iss-omission, #2 mass-STALE) are now fixed and asserted as
real defenses; no strict-xfail probes remain.
"""
import base64
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase1"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase3"))
import oidc_flows  # noqa: E402
import dpop as dpop_lib  # noqa: E402

KC_BASE = "http://localhost:8080"
REALM = "mcp-plane"
INTERNAL = "http://localhost:8100"
EXTERNAL = "http://localhost:8200"
EGRESS_MOCKHUB = f"{INTERNAL}/egress/mockhub"
BROKER = "http://localhost:8300"
MOCK = "http://localhost:8310"
LOKI = "http://localhost:3100"
BROKER_CONTAINER = "mcp-phase5-broker-1"
ENV_FILE = Path(__file__).resolve().parents[2] / "compose" / "phase5" / ".env"
EGRESS_SCOPES = "openid egress-github egress-mockhub"
ACCEPT = "application/json, text/event-stream"

# Every container the audit spine ships to Loki; the token-in-log grep sweeps
# all of them plus Loki itself.
PROJECT = "mcp-phase5"


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


def login(env, user, scope=EGRESS_SCOPES) -> str:
    return oidc_flows.authorization_code_login(
        KC_BASE, REALM, "claude-code", "http://localhost:8765/callback",
        user, env["FAKE_PING_PASSWORD"], idp_hint="ping", scope=scope,
    )["access_token"]


@pytest.fixture(scope="session")
def alice(env) -> str:
    """Workforce clinician, internal tier, egress audiences."""
    return login(env, "dr-alice")


@pytest.fixture(scope="session")
def bob(env) -> str:
    """Workforce analyst, internal tier, non-clinical group."""
    return login(env, "bob-analyst")


@pytest.fixture(scope="session")
def alice_dpop(env):
    """Workforce clinician on the DPoP client: a per-client EC key and the
    cnf.jkt-bound access token minted with a proof (RFC 9449). Returns
    (key, token)."""
    key = dpop_lib.make_key()
    token = oidc_flows.authorization_code_login(
        KC_BASE, REALM, "workforce-dpop", "http://localhost:8765/callback",
        "dr-alice", env["FAKE_PING_PASSWORD"], idp_hint="ping",
        scope="openid", dpop_key=key,
    )["access_token"]
    return key, token


def claims_of(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def resolve(token: str, vendor: str = "mockhub", min_ttl_s: int = 30) -> requests.Response:
    return requests.post(f"{BROKER}/v1/tokens/resolve",
                         json={"vendor": vendor, "min_ttl_s": min_ttl_s},
                         headers={"Authorization": f"Bearer {token}"}, timeout=15)


def revoke_grant(token: str, vendor: str = "mockhub") -> None:
    """Self-service revoke so a probe starts from a clean needs-consent state
    regardless of grants left by earlier runs (broker vault persists)."""
    sub = claims_of(token)["sub"]
    requests.delete(f"{BROKER}/v1/grants/{vendor}/{sub}",
                    headers={"Authorization": f"Bearer {token}"}, timeout=15)


def new_consent_state(token: str) -> str:
    """Drive resolve -> needs-consent -> /v1/authorize and capture the
    unconsumed callback `state` from the redirect to the vendor (without
    following it), so a probe can hit /v1/callback directly."""
    revoke_grant(token)  # force a fresh needs-consent
    r = resolve(token)
    assert r.status_code == 404, f"expected needs-consent, got {r.status_code}: {r.text}"
    auth_uri = r.json()["authorize_uri"]
    redirect = requests.get(auth_uri, allow_redirects=False, timeout=15)
    assert redirect.status_code in (302, 307), redirect.text
    loc = redirect.headers["Location"]
    return re.search(r"[?&]state=([^&]+)", loc).group(1)


def do_consent(token: str) -> None:
    r = resolve(token)
    if r.status_code == 200:
        return
    assert r.status_code == 404, r.text
    page = requests.get(r.json()["authorize_uri"], timeout=15)
    assert page.status_code == 200 and "Connected" in page.text, page.text
    assert resolve(token).status_code == 200


def mock_reset() -> None:
    requests.post(f"{MOCK}/_test/reset", timeout=10)


def mock_state() -> dict:
    return requests.get(f"{MOCK}/_test/state", timeout=10).json()


def broker_audit(since: str = "3m") -> list[dict]:
    """Every one-line JSON audit record off the broker container log."""
    out = subprocess.run(["docker", "logs", "--since", since, BROKER_CONTAINER],
                         capture_output=True, text=True, check=True)
    events = []
    for line in (out.stdout + out.stderr).splitlines():
        for m in re.finditer(r'\{"audit".*?\}', line):
            try:
                events.append(json.loads(m.group(0)))
            except json.JSONDecodeError:
                continue
    return events


def running_containers() -> list[str]:
    out = subprocess.run(
        ["docker", "ps", "--filter", f"name={PROJECT}", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=True)
    return [n for n in out.stdout.splitlines() if n.strip()]


def grep_container_logs(needle: str, since: str = "30m") -> dict[str, int]:
    """Count occurrences of `needle` in each project container's logs."""
    hits = {}
    for name in running_containers():
        out = subprocess.run(["docker", "logs", "--since", since, name],
                             capture_output=True, text=True)
        n = (out.stdout + out.stderr).count(needle)
        if n:
            hits[name] = n
    return hits


def grep_loki(needle: str, since: str = "30m") -> int:
    """Count Loki log lines across all services containing `needle`."""
    r = requests.get(f"{LOKI}/loki/api/v1/query_range",
                     params={"query": '{service_name=~".+"} |= "' + needle + '"',
                             "since": since, "limit": "1000"}, timeout=20)
    if r.status_code != 200:
        return -1
    return sum(len(s["values"]) for s in r.json()["data"]["result"])


def wait_for(predicate, timeout: float, interval: float = 1.0, what: str = "condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    pytest.fail(f"timed out after {timeout}s waiting for {what}")
