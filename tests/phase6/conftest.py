"""Phase 6 fixtures: tokens, the mockhub consent dance, and query helpers
for the audit spine (Loki logs, Tempo traces, Grafana provisioning)."""

import base64
import json
import re
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
SCHED_MCP = f"{INTERNAL}/scheduling/mcp"
BROKER = "http://localhost:8300"
LOKI = "http://localhost:3100"
TEMPO = "http://localhost:3200"
GRAFANA = "http://localhost:3000"
ENV_FILE = Path(__file__).resolve().parents[2] / "compose" / "phase5" / ".env"
EGRESS_SCOPES = "openid egress-github egress-mockhub"
ACCEPT = "application/json, text/event-stream"

# The one-query §9 walk-back: every audit record on the spine that carries
# the jti, regardless of which component emitted it or how it was shipped
# (Kong via OTLP, everything else via container stdout -> Alloy).
TUPLE_QUERY = '{{service_name=~".+"}} | json | __error__="" | token_id="{jti}" or hub_jti="{jti}"'


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


def _login(env, user, scope) -> str:
    return oidc_flows.authorization_code_login(
        KC_BASE,
        REALM,
        "claude-code",
        "http://localhost:8765/callback",
        user,
        env["FAKE_PING_PASSWORD"],
        idp_hint="ping",
        scope=scope,
    )["access_token"]


@pytest.fixture(scope="session")
def alice(env) -> str:
    """Workforce clinician with the egress audiences (vendor leg)."""
    return _login(env, "dr-alice", EGRESS_SCOPES)


@pytest.fixture(scope="session")
def alice_internal(env) -> str:
    """Workforce clinician, floor scopes (first-party server leg)."""
    return _login(env, "dr-alice", "openid")


def claims_of(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def mcp_call(url: str, token: str, tool: str, args: dict) -> requests.Response:
    return requests.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": ACCEPT},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        },
        timeout=15,
    )


def resolve(token: str, vendor: str) -> requests.Response:
    return requests.post(
        f"{BROKER}/v1/tokens/resolve",
        json={"vendor": vendor, "min_ttl_s": 30},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )


def do_consent(token: str) -> None:
    r = resolve(token, "mockhub")
    if r.status_code == 200:
        return
    assert r.status_code == 404, r.text
    page = requests.get(r.json()["authorize_uri"], timeout=15)
    assert page.status_code == 200 and "Connected" in page.text, page.text
    assert resolve(token, "mockhub").status_code == 200


def loki_query(logql: str, since: str = "15m") -> list[tuple[dict, str]]:
    """(stream labels, raw line) for every entry the query matches."""
    r = requests.get(
        f"{LOKI}/loki/api/v1/query_range",
        params={"query": logql, "since": since, "limit": "1000"},
        timeout=15,
    )
    r.raise_for_status()
    return [(s["stream"], v[1]) for s in r.json()["data"]["result"] for v in s["values"]]


def tuple_records(jti: str) -> list[tuple[dict, dict]]:
    """(stream labels, parsed audit record) joined on the jti — one query."""
    out = []
    for stream, line in loki_query(TUPLE_QUERY.format(jti=jti)):
        try:
            out.append((stream, json.loads(line)))
        except json.JSONDecodeError:
            continue
    return out


def wait_for(predicate, timeout: float, interval: float = 2.0, what: str = "condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    pytest.fail(f"timed out after {timeout}s waiting for {what}")
