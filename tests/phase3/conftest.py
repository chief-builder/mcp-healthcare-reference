"""Phase 3 fixtures: tokens (with step-up scopes) and MCP endpoint URLs."""
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase1"))
import oidc_flows  # noqa: E402

KC_BASE = "http://localhost:8080"
REALM = "mcp-plane"
INTERNAL = "http://localhost:8100"  # internal DP
EXTERNAL = "http://localhost:8200"  # external DP
FHIR_MCP_INTERNAL = f"{INTERNAL}/fhir-clinical/mcp"
FHIR_MCP_EXTERNAL = f"{EXTERNAL}/fhir-clinical/mcp"
SCHED_MCP_INTERNAL = f"{INTERNAL}/scheduling/mcp"
ENV_FILE = Path(__file__).resolve().parents[2] / "compose" / "phase3" / ".env"


def _env() -> dict[str, str]:
    env = {}
    for line in ENV_FILE.read_text().splitlines():
        m = re.match(r"^([A-Z0-9_]+)=(.*)$", line.strip())
        if m:
            v = m.group(2)
            if v.startswith("'") and v.endswith("'"):
                v = v[1:-1].replace("'\\''", "'")
            env[m.group(1)] = v
    return env


@pytest.fixture(scope="session")
def env() -> dict[str, str]:
    return _env()


def _login(env, user, scope="openid"):
    return oidc_flows.authorization_code_login(
        KC_BASE, REALM, "claude-code", "http://localhost:8765/callback",
        user, env["FAKE_PING_PASSWORD"], idp_hint="ping", scope=scope,
    )["access_token"]


@pytest.fixture(scope="session")
def alice_floor(env) -> str:
    """Workforce clinician, floor scopes only (no step-up)."""
    return _login(env, "dr-alice")


@pytest.fixture(scope="session")
def alice_everything(env) -> str:
    """Clinician stepped up with the broad $everything scope."""
    return _login(env, "dr-alice", scope="openid mcp:fhir-clinical:everything:read")


@pytest.fixture(scope="session")
def alice_scheduling(env) -> str:
    """Clinician stepped up with scheduling hold + confirm scopes."""
    return _login(env, "dr-alice",
                  scope="openid mcp:scheduling:hold-slot:execute mcp:scheduling:confirm:execute")


@pytest.fixture(scope="session")
def bob_analyst(env) -> str:
    """Workforce analyst — internal tier, but NOT the clinical group."""
    return _login(env, "bob-analyst")


import requests  # noqa: E402

FHIR_BASE = "http://localhost:8081/fhir"


def _seeded_patient_ids(n=2) -> list[str]:
    r = requests.get(f"{FHIR_BASE}/Patient", params={"_count": n})
    r.raise_for_status()
    return [e["resource"]["id"] for e in r.json().get("entry", [])]


def _link_patient(env, patient_id: str) -> None:
    """Link the federated Auth0 user to a seeded patient (contract §6.5)."""
    at = requests.post(f"{KC_BASE}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": env["KC_BOOTSTRAP_ADMIN_USERNAME"], "password": env["KC_BOOTSTRAP_ADMIN_PASSWORD"],
    }).json()["access_token"]
    h = {"Authorization": f"Bearer {at}"}
    users = requests.get(f"{KC_BASE}/admin/realms/{REALM}/users",
                         params={"email": env["AUTH0_TEST_USER_EMAIL"], "exact": "true"}, headers=h).json()
    assert users, "federated Auth0 user not found — log in via patient-agent once first"
    user = users[0]
    attrs = user.get("attributes", {})
    attrs["fhir_patient"] = [patient_id]
    user["attributes"] = attrs
    requests.put(f"{KC_BASE}/admin/realms/{REALM}/users/{user['id']}", json=user, headers=h).raise_for_status()


@pytest.fixture(scope="session")
def seeded_patients() -> list[str]:
    ids = _seeded_patient_ids(2)
    assert len(ids) >= 2, "need >= 2 seeded patients"
    return ids


@pytest.fixture(scope="session")
def patient_token(env, seeded_patients) -> str:
    if not env.get("AUTH0_DOMAIN"):
        pytest.skip("Auth0 leg not configured (AUTH0_* unset)")

    def login():
        return oidc_flows.authorization_code_login(
            KC_BASE, REALM, "patient-agent", "http://localhost:8766/callback",
            env["AUTH0_TEST_USER_EMAIL"], env["AUTH0_TEST_USER_PASSWORD"],
            idp_hint="auth0", scope="openid patient/Patient.read patient/Observation.read",
        )["access_token"]

    login()  # materialize the federated user
    _link_patient(env, seeded_patients[0])  # link to the first seeded patient
    return login()
