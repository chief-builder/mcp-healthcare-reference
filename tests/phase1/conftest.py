"""Phase 1 acceptance fixtures: one contract-conformant token per grant path.

Legs (claims contract §6):
  workforce — fake-Ping brokered login (dr-alice)          → §6.1
  legacy    — homegrown AS token + RFC 8693 exchange       → §6.2
  customer  — real Auth0 brokered login (skips w/o creds)  → §6.5
  smoke     — Keycloak-native client credentials           → §6.4-ish (phase 0)
"""

import base64
import json
import re
from pathlib import Path

import oidc_flows
import pytest
import requests

KC_BASE = "http://localhost:8080"
REALM = "mcp-plane"
FHIR_BASE = "http://localhost:8081/fhir"
HOMEGROWN_BASE = "http://localhost:7001"
ENV_FILE = Path(__file__).resolve().parents[2] / "compose" / "phase1" / ".env"

INTERACTIVE_LEGS = {"workforce", "customer"}
ALL_LEGS = ["workforce", "legacy", "customer", "smoke"]


def _load_env() -> dict[str, str]:
    assert ENV_FILE.exists(), f"missing {ENV_FILE} (copy .env.example and fill in)"
    env = {}
    for line in ENV_FILE.read_text().splitlines():
        match = re.match(r"^([A-Z0-9_]+)=(.*)$", line.strip())
        if match:
            value = match.group(2)
            if value.startswith("'") and value.endswith("'"):
                value = value[1:-1].replace("'\\''", "'")
            env[match.group(1)] = value
    return env


@pytest.fixture(scope="session")
def env() -> dict[str, str]:
    return _load_env()


@pytest.fixture(scope="session")
def realm_jwks() -> dict:
    response = requests.get(f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/certs")
    response.raise_for_status()
    return response.json()


def decode_claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _admin_token(env: dict[str, str]) -> str:
    response = requests.post(
        f"{KC_BASE}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": env["KC_BOOTSTRAP_ADMIN_USERNAME"],
            "password": env["KC_BOOTSTRAP_ADMIN_PASSWORD"],
        },
    )
    response.raise_for_status()
    return response.json()["access_token"]


def _seeded_patient_id() -> str:
    response = requests.get(f"{FHIR_BASE}/Patient", params={"_count": 1})
    response.raise_for_status()
    entries = response.json().get("entry") or []
    assert entries, "no patients in HAPI — run compose/phase0/seed-synthea.sh first"
    return entries[0]["resource"]["id"]


def _ensure_patient_linkage(env: dict[str, str]) -> str:
    """Link the federated Auth0 user to a seeded patient (contract §6.5).

    The linkage store is a Keycloak user attribute read by the mcp-fhir-patient
    protocol mapper. Attributes are merged, not replaced, so the idp_origin
    attribute stamped by the broker mapper survives.
    """
    patient_id = _seeded_patient_id()
    headers = {"Authorization": f"Bearer {_admin_token(env)}"}
    response = requests.get(
        f"{KC_BASE}/admin/realms/{REALM}/users",
        params={"email": env["AUTH0_TEST_USER_EMAIL"], "exact": "true"},
        headers=headers,
    )
    response.raise_for_status()
    users = response.json()
    assert users, f"federated Auth0 user {env['AUTH0_TEST_USER_EMAIL']} not found"
    user = users[0]
    attributes = user.get("attributes", {})
    if attributes.get("fhir_patient") != [patient_id]:
        attributes["fhir_patient"] = [patient_id]
        user["attributes"] = attributes
        update = requests.put(
            f"{KC_BASE}/admin/realms/{REALM}/users/{user['id']}",
            json=user,
            headers=headers,
        )
        update.raise_for_status()
    return patient_id


@pytest.fixture(scope="session")
def workforce_token(env) -> dict:
    return oidc_flows.authorization_code_login(
        KC_BASE,
        REALM,
        "claude-code",
        "http://localhost:8765/callback",
        "dr-alice",
        env["FAKE_PING_PASSWORD"],
        idp_hint="ping",
    )


@pytest.fixture(scope="session")
def legacy_token(env) -> dict:
    return oidc_flows.homegrown_exchange_token(
        KC_BASE,
        REALM,
        HOMEGROWN_BASE,
        "svc-legacy-batch",
        env["HOMEGROWN_CLIENT_SECRET"],
        "legacy-exchange",
        env["LEGACY_EXCHANGE_SECRET"],
    )


@pytest.fixture(scope="session")
def smoke_token(env) -> dict:
    return oidc_flows.client_credentials_token(
        KC_BASE,
        REALM,
        "phase0-smoke",
        env["PHASE0_CLIENT_SECRET"],
    )


@pytest.fixture(scope="session")
def customer_token(env) -> dict:
    if not env.get("AUTH0_DOMAIN"):
        pytest.skip("Auth0 leg not configured (AUTH0_* unset in compose/phase1/.env)")

    def login():
        return oidc_flows.authorization_code_login(
            KC_BASE,
            REALM,
            "patient-agent",
            "http://localhost:8766/callback",
            env["AUTH0_TEST_USER_EMAIL"],
            env["AUTH0_TEST_USER_PASSWORD"],
            idp_hint="auth0",
            scope="openid patient/Patient.read",
        )

    login()  # first login materializes the federated user
    _ensure_patient_linkage(env)
    return login()  # second login carries fhir_patient


@pytest.fixture(scope="session", params=ALL_LEGS)
def leg_bundle(request) -> tuple[str, dict, str]:
    """(leg name, decoded claims, raw access token) for every grant path."""
    token = request.getfixturevalue(f"{request.param}_token")
    raw = token["access_token"]
    return request.param, decode_claims(raw), raw
