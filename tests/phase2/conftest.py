"""Phase 2 acceptance fixtures: tokens per population + gateway endpoints."""
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase1"))
import oidc_flows  # noqa: E402

KC_BASE = "http://localhost:8080"
REALM = "mcp-plane"
INTERNAL_GW = "http://localhost:8100"
EXTERNAL_GW = "http://localhost:8200"
COMPOSE_DIR = Path(__file__).resolve().parents[2] / "compose" / "phase2"
DECK_DIR = Path(__file__).resolve().parents[2] / "deck"
ENV_FILE = COMPOSE_DIR / ".env"


def _load_env() -> dict[str, str]:
    assert ENV_FILE.exists(), f"missing {ENV_FILE}"
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
def alice_token(env) -> str:
    """Workforce, internal tier, mcp-clinical-tools group."""
    return oidc_flows.authorization_code_login(
        KC_BASE, REALM, "claude-code", "http://localhost:8765/callback",
        "dr-alice", env["FAKE_PING_PASSWORD"], idp_hint="ping",
    )["access_token"]


@pytest.fixture(scope="session")
def bob_token(env) -> str:
    """Workforce, internal tier, analytics group (not clinical)."""
    return oidc_flows.authorization_code_login(
        KC_BASE, REALM, "claude-code", "http://localhost:8765/callback",
        "bob-analyst", env["FAKE_PING_PASSWORD"], idp_hint="ping",
    )["access_token"]


@pytest.fixture(scope="session")
def smoke_token(env) -> str:
    """m2m, internal tier, no groups."""
    return oidc_flows.client_credentials_token(
        KC_BASE, REALM, "phase0-smoke", env["PHASE0_CLIENT_SECRET"],
    )["access_token"]


@pytest.fixture(scope="session")
def customer_token(env) -> str:
    """End customer via Auth0, external tier, mcp-external-curated group."""
    if not env.get("AUTH0_DOMAIN"):
        pytest.skip("Auth0 leg not configured (AUTH0_* unset)")
    return oidc_flows.authorization_code_login(
        KC_BASE, REALM, "patient-agent", "http://localhost:8766/callback",
        env["AUTH0_TEST_USER_EMAIL"], env["AUTH0_TEST_USER_PASSWORD"],
        idp_hint="auth0", scope="openid patient/Patient.read",
    )["access_token"]
