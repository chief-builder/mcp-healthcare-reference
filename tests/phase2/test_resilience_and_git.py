"""Phase 2 acceptance: DPs survive CP severance; git is the config truth."""

import subprocess
import time

import requests
from conftest import COMPOSE_DIR, DECK_DIR, INTERNAL_GW


def _compose(*args) -> None:
    subprocess.run(
        ["docker", "compose", *args],
        cwd=COMPOSE_DIR,
        check=True,
        capture_output=True,
    )


def _running_cp_uplink() -> str:
    """Find the live cp-uplink container by name, whichever phase stack is up."""
    out = subprocess.run(
        ["docker", "ps", "--filter", "name=cp-uplink", "--format", "{{.Names}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    assert out, "no running cp-uplink container found"
    return out[0]


def test_dp_keeps_proxying_with_cp_uplink_severed(alice_token):
    """Stop the cp-uplink proxy (the DPs' only path to Konnect) and prove the
    data plane still serves from its cached config. Stack-agnostic: targets the
    running cp-uplink container by name (works against any phase's stack)."""
    headers = {"Authorization": f"Bearer {alice_token}"}
    assert requests.get(f"{INTERNAL_GW}/fhir/Patient", headers=headers).status_code == 200

    container = _running_cp_uplink()
    subprocess.run(["docker", "stop", container], check=True, capture_output=True)
    try:
        time.sleep(5)  # let the websocket actually drop
        for _ in range(5):
            response = requests.get(f"{INTERNAL_GW}/fhir/Patient", headers=headers)
            assert response.status_code == 200, "DP stopped serving without its CP"
            time.sleep(1)
    finally:
        subprocess.run(["docker", "start", container], check=True, capture_output=True)


def test_deck_state_matches_live_config(env):
    """deck diff must be empty for both control planes: any drift means
    someone changed the gateway outside git."""
    import os

    deck_env = {**os.environ, "DECK_KONNECT_TOKEN": env["KONNECT_TOKEN"]}
    for tier in ("internal", "external"):
        # token passed via env on purpose: argv would leak it into error traces
        result = subprocess.run(
            [
                "deck",
                "gateway",
                "diff",
                str(DECK_DIR / f"{tier}.yaml"),
                "--konnect-addr",
                f"https://{env['KONNECT_REGION']}.api.konghq.com",
                "--konnect-control-plane-name",
                f"mcp-{tier}",
            ],
            capture_output=True,
            text=True,
            env=deck_env,
        )
        assert result.returncode == 0, f"deck diff failed for {tier}: {result.stderr[:400]}"
        for line in ("Created: 0", "Updated: 0", "Deleted: 0"):
            assert line in result.stdout, f"{tier} drifted from git:\n{result.stdout}"
