"""Claim normalization (contract §3.1): raw upstream vocabulary never leaks.

The fake-ping realm deliberately uses `hospital-*` group names; Keycloak's
broker mappers must translate them so no consumer ever sees upstream strings.
"""

import json


def test_no_upstream_vocabulary_anywhere(leg_bundle):
    leg, claims, _ = leg_bundle
    serialized = json.dumps(claims)
    assert "hospital-" not in serialized, (
        f"{leg}: raw upstream group vocabulary leaked into an mcp-plane token"
    )


def test_upstream_issuer_never_leaks(leg_bundle):
    """Every token on the plane is minted by the hub — no upstream iss values."""
    leg, claims, _ = leg_bundle
    assert "fake-ping" not in claims["iss"]
    assert "auth0.com" not in claims["iss"]
    assert "homegrown" not in claims["iss"]
