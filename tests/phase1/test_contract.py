"""Validates every claim in docs/mcp-token-claims-contract.md §3 on all legs.

Deferred by phase (explicit xfail, not silence):
  - aud second level (per-server resource URIs)  → Phase 2 (gateway tiers)
  - mcp: scope grammar on workforce/m2m paths    → Phase 3 (first-party MCP)
  - cnf on the m2m path                          → Phase 4 (cert-bound m2m)
"""

import jwt
import requests
from conftest import FHIR_BASE, INTERACTIVE_LEGS, KC_BASE, REALM

ISSUER = f"{KC_BASE}/realms/{REALM}"
GROUP_VOCABULARY = {
    "mcp-platform-admin",
    "mcp-clinical-tools",
    "mcp-scheduling-tools",
    "mcp-analytics-readonly",
    "mcp-external-curated",
    "mcp-agent-operators",
}
EXPECTED = {
    "workforce": {"tier": "internal", "idp_origin": "ping"},
    "legacy": {"tier": "internal", "idp_origin": "homegrown"},
    "customer": {"tier": "external", "idp_origin": "auth0"},
    "smoke": {"tier": "internal", "idp_origin": "keycloak"},
}
PII_CLAIMS = (
    "email",
    "name",
    "given_name",
    "family_name",
    "preferred_username",
    "phone_number",
    "birthdate",
    "address",
)


def _aud_list(claims) -> list[str]:
    aud = claims.get("aud", [])
    return [aud] if isinstance(aud, str) else list(aud)


def test_signature_alg_and_issuer(leg_bundle, realm_jwks):
    leg, claims, raw = leg_bundle
    header = jwt.get_unverified_header(raw)
    assert header["alg"] == "PS256", f"{leg}: contract §2 requires PS256, got {header['alg']}"
    key = next(k for k in realm_jwks["keys"] if k["kid"] == header["kid"])
    verified = jwt.decode(
        raw,
        jwt.PyJWK(key).key,
        algorithms=["PS256"],
        issuer=ISSUER,
        options={"verify_aud": False},
    )
    assert verified["iss"] == ISSUER


def test_sub_stable_non_email(leg_bundle):
    leg, claims, _ = leg_bundle
    assert claims.get("sub"), f"{leg}: sub missing"
    assert "@" not in claims["sub"], f"{leg}: sub must never be an email (§3)"


def test_azp_present(leg_bundle):
    leg, claims, _ = leg_bundle
    expected_azp = {
        "workforce": "claude-code",
        "legacy": "legacy-exchange",
        "customer": "patient-agent",
        "smoke": "phase0-smoke",
    }[leg]
    assert claims.get("azp") == expected_azp


def test_lifetimes(leg_bundle):
    leg, claims, _ = leg_bundle
    lifetime = claims["exp"] - claims["iat"]
    ceiling = 600 if leg in INTERACTIVE_LEGS else 300
    assert 0 < lifetime <= ceiling, f"{leg}: lifetime {lifetime}s exceeds §2 ceiling {ceiling}s"


def test_jti_present(leg_bundle):
    leg, claims, _ = leg_bundle
    assert claims.get("jti"), f"{leg}: jti missing (audit joinability, §3/§9)"


def test_mcp_contract_version(leg_bundle):
    leg, claims, _ = leg_bundle
    assert claims.get("mcp_contract") == "1.0", f"{leg}: mcp_contract missing/wrong (§11)"


def test_tier_and_tier_audience(leg_bundle):
    leg, claims, _ = leg_bundle
    tier = claims.get("mcp_tier")
    assert tier == EXPECTED[leg]["tier"], f"{leg}: mcp_tier {tier}"
    tier_audiences = [a for a in _aud_list(claims) if a.startswith("mcp://tier/")]
    assert tier_audiences == [f"mcp://tier/{tier}"], (
        f"{leg}: aud must carry exactly one tier audience matching mcp_tier (§4), "
        f"got {tier_audiences}"
    )


def test_aud_second_level(leg_bundle):
    """Two-level aud (contract §4). Graduated in Phase 3: interactive clients
    that target first-party servers now carry per-server resource URIs. The m2m
    smoke/legacy legs are not server-targeted, so they carry only the tier aud."""
    leg, claims, _ = leg_bundle
    server_auds = [a for a in _aud_list(claims) if a.startswith("mcp://srv/")]
    if leg in ("workforce", "customer"):
        assert server_auds, f"{leg}: §4 requires a per-server resource URI in aud"


def test_idp_origin(leg_bundle):
    leg, claims, _ = leg_bundle
    assert claims.get("idp_origin") == EXPECTED[leg]["idp_origin"]


def test_scope_present_and_path_appropriate(leg_bundle):
    leg, claims, _ = leg_bundle
    assert "scope" in claims and isinstance(claims["scope"], str), f"{leg}: scope claim missing"
    scopes = set(claims["scope"].split()) - {""}
    if leg == "customer":
        # §6.5: SMART-style scopes only; mcp: scopes forbidden on this path
        assert not any(s.startswith("mcp:") for s in scopes), f"{leg}: mcp: scope on customer path"
        assert any(s.startswith("patient/") for s in scopes), f"{leg}: no patient/ scope granted"
        assert all(s.startswith(("patient/", "openid", "profile", "email")) for s in scopes)


def test_groups_normalized(leg_bundle):
    leg, claims, _ = leg_bundle
    groups = claims.get("groups")
    if leg == "workforce":
        assert groups == ["mcp-clinical-tools"], (
            f"{leg}: dr-alice must carry exactly the normalized clinical group, got {groups}"
        )
    if groups is not None:
        assert set(groups) <= GROUP_VOCABULARY, f"{leg}: non-vocabulary groups {groups} (§3.1)"


def test_amr_on_interactive_paths(leg_bundle):
    leg, claims, _ = leg_bundle
    if leg in INTERACTIVE_LEGS:
        amr = claims.get("amr")
        assert isinstance(amr, list) and amr, f"{leg}: amr mandatory on interactive paths (§3)"
    else:
        assert "amr" not in claims, f"{leg}: amr must not appear on m2m paths"


def test_fhir_patient_compartment(leg_bundle):
    leg, claims, _ = leg_bundle
    if leg == "customer":
        patient_id = claims.get("fhir_patient")
        assert patient_id, "customer path requires fhir_patient (§6.5)"
        response = requests.get(f"{FHIR_BASE}/Patient/{patient_id}")
        assert response.status_code == 200, f"fhir_patient {patient_id} not resolvable in HAPI"
    else:
        assert "fhir_patient" not in claims, (
            f"{leg}: fhir_patient forbidden off the Auth0 path (§3)"
        )


def test_act_absent_without_delegation(leg_bundle):
    leg, claims, _ = leg_bundle
    assert "act" not in claims, f"{leg}: act must only appear on on-behalf-of flows (§7)"


def test_cnf_absent_without_mtls(leg_bundle):
    leg, claims, _ = leg_bundle
    assert "cnf" not in claims, f"{leg}: cnf forbidden absent mTLS (§3); Phase 4 adds the mTLS path"


def test_no_pii_claims(leg_bundle):
    leg, claims, _ = leg_bundle
    leaked = [c for c in PII_CLAIMS if c in claims]
    assert not leaked, f"{leg}: access token carries PII claims {leaked} (§3 forbids)"
