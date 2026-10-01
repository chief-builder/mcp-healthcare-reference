#!/usr/bin/env bash
# Phase 0 acceptance checks (docs/prototype-plan.md §3):
#   1. Keycloak issues a client-credentials token carrying the contract
#      claims mcp_contract / mcp_tier / idp_origin (claims contract §3).
#   2. HAPI serves Patient/$everything for a seeded synthetic patient.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

KC_BASE="${KC_BASE:-http://localhost:8080}"
FHIR_BASE="${FHIR_BASE:-http://localhost:8081/fhir}"
ENV_FILE="compose/phase0/.env"

fail=0
pass() { echo "PASS: $1"; }
failure() { echo "FAIL: $1" >&2; fail=1; }

[ -f "$ENV_FILE" ] || { echo "Missing $ENV_FILE (cp compose/phase0/.env.example → .env)" >&2; exit 1; }
# shellcheck disable=SC1090
source "$ENV_FILE"
: "${PHASE0_CLIENT_SECRET:?PHASE0_CLIENT_SECRET not set in $ENV_FILE}"

curl -sf "${KC_BASE}/realms/mcp-plane/.well-known/openid-configuration" -o /dev/null \
  || { echo "Keycloak realm mcp-plane unreachable at ${KC_BASE} — is compose/phase0 up?" >&2; exit 1; }
curl -sf "${FHIR_BASE}/metadata" -o /dev/null \
  || { echo "HAPI FHIR unreachable at ${FHIR_BASE} — is compose/phase0 up?" >&2; exit 1; }

# --- Check 1: contract claims on a client-credentials token ---------------
token=$(curl -sf "${KC_BASE}/realms/mcp-plane/protocol/openid-connect/token" \
  -d grant_type=client_credentials \
  -d client_id=phase0-smoke \
  -d client_secret="$PHASE0_CLIENT_SECRET" | jq -r '.access_token // empty')

if [ -z "$token" ]; then
  failure "no access token from client_credentials grant"
else
  payload=$(printf '%s' "$token" | cut -d. -f2 | tr '_-' '/+')
  case $(( ${#payload} % 4 )) in 2) payload="${payload}==" ;; 3) payload="${payload}=" ;; esac
  claims=$(printf '%s' "$payload" | base64 -d 2>/dev/null)

  for check in 'mcp_contract:"1.0"' 'mcp_tier:"internal"' 'idp_origin:"keycloak"'; do
    name="${check%%:*}"; want="${check#*:}"
    if printf '%s' "$claims" | jq -e ".${name} == ${want}" > /dev/null; then
      pass "token claim ${name} = ${want}"
    else
      failure "token claim ${name}: expected ${want}, got $(printf '%s' "$claims" | jq -c ".${name}")"
    fi
  done
fi

# --- Check 2: Patient/$everything for a seeded patient --------------------
patient_id=$(curl -sf "${FHIR_BASE}/Patient?_count=1" | jq -r '.entry[0].resource.id // empty')

if [ -z "$patient_id" ]; then
  failure "no patients in HAPI — run compose/phase0/seed-synthea.sh first"
else
  everything=$(curl -sf "${FHIR_BASE}/Patient/${patient_id}/\$everything")
  if printf '%s' "$everything" | jq -e '.resourceType == "Bundle" and ((.entry | length) > 0)' > /dev/null; then
    pass "Patient/${patient_id}/\$everything returned a Bundle with $(printf '%s' "$everything" | jq '.entry | length') entries"
  else
    failure "Patient/${patient_id}/\$everything did not return a non-empty Bundle"
  fi
fi

# ---------------------------------------------------------------------------
if [ "$fail" -eq 0 ]; then
  echo "phase0: ALL CHECKS GREEN"
else
  echo "phase0: FAILURES" >&2
fi
exit "$fail"
