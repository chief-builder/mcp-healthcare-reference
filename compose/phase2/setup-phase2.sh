#!/usr/bin/env bash
# Phase 2 provisioning + bring-up. Idempotent.
#
#  A. Konnect (API, never the UI): two hybrid control planes, pinned DP client
#     certificates, generated DP env + uplink proxy config.
#  B. Stack bring-up (docker compose), then the phase 1 Keycloak setup
#     (reused verbatim) plus the phase 2 realm delta.
#  C. deck gateway sync of the git-tracked state in deck/.
#
# Requires: .env with KONNECT_REGION + KONNECT_TOKEN (and the phase 1 vars),
# deck installed (brew install deck), openssl, jq.
set -euo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a

API="https://${KONNECT_REGION}.api.konghq.com/v2"
AUTH=(-H "Authorization: Bearer ${KONNECT_TOKEN}")

mkdir -p certs generated

# --- A1: control planes ------------------------------------------------------
cp_id() { # name -> id (empty if absent)
  curl -sf "${AUTH[@]}" "${API}/control-planes?filter%5Bname%5D=$1" | jq -r '.data[0].id // empty'
}

ensure_cp() { # name
  local id
  id=$(cp_id "$1")
  if [ -z "$id" ]; then
    echo "==> Creating control plane $1..." >&2
    local resp
    resp=$(curl -s "${AUTH[@]}" -H 'Content-Type: application/json' \
      -d "{\"name\":\"$1\",\"cluster_type\":\"CLUSTER_TYPE_HYBRID\",\"description\":\"mcp lab ($1 tier), managed by deck + setup-phase2.sh — do not edit in UI\"}" \
      "${API}/control-planes")
    id=$(echo "$resp" | jq -r '.id // empty')
    if [ -z "$id" ]; then
      echo "FAILED to create control plane $1 — likely a plan quota limit." >&2
      echo "Konnect said: $(echo "$resp" | jq -c .)" >&2
      exit 1
    fi
  fi
  echo "$id"
}

INTERNAL_ID=$(ensure_cp mcp-internal)
EXTERNAL_ID=$(ensure_cp mcp-external)
echo "==> Control planes: mcp-internal=${INTERNAL_ID} mcp-external=${EXTERNAL_ID}"

# --- A2: pinned DP client certificates ---------------------------------------
ensure_cert() { # tier cp_id
  local tier=$1 id=$2
  if [ ! -f "certs/${tier}.crt" ]; then
    echo "==> Generating DP client certificate for ${tier}..."
    openssl req -new -x509 -nodes -newkey rsa:2048 -sha256 -days 90 \
      -subj "/CN=mcp-${tier}-dp" \
      -keyout "certs/${tier}.key" -out "certs/${tier}.crt" 2>/dev/null
  fi
  # pin (idempotent: Konnect de-duplicates identical certs; ignore conflict)
  jq -n --rawfile cert "certs/${tier}.crt" '{cert: $cert}' \
    | curl -s "${AUTH[@]}" -H 'Content-Type: application/json' -d @- \
      "${API}/control-planes/${id}/dp-client-certificates" > /dev/null
}
ensure_cert internal "$INTERNAL_ID"
ensure_cert external "$EXTERNAL_ID"

# --- A3: generated DP env + uplink proxy config ------------------------------
endpoint_host() { # cp_id endpoint_field
  curl -sf "${AUTH[@]}" "${API}/control-planes/$1" \
    | jq -r ".config.$2" | sed -E 's#^https?://##'
}
INT_CLUSTER=$(endpoint_host "$INTERNAL_ID" control_plane_endpoint)
INT_TELEMETRY=$(endpoint_host "$INTERNAL_ID" telemetry_endpoint)
EXT_CLUSTER=$(endpoint_host "$EXTERNAL_ID" control_plane_endpoint)
EXT_TELEMETRY=$(endpoint_host "$EXTERNAL_ID" telemetry_endpoint)

# DPs use the real endpoints; the cp-uplink container intercepts them via
# network aliases (see docker-compose.yml + uplink.conf)
cat > generated/dp-internal.env <<EOF
KONG_CLUSTER_CONTROL_PLANE=${INT_CLUSTER}:443
KONG_CLUSTER_SERVER_NAME=${INT_CLUSTER}
KONG_CLUSTER_TELEMETRY_ENDPOINT=${INT_TELEMETRY}:443
KONG_CLUSTER_TELEMETRY_SERVER_NAME=${INT_TELEMETRY}
EOF
cat > generated/dp-external.env <<EOF
KONG_CLUSTER_CONTROL_PLANE=${EXT_CLUSTER}:443
KONG_CLUSTER_SERVER_NAME=${EXT_CLUSTER}
KONG_CLUSTER_TELEMETRY_ENDPOINT=${EXT_TELEMETRY}:443
KONG_CLUSTER_TELEMETRY_SERVER_NAME=${EXT_TELEMETRY}
EOF

# maintain the four alias vars in .env (compose interpolates network aliases)
update_env() { # key value
  if grep -q "^$1=" .env; then
    sed -i '' "s|^$1=.*|$1=$2|" .env
  else
    [ -z "$(tail -c1 .env)" ] || echo >> .env  # guard: file may lack trailing newline
    printf '%s=%s\n' "$1" "$2" >> .env
  fi
  # Export too: the script sourced .env with `set -a`, and docker compose
  # prefers the shell environment over .env, so a stale exported value would win.
  export "$1=$2"
}
update_env INT_CLUSTER_HOST "$INT_CLUSTER"
update_env INT_TELEMETRY_HOST "$INT_TELEMETRY"
update_env EXT_CLUSTER_HOST "$EXT_CLUSTER"
update_env EXT_TELEMETRY_HOST "$EXT_TELEMETRY"
echo "==> Wrote generated/dp-*.env and uplink aliases into .env"

# --- B: stack + keycloak setup ------------------------------------------------
docker compose up -d --build
echo "==> Waiting for Keycloak realms..."
for i in $(seq 1 60); do
  curl -sf http://localhost:8080/realms/fake-ping/.well-known/openid-configuration -o /dev/null && break
  [ "$i" -eq 60 ] && { echo "Keycloak not ready" >&2; exit 1; }
  sleep 5
done
COMPOSE_DIR="$(pwd)" ../phase1/setup-phase1.sh

# phase 2 realm delta: patient-agent emits groups (external-tier route ACLs)
KCADM="docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"
cid=$($KCADM get clients -r mcp-plane -q clientId=patient-agent --fields id | jq -r '.[0].id')
sid=$($KCADM get client-scopes -r mcp-plane --fields id,name | jq -r '.[] | select(.name=="mcp-groups").id')
$KCADM update "clients/${cid}/default-client-scopes/${sid}" -r mcp-plane -n -s realm=mcp-plane
echo "==> patient-agent now emits groups"

# --- C: gateway config from git ------------------------------------------------
# token via env, not argv — keeps it out of process lists and error traces
export DECK_KONNECT_TOKEN="${KONNECT_TOKEN}"
for tier in internal external; do
  echo "==> deck sync (${tier})..."
  deck gateway sync "../../deck/${tier}.yaml" \
    --konnect-addr "https://${KONNECT_REGION}.api.konghq.com" \
    --konnect-control-plane-name "mcp-${tier}"
done

echo "==> Done. Seed with: FHIR_BASE=http://localhost:8081/fhir ../phase0/seed-synthea.sh"
