#!/usr/bin/env bash
# Phase 5 provisioning + bring-up. Idempotent. Everything phase 4 did (same
# Konnect CPs, lab CA, k3d/SPIRE workload side) plus: OpenBao provisioning
# (mounts, broker policy + scoped token, vendor client credentials), the
# broker + mockhub services, and the dlp-egress / vendor-token plugin
# schemas + egress routes.
#
# GitHub leg: set GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET in .env (an
# org-owned GitHub App with callback http://localhost:8300/v1/callback/github
# and user-token expiry enabled) — everything else works without it.
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || { echo "==> Copying ../phase4/.env"; cp ../phase4/.env .env; }
set -a; source .env; set +a

for tool in deck k3d kubectl openssl jq; do
  command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 1; }
done

update_env() {
  if grep -q "^$1=" .env; then sed -i '' "s|^$1=.*|$1=$2|" .env
  else [ -z "$(tail -c1 .env)" ] || echo >> .env; printf '%s=%s\n' "$1" "$2" >> .env; fi
}
ensure_env_secret() {
  local name=$1
  if ! grep -q "^${name}=" .env; then
    update_env "$name" "$(openssl rand -hex 24)"
  fi
}
ensure_env_secret VAULT_DEV_ROOT_TOKEN
ensure_env_secret MOCK_CLIENT_SECRET
set -a; source .env; set +a

API="https://${KONNECT_REGION}.api.konghq.com/v2"
AUTH=(-H "Authorization: Bearer ${KONNECT_TOKEN}")
mkdir -p certs generated

# ---------- Konnect control planes (same two as phases 2-4) ----------
cp_id() { curl -sf "${AUTH[@]}" "${API}/control-planes?filter%5Bname%5D=$1" | jq -r '.data[0].id // empty'; }
ensure_cp() {
  local id; id=$(cp_id "$1")
  if [ -z "$id" ]; then
    echo "==> Creating control plane $1..." >&2
    local resp; resp=$(curl -s "${AUTH[@]}" -H 'Content-Type: application/json' \
      -d "{\"name\":\"$1\",\"cluster_type\":\"CLUSTER_TYPE_HYBRID\",\"description\":\"mcp lab ($1 tier), managed by deck + setup-phase*.sh — do not edit in UI\"}" \
      "${API}/control-planes")
    id=$(echo "$resp" | jq -r '.id // empty')
    [ -n "$id" ] || { echo "FAILED to create control plane $1: $(echo "$resp" | jq -c .)" >&2; exit 1; }
  fi
  echo "$id"
}
INTERNAL_ID=$(ensure_cp mcp-internal)
EXTERNAL_ID=$(ensure_cp mcp-external)
echo "==> Control planes: mcp-internal=${INTERNAL_ID} mcp-external=${EXTERNAL_ID}"

ensure_dp_cert() {
  local tier=$1 id=$2
  if [ ! -f "certs/${tier}.crt" ]; then
    echo "==> Generating DP client certificate for ${tier}..."
    openssl req -new -x509 -nodes -newkey rsa:2048 -sha256 -days 90 \
      -subj "/CN=mcp-${tier}-dp" -keyout "certs/${tier}.key" -out "certs/${tier}.crt" 2>/dev/null
  fi
  jq -n --rawfile cert "certs/${tier}.crt" '{cert: $cert}' \
    | curl -s "${AUTH[@]}" -H 'Content-Type: application/json' -d @- \
      "${API}/control-planes/${id}/dp-client-certificates" > /dev/null
}
ensure_dp_cert internal "$INTERNAL_ID"
ensure_dp_cert external "$EXTERNAL_ID"

endpoint_host() { curl -sf "${AUTH[@]}" "${API}/control-planes/$1" | jq -r ".config.$2" | sed -E 's#^https?://##'; }
INT_CLUSTER=$(endpoint_host "$INTERNAL_ID" control_plane_endpoint)
INT_TELEMETRY=$(endpoint_host "$INTERNAL_ID" telemetry_endpoint)
EXT_CLUSTER=$(endpoint_host "$EXTERNAL_ID" control_plane_endpoint)
EXT_TELEMETRY=$(endpoint_host "$EXTERNAL_ID" telemetry_endpoint)

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
update_env INT_CLUSTER_HOST "$INT_CLUSTER"
update_env INT_TELEMETRY_HOST "$INT_TELEMETRY"
update_env EXT_CLUSTER_HOST "$EXT_CLUSTER"
update_env EXT_TELEMETRY_HOST "$EXT_TELEMETRY"
echo "==> Wrote generated/dp-*.env and uplink aliases into .env"

# ---------- Lab CA + server certs (unchanged from phase 4) ----------
# Inherit the phase 4 PKI when it exists: the k3d/SPIRE side keeps running
# across the phase transition, and its SVIDs must keep chaining to the same
# root that Keycloak and Kong trust.
if [ ! -f certs/lab-ca.crt ] && [ -f ../phase4/certs/lab-ca.crt ]; then
  echo "==> Inheriting lab CA + server certs from phase 4..."
  cp ../phase4/certs/lab-ca.crt ../phase4/certs/lab-ca.key \
     ../phase4/certs/keycloak.crt ../phase4/certs/keycloak.key \
     ../phase4/certs/kong-internal.crt ../phase4/certs/kong-internal.key certs/
fi
if [ ! -f certs/lab-ca.crt ]; then
  echo "==> Generating lab CA..."
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
    -subj "/O=mcp-lab/CN=mcp-lab root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout certs/lab-ca.key -out certs/lab-ca.crt 2>/dev/null
fi
server_cert() {
  local name=$1 sans=$2
  [ -f "certs/${name}.crt" ] && return
  echo "==> Generating server certificate for ${name}..."
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=${name}" \
    -keyout "certs/${name}.key" -out "certs/${name}.csr" 2>/dev/null
  openssl x509 -req -in "certs/${name}.csr" -CA certs/lab-ca.crt -CAkey certs/lab-ca.key \
    -CAcreateserial -days 90 -out "certs/${name}.crt" \
    -extfile <(printf 'subjectAltName=%s\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' "$sans") 2>/dev/null
  rm -f "certs/${name}.csr"
}
server_cert keycloak "DNS:localhost,DNS:keycloak,DNS:host.k3d.internal"
server_cert kong-internal "DNS:localhost,DNS:kong-internal,DNS:host.k3d.internal"

# ---------- Custom plugin schemas on the internal CP ----------
ensure_plugin_schema() {
  local name=$1 code resp body
  code=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" \
    "${API}/control-planes/${INTERNAL_ID}/core-entities/plugin-schemas/${name}")
  body=$(jq -n --rawfile s "../../plugins/${name}/schema.lua" '{lua_schema: $s}')
  if [ "$code" = "404" ]; then
    echo "==> Registering ${name} plugin schema on mcp-internal..."
    resp=$(curl -s -w '\n%{http_code}' "${AUTH[@]}" -H 'Content-Type: application/json' \
      -d "$body" "${API}/control-planes/${INTERNAL_ID}/core-entities/plugin-schemas")
  else
    echo "==> Updating ${name} plugin schema on mcp-internal..."
    resp=$(curl -s -w '\n%{http_code}' "${AUTH[@]}" -H 'Content-Type: application/json' -X PUT \
      -d "$body" "${API}/control-planes/${INTERNAL_ID}/core-entities/plugin-schemas/${name}")
  fi
  code=$(echo "$resp" | tail -1)
  case "$code" in
    2*) ;;
    *) echo "FAILED to register ${name} schema (HTTP $code): $(echo "$resp" | head -1)" >&2; exit 1 ;;
  esac
}
ensure_plugin_schema cnf-check
ensure_plugin_schema dlp-egress
ensure_plugin_schema vendor-token

# ---------- compose stack ----------
if docker ps --format '{{.Names}}' | grep -q '^mcp-phase4-'; then
  echo "==> Stopping the phase 4 stack (same host ports)..."
  docker compose --project-directory ../phase4 down --remove-orphans
fi
docker compose up -d --build

echo "==> Waiting for Keycloak realms..."
for i in $(seq 1 60); do
  curl -sf http://localhost:8080/realms/fake-ping/.well-known/openid-configuration -o /dev/null && break
  [ "$i" -eq 60 ] && { echo "Keycloak not ready" >&2; exit 1; }
  sleep 5
done
COMPOSE_DIR="$(pwd)" ../phase1/setup-phase1.sh

# ---------- OpenBao provisioning (design §5) ----------
VAULT="http://localhost:8210"
VH=(-H "X-Vault-Token: ${VAULT_DEV_ROOT_TOKEN}")
echo "==> Waiting for OpenBao..."
for i in $(seq 1 30); do
  curl -sf "${VAULT}/v1/sys/health" -o /dev/null && break
  [ "$i" -eq 30 ] && { echo "OpenBao not ready" >&2; exit 1; }
  sleep 2
done
ensure_mount() {
  local resp
  resp=$(curl -s -w '%{http_code}' -o /dev/null "${VH[@]}" \
    -d '{"type":"kv","options":{"version":"2"}}' "${VAULT}/v1/sys/mounts/$1")
  case "$resp" in 2*|400) ;; *) echo "FAILED to mount $1 ($resp)" >&2; exit 1;; esac
}
ensure_mount vendor-tokens
ensure_mount vendor-clients

# Broker policy: read/write custody, read-only vendor client creds. No human
# read path to token material — the root token is the lab's KMS-substitute.
curl -s "${VH[@]}" -X PUT -d '{"policy":"path \"vendor-tokens/data/*\" { capabilities = [\"create\",\"read\",\"update\",\"delete\"] }\npath \"vendor-tokens/metadata/*\" { capabilities = [\"read\",\"delete\",\"list\"] }\npath \"vendor-clients/data/*\" { capabilities = [\"read\"] }"}' \
  "${VAULT}/v1/sys/policies/acl/broker" > /dev/null
BROKER_TOKEN=$(curl -s "${VH[@]}" -d '{"policies":["broker"],"ttl":"768h","display_name":"broker"}' \
  "${VAULT}/v1/auth/token/create" | jq -r '.auth.client_token')
[ -n "$BROKER_TOKEN" ] && [ "$BROKER_TOKEN" != "null" ] || { echo "FAILED to mint broker vault token" >&2; exit 1; }
update_env BROKER_VAULT_TOKEN "$BROKER_TOKEN"

echo "==> Writing vendor client credentials to vendor-clients/..."
curl -s "${VH[@]}" -d "{\"data\":{\"client_id\":\"mcp-lab-broker\",\"client_secret\":\"${MOCK_CLIENT_SECRET}\"}}" \
  "${VAULT}/v1/vendor-clients/data/mockhub" > /dev/null
if [ -n "${GITHUB_CLIENT_ID:-}" ]; then
  curl -s "${VH[@]}" -d "{\"data\":{\"client_id\":\"${GITHUB_CLIENT_ID}\",\"client_secret\":\"${GITHUB_CLIENT_SECRET}\"}}" \
    "${VAULT}/v1/vendor-clients/data/github" > /dev/null
  echo "==> GitHub vendor configured (client_id=${GITHUB_CLIENT_ID})"
else
  echo "==> GitHub vendor NOT configured (set GITHUB_CLIENT_ID/SECRET in .env to enable)"
fi

echo "==> Restarting broker with its scoped vault token..."
# force-recreate: on a re-run after a vault wipe the token value changes and
# compose otherwise keeps the stale container (and its dead token).
docker compose up -d --force-recreate broker

export DECK_KONNECT_TOKEN="${KONNECT_TOKEN}"
for tier in internal external; do
  echo "==> deck sync (${tier})..."
  deck gateway sync "../../deck/${tier}.yaml" \
    --konnect-addr "https://${KONNECT_REGION}.api.konghq.com" \
    --konnect-control-plane-name "mcp-${tier}"
done

# ---------- k3d + SPIRE + loop agent (unchanged from phase 4) ----------
if ! k3d cluster list 2>/dev/null | grep -q '^mcp-lab '; then
  echo "==> Creating k3d cluster mcp-lab..."
  k3d cluster create mcp-lab --servers 1 --wait
fi
KCTL=(kubectl --context k3d-mcp-lab)

echo "==> Deploying SPIRE..."
"${KCTL[@]}" create namespace spire --dry-run=client -o yaml | "${KCTL[@]}" apply -f - > /dev/null
"${KCTL[@]}" -n spire create secret generic spire-upstream-ca \
  --from-file=lab-ca.crt=certs/lab-ca.crt --from-file=lab-ca.key=certs/lab-ca.key \
  --dry-run=client -o yaml | "${KCTL[@]}" apply -f - > /dev/null
"${KCTL[@]}" apply -f ../phase4/k8s/spire.yaml > /dev/null
"${KCTL[@]}" -n spire rollout status statefulset/spire-server --timeout=180s
"${KCTL[@]}" -n spire rollout status daemonset/spire-agent --timeout=180s

spire_entry() {
  local spiffe_id=$1; shift
  if "${KCTL[@]}" -n spire exec statefulset/spire-server -- \
      /opt/spire/bin/spire-server entry show -spiffeID "$spiffe_id" | grep -q "$spiffe_id"; then
    return
  fi
  echo "==> Registering SPIRE entry $spiffe_id..."
  "${KCTL[@]}" -n spire exec statefulset/spire-server -- \
    /opt/spire/bin/spire-server entry create -spiffeID "$spiffe_id" "$@" > /dev/null
}
spire_entry spiffe://mcp-lab/k8s-node -node -selector k8s_psat:cluster:mcp-lab
spire_entry spiffe://mcp-lab/mcp-agents/loop-agent \
  -parentID spiffe://mcp-lab/k8s-node \
  -selector k8s:ns:mcp-agents -selector k8s:sa:loop-agent \
  -dns loop-agent.mcp-agents.svc -x509SVIDTTL 180

echo "==> Deploying loop agent..."
docker build -q -t mcp-loop-agent:phase4 ../../agents/loop-agent > /dev/null
k3d image import -c mcp-lab mcp-loop-agent:phase4 > /dev/null
"${KCTL[@]}" create namespace mcp-agents --dry-run=client -o yaml | "${KCTL[@]}" apply -f - > /dev/null
"${KCTL[@]}" -n mcp-agents create configmap lab-ca --from-file=lab-ca.crt=certs/lab-ca.crt \
  --dry-run=client -o yaml | "${KCTL[@]}" apply -f - > /dev/null
"${KCTL[@]}" apply -f ../phase4/k8s/loop-agent.yaml > /dev/null
"${KCTL[@]}" -n mcp-agents rollout status deploy/loop-agent --timeout=180s

echo "==> Done. Gate: ../../tests/phase5.sh"
echo "    Seed FHIR if needed (memory-tight: PATIENT_COUNT=10):"
echo "    FHIR_BASE=http://localhost:8081/fhir PATIENT_COUNT=10 ../phase0/seed-synthea.sh"