#!/usr/bin/env bash
# Phase 4 provisioning + bring-up. Idempotent. Reuses the phase 2/3 Konnect
# control planes and the phase 1 Keycloak setup; adds the cert-bound m2m
# surface: lab CA, Keycloak mTLS listener, Kong internal TLS listener with
# the cnf-check plugin, and a k3d cluster running SPIRE + the loop agent.
#
# Requires: .env with KONNECT_REGION + KONNECT_TOKEN (+ phase 1 vars) — copied
# from ../phase3/.env if missing; deck, k3d, kubectl, openssl, jq.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -f .env ]; then
  # Reuse the previous phase's credentials when that phase was set up first;
  # otherwise start from this phase's own template.
  if [ -f ../phase3/.env ]; then
    echo "==> Copying ../phase3/.env"; cp ../phase3/.env .env
  else
    echo "Missing .env: cp .env.example .env and fill it in (KONNECT_TOKEN etc.)" >&2
    exit 1
  fi
fi
set -a; source .env; set +a
case "${KONNECT_TOKEN:-}" in
  ""|kpat_change-me) echo "Set KONNECT_TOKEN in .env (Konnect personal access token)" >&2; exit 1 ;;
esac

for tool in deck k3d kubectl openssl jq; do
  command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 1; }
done

API="https://${KONNECT_REGION}.api.konghq.com/v2"
AUTH=(-H "Authorization: Bearer ${KONNECT_TOKEN}")
mkdir -p certs generated

# ---------- Konnect control planes (same two as phases 2/3) ----------
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

update_env() {
  if grep -q "^$1=" .env; then sed -i '' "s|^$1=.*|$1=$2|" .env
  else [ -z "$(tail -c1 .env)" ] || echo >> .env; printf '%s=%s\n' "$1" "$2" >> .env; fi
  # Export too: the script sourced .env with `set -a`, and docker compose
  # prefers the shell environment over .env, so a stale exported value would win.
  export "$1=$2"
}
update_env INT_CLUSTER_HOST "$INT_CLUSTER"
update_env INT_TELEMETRY_HOST "$INT_TELEMETRY"
update_env EXT_CLUSTER_HOST "$EXT_CLUSTER"
update_env EXT_TELEMETRY_HOST "$EXT_TELEMETRY"
echo "==> Wrote generated/dp-*.env and uplink aliases into .env"

# ---------- Lab CA + server certs (the mTLS trust root, phase 4) ----------
# One root for the whole cert-bound path: SPIRE chains its intermediate to
# it (UpstreamAuthority disk), Keycloak trusts it for client certs, and the
# agent/tests trust it for Keycloak's and Kong's server TLS.
# RFC 5280-conformant (keyUsage etc.): Python 3.13 clients verify with
# VERIFY_X509_STRICT, which rejects a CA without a keyUsage extension.
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
# shellcheck source=../lib/konnect.sh
source ../lib/konnect.sh
register_custom_plugins

# ---------- compose stack ----------
if docker ps --format '{{.Names}}' | grep -q '^mcp-phase3-'; then
  echo "==> Stopping the phase 3 stack (same host ports)..."
  docker compose --project-directory ../phase3 down --remove-orphans
fi
docker compose up -d --build

echo "==> Waiting for Keycloak realms..."
for i in $(seq 1 60); do
  curl -sf http://localhost:8080/realms/fake-ping/.well-known/openid-configuration -o /dev/null && break
  [ "$i" -eq 60 ] && { echo "Keycloak not ready" >&2; exit 1; }
  sleep 5
done
COMPOSE_DIR="$(pwd)" ../phase1/setup-phase1.sh

export DECK_KONNECT_TOKEN="${KONNECT_TOKEN}"
for tier in internal external; do
  echo "==> deck sync (${tier})..."
  deck gateway sync "../../deck/${tier}.yaml" \
    --konnect-addr "https://${KONNECT_REGION}.api.konghq.com" \
    --konnect-control-plane-name "mcp-${tier}"
done

# ---------- k3d + SPIRE + loop agent ----------
if ! k3d cluster list 2>/dev/null | grep -q '^mcp-lab '; then
  echo "==> Creating k3d cluster mcp-lab..."
  k3d cluster create mcp-lab --servers 1 --wait --image rancher/k3s:v1.37.0-k3s1
fi
KCTL=(kubectl --context k3d-mcp-lab)

# k3d writes host.k3d.internal into CoreDNS's NodeHosts after the cluster is
# up; with k3s newer than k3d's default the running CoreDNS can miss it, and
# the loop agent then cannot reach Keycloak/Kong on the host. Verify the name
# resolves in-cluster; restart CoreDNS once if it does not.
dns_ok() {
  "${KCTL[@]}" run k3d-dns-check --rm -i --restart=Never --image=busybox:1.37 \
    --command -- nslookup host.k3d.internal >/dev/null 2>&1
}
if ! dns_ok; then
  echo "==> host.k3d.internal not resolvable in-cluster; restarting CoreDNS..."
  "${KCTL[@]}" -n kube-system rollout restart deploy/coredns > /dev/null
  "${KCTL[@]}" -n kube-system rollout status deploy/coredns --timeout=120s
  dns_ok || { echo "host.k3d.internal still unresolvable in k3d" >&2; exit 1; }
fi

echo "==> Deploying SPIRE..."
"${KCTL[@]}" create namespace spire --dry-run=client -o yaml | "${KCTL[@]}" apply -f - > /dev/null
"${KCTL[@]}" -n spire create secret generic spire-upstream-ca \
  --from-file=lab-ca.crt=certs/lab-ca.crt --from-file=lab-ca.key=certs/lab-ca.key \
  --dry-run=client -o yaml | "${KCTL[@]}" apply -f - > /dev/null
"${KCTL[@]}" apply -f k8s/spire.yaml > /dev/null
"${KCTL[@]}" -n spire rollout status statefulset/spire-server --timeout=180s
"${KCTL[@]}" -n spire rollout status daemonset/spire-agent --timeout=180s

spire_entry() { # spiffe_id, extra args...
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
# 180s SVID: absurdly short on purpose so the rotation gate is observable in
# a test run (production cap is 30 days, plan gate is <=24h).
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
"${KCTL[@]}" apply -f k8s/loop-agent.yaml > /dev/null
"${KCTL[@]}" -n mcp-agents rollout status deploy/loop-agent --timeout=180s

echo "==> Done. Watch the agent:  kubectl --context k3d-mcp-lab -n mcp-agents logs -f deploy/loop-agent -c agent"
echo "    Seed FHIR if needed:   FHIR_BASE=http://localhost:8081/fhir ../phase0/seed-synthea.sh"
