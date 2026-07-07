#!/usr/bin/env bash
# Post-import setup that a plain realm import cannot express. Idempotent.
#
# 1. Grant the legacy-exchange client permission to perform external->internal
#    token exchange against the `homegrown` identity provider (legacy V1
#    exchange, claims contract §6.2) — fine-grained-authz permissions.
# 2. Allow admin-edited unmanaged user attributes (KC 26 user profile), so the
#    fhir_patient linkage (contract §6.5) can be written via the admin API.
#    Broker mappers bypass the user profile; the admin API does not.
set -euo pipefail
cd "$(dirname "$0")"
source .env

KCADM="docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"

$KCADM config credentials --server http://localhost:8080 --realm master \
  --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" > /dev/null

echo "==> Master realm over HTTP (admin console + admin API for the lab)..."
$KCADM update realms/master -s sslRequired=NONE

echo "==> Enabling permissions on identity provider 'homegrown'..."
$KCADM update identity-provider/instances/homegrown/management/permissions \
  -r mcp-plane -s enabled=true > /dev/null

perm_id=$($KCADM get identity-provider/instances/homegrown/management/permissions -r mcp-plane \
  | jq -r '.scopePermissions."token-exchange"')
rm_id=$($KCADM get clients -r mcp-plane -q clientId=realm-management --fields id | jq -r '.[0].id')

echo "==> Ensuring client policy 'legacy-exchange-can-exchange'..."
policy_id=$($KCADM get "clients/${rm_id}/authz/resource-server/policy" -r mcp-plane \
  -q name=legacy-exchange-can-exchange | jq -r '.[0].id // empty')
if [ -z "$policy_id" ]; then
  $KCADM create "clients/${rm_id}/authz/resource-server/policy/client" -r mcp-plane \
    -b '{"name":"legacy-exchange-can-exchange","clients":["legacy-exchange"]}' > /dev/null
  policy_id=$($KCADM get "clients/${rm_id}/authz/resource-server/policy" -r mcp-plane \
    -q name=legacy-exchange-can-exchange | jq -r '.[0].id // empty')
fi
[ -n "$policy_id" ] || { echo "failed to resolve policy id" >&2; exit 1; }

echo "==> Attaching policy to the token-exchange permission..."
$KCADM get "clients/${rm_id}/authz/resource-server/permission/scope/${perm_id}" -r mcp-plane \
  | jq --arg p "$policy_id" '. + {policies: [$p]}' \
  | $KCADM update "clients/${rm_id}/authz/resource-server/permission/scope/${perm_id}" -r mcp-plane -f - > /dev/null

echo "==> Wiring the built-in account console (needs roles/acr/basic-claims scopes)..."
# our realm import declares clientScopes explicitly, so KC built-ins are absent;
# the account console SPA breaks without role claims in its tokens
console_id=$($KCADM get clients -r mcp-plane -q clientId=account-console --fields id | jq -r '.[0].id')
for scope_name in roles acr basic-claims; do
  scope_id=$($KCADM get client-scopes -r mcp-plane --fields id,name \
    | jq -r --arg n "$scope_name" '.[] | select(.name==$n).id')
  $KCADM update "clients/${console_id}/default-client-scopes/${scope_id}" -r mcp-plane -n -s realm=mcp-plane
done

echo "==> Allowing admin-edited unmanaged user attributes (fhir_patient linkage store)..."
$KCADM get users/profile -r mcp-plane \
  | jq '.unmanagedAttributePolicy = "ADMIN_EDIT"' \
  | $KCADM update users/profile -r mcp-plane -f - > /dev/null

echo "==> Done: exchange permission + linkage-store attribute policy applied."
