# shellcheck shell=bash
# Shared Konnect helpers for compose/phase{2..5}/setup-phaseN.sh (sourced).
# Expects: API (Konnect v2 base URL), AUTH (curl auth args array),
# INTERNAL_ID (mcp-internal control-plane id), cwd = compose/phaseN.

# Every custom plugin deck/internal.yaml references. deck/ is one source of
# truth for all phases, so every phase registers every schema (and every
# phase's internal DP loads every plugin); each plugin is claim- or
# route-driven and inert where a phase does not use it.
CUSTOM_PLUGINS=(cnf-check dlp-egress vendor-token dpop-check)

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
    *) echo "FAILED to register ${name} schema (HTTP $code): $(echo "$resp" | head -1)" >&2
       exit 1 ;;
  esac
}

register_custom_plugins() {
  local p
  for p in "${CUSTOM_PLUGINS[@]}"; do ensure_plugin_schema "$p"; done
}
