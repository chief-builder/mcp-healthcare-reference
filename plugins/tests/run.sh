#!/usr/bin/env bash
# Offline gateway suite: the bespoke plugins (cnf-check, dlp-egress,
# dpop-check, vendor-token) and the deck tier-wall pre-function, run against
# a DB-less Kong in Docker with stub upstreams. No Konnect account needed.
#
#   plugins/tests/run.sh [pytest args...]      (or: make test-plugins)
#
# Requires Docker and the repo venv (created via `make install` if missing).
set -euo pipefail
cd "$(dirname "$0")/../.."

KONG_IMAGE="${KONG_IMAGE:-kong/kong-gateway:3.16.0.0}"
STUB_IMAGE="${STUB_IMAGE:-python:3.14-slim}"
# No versioned multi-arch tags upstream; pinned by digest (resolved 2026-09-30).
LUACHECK_IMAGE="${LUACHECK_IMAGE:-pipelinecomponents/luacheck@sha256:29b50ed2cb99e4eea19522f0c9b3b104661437e0b5158921df2d111eb6c5af2e}"
PY=".venv/bin/python"
RUN_ID="plugintest-$$"
NET="${RUN_ID}-net"
KONG="${RUN_ID}-kong"
STUB="${RUN_ID}-stub"
# Inside the repo, not $TMPDIR: Docker Desktop/Colima only share the home tree.
WORK="$PWD/plugins/tests/.run-${RUN_ID}"

cleanup() {
  docker rm -f "$KONG" "$STUB" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$PY" ] || make .venv/.installed

echo "==> luacheck plugins/"
docker run --rm -v "$PWD/plugins:/plugins:ro" -w /plugins "$LUACHECK_IMAGE" luacheck .

mkdir -p "$WORK"
"$PY" plugins/tests/build_config.py "$WORK/kong.yml"

docker network create "$NET" >/dev/null
docker run -d --name "$STUB" --network "$NET" --network-alias stub \
  -v "$PWD/plugins/tests/stubs:/stub:ro" "$STUB_IMAGE" python /stub/stub.py >/dev/null

plugin_mounts=()
for p in cnf-check dlp-egress dpop-check vendor-token; do
  plugin_mounts+=(-v "$PWD/plugins/$p:/opt/kong-plugins/kong/plugins/$p:ro")
done

docker run -d --name "$KONG" --network "$NET" \
  -e KONG_DATABASE=off \
  -e KONG_DECLARATIVE_CONFIG=/kong/kong.yml \
  -e KONG_PROXY_LISTEN=0.0.0.0:8000 \
  -e KONG_ADMIN_LISTEN=off \
  -e KONG_PLUGINS=bundled,cnf-check,dlp-egress,vendor-token,dpop-check \
  -e "KONG_LUA_PACKAGE_PATH=/opt/kong-plugins/?.lua;;" \
  -e KONG_UNTRUSTED_LUA_SANDBOX_REQUIRES=cjson.safe \
  -e "KONG_NGINX_HTTP_LUA_SHARED_DICT=dpop_jti 5m" \
  -e KONG_NGINX_WORKER_PROCESSES=1 \
  -e KONG_PROXY_ACCESS_LOG=/dev/stdout \
  -e KONG_PROXY_ERROR_LOG=/dev/stderr \
  -v "$WORK:/kong:ro" \
  "${plugin_mounts[@]}" \
  -p 127.0.0.1::8000 \
  "$KONG_IMAGE" >/dev/null

PORT="$(docker port "$KONG" 8000/tcp | head -1 | sed 's/.*://')"
URL="http://127.0.0.1:${PORT}"

echo "==> Waiting for $KONG_IMAGE on $URL..."
for i in $(seq 1 60); do
  # An unrouted path answers 404 once the proxy is serving.
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$URL/__ready" || true)" = "404" ] && break
  if [ "$i" -eq 60 ] || [ "$(docker inspect -f '{{.State.Running}}' "$KONG")" != "true" ]; then
    echo "Kong did not start:" >&2
    docker logs "$KONG" 2>&1 | tail -30 >&2
    exit 1
  fi
  sleep 1
done

KONG_URL="$URL" KONG_CONTAINER="$KONG" "$PY" -m pytest plugins/tests -q "$@"
