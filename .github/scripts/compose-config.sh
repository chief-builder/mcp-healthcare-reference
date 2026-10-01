#!/usr/bin/env bash
# Validate every compose/phaseN stack with `docker compose config` using the
# committed .env.example placeholders (phases 4-5 reuse phase 3's, as their
# setup scripts do). Files the setup scripts generate at bring-up (DP env
# files, certs) are stubbed with empty files in a throwaway copy.
set -euo pipefail
cd "${REPO_ROOT:-$(dirname "$0")/../..}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rsync -a --exclude node_modules --exclude .venv --exclude dist \
  compose realm deck plugins servers broker agents "$work/"

status=0
for dir in "$work"/compose/phase*/; do
  phase="$(basename "$dir")"
  example="$dir/.env.example"
  [ -f "$example" ] || example="$work/compose/phase3/.env.example"
  cp "$example" "$dir/.env"
  # Stub generated env_files so config can resolve them.
  { grep -hoE 'generated/[A-Za-z0-9_.-]+\.env' "$dir/docker-compose.yml" || true; } | sort -u | while read -r f; do
    mkdir -p "$dir/$(dirname "$f")"
    : > "$dir/$f"
  done
  if out="$(docker compose -f "$dir/docker-compose.yml" --env-file "$dir/.env" config -q 2>&1)"; then
    echo "ok   $phase"
  else
    echo "FAIL $phase: $out"
    status=1
  fi
done
exit "$status"
