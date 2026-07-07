#!/usr/bin/env bash
# Phase 1 acceptance gate (docs/prototype-plan.md §3):
#   three differently-authenticated logins all yield contract-conformant JWTs
#   from the single issuer; pytest validates every claim in
#   docs/mcp-token-claims-contract.md §3.
#
# Requires the compose/phase1 stack up and seeded. The Auth0 leg skips cleanly
# when AUTH0_* is unset in compose/phase1/.env.
set -euo pipefail
cd "$(dirname "$0")/phase1"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
.venv/bin/pip install -q -r requirements.txt

exec .venv/bin/pytest -v "$@"
