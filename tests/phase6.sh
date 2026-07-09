#!/usr/bin/env bash
# Phase 6 acceptance gate (docs/prototype-plan.md §3):
#   pick a vendor action and walk it back to the human, client, gateway
#   decision, and DLP verdict in ONE Loki query keyed by jti; DLP blocks
#   and first-party tool calls join the same way; Kong traces in Tempo;
#   the tuple dashboard is provisioned; no token material on the spine.
#
# Requires the compose/phase5 stack up — re-run ./setup-phase5.sh after
# pulling phase 6 (rebuilds servers, syncs the otel deck config, starts
# Alloy).
set -euo pipefail
cd "$(dirname "$0")/phase6"

if [ ! -d ../phase1/.venv ]; then python3 -m venv ../phase1/.venv; fi
../phase1/.venv/bin/pip install -q -r ../phase1/requirements.txt

exec ../phase1/.venv/bin/pytest -v -p no:randomly "$@"
