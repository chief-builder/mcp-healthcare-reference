#!/usr/bin/env bash
# Phase 2 acceptance gate (docs/prototype-plan.md §3):
#   internal-tier token replayed at the external DP -> 401;
#   DPs keep proxying with the CP uplink severed;
#   deck state in git matches the live control planes.
#
# Requires the compose/phase2 stack up (./setup-phase2.sh) and seeded.
set -euo pipefail
cd "$(dirname "$0")/phase2"

if [ ! -d ../phase1/.venv ]; then
  python3 -m venv ../phase1/.venv
fi
../phase1/.venv/bin/pip install -q -r ../phase1/requirements.txt

exec ../phase1/.venv/bin/pytest -v "$@"
