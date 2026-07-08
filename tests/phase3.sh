#!/usr/bin/env bash
# Phase 3 acceptance gate (docs/prototype-plan.md §3):
#   tool visibility by role; under-scoped -> 403 insufficient_scope + step-up;
#   patient-scoped token retrieves only its own compartment; a scheduling hold
#   survives replica loss (statelessness).
#
# Requires the compose/phase3 stack up (./setup-phase3.sh) and seeded.
set -euo pipefail
cd "$(dirname "$0")/phase3"

if [ ! -d ../phase1/.venv ]; then python3 -m venv ../phase1/.venv; fi
../phase1/.venv/bin/pip install -q -r ../phase1/requirements.txt

exec ../phase1/.venv/bin/pytest -v "$@"
