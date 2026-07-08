#!/usr/bin/env bash
# Phase 4 acceptance gate (docs/prototype-plan.md §3):
#   agent obtains cert-bound tokens with zero secrets in its manifest;
#   token without mTLS or with a different cert -> 401 + audit event;
#   cert rotation happens without pod restart.
#
# Requires the compose/phase4 stack + k3d cluster up (./setup-phase4.sh).
set -euo pipefail
cd "$(dirname "$0")/phase4"

if [ ! -d ../phase1/.venv ]; then python3 -m venv ../phase1/.venv; fi
../phase1/.venv/bin/pip install -q -r ../phase1/requirements.txt

exec ../phase1/.venv/bin/pytest -v "$@"
