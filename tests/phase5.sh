#!/usr/bin/env bash
# Phase 5 acceptance gate (docs/prototype-plan.md §3):
#   first call -> consent dance -> vendor MCP tool works;
#   planted MRN -> blocked + audited at the egress DP;
#   20 parallel resolves inside the refresh window -> exactly one vendor
#   refresh (single-flight + generation CAS);
#   DELETE /grants revokes at the vendor (RFC 7009).
#
# Requires the compose/phase5 stack up (./setup-phase5.sh). The GitHub leg
# runs when GITHUB_CLIENT_ID/SECRET are set and consent has been granted.
set -euo pipefail
cd "$(dirname "$0")/phase5"

if [ ! -d ../phase1/.venv ]; then python3 -m venv ../phase1/.venv; fi
../phase1/.venv/bin/pip install -q -r ../phase1/requirements.txt

exec ../phase1/.venv/bin/pytest -v -p no:randomly "$@"
