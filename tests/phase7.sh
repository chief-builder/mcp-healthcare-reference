#!/usr/bin/env bash
# Phase 7 — red-team weekend (docs/prototype-plan.md §3):
#   arch-doc §13 acceptance list + cross-tier replay, scope-ceiling probes,
#   broker state replay, RFC 9207 iss tampering/omission, STALE-storm,
#   token-in-log grep, and the CIMD external-tier experiment. Findings are
#   filed as GitHub issues in this repo.
#
# Passing = defense held. Two probes are xfail(strict), documenting confirmed
# gaps (see the filed issues); an XPASS there means a gap was fixed and the
# marker should be removed. Requires the compose/phase5 stack up (+ phase 6
# spine) — the same target as tests/phase6.sh.
set -euo pipefail
cd "$(dirname "$0")/phase7"

if [ ! -d ../phase1/.venv ]; then python3 -m venv ../phase1/.venv; fi
../phase1/.venv/bin/pip install -q -r ../phase1/requirements.txt

exec ../phase1/.venv/bin/pytest -v -p no:randomly "$@"
