# tests/

Acceptance gates, one per phase (docs/prototype-plan.md §3). `phaseN.sh`
is the gate; a phase is done only when it is green. Phase 0 is plain
shell checks; phases 1–7 run pytest suites from one shared venv
(`phase1/.venv`, created by `phase1.sh` and reused by the others).

These gates need the live stack (Docker; Kong Konnect from phase 2;
k3d from phase 4). The offline suites that need no accounts — servers,
broker, gateway plugins, kit vectors — run with `make test` at the repo root.

Gates are cumulative: each phase's stack is a superset of the last (phase 6
rides the phase 5 stack), so re-run any earlier gate against the running
stack to check for regressions. Current item counts: phase1 72, phase2 11,
phase3 12, phase4 9, phase5 17, phase6 6, phase7 32 (159), plus phase 0's
four shell checks. The last full run of all eight gates was green on
2026-10-01: 159 of 159, nothing skipped (phase 5's real-GitHub leg ran after its
one-time browser consent; the Auth0 leg ran against the lab tenant).

`phase7.sh` is the red-team weekend (plan §3) — adversarial probes against
the same stack; passing means the defense held. All probes are plain
asserts: the two gaps they originally documented as `xfail(strict)`
(issues #1, #2) were remediated and the markers removed; see
`phase7/README.md`.
