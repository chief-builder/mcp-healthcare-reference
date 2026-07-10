# tests/

Acceptance gates, one per phase (docs/prototype-plan.md §3). `phaseN.sh`
is the gate; a phase is done only when it is green. Phase 0 is plain
shell checks; phases 1–6 each create a venv in `phaseN/` and run its
pytest suite.

Gates are cumulative: phases 0–6 all pass on the current stack (phase 5
plus the phase 6 audit spine). Re-run any earlier gate against the running
stack to check for regressions.

`phase7.sh` is the red-team weekend (plan §3) — adversarial probes against
the same stack; passing means the defense held. Two probes are
`xfail(strict)`, documenting confirmed gaps filed as GitHub issues (#1, #2);
see `phase7/README.md`.
