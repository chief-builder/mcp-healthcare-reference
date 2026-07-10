# compose/

One docker-compose stack per phase, each a superset of the last
(docs/prototype-plan.md §3). Bring-up, endpoints, and quirks are in each
`phaseN/README.md`; the acceptance gate is `../tests/phaseN.sh`.

The highest-numbered stack is the lab: `phase5/` runs everything, and the
phase 6 audit spine rides it (there is no `compose/phase6` — see
`phase5/README.md`). Earlier stacks remain runnable for reproducing a phase
in isolation. Shared infra config is bind-mounted from the phase that owns
it (e.g. later phases mount `phase0/`'s Grafana/OTel config), so there is a
single source of truth per file.
