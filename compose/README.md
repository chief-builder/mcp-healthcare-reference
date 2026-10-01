# compose/

One docker-compose stack per phase, each a superset of the last
(docs/prototype-plan.md §3). Bring-up, endpoints, and quirks are in each
`phaseN/README.md`; the acceptance gate is `../tests/phaseN.sh`.

The highest-numbered stack is the lab: `phase5/` runs everything, and the
phase 6 audit spine rides it (there is no `compose/phase6` — see
`phase5/README.md`). Earlier stacks remain runnable for reproducing a phase
in isolation (verified from a clean clone, 2026-10-01 — see below). Shared infra config is bind-mounted from the phase that owns
it (e.g. later phases mount `phase0/`'s Grafana/OTel config), so there is a
single source of truth per file.

## Starting a phase from a clean clone

Every phase starts from its own `.env.example` with the command block in its
README (`cp .env.example .env`, replace every `change-me`, run the setup script,
seed, run the gate). Phases 4 and 5 reuse the previous phase's `.env` if it
exists, otherwise they stop and ask you to create one. CI runs the phase 0 and
phase 1 quickstarts on every push and pull request; phases 2–5 need a
[Kong Konnect](https://konghq.com/products/kong-konnect) personal access token
and are run by hand.

## Resource needs

Measured on 2026-10-01 from a clean clone of each phase, one phase at a time,
on a Docker VM with 4 CPUs and 7.7 GiB of memory, with 10 seeded patients and
images already pulled. Memory is the sum of the phase's containers after its
gate ran; first runs add image pulls (several GB).

| Phase | Accounts | Extra tools | Container memory | Setup + seed + gate | Gate result |
|---|---|---|---|---|---|
| 0 | none | — | subset of phase 1 | — (CI smoke test) | 4 checks |
| 1 | none (Auth0 optional) | — | 2.6 GiB | 84 s | 54 passed, 18 skipped (Auth0 leg) |
| 2 | Konnect | `deck` | 5.5 GiB | 161 s | 9 passed, 2 skipped (Auth0 leg) |
| 3 | Konnect | `deck` | 4.4 GiB | 155 s | 10 passed, 2 skipped (Auth0 leg) |
| 4 | Konnect | `deck`, `k3d`, `kubectl` | 5.7 GiB (k3d node 1.0 GiB) | 265 s | 9 passed |
| 5 (+6, 7) | Konnect (GitHub App optional) | `deck`, `k3d`, `kubectl` | 5.0 GiB (k3d node 1.1 GiB) | 274 s | 16 passed + 1 skipped (GitHub leg); 6; 32 |

- **Memory:** give Docker at least 8 GB for phases 2–5. The two Kong data
  planes alone hold about 1.7 GiB and HAPI about 1.4 GiB. In a tight VM, seed
  with `PATIENT_COUNT=10`, and don't run a second stack (or the k3d cluster
  of another phase) at the same time: HAPI or the Synthea JVM gets
  OOM-killed and seeding stalls.
- **Disk:** about 9 GB of images for the phase 5 stack (6.7 GB pulled, about
  1.5 GB built locally, plus k3s, SPIRE, and the Synthea JRE), on top of
  Docker's build cache.
- **Ports:** 8080, 8081, 3000, 3100, 3200, 4317, 4318 (all phases); 8100,
  8200 (phases 2+); 8143, 8443 (phases 4+); 8210, 8300, 8310 (phase 5). Phases
  share ports, so run one at a time (`setup-phase4.sh` and `setup-phase5.sh`
  stop the previous phase's stack).

## Versions

Pinned in the compose files and checked against upstream releases on
2026-09-30: Keycloak 26.7.5, Kong Gateway 3.16.0.0 (decK 1.68.0 in CI),
OpenBao 2.7.0, HAPI FHIR v8.12.0-1, Postgres 18.6, Grafana 13.2.3, Loki 3.7.8,
Tempo 3.1.0, OpenTelemetry Collector contrib 0.161.0, Alloy v1.20.1,
nginx 1.30.5, SPIRE 1.15.3, spiffe-helper 0.12.1, k3s v1.37.0-k3s1,
Synthea v4.0.0. The MCP servers implement MCP 2026-07-28, the current
specification revision. Dependabot proposes updates weekly.
