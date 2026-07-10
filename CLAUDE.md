# mcp-healthcare-reference — working agreements

This repo is a home-lab reference implementation of the architecture in docs/.
Read docs/prototype-plan.md FIRST in any session — it defines phases and gates.

## Non-negotiables (fidelity contract, plan §1)
Single issuer (Keycloak) · two-level audiences w/ cross-tier replay failing ·
cert-bound m2m (cnf) · stateless MCP (2026-07-28) · egress DLP · broker
single-flight refresh · jti-joinable audit. Never stub these — enforce them.

## Conventions
- Work phase-by-phase; a phase is done only when tests/phaseN.sh is green.
- Identity/gateway config is declarative and committed: realm/ (Keycloak
  exports), deck/ (Kong). Never hand-edit live state without exporting back.
- Conventional commits, one commit per acceptance gate minimum.
- NEVER commit secrets, certs, or tokens (.gitignore is pre-set — respect it).
- Canonical JWT shape: docs/mcp-token-claims-contract.md §3. All validation
  code targets it exactly.
- Broker code must follow docs/vendor-token-broker-design.md (esp. §6 consent,
  §9 refresh race, no-issuance rule §11).

## Current status
Phase 6 complete (tests/phase6.sh green: one Loki query keyed by jti walks
a vendor call back through vendor-token allow + dlp-egress verdict +
broker.resolve; a planted-MRN block joins the same way; first-party
tools/call carries the §9 tuple; Kong traces in Tempo; the "MCP Audit
Tuple" Grafana dashboard is provisioned; no token material on the spine;
phases 0–5 still green). The audit spine rides the phase5 stack (no
compose/phase6): Kong DPs export traces + kong.log audit records via a
global opentelemetry plugin in deck/*.yaml (KONG_TRACING_* env in
compose); everything else (broker, servers, mock-vendor) emits one JSON
audit line per event on stdout, shipped by Alloy
(compose/phase5/alloy/config.alloy) over the Docker API to Loki. Grafana
provisioning (datasources + tuple dashboard) = compose/phase0/grafana/.
MCP servers emit §9 records per tools/call (servers/*/src/audit.ts);
dlp-egress logs allow verdicts on clean passes too.
Phase 5 unchanged: Vendor Token Broker (broker/) over OpenBao custody;
dlp-egress + vendor-token plugins on the egress routes; mockhub vendor AS
(compose/phase5/mock-vendor) drives the gates headless; real GitHub leg
activates when GITHUB_CLIENT_ID/SECRET set. Cert-bound m2m (phase 4) =
SPIRE in k3d → Keycloak client-x509 :8443 → Kong :8143 + plugins/cnf-check.
Canonical identity config = realm/*.json + compose/phase1/setup-phase1.sh.
Canonical gateway config = deck/*.yaml + compose/phaseN/setup-phaseN.sh.
Canonical workload config = compose/phase4/k8s/*.yaml. Broker/vendor config =
broker/registry.json + compose/phase5/setup-phase5.sh (vault provisioning).
First-party MCP servers = servers/; loop agent = agents/loop-agent.
Phase 7 (red-team weekend, plan §3) run once: tests/phase7.sh green (18
passed, 2 xfail). Arch §13 list + cross-tier replay, scope-ceiling, broker
state replay, RFC 9207 iss tamper, per-entry STALE, token-in-log grep,
broker no-issuance all hold. Three findings filed as GitHub issues: #1
(High) broker skips RFC 9207 iss check when the callback omits iss — mix-up
bypass; #2 (Med) no mass-STALE/page signal on org-app uninstall; #3 (Low)
external-tier CIMD origin-allowlist control not implemented. The two open
gaps are the xfail(strict) probes in tests/phase7/. Note: HAPI may be
OOM-down (Exited 137) in a tight Docker VM — restart before FHIR gates.
