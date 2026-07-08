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
Phase 5 complete (tests/phase5.sh green: consent dance → vendor MCP tool;
planted MRN blocked + audited at the egress DP; 20 parallel resolves →
exactly one vendor refresh (single-flight + generation CAS); DELETE /grants
revokes at the vendor RFC 7009; plus state-replay/iss-mismatch security
alerts, STALE→re-consent, fail-closed vault, no-issuance route audit;
phases 0–4 still green on the phase5 stack). Egress + broker are live:
Vendor Token Broker (broker/, per docs/vendor-token-broker-design.md) over
OpenBao custody; dlp-egress + vendor-token bespoke Kong plugins on the
egress routes; mockhub vendor AS (compose/phase5/mock-vendor) drives the
gates headless; real GitHub leg activates when GITHUB_CLIENT_ID/SECRET set.
Prior phases unchanged: cert-bound m2m (phase 4) = SPIRE in k3d → Keycloak
client-x509 :8443 → Kong :8143 + plugins/cnf-check.
Canonical identity config = realm/*.json + compose/phase1/setup-phase1.sh.
Canonical gateway config = deck/*.yaml + compose/phaseN/setup-phaseN.sh.
Canonical workload config = compose/phase4/k8s/*.yaml. Broker/vendor config =
broker/registry.json + compose/phase5/setup-phase5.sh (vault provisioning).
First-party MCP servers = servers/; loop agent = agents/loop-agent.
Phase 6 (audit spine — OTel → Loki/Tempo, jti tuple dashboard) not started.
