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
Phase 3 complete (tests/phase3.sh green: tool visibility by group, 403
insufficient_scope + step-up, fhir_patient compartment, replica-loss
statelessness; phases 0/1/2 still green on the phase3 stack). Two-level aud
and mcp: scope grammar are now live (phase 1 xfails graduated).
Canonical identity config = realm/*.json + compose/phase1/setup-phase1.sh.
Canonical gateway config = deck/*.yaml + compose/phaseN/setup-phaseN.sh.
First-party MCP servers = servers/ (fhir-clinical generated via
openapi-mcp-generator + authz-hook; scheduling hand-built, Postgres holds).
Phase 4 (cert-bound m2m) not started.
