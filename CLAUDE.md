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
Phase 2 complete (tests/phase2.sh green: tier wall w/ 401 replay semantics,
CP-severance resilience, deck-state-matches-git; phases 0/1 still green).
Canonical identity config = realm/*.json + compose/phase1/setup-phase1.sh.
Canonical gateway config = deck/*.yaml + compose/phase2/setup-phase2.sh.
Phase 3 (first-party MCP servers) not started.
