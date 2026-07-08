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
Phase 4 complete (tests/phase4.sh green: zero-secrets agent manifest,
contract §6.3 claims incl. cnf, no-mTLS/wrong-cert replay → 401 + audit,
SVID rotation without pod restart; phases 0–3 still green on the phase4
stack). Cert-bound m2m is live: SPIRE in k3d (trust domain mcp-lab, lab CA
root, 180s SVIDs) → Keycloak client-x509 mTLS listener :8443 (issuer pinned
via KC_HOSTNAME) → Kong internal TLS listener :8143 with the bespoke
plugins/cnf-check plugin (global on the internal CP; schema registered by
setup-phase4.sh).
Canonical identity config = realm/*.json + compose/phase1/setup-phase1.sh.
Canonical gateway config = deck/*.yaml + compose/phaseN/setup-phaseN.sh.
Canonical workload config = compose/phase4/k8s/*.yaml (+ SPIRE entries in
setup-phase4.sh). First-party MCP servers = servers/; loop agent =
agents/loop-agent. Phase 5 (egress + broker, the centerpiece) not started.
