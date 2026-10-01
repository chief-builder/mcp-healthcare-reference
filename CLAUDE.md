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
Phases 0–7 built. Last full run of all eight gates: green on 2026-09-30
on the hardening branch (MCP 2026-07-28, Kong 3.16, current images):
158 passed + 1 skipped of 159 (the skip is the optional real-GitHub leg,
which needs a one-time browser consent), plus phase 0's 4 checks.
Phases 2–7 need a valid Konnect PAT in compose/phase{2..5}/.env and free
host ports 8210/8300/8310 (stop the vtb-* containers). Offline: `make test` (servers vitest 89, broker pytest 97,
DB-less Kong plugin suite 47, kit vectors 15+4 skipped) — no accounts.

Hardening (2026-09-30): MCP 2026-07-28 via @modelcontextprotocol/server
2.x + /express + /node, zod 4 (#8 resolved; createMcpHandler with the SDK's
stateless 2025-11-25 fallback); shared resource-server core in
servers/shared (token-verifier, dpop, audit, app guards, tool-policy) —
the old per-server copies are gone. Fixed: JSON-RPC batch bypassed per-tool
scope (batches refused + handler-level re-check); dlp-egress now screens
JSON-decoded strings (escaped-MRN bypass); dpop-check now sees a second
DPoP header; vendor-token refuses DPoP-scheme tokens. New: clinical
step-up scopes (MCP_MFA_SCOPES) require amr∋mfa → 401
insufficient_user_authentication (RFC 9470). Node 24, Python 3.14, Kong
3.16.0.0 (3.14+ defaults routes to https — every deck route declares
protocols [http, https]). Broker: validated config (app/config.py),
injectable clients, 4xx problems for bad input.

Layout reminders: the audit spine rides the phase5 stack (no
compose/phase6): Kong DPs export traces + kong.log audit records via a
global opentelemetry plugin in deck/*.yaml; broker, servers, mock-vendor
emit one JSON audit line per event on stdout, shipped by Alloy
(compose/phase5/alloy/config.alloy) to Loki; Grafana provisioning =
compose/phase0/grafana/. mockhub (compose/phase5/mock-vendor) drives the
egress gates headless; the real GitHub leg activates when
GITHUB_CLIENT_ID/SECRET are set. Cert-bound m2m (phase 4) = SPIRE in k3d →
Keycloak client-x509 :8443 → Kong :8143 + plugins/cnf-check.
Canonical identity config = realm/*.json + compose/phase1/setup-phase1.sh.
Canonical gateway config = deck/*.yaml + compose/phaseN/setup-phaseN.sh.
Canonical workload config = compose/phase4/k8s/*.yaml. Broker/vendor config =
broker/registry.json + compose/phase5/setup-phase5.sh (vault provisioning).
Server images build with context servers/ (npm workspace).

DPoP (RFC 9449): parallel public client `workforce-dpop`
(dpop.bound.access.tokens=true → cnf.jkt). Gateway-first plugins/dpop-check
(structure + jkt binding + htm/htu/iat/ath + jti replay via the dpop_jti
shared dict; no signature check, matching the DP's
no-crypto-on-first-party-routes posture), authoritatively re-checked by
servers/shared/src/dpop.ts (jose EmbeddedJWK). The deck tier-wall accepts
both Bearer and DPoP schemes. claude-code stays bearer — tracked gap.

Issues: #1–#2, #4–#7, #9–#16 closed; #8 resolved on the hardening branch
(closes on merge); #3 (external-tier CIMD control) open — tracked gap.
#13 (mcp:// resource URIs) is a documented deviation. Applying
gateway-side changes live needs setup-phase5.sh (plugin schema
re-register + deck sync + DP restart); realm scope additions need a realm
re-import (avoid re-importing over the Auth0-federated user; kcadm client
updates are the non-destructive path). HAPI may OOM (Exited 137) in a tight
Docker VM — restart it before FHIR gates; stopping k3d frees RAM.
