# MCP Healthcare Reference — One-Page Summary

*A runnable reference implementation of governed, enterprise-grade MCP (Model Context Protocol) for regulated healthcare. Phase 7 complete — all eight acceptance gates green (154 tests, incl. a 32-probe red-team suite, 0 failures).*

## What it does

The lab proves that an enterprise can let four very different AI populations — workforce users with coding assistants, clinicians with scheduling assistants, unattended autonomous agents, and patient-facing apps — work against clinical systems (FHIR, scheduling) and SaaS vendors (GitHub etc.) through **one governed plane**, while keeping the three things regulators ask for: control over who connects, certainty about what data left, and a complete answer to "who did that?"

Five invariants, never stubbed, each enforced by executable tests:

1. **One token issuer.** Keycloak mints every token the plane validates; upstream IdPs (Ping-style workforce, Auth0 patients, legacy issuers, SPIFFE workloads) are normalized into one canonical JWT vocabulary.
2. **Tiered gateways with cryptographic walls.** Internal and external Kong tiers carry separate token audiences — a token replayed across tiers fails cryptographically, not by policy.
3. **Sender-constrained tokens.** Workloads use mTLS certificate-bound tokens (`cnf.x5t#S256`, SPIRE-issued SPIFFE identities — no secrets anywhere); interactive workforce uses DPoP proof-of-possession (`cnf.jkt`). A stolen token is inert without the key.
4. **Governed egress.** Outbound vendor calls are DLP-screened for patient identifiers (fail-closed), and a vault-backed (OpenBao) Vendor Token Broker holds per-user vendor OAuth grants — no personal access tokens on laptops, single-flight refresh, one-click revocation on offboarding. The MCP-plane token never reaches a vendor.
5. **jti-joinable audit spine.** Every gateway verdict, broker decision, and tool outcome (including denials) carries the token's `jti` — one Loki query walks any action back to a named human or workload.

Additional structural controls: patient tokens are compartmented (`fhir_patient` claim — a patient assistant *cannot express* a request for another chart), scope step-up with MFA marks for clinical tools, stateless MCP servers (kill-a-replica-mid-conversation is a non-event), and PHI never reaching the SaaS management plane.

## Standards it follows

- **MCP** + the **Enterprise-Managed Authorization (EMA)** extension — IdP-governed client-to-server connections via **ID-JAG** (RFC 8693 token exchange + RFC 7523 JWT grant)
- **OAuth 2.1** posture: PKCE S256, RFC 9728 Protected Resource Metadata, RFC 9207 issuer identification, RFC 8414 AS metadata, RFC 7009 revocation
- **RFC 9449 DPoP** and **RFC 8705 mTLS** sender-constrained tokens; PS256/ES256-only JWTs, 5–10 min lifetimes
- **SPIFFE/SVID** workload identity (SPIRE); **HL7 FHIR R4** clinical data (synthetic, via Synthea); **OpenTelemetry** → Loki/Tempo/Grafana evidence plane; HIPAA-shaped controls throughout

## Next steps to build on it

**Close the tracked gaps (repo issues):** migrate to the MCP 2026-07-28 wire protocol and v2 SDK (#8); move `mcp://` resource URIs to canonical HTTPS identifiers per RFC 9728 (#13); exact-match redirect URIs per RFC 9700 (#15); Origin/rebinding guard on the scheduling server (#16); external-tier client-identity controls (#3); extend DPoP to all interactive clients as they ship proof support.

**Production-harden the lab substitutions:** TLS everywhere, production Keycloak/OpenBao modes, distributed broker locking for multi-replica refresh, immutable SIEM with retention policy, HA data planes, device-posture and anomaly detection on the audit spine.

**Turn the reference into an enterprise rollout kit:** extract the token claims contract, gateway policy, and broker design as portable blueprints; add adapter guides for other IdPs (Entra, Okta, Ping) and gateways; map controls to HIPAA / SOC 2 / HITRUST for compliance sign-off; package the phase-gate test suites as an acceptance framework a customer can run against *their* deployment; publish a pilot playbook (phase 0–7 mirrors a real rollout sequence: identity → tiers → first-party tools → workload identity → egress → audit → red team).

*All patient data synthetic; design authority in `docs/`, executable proof in `tests/`.*
