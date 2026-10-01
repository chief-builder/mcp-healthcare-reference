# MCP Healthcare Reference — One-Page Summary

*A runnable reference implementation of governed, enterprise-grade MCP (Model Context Protocol) for regulated healthcare. Phases 0–7 built; the last full run of all eight acceptance gates (2026-09-30) was green: 158 of 159 live tests, the one skip being the optional real-GitHub leg. The live suites now hold 159 tests (incl. a 32-probe red-team suite), plus 248 offline tests (`make test`) that need no accounts.*

## What it does

The lab proves that an enterprise can let four very different AI populations — workforce users with coding assistants, clinicians with scheduling assistants, unattended autonomous agents, and patient-facing apps — work against clinical systems (FHIR, scheduling) and SaaS vendors (GitHub etc.) through **one governed plane**, while keeping the three things regulators ask for: control over who connects, certainty about what data left, and a complete answer to "who did that?"

Five load-bearing controls, never stubbed, each enforced by executable tests (the architecture's five design invariants are in `mcp-e2e-reference-architecture.md` §1):

1. **One token issuer.** Keycloak mints every token the plane validates; upstream IdPs (an enterprise workforce IdP, Auth0 patients, a legacy in-house issuer, SPIFFE workloads) are normalized into one canonical JWT vocabulary.
2. **Tiered gateways with cryptographic walls.** Internal and external Kong tiers carry separate token audiences — a token replayed across tiers fails cryptographically, not by policy.
3. **Sender-constrained tokens.** Workloads use mTLS certificate-bound tokens (`cnf.x5t#S256`, SPIRE-issued SPIFFE identities — no secrets anywhere); interactive workforce uses DPoP proof-of-possession (`cnf.jkt`). A stolen token is inert without the key.
4. **Governed egress.** Outbound vendor calls are DLP-screened for patient identifiers (fail-closed), and a vault-backed (OpenBao) Vendor Token Broker holds per-user vendor OAuth grants — no personal access tokens on laptops, single-flight refresh, one-click revocation on offboarding. The MCP-plane token never reaches a vendor.
5. **jti-joinable audit spine.** Every gateway verdict, broker decision, and tool outcome (including denials) carries the token's `jti` — one Loki query walks any action back to a named human or workload.

Additional structural controls: patient tokens are compartmented (`fhir_patient` claim — a patient assistant *cannot express* a request for another chart), scope step-up with the `mfa` authentication mark required for clinical scopes (RFC 9470 challenge when absent), stateless MCP 2026-07-28 servers (kill-a-replica-mid-conversation is a non-event), and PHI never reaching the SaaS management plane.

## Standards it follows

- **MCP 2026-07-28** (stateless, served natively via the MCP TypeScript SDK v2), designed so the brokered login legs can upgrade in place to the **Enterprise-Managed Authorization (EMA)** extension / **ID-JAG** (RFC 8693 + RFC 7523) when the IdPs ship it — that upgrade is not implemented yet
- **OAuth 2.1** posture: PKCE S256, RFC 9728 Protected Resource Metadata, RFC 9207 issuer identification, RFC 8414 AS metadata, RFC 7009 revocation
- **RFC 9449 DPoP** and **RFC 8705 mTLS** sender-constrained tokens; PS256/ES256-only JWTs, 5–10 min lifetimes
- **SPIFFE/SVID** workload identity (SPIRE); **HL7 FHIR R4** clinical data (synthetic, via Synthea); **OpenTelemetry** → Loki/Tempo/Grafana evidence plane; HIPAA-shaped controls throughout

## Next steps to build on it

**Close the tracked gaps:** external-tier client-identity (CIMD) controls (#3); move `mcp://` resource URIs to canonical HTTPS identifiers per RFC 9728 (a documented deviation, #13); extend DPoP to all interactive clients as they ship proof support. (Done: the MCP 2026-07-28 migration #8, exact-match redirect URIs #15, the scheduling Origin guard #16.)

**Production-harden the lab substitutions:** TLS everywhere, production Keycloak/OpenBao modes, distributed broker locking for multi-replica refresh, immutable SIEM with retention policy, HA data planes, device-posture and anomaly detection on the audit spine.

**Turn the reference into an enterprise rollout kit:** extract the token claims contract, gateway policy, and broker design as portable blueprints; add adapter guides for other IdPs (Entra, Okta, Ping) and gateways; map controls to HIPAA / SOC 2 / HITRUST for compliance sign-off; package the phase-gate test suites as an acceptance framework a customer can run against *their* deployment; publish a pilot playbook (phase 0–7 mirrors a real rollout sequence: identity → tiers → first-party tools → workload identity → egress → audit → red team).

*All patient data synthetic; design authority in `docs/`, executable proof in `tests/`.*
