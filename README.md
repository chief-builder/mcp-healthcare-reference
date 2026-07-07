# mcp-healthcare-reference

Reference implementation lab for an enterprise MCP platform architecture: multi-IdP identity
hub (Keycloak), Kong Konnect hybrid gateway in three tiers, certificate-bound m2m identity,
stateless MCP servers (2026-07-28) over synthetic FHIR, and a vault-backed vendor token
broker for SaaS MCP egress with DLP.

## Documents
- [End-to-End Reference Architecture](docs/mcp-e2e-reference-architecture.md) — the five invariants, tiers, HIPAA mapping, WAF appendix
- [Token Claims Contract](docs/mcp-token-claims-contract.md) — the canonical JWT every component validates
- [Vendor Token Broker Design](docs/vendor-token-broker-design.md) — consent dance, refresh race, vault schema
- [Prototype Plan](docs/prototype-plan.md) — fidelity contract, substitution map, phases 0–7

## Status
Phase 0 not started. Directory skeleton in place; see the prototype plan for phase gates.
