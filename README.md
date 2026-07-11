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
- [overview.html](overview.html) — rendered tour of the repo and phase status

### Showcase pages

- [Product showcase](docs/showcase/product.html) — what the platform is and why it matters: promises, persona threads, scenarios
- [Technical overview](docs/showcase/technical-overview.html) — invariants, master diagram, EMA alignment, phase gates, consistency-review verdict
- [Token lifecycle](docs/showcase/token-lifecycle.html) — the workforce path token by token: creation, storage, lifetimes, refresh, step-up, credential-store hardening

### Verified codebase walkthroughs

- [Modules — functional](docs/walkthrough/modules-functional.html) — what every repository module does and why it exists
- [Modules — technical](docs/walkthrough/modules-technical.html) — entry points, algorithms, state, endpoints, validation, and known limits
- [Overall — functional](docs/walkthrough/overall-functional.html) — actors, end-to-end journeys, trust boundaries, and operating outcomes
- [Overall — technical](docs/walkthrough/overall-technical.html) — runtime topology, ports, protocol sequences, validation matrix, and reassessment criteria

## Layout
Repo layout is prototype-plan §5; each component directory carries its own
README. Bring-up is per phase (`compose/phaseN/README.md`); the acceptance
gate for each phase is `tests/phaseN.sh`.

## Status
Phases 0–7 complete; the gates are green on the current stack. The phase 6
audit spine rides the phase 5 stack (`compose/phase5/README.md`) — one Loki
query keyed by `jti` walks a vendor call across the gateway, DLP, and broker
records. Phase 7 (red-team weekend) ran the arch §13 acceptance list plus the
named probes; its findings were filed as GitHub issues in this repo and the
remediation is folded back into the code (contract-exact token validation,
per-resource patient scopes, outcome-accurate audit, RFC 9207 iss-omission
defense, mass-STALE paging, broker scope minimization, and scheduling hold
lifecycle). Conformance is to the **draft** MCP 2026-07-28 model, not a final
certification; intentional lab substitutions are documented in
`docs/prototype-plan.md` §2 and the claims contract §4.
