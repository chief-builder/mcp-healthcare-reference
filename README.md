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

## Layout
Repo layout is prototype-plan §5; each component directory carries its own
README. Bring-up is per phase (`compose/phaseN/README.md`); the acceptance
gate for each phase is `tests/phaseN.sh`.

## Status
Phases 0–6 complete; all seven gates are green on the current stack. The
phase 6 audit spine rides the phase 5 stack (`compose/phase5/README.md`) —
one Loki query keyed by `jti` walks a vendor call across the gateway, DLP,
and broker records. Phase 7 (red-team weekend) not started.
