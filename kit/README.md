# Enterprise Rollout Kit

Portable artifacts extracted from the mcp-healthcare-reference lab, per
`docs/enterprise-rollout-kit-plan.md`. The lab is the reference implementation;
these documents are what travels to a customer engagement.

The blueprints are written as requirements (MUST/SHOULD, RFC 2119 sense) with
deployment parameters in place of lab-specific values. Where a lab file is
cited it is cited as the *conforming implementation*, not as the requirement.

## Layout

```
kit/
  blueprints/
    control-catalog.md            The control spine: every control the platform
                                  enforces, with a stable ID, a normative
                                  statement, enforcing code, and proving test.
                                  All other kit documents reference these IDs.
    token-claims-contract.md      Portable version of the canonical JWT contract.
    gateway-policy.md             Vendor-neutral gateway policy spec (tier wall,
                                  sender-constraint, DLP, credential swap).
    broker.md                     Vendor Token Broker portability profile:
                                  custody interface, multi-replica deployment,
                                  registry schema.
    schemas/
      canonical-jwt.schema.json   Machine-readable claim shape (JSON Schema).
      vendor-registry.schema.json Machine-readable vendor registry shape.
    vectors/
      valid/ invalid/             Claim-set test fixtures with expected verdicts.
                                  Unsigned by policy — see vectors/README.md.
```

## Status

| Workstream (plan) | Status |
|---|---|
| A — Portable blueprints | This directory |
| B — Adapter guides (IdPs, gateways) | Not started |
| C — Compliance mapping (HIPAA / SOC 2 / HITRUST) | Not started |
| D — Acceptance framework | Not started (fixtures here are its input) |
| E — Pilot playbook | Not started |

## Provenance

Extracted from `docs/mcp-token-claims-contract.md` (v1.0-draft),
`docs/vendor-token-broker-design.md` (v1.0-draft), `deck/*.yaml`, `plugins/`,
and `broker/registry.json` as of Phase 7 (all eight acceptance gates green).
Known lab-vs-production deltas are carried forward explicitly, never silently
promoted to implemented status.
