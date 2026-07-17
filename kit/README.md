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
      valid.json invalid.json     Claim-set test fixtures with expected verdicts.
                                  Unsigned by policy — see vectors/README.md.
  adapters/                       Workstream B: hub AS requirements, per-IdP
                                  guides (Entra ID, Okta, Ping) in brokered and
                                  EMA/ID-JAG shapes, and the gateway capability
                                  matrix. Desk-checked until a real second-IdP
                                  leg runs the acceptance suite — see
                                  adapters/README.md for the validation rule.
  acceptance/                     Workstream D: portable conformance probes a
                                  customer runs against their own deployment,
                                  parameterized on an environment descriptor.
                                  Reuses the blueprints' vectors as its unit
                                  layer. See acceptance/README.md.
```

## Status

| Workstream (plan) | Status |
|---|---|
| A — Portable blueprints | `blueprints/` |
| B — Adapter guides (IdPs, gateways) | `adapters/` (desk-checked; real-tenant validation pending) |
| C — Compliance mapping (HIPAA / SOC 2 / HITRUST) | Not started |
| D — Acceptance framework | `acceptance/` |
| E — Pilot playbook | Not started |

## Provenance

Extracted from `docs/mcp-token-claims-contract.md` (v1.0-draft),
`docs/vendor-token-broker-design.md` (v1.0-draft), `deck/*.yaml`, `plugins/`,
and `broker/registry.json` as of Phase 7 (all eight acceptance gates green).
Known lab-vs-production deltas are carried forward explicitly, never silently
promoted to implemented status.
