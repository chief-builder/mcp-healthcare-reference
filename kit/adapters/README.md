# Adapter Guides (Workstream B)

How the portable blueprints land on the identity providers and gateway
platforms customers actually run. `hub-requirements.md` is the anchor —
every IdP guide scores against it, and the pattern it states (upstream IdPs
vary; one hub issuer normalizes, IDN-01) is what makes the per-IdP deltas
survivable.

```
adapters/
  hub-requirements.md           B5 — what the hub AS must support (normative),
                                plus the "our IdP as the hub" scorecard.
  idp-entra-id.md               B6 — per-IdP guides, each in two shapes:
  idp-okta.md                        brokered-behind-the-hub (works today) and
  idp-ping.md                        EMA/ID-JAG issuer (target state).
  gateway-capability-matrix.md  B7 — gateway-policy P1–P9 on Envoy/Istio,
                                Apigee, Azure APIM, AWS API Gateway.
```

## Status labels — the validation rule

**No unvalidated adapter ships as validated** (plan item B8). Two labels:

- **validated** — the Workstream-D acceptance suite has run green through
  this adapter against a real deployment, and the run is recorded here.
- **desk-checked** — written against vendor documentation and the author's
  platform knowledge (as of July 2026); vendor capability claims MUST be
  re-verified against current vendor docs at engagement time.

Current state: **everything here is desk-checked.** The first planned
validation leg is an Entra ID dev tenant brokered behind the lab hub
(mirroring how the real Auth0 leg was proven), then the phase-1/-3 gates and
the kit acceptance IDN/TIER probes through it. That run requires a tenant
and cannot be desk-simulated.

## Fidelity note

An adapter guide never relaxes a control. Where a platform cannot carry a
control (Entra-as-hub vs SC-01/02; AWS API Gateway vs fail-closed body
inspection), the guide says so and states the compensating design — the
control catalog's honesty-ledger convention, applied to vendors.
