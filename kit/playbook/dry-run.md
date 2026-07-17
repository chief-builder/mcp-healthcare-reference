# Dry-Run Protocol

**Kit playbook E18** · Status: **NOT YET EXECUTED** — this file defines the
exercise; the playbook stays *draft* until a run has happened and its punch
list is folded back into the kit.

## Purpose

Prove the kit's definition of done before a customer does: a delivery
engineer who has never seen the lab stands up a pilot **using only `kit/`**,
passes the acceptance gates, and fills the evidence matrix — without opening
the lab repository's source.

## Ground rules

1. **Fresh environment.** A clean machine or an empty cloud project. Nothing
   from the lab is reachable: no lab containers, no lab realm exports, no
   lab `.env` files.
2. **Kit artifacts only.** The operator gets the `kit/` tree and the public
   docs site. The lab repo's `compose/`, `realm/`, `deck/`, `servers/`,
   `broker/` are off-limits — if the operator needs one of those files, that
   *is* a punch-list finding (the kit is missing an artifact or an
   instruction).
3. **Fresh operator.** Someone who has not worked on the lab. The author of
   the kit may observe and take notes but not touch a keyboard or answer
   questions beyond "that goes on the punch list."
4. **Timebox honestly.** Record wall-clock per stage; the plan's per-phase
   estimates get corrected from data, not optimism.

## Scope of the run

Minimum viable dry run = stages 0–3 of `rollout-sequence.md` (hub, one
brokered IdP leg, two gateway tiers, one first-party MCP server) plus the
corresponding probe families green against the fresh deployment's
descriptor. Stages 4–7 SHOULD follow in the same or a second run; a kit
that only proves 0–3 says so in its status.

Suggested substitutions for a zero-cost run: any OIDC-capable free tenant as
the workforce IdP (an Entra dev tenant doubles as the B8 adapter
validation — one stone, two birds), a fresh Keycloak as hub, Kong OSS or
Envoy as gateway, HAPI + Synthea for data.

## What gets recorded

| Artifact | Content |
|---|---|
| Punch list | Every stop: missing artifact, ambiguous instruction, lab-repo dependency, wrong default. Each entry: stage, blocking/annoying, what the operator did instead |
| Stage timings | Wall-clock per stage vs the plan's estimate |
| Acceptance runs | The probe outputs per stage — these are the proof the run happened |
| Descriptor + worksheet | The environment descriptor and filled production-choices worksheet as the operator wrote them |

## Exit

The run is complete when the in-scope stages' probe families are green from
the fresh environment. The punch list is then triaged into kit changes
(fix before first customer use) vs playbook wording, the corrections are
committed, and this file's status flips to **executed** with the run date,
scope, and operator noted. Only then does the kit's definition of done stand
proven.
