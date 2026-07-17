# Pilot Playbook (Workstream E)

How a delivery team runs the platform into a customer environment. The
playbook synthesizes the rest of the kit: stages come from the lab's proven
phase sequence, exit criteria are the acceptance framework's probe families,
production choices come from the substitution map, and the compliance
artifacts ride along from stage 0.

```
playbook/
  rollout-sequence.md    E16 — stages 0–7: entry criteria, activities,
                         stakeholder owners, exit criteria (= acceptance gates).
  production-choices.md  E16 — the decision worksheet: every lab substitution
                         restated as a production choice with its constraint.
  dry-run.md             E18 — the fresh-environment dry-run protocol and punch
                         list. NOT YET EXECUTED — see status below.
```

## How to use it

1. Before anything: walk `compliance/shared-responsibility.md` with the
   customer's compliance owner; every customer-side cell gets a named owner.
2. Fill `production-choices.md` — the answers parameterize everything after.
3. Run the stages in `rollout-sequence.md` in order. **Do not advance on
   red**: a stage is done when its probe families pass against the customer
   deployment (`acceptance/` with the customer's environment descriptor),
   not when its components are installed.
4. Stage 7 requires a signed rules-of-engagement
   (`acceptance/RULES-OF-ENGAGEMENT.md`) before any adversarial probe runs.

## Stakeholder collateral (E17)

The public docs site is written for exactly the audiences a pilot must brief;
reuse it instead of writing new decks:

| Audience / moment | Page |
|---|---|
| Executive sponsor, kickoff | Product overview (`showcase/product.html`) — includes the kit framing itself |
| Security review, stage 1–2 | Token lifecycle (`showcase/token-lifecycle.html`) |
| Architecture review board | Technical overview (`showcase/technical-overview.html`) |
| Delivery + platform teams | Walkthroughs (`walkthrough/*.html`) |

Live site: https://chief-builder.github.io/mcp-healthcare-reference-docs/
(serves the same pages; nothing on it is customer-confidential).

## Definition of done (from the kit plan)

A delivery engineer who has never seen the lab can take `kit/`, stand up a
pilot at a customer, pass the acceptance gates against the customer's
deployment, and hand compliance a filled evidence matrix — **without opening
the lab repository's source**.

## Status

Playbook desk work complete. **The E18 dry run has not been executed** — the
definition of done above is unproven until someone runs `dry-run.md` against
a fresh environment using only kit artifacts, and the punch list from that
run is folded back in. Treat this playbook as *draft* until then. Other
standing prerequisites: the adapter guides are desk-checked pending the B8
real-tenant validation, and the compliance directory is pending SME review.
