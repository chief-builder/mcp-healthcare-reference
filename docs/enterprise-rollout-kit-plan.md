# Plan: Enterprise Rollout Kit

**Goal:** turn the lab from *one proof* into *a portable kit* — specs, adapters, compliance
evidence, acceptance tests, and a playbook — that a delivery team can take into any enterprise.
The lab stays the reference implementation; the kit is what travels.

**Packaging decision (make first):** create a separate `kit/` tree (or sibling repo, following
the docs-site mirror precedent) so kit artifacts are cleanly separable from lab internals and can
be shared with customers without exposing the private repo.

---

## Workstream A — Portable blueprints (the foundation; do first)

Everything else references these, so extract them before writing adapters or mappings.

1. **Control catalog** *(new, small, highest leverage)* — enumerate every control the lab
   enforces (the five invariants plus supporting controls: compartment filter, scope step-up,
   single-flight refresh, fail-closed DLP, etc.), each with a stable ID, a normative statement,
   and pointers to enforcing code and proving test. This becomes the spine that blueprints,
   compliance maps, and acceptance tests all key off.
2. **Token claims contract blueprint** — `docs/mcp-token-claims-contract.md` is already close.
   Genericize issuer specifics, restate as MUST/SHOULD requirements, and add machine-readable
   artifacts: a JSON Schema for the canonical JWT plus signed test vectors (valid tokens and the
   forbidden shapes — wrong tier, missing `mcp_contract`, `fhir_patient` where prohibited).
3. **Gateway policy blueprint** — extract the *behavior* of `deck/*.yaml` + `plugins/` (tier
   wall, cnf-check, dpop-check, dlp-egress, vendor-token swap, rate limits) into a vendor-neutral
   policy spec with pseudocode per check, with the Kong config kept as the reference
   implementation. Flag the genuinely hard-to-port pieces explicitly (DPoP jti replay cache
   semantics, fail-closed body inspection).
4. **Broker blueprint** — `docs/vendor-token-broker-design.md` is nearly spec-grade already.
   Add: a vault interface abstraction (OpenBao/Vault/cloud secret managers), a multi-replica
   deployment profile (distributed lock — currently a documented single-replica limitation), and
   the vendor `registry.json` schema as a normative artifact.

## Workstream B — Adapter guides (IdPs and gateways)

5. **Hub requirements doc first** — the lab's pattern is "upstream IdPs vary, one hub issuer
   normalizes." Write down what the hub AS must support (claim mappers, token exchange,
   client-x509, DPoP issuance) so customers can evaluate "Keycloak as hub" vs "our IdP as hub"
   honestly.
6. **Per-IdP guides (Entra ID, Okta, Ping)** — each in two shapes: *brokered-behind-the-hub*
   (works today; this is what fake-ping and the real Auth0 leg already prove) and *EMA/ID-JAG
   issuer* (target state, gated on vendor adoption). Each guide: claim/group mapping table to the
   canonical vocabulary, MFA/`amr` propagation, sender-constraint support matrix, known
   limitations.
7. **Gateway capability matrix** — what each Kong plugin does → equivalents in Envoy/Istio,
   Apigee, Azure APIM, AWS API Gateway, with red flags where a platform can't fail closed or
   can't do body inspection.
8. **Validation rule: no unvalidated adapter ships.** Stand up at least one real second-IdP leg
   (an Entra dev tenant is the obvious pick, mirroring how Auth0 was done) and run the acceptance
   suite through it. Guides for the others can be desk-checked but must be labeled as such.

## Workstream C — Compliance mapping (after A stabilizes)

9. **Map the control catalog** to HIPAA Security Rule citations (§164.312 access control, audit
   controls, integrity, transmission security), SOC 2 TSC (CC6/CC7 families), and HITRUST CSF —
   one matrix, controls as rows, frameworks as columns, **evidence pointer per cell naming the
   phase-gate test that produces the proof**.
10. **Shared-responsibility matrix** — what the kit enforces vs what the customer must supply
    (retention/immutable SIEM, device posture, BAAs, production TLS). Keep the docs site's
    "evidence, not certification" framing — it's a credibility asset.
11. **External dependencies to schedule early:** a compliance SME review, and a check on HITRUST
    CSF licensing (the framework text is licensed; the mapping format must respect that).

## Workstream D — Acceptance framework (start alongside A; it validates A)

12. **Split the suites** — today `tests/phase0-7.sh` are lab-coupled (ports, container names,
    mockhub). Separate *portable invariant probes* (token shape, cross-tier replay, DPoP probe
    pack, DLP block, compartment escape, audit join, broker no-issuance) from *lab harness tests*
    (compose wiring, Synthea seeding).
13. **Parameterize on an environment descriptor** — one config file (issuer URL, tier endpoints,
    expected audiences, test identities) so the same probes run against the lab *and* a customer
    deployment. The lab becomes the framework's own CI fixture.
14. **Conformance profile doc** — which probes prove which blueprint requirements (joins back to
    the control catalog IDs), and what "green" does and does not claim.
15. **Rules-of-engagement template** — the phase-7 red-team pack pointed at customer
    infrastructure needs written authorization scope, safe test identities, and data-handling
    rules baked into the kit, not improvised per engagement.

## Workstream E — Pilot playbook (last; synthesizes everything)

16. **Phase 0–7 as the rollout sequence** — for each stage (identity → tiers → first-party tools
    → workload identity → egress → audit → red team): entry criteria, activities, stakeholder
    owners (the walkthrough's identity/platform/security/compliance split maps directly),
    production-choices worksheet (the lab's substitution map — SPIRE→Athenz, OpenBao→Vault,
    mockhub→real vendor — becomes a decision template), and **exit criteria = the corresponding
    acceptance gate from D**.
17. **Reuse the docs site** as stakeholder-facing collateral (product overview for executives,
    token lifecycle for security review) — it's already written for exactly this audience.
18. **Dry-run pilot** — execute the playbook end-to-end against a fresh environment (clean
    machine or cloud project) using only kit artifacts, no tribal knowledge. What breaks is the
    punch list before first customer use.

---

## Prerequisites and sequencing

**Gaps to disposition before the kit ships** (decide: fix vs document-as-delta): #8 MCP
2026-07-28 wire migration (biggest — the acceptance suite currently verifies legacy wire
behavior), #13 HTTPS resource identifiers, #15 exact redirect URIs, #16 scheduling Origin guard.
Recommendation: fix #15/#16 (small), schedule #8/#13 in parallel with Workstream A, and have the
acceptance framework assert the *post-fix* behavior.

**Order of execution:** A1 control catalog → A2–A4 blueprints + D12–13 suite split (in parallel,
each validates the other) → B adapters (with one real Entra validation) → C compliance map → E
playbook → E18 dry run.

**Relative effort:** A = medium, B = large (the real-tenant validation is most of it), C = medium
plus external SME, D = large (test refactor touches everything), E = medium. D and A are the
critical path.

**Definition of done:** a delivery engineer who has never seen the lab can take `kit/`, stand up
a pilot at a customer, pass the acceptance gates against the customer's deployment, and hand
compliance a filled evidence matrix — without opening this repo's source.
