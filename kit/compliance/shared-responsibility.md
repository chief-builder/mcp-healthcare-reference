# Shared Responsibility Matrix

**Kit compliance C10** · Status: **desk-checked, compliance-SME review pending**

What the platform enforces (and proves, via the acceptance framework) versus
what the customer organization must supply. A deployment where the left
column is green and the right column is unowned is **not** a defensible
posture — the right column is where most audit findings actually land.

The lab's docs-site framing carries over deliberately: the kit produces
**evidence, not certification**.

| Area | The platform enforces (evidence: acceptance run) | The customer must supply | Related controls |
|---|---|---|---|
| Identity lifecycle | Single-issuer token discipline; normalized roles; delegation chains | The upstream IdP itself: joiner/mover/leaver processes, MFA enrollment and policy, directory hygiene | IDN-01..09 |
| Authentication strength | `amr` propagation; scope policy gated on the `mfa` mark | Actually enforcing MFA at the IdP (Conditional Access / sign-on policy); authenticator management | IDN-08 |
| Access control | Tier walls, per-server audiences, tool-level scopes, patient-compartment filtering | Role definitions and assignment governance — *who* belongs in `mcp-clinical-tools` is a human decision with a review cadence | TIER-*, AZ-* |
| Sender constraint | cnf enforcement at gateway and server; secretless workload identity | The workload-identity plane's root of trust (CA/SPIRE deployment, attestation policy) and client-side key custody | SC-01..05 |
| Egress governance | Fail-closed DLP, credential swap, scope ceilings, consent lifecycle | The DLP pattern set for *their* data (the lab ships MRN/SSN exemplars, not a clinical-grade catalog); vendor risk assessments and DPAs/BAAs with each SaaS vendor | EG-* |
| Secrets custody | Vault-backed grant custody, fail-closed on vault loss | Production vault deployment: HA, seal/unseal custody, **HSM/KMS envelope (consciously absent from the lab)**, backup/restore drills | EG-06/07 |
| Audit | jti-joinable, outcome-accurate, token-free records emitted at every decision point | **Immutable, retention-managed SIEM** (the lab's Loki/Tempo is neither), retention schedule (HIPAA: 6 years for required documentation), log review procedures, alert response | AU-01..03 |
| Transport security | mTLS on the workload leg; token-level binding elsewhere | Production TLS everywhere with real certificates and rotation (the lab is deliberately HTTP-first outside the mTLS leg); network segmentation | SC-01, OPS-02 |
| Gateway operations | Declarative git-authoritative config; drift detection; rate ceilings; CP/DP data isolation | Change-management process around the git repo (review, approval, emergency change); capacity planning; **WAF managed rules on the public tier (documented gap)** | OPS-01..03, TIER-04 |
| Endpoint / client posture | Token binding makes stolen bearer material inert on constrained paths | Device posture, EDR, browser policy, and the `claude-code` bearer-client gap until DPoP ships in real clients | SC-02 (gap register) |
| Legal / administrative | — | BAAs (covered entity ↔ every business associate: gateway control-plane vendor, cloud, SaaS vendors, IdP); Privacy Rule program; sanctions policy; workforce training; risk analysis (§164.308(a)(1)) | §164.308/§164.314 (customer-side) |
| Physical | — | Data-center / device physical safeguards (§164.310) | — |
| Incident response | Audit spine + STALE-storm and binding-violation alerts give the *signals* | The IR plan, on-call, breach-notification process (§164.404+), tabletop exercises | AU-01, EG-10 |
| Availability / DR | Stateless servers make replica loss survivable; DP survives CP loss | Backup and disaster recovery for the stateful pieces (Postgres, vault, IdP), contingency plan (§164.308(a)(7)), RTO/RPO targets | ST-01, OPS-02 |
| FIPS 140-3 | — (skipped in the lab, documented) | FIPS-validated crypto modules where required by policy/contract | IDN-02 note |
| Patient linkage | `fhir_patient` injection and bidirectional enforcement once linkage exists | The identity-proofing and account-linkage process that decides *which* patient a customer identity maps to — the highest-stakes human process in the system | AZ-04, HUB-14 |

## Reading it in an engagement

1. Walk the table with the customer's compliance owner before Phase 0 of the
   pilot; every right-column cell gets a named owner or an accepted risk.
2. The left column is proven by running `kit/acceptance/` against the
   deployment — attach the run output to the evidence package.
3. Gaps the platform documents (WAF rules, HSM envelope, FIPS, bearer
   `claude-code`) transfer to the right column *explicitly* — they are
   customer decisions to compensate or accept, never silent.
