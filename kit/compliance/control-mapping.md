# Control ↔ Framework Mapping

**Kit compliance C9** · Status: **desk-checked, compliance-SME review pending**
(see `README.md`) · Source of control statements: `../blueprints/control-catalog.md`

Columns: HIPAA Security Rule (45 CFR; Privacy Rule cited explicitly where
used) · SOC 2 Trust Services Criteria (2017, 2022 revision; CC = common
criteria, A = availability, C = confidentiality) · HITRUST assessment domain
(public 19-domain taxonomy only — see the licensing disposition in
`README.md`) · Evidence: the lab phase-gate test(s) proving the control, plus
the portable probe family (`kit/acceptance/probes/`) where one exists.
"Analogue" marks a citation whose text addresses the classical control this
one replaces.

## IDN — Identity and token issuance

| Control | HIPAA | SOC 2 | HITRUST domain | Evidence |
|---|---|---|---|---|
| IDN-01 single hub issuer | §164.312(d) | CC6.1 | 11 Access Control | phase1 `test_signature_alg_and_issuer`, `test_upstream_issuer_never_leaks`; probes: `test_identity.py` |
| IDN-02 PS256/ES256 pinning | §164.312(c)(1), (e)(2)(i) | CC6.1, CC6.7 | 09 Transmission Protection | phase1 `test_signature_alg_and_issuer`; probes: `test_identity.py`, `test_claim_vectors.py` |
| IDN-03 token lifetimes ≤300/600 s | §164.312(a)(2)(iii) *(automatic logoff — analogue)* | CC6.1 | 11 Access Control | phase1 `test_lifetimes`; probes: `test_identity.py` |
| IDN-04 no PII in access tokens | §164.502(b) *(Privacy Rule minimum necessary)* | C1.1, CC6.7 | 19 Data Protection & Privacy | phase1 `test_no_pii_claims`; probes: `test_identity.py` |
| IDN-05 normalized group vocabulary | §164.308(a)(4) | CC6.3 | 11 Access Control | phase1 `test_groups_normalized`, `test_no_upstream_vocabulary_anywhere` |
| IDN-06 contract version pin | §164.312(c)(1) | CC6.1, CC8.1 | 06 Configuration Management | phase1 `test_mcp_contract_version`; probes: `test_identity.py`, `test_claim_vectors.py` |
| IDN-07 unique `jti`, stable non-email `sub` | §164.312(a)(2)(i) *(unique user identification)*, (b) | CC6.1, CC7.2 | 11 / 12 Audit Logging | phase1 `test_jti_present`, `test_sub_stable_non_email`; probes: `test_identity.py` |
| IDN-08 `amr` + MFA for clinical scopes | §164.312(d) *(2024/2025 NPRM proposes explicit MFA)* | CC6.1 | 11 Access Control | phase1 `test_amr_on_interactive_paths` |
| IDN-09 `act` delegation discipline | §164.312(a)(1), (b) | CC6.1, CC6.3 | 11 Access Control | phase1 `test_act_absent_without_delegation` |

## TIER — Audience discipline and tier isolation

| Control | HIPAA | SOC 2 | HITRUST domain | Evidence |
|---|---|---|---|---|
| TIER-01 exactly one tier aud + server URIs | §164.312(a)(1) | CC6.1 | 11 Access Control | phase1 `test_aud_second_level`, `test_tier_and_tier_audience`; probes: `test_tier.py`, `test_claim_vectors.py` |
| TIER-02 cross-tier replay fails | §164.312(a)(1), (e)(1) | CC6.6 | 08 Network Protection | phase2 + phase7 cross-tier replay tests; probes: `test_tier.py` |
| TIER-03 per-server audience rejection | §164.312(a)(1) | CC6.1 | 11 Access Control | phase3 tool suites; probes: `test_tier.py` |
| TIER-04 curated external catalog, no egress routes | §164.312(a)(1) | CC6.6 | 08 Network Protection | phase2 ACL tests; deck drift check (OPS-01) |

## SC — Sender constraint

| Control | HIPAA | SOC 2 | HITRUST domain | Evidence |
|---|---|---|---|---|
| SC-01 `cnf.x5t#S256` mTLS binding | §164.312(d), (e)(1) | CC6.1, CC6.7 | 09 / 11 | phase4 replay-without-cert / different-cert / matching-cert tests; probes: `test_sender_constraint.py` |
| SC-02 `cnf.jkt` DPoP binding | §164.312(d), (e)(1) | CC6.1, CC6.7 | 09 / 11 | phase7 `test_dpop_*` (11 probes); probes: `test_sender_constraint.py` |
| SC-03 claim-driven activation | §164.312(d) | CC6.1 | 11 Access Control | phase7 `test_bearer_client_unaffected`; probes: `test_sender_constraint.py` |
| SC-04 fail-closed replay cache; server re-validates | §164.312(d) | CC6.1, CC7.1 | 11 Access Control | phase7 `test_dpop_jti_replay_rejected`, `test_dpop_server_revalidates_without_gateway`; probes: `test_sender_constraint.py` |
| SC-05 secretless workload identity | §164.312(a)(2)(i), §164.308(a)(5)(ii)(D) *(analogue)* | CC6.1 | 10 / 11 | phase4 zero-secrets-manifest, no-cert-refusal, rotation-without-restart tests |

## AZ — Authorization at the tool layer

| Control | HIPAA | SOC 2 | HITRUST domain | Evidence |
|---|---|---|---|---|
| AZ-01 server-authoritative scope check | §164.312(a)(1), §164.308(a)(4) | CC6.1, CC6.3 | 11 Access Control | phase3 `test_hold_requires_step_up_scope`; phase7 `test_scope_string_alone_is_not_authorization`; probes: `test_authorization.py` |
| AZ-02 single-shot step-up 403 | §164.312(a)(1) | CC6.1 | 11 Access Control | phase3 under-scoped-challenge + step-up tests; probes: `test_authorization.py` |
| AZ-03 role-shaped tool visibility | §164.308(a)(4) | CC6.3 | 11 Access Control | phase3 tool-visibility tests |
| AZ-04 patient compartment hard filter | §164.312(a)(1); §164.502(b) *(minimum necessary)* | CC6.1, C1.1 | 11 / 19 | phase3 compartment tests; phase7 cross-patient-read / search-scope tests; probes: `test_authorization.py` |
| AZ-05 no wildcard scopes for ordinary clients | §164.308(a)(4) | CC6.1, CC6.3 | 11 Access Control | phase7 `test_wildcard_tool_scope_is_not_grantable`; probes: `test_authorization.py` |
| AZ-06 challenge semantics, no token echo | §164.312(a)(1) | CC6.1, CC6.7 | 11 Access Control | phase2 anonymous/garbage-token tests; probes: `test_authorization.py` |

## ST — Statelessness

| Control | HIPAA | SOC 2 | HITRUST domain | Evidence |
|---|---|---|---|---|
| ST-01 no protocol session; durable handles; any replica | §164.308(a)(7) *(contingency — analogue)* | A1.2 *(availability, when in scope)* | 16 Business Continuity | phase3 `test_hold_survives_replica_loss`; probes: `test_statelessness.py` |

## EG — Governed egress

| Control | HIPAA | SOC 2 | HITRUST domain | Evidence |
|---|---|---|---|---|
| EG-01 fail-closed egress DLP | §164.312(e)(1); §164.502(b) *(minimum necessary)* | CC6.7 | 19 / 09 | phase5 planted-MRN / SSN / clean-pass tests; probes: `test_egress.py` |
| EG-02 hub token never reaches vendor | §164.312(e)(1) | CC6.7 | 09 / 14 Third-Party Assurance | phase5 consent-dance test (token isolation asserted); probes: `test_egress.py` |
| EG-03 egress is not an open proxy | §164.312(e)(1) | CC6.6 | 08 Network Protection | deck drift check; route audit |
| EG-04 broker no-issuance rule | §164.312(d) | CC6.1 | 11 Access Control | phase7 no-issuance tests; probes: `test_egress.py` |
| EG-05 broker re-validation; sub-bound single-use consent | §164.312(d), (a)(1) | CC6.1 | 11 / 14 | phase7 resolve/sub-mismatch/consent tests; phase5 state-replay test; probes: `test_egress.py` |
| EG-06 single-flight refresh + generation CAS | §164.312(c)(1) | CC6.1, CC7.1 | 11 Access Control | phase5 twenty-parallel-resolves + generation tests |
| EG-07 vault loss fails closed | §164.312(a)(1) | CC6.1, CC7.1 | 11 Access Control | phase5 `test_vault_loss_fails_closed` |
| EG-08 RFC 9207 `iss` validation | §164.312(d) | CC6.1 | 11 Access Control | phase7 iss-tampering/omission tests; probes: `test_egress.py` |
| EG-09 registry scope ceilings; re-consent on escalation | §164.308(a)(4) | CC6.3 | 11 / 14 | phase7 `test_broker_never_requests_beyond_registry_ceiling` |
| EG-10 owner-controlled grant lifecycle; STALE paging | §164.308(a)(3)(ii)(C) *(termination — analogue)*, (a)(4) | CC6.2, CC6.3 | 11 / 14 | phase5 revoke/self-service tests; phase7 stale-storm tests |
| EG-11 CIMD URL-form client refusal | §164.312(d) | CC6.1 | 11 Access Control | phase7 CIMD test *(partial — tracked gap #3)* |

## AU — Audit spine

| Control | HIPAA | SOC 2 | HITRUST domain | Evidence |
|---|---|---|---|---|
| AU-01 jti-joinable tuple on every decision | §164.312(b); §164.308(a)(1)(ii)(D) | CC7.2 | 12 Audit Logging & Monitoring | phase6 walk-back / DLP-join / tuple tests; probes: `test_audit.py` |
| AU-02 outcome-accurate records | §164.312(b), (c)(1) | CC7.2 | 12 Audit Logging & Monitoring | phase3/6 tuple assertions |
| AU-03 no token material on the spine | §164.312(b); C-series confidentiality | CC6.7, C1.1 | 12 / 19 | phase6 + phase7 token-in-log greps; probes: `test_audit.py` |

## OPS — Operational posture

| Control | HIPAA | SOC 2 | HITRUST domain | Evidence |
|---|---|---|---|---|
| OPS-01 git-authoritative identity/gateway config | §164.316; §164.308(a)(8) | CC8.1 | 06 Configuration Management | phase2 `test_deck_state_matches_live_config` |
| OPS-02 PHI/tokens never on the SaaS management plane; DPs survive uplink loss | §164.312(e)(1); §164.308(b) *(business associate arrangements)* | CC6.7, A1.2 | 09 / 14 | phase2 `test_dp_keeps_proxying_with_cp_uplink_severed` |
| OPS-03 abuse ceilings on every route | §164.312(a)(1) | CC6.6 | 08 Network Protection | config review; deck drift check |

## Coverage notes (honesty ledger)

- The mapping row for a control marked *partial* in the control catalog
  (EG-11) inherits that qualifier — the evidence covers the implemented part
  only.
- SOC 2 availability (A-series) rows apply only when Availability is in the
  customer's report scope; the kit does not force that choice.
- No row claims administrative-safeguard coverage (§164.308 policies,
  training, sanctions) beyond the two analogues marked — those live in
  `shared-responsibility.md` on the customer side.
