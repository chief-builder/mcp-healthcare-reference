# Control Catalog

**Kit blueprint A1** · Status: extracted from the Phase-7 lab (all gates green)

Every control the platform enforces, with a stable ID. This catalog is the
spine of the kit: the token contract, gateway policy, and broker blueprints
state *how* these controls work; the compliance mapping (Workstream C) maps
them to frameworks; the acceptance framework (Workstream D) proves them
against a deployment.

Rules for IDs:

- IDs are stable forever. A control that is retired keeps its ID with status
  `retired`; IDs are never reused.
- "Enforced by" cites the reference implementation (this repo). A customer
  deployment may enforce a control differently; the acceptance probe, not the
  file path, is the conformance test.
- "Proven by" names the lab test(s). Tests marked **(portable)** assert the
  control's externally observable behavior and are candidates for the
  Workstream-D acceptance framework; unmarked tests are lab-harness-coupled.

## IDN — Identity and token issuance

| ID | Control (normative statement) | Enforced by | Proven by |
|---|---|---|---|
| IDN-01 | All tokens presented to the plane MUST be minted by the single hub issuer. Upstream IdP tokens MUST never be accepted by any gateway, server, or broker. | `realm/mcp-plane.json` (brokering, token exchange); `servers/shared/src/token-verifier.ts` and `broker/app/hub.py` (exact `iss` check) | phase1 `test_signature_alg_and_issuer`, `test_upstream_issuer_never_leaks` **(portable)** |
| IDN-02 | Signing algorithms MUST be pinned to PS256/ES256; RS256 and all HMAC MUST be rejected. | server + broker verifiers | phase1 `test_signature_alg_and_issuer` **(portable)** |
| IDN-03 | Access-token lifetime MUST NOT exceed 300 s (m2m) / 600 s (interactive). | realm token policy | phase1 `test_lifetimes` **(portable)** |
| IDN-04 | Access tokens MUST NOT carry directory PII (email, name, etc.). | realm protocol mappers | phase1 `test_no_pii_claims` **(portable)** |
| IDN-05 | Upstream group vocabularies MUST be normalized to the contract's `mcp-*` names; no consumer may match on raw upstream strings. | realm mappers; consumers by convention | phase1 `test_groups_normalized`, `test_no_upstream_vocabulary_anywhere` |
| IDN-06 | Every token MUST carry the contract version pin (`mcp_contract`); validators MUST reject other versions. | realm mappers; server/broker checks | phase1 `test_mcp_contract_version` **(portable)** |
| IDN-07 | Every token MUST carry a unique opaque `jti`; `sub` MUST be a stable non-email identifier. | realm; verifiers | phase1 `test_jti_present`, `test_sub_stable_non_email` **(portable)** |
| IDN-08 | Interactive tokens MUST carry `amr`; clinical scopes MUST require the `mfa` mark. | realm mappers (`amr`); fhir-clinical tool policy — scopes in `MCP_MFA_SCOPES` (default `mcp:fhir-clinical:everything:read`) require `amr` ∋ `mfa`, else `401 insufficient_user_authentication` (RFC 9470); `servers/shared/src/tool-policy.ts` | phase1 `test_amr_on_interactive_paths`; phase3 `test_clinical_step_up_token_carries_the_mfa_mark`; offline `servers/fhir-clinical/test/server.test.ts` (no-`mfa` rejection) |
| IDN-09 | `act` MUST appear only on delegated (on-behalf-of) tokens; delegated scopes MUST be the intersection of both parties' ceilings. | realm exchange policy | phase1 `test_act_absent_without_delegation` |

## TIER — Audience discipline and tier isolation

| ID | Control | Enforced by | Proven by |
|---|---|---|---|
| TIER-01 | Every token's `aud` MUST contain exactly one tier audience plus one or more server resource URIs. | realm client policy; server/broker validation | phase1 `test_aud_second_level`, `test_tier_and_tier_audience` **(portable)** |
| TIER-02 | A gateway tier MUST reject any token whose tier audience is not its own — cross-tier replay fails cryptographically, before routing. | tier-wall pre-function in `deck/internal.yaml` / `deck/external.yaml` | phase2 `test_gate_internal_token_replayed_at_external_dp`, `test_customer_token_replayed_at_internal_dp`; phase7 `test_internal_token_replayed_at_external_dp` **(portable)** |
| TIER-03 | Each MCP server MUST reject tokens whose `aud` lacks its own resource URI (a token for server A is useless at server B). | `servers/shared/src/token-verifier.ts` | phase3 tool suites (audience checks exercised on every call) **(portable)** |
| TIER-04 | The external tier MUST expose only the curated catalog; egress routes MUST NOT exist on the external tier. | `deck/external.yaml` route set | phase2 ACL tests; deck drift check (OPS-01) |

## SC — Sender constraint (proof of possession)

| ID | Control | Enforced by | Proven by |
|---|---|---|---|
| SC-01 | A token carrying `cnf.x5t#S256` MUST only be accepted over mTLS with the matching client certificate; absence of a certificate is a hard failure and an alert. | `plugins/cnf-check/handler.lua` at the internal DP | phase4 `test_token_replayed_without_client_cert_is_401_and_audited`, `test_token_replayed_with_different_cert_is_401_and_audited`, `test_matching_cert_succeeds_end_to_end` **(portable)** |
| SC-02 | A token carrying `cnf.jkt` MUST only be accepted with a valid DPoP proof (RFC 9449): thumbprint match, `htm`/`htu`/`iat`/`ath` valid, single-use proof `jti`. Presenting it as plain `Bearer` MUST fail. | `plugins/dpop-check/handler.lua` (gateway-first) + `servers/shared/src/dpop.ts` (authoritative re-check incl. signature) | phase7 `test_dpop_*` suite (11 probes) **(portable)** |
| SC-03 | Sender-constraint checks MUST be claim-driven: plain bearer tokens without `cnf` pass unaffected. | both plugins | phase7 `test_bearer_client_unaffected` **(portable)** |
| SC-04 | The DPoP replay cache MUST fail closed (reject when the cache is unavailable), and the resource server MUST re-validate independently of the gateway. | dpop-check 503 path; `requireDpop` in servers | phase7 `test_dpop_jti_replay_rejected`, `test_dpop_server_revalidates_without_gateway` **(portable)** |
| SC-05 | Workload identity MUST be secretless: short-lived attested certificates (SPIFFE SVID), no client secrets in manifests, rotation without restart. | `compose/phase4/k8s/*.yaml`; `agents/loop-agent/agent.py` | phase4 `test_agent_manifest_contains_zero_secrets`, `test_keycloak_refuses_client_without_certificate`, `test_cert_rotation_happens_without_pod_restart` |

## AZ — Authorization at the tool layer

| ID | Control | Enforced by | Proven by |
|---|---|---|---|
| AZ-01 | The MCP server is the authoritative scope check: every `tools/call` MUST be authorized by a scope naming that server, tool, and verb. The gateway is early rejection only. | server tool policy (`servers/shared/src/tool-policy.ts`): HTTP-layer challenge plus a re-check inside every tool handler; JSON-RPC batches refused (`-32600`) so no call bypasses it | phase3 `test_hold_requires_step_up_scope`, `test_batch_cannot_smuggle_a_tool_call_past_step_up`; phase7 `test_scope_string_alone_is_not_authorization` **(portable)** |
| AZ-02 | Under-scoped calls MUST receive a single-shot `403 insufficient_scope` naming the complete required set (step-up, never incremental). | server tool policy | phase3 `test_under_scoped_call_triggers_insufficient_scope_challenge`, `test_step_up_token_is_accepted` **(portable)** |
| AZ-03 | Tool visibility MUST be shaped by normalized groups: a caller lists only the tools their role permits. | server tool listing | phase3 `test_clinician_lists_clinical_tools`, `test_non_clinical_role_does_not_see_clinical_only_tool` |
| AZ-04 | When `fhir_patient` is present, every FHIR interaction MUST be hard-filtered to that compartment (by-ID equality, forced search parameters). Tokens on the customer path MUST carry it; tokens on other paths MUST NOT. | `servers/fhir-clinical/src/authz-hook.ts`; both directions in `servers/shared/src/token-verifier.ts` | phase1 `test_fhir_patient_compartment`; phase3 `test_cross_patient_read_is_blocked`, `test_search_is_hard_scoped_to_the_token_patient` **(portable)** |
| AZ-05 | Wildcard tool scopes MUST NOT be grantable to ordinary clients; scope ceilings are client policy at the issuer. | realm client policy | phase7 `test_wildcard_tool_scope_is_not_grantable` **(portable)** |
| AZ-06 | Requests without a token MUST receive an RFC 6750 challenge with resource metadata; garbage tokens MUST be 401 without echoing token contents. | servers (PRM + challenges); gateway | phase2 `test_anonymous_is_401_with_challenge`, `test_garbage_token_is_401` **(portable)** |

## ST — Statelessness

| ID | Control | Enforced by | Proven by |
|---|---|---|---|
| ST-01 | MCP servers MUST hold no protocol session; identity and capability ride every request; continuity uses explicit durable handles (e.g. `slot_hold_id` in Postgres), so any request can hit any replica. | MCP 2026-07-28 per-request serving (`createMcpHandler`, fresh server per POST, no `initialize`); `servers/scheduling/` DB-backed holds | phase3 `test_hold_survives_replica_loss`, `test_server_negotiates_2026_07_28_through_the_gateway` **(portable)** |

## EG — Governed egress

| ID | Control | Enforced by | Proven by |
|---|---|---|---|
| EG-01 | Vendor-bound request bodies MUST be DLP-screened before leaving the boundary; a match blocks the call; an unscannable body fails closed; audit records carry the pattern name, never the matched value. | `plugins/dlp-egress/handler.lua` (raw body and every JSON-decoded string; undecodable declared-JSON fails closed) | phase5 `test_planted_mrn_is_blocked_and_audited`, `test_json_escaped_mrn_is_blocked`, `test_ssn_pattern_also_blocked`, `test_clean_payload_passes` **(portable)**; offline `plugins/tests/test_gateway.py` |
| EG-02 | The hub token MUST never reach a vendor: the gateway replaces it with the user's brokered vendor credential after DLP passes. | `plugins/vendor-token/handler.lua` | phase5 `test_first_call_consent_dance_then_tool_works` (token isolation asserted) **(portable)** |
| EG-03 | Egress MUST NOT be an open proxy: only registered vendor hosts are routable (the route's upstream is the allowlist). | `deck/internal.yaml` egress services | deck drift check (OPS-01); route audit |
| EG-04 | The broker MUST NOT mint, sign, or transform tokens — no signing keys, no JWKS, no token endpoint (no-issuance rule). | `broker/` (by construction) | phase5 `test_no_issuance_rule_route_audit`; phase7 `test_broker_exposes_no_issuance_endpoint` **(portable)** |
| EG-05 | The broker MUST independently re-validate the hub JWT (never trust the gateway) and MUST bind consent transactions to the initiating subject with single-use, unexpired `state`. | `broker/app/hub.py`; consent state machine in `broker/app/main.py` | phase5 `test_sub_mismatch_is_rejected`, `test_consent_transaction_is_sub_bound`, `test_state_replay_is_a_security_event`; phase7 `test_broker_resolve_requires_valid_hub_token` **(portable)** |
| EG-06 | Concurrent resolves on an expiring grant MUST produce exactly one vendor refresh (single-flight), with a monotonic generation CAS preventing stale writes. | broker lock + `broker/app/vault_store.py` CAS | phase5 `test_twenty_parallel_resolves_one_vendor_refresh`, `test_generation_advances_on_next_refresh` **(portable)** |
| EG-07 | Vault unavailability MUST fail closed: resolve returns 503, no grace beyond the short in-memory cache. | broker vault adapter | phase5 `test_vault_loss_fails_closed` **(portable)** |
| EG-08 | OAuth client legs MUST validate RFC 9207 `iss` (including error responses, strict string compare); when the vendor advertises `iss`, its omission MUST also reject. | broker callback validation | phase5 `test_iss_tampering_never_redeems_the_code`; phase7 `test_iss_tampering_is_rejected_and_alerts`, `test_iss_omission_is_rejected_when_vendor_advertises_iss` **(portable)** |
| EG-09 | Requested vendor scopes MUST be capped at the registry ceiling; grants narrower than a tool's requirement MUST trigger re-consent (409), never silent escalation. | broker resolve; `broker/registry.json` | phase7 `test_broker_never_requests_beyond_registry_ceiling` **(portable)** |
| EG-10 | Grant lifecycle MUST be owner-controlled: revocation at the vendor precedes vault deletion; vendor-side revocation surfaces as STALE → re-consent; a mass-STALE burst pages. Grants are self-service (subject match) or admin only. | broker grants API + sweeper | phase5 `test_delete_grant_revokes_at_vendor`, `test_vendor_side_revocation_goes_stale_then_reconsent`, `test_grants_are_self_service_only`; phase7 `test_stale_storm_*` **(portable)** |
| EG-11 | External-tier clients supplying URL-form (CIMD) client IDs MUST be refused; clients are pre-registered. | realm client policy | phase7 `test_cimd_url_form_client_id_is_refused` (partial — full external-tier CIMD control is tracked gap #3) |

## AU — Audit spine

| ID | Control | Enforced by | Proven by |
|---|---|---|---|
| AU-01 | Every gateway verdict, broker decision, and tool outcome — including denials — MUST emit one audit record carrying the contract §9 tuple, keyed by the token's `jti`, such that one query walks an action end to end. | `servers/shared/src/audit.ts`; plugin `kong.log` records; `broker/app/audit.py`; Alloy/OTel → Loki | phase6 `test_vendor_call_walks_back_in_one_query`, `test_dlp_block_joins_on_the_same_jti`, `test_first_party_tool_call_carries_the_tuple` **(portable)** |
| AU-02 | Audit records MUST be outcome-accurate: `allow` only after the backend action succeeded. | server audit emit points | phase3/phase6 tuple assertions |
| AU-03 | Token material MUST never appear in logs, traces, errors, or audit records. | all emitters by construction | phase6 `test_no_token_material_on_the_spine`; phase7 `test_no_token_material_in_any_log` **(portable)** |

## OPS — Operational posture

| ID | Control | Enforced by | Proven by |
|---|---|---|---|
| OPS-01 | Identity and gateway configuration MUST be declarative and git-authoritative; live state MUST match the committed state. | `realm/*.json`, `deck/*.yaml`, setup scripts | phase2 `test_deck_state_matches_live_config` |
| OPS-02 | PHI, tokens, and audit records MUST never reach the SaaS management plane; data planes MUST keep serving when the control-plane uplink is severed. | Konnect hybrid topology; local DP caches | phase2 `test_dp_keeps_proxying_with_cp_uplink_severed` |
| OPS-03 | Every route MUST carry an abuse ceiling (rate limit), tighter on the external tier. | `deck/*.yaml` rate-limiting plugins | config review; deck drift check |

## Known gaps carried forward (not controls — honesty ledger)

- #3 external-tier CIMD control (EG-11 is partial)
- `mcp://` opaque resource URIs vs RFC 9728 HTTPS identifiers — a documented interop deviation (issue #13, closed as documented); the TIER-01/03 property is preserved
- `claude-code` client remains bearer until the real client ships DPoP proofs (SC-02 proven via `workforce-dpop`)
