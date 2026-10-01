# Phase 7 — red-team weekend (plan §3)

Adversarial probes against the running phase-5 stack + phase-6 audit spine.
The arch-doc §13 acceptance list plus the named probes: cross-tier replay,
scope-ceiling, broker `state` replay, RFC 9207 `iss` tampering/omission,
STALE-storm, token-in-log grep, the CIMD external-tier experiment, and the
P8 DPoP sender-constraint section (RFC 9449) on the `workforce-dpop` client.
32 probes, 0 xfail — green in the 2026-10-01 full run.

Run against the same target as `tests/phase6.sh` (phase-5 stack up):

```sh
../../tests/phase7.sh
```

A passing test means the defense held. Every probe is a plain assert: the
two that originally shipped as `xfail(strict)` (iss omission — issue #1;
mass-STALE signal — issue #2) were remediated, their markers removed, and
both issues closed.

## Probe → property map

| Probe | Test(s) | Property |
|---|---|---|
| Cross-tier replay | `test_internal_token_replayed_at_external_dp` | tier audience wall (arch §13) |
| Scope-ceiling | `test_wildcard_tool_scope_is_not_grantable`, `test_scope_string_alone_is_not_authorization`, `test_broker_never_requests_beyond_registry_ceiling` | scope grammar / registry ceiling / defense in depth |
| Broker `state` replay | `test_state_replay_is_a_security_event` | consent CSRF/binding (design §4.3) |
| RFC 9207 `iss` tamper | `test_iss_tampering_is_rejected_and_alerts` | mix-up defense (holds) |
| RFC 9207 `iss` omission | `test_iss_omission_...` | mix-up defense (fixed — issue #1, closed) |
| STALE-storm | `test_stale_storm_marks_each_entry_and_audits` | per-entry STALE + audit (holds) |
| STALE-storm mass signal | `test_stale_storm_raises_mass_stale_signal` | anomaly paging (fixed — issue #2, closed) |
| Token-in-log grep | `test_no_token_material_in_any_log` | no secrets on logs/spine |
| CIMD non-allowlisted | `test_cimd_url_form_client_id_is_refused` | refused (control absent — issue #3) |
| Broker no-issuance | `test_broker_exposes_no_issuance_endpoint[*]`, `test_broker_resolve_requires_valid_hub_token` | custodian-not-issuer (design §11) |
| **P8** DPoP token binding | `test_dpop_token_carries_cnf_jkt`, `test_dpop_valid_proof_admitted` | `cnf.jkt` issued + valid proof admitted (controls) |
| P8 stolen-token replay | `test_dpop_token_replayed_as_plain_bearer_rejected`, `test_dpop_missing_proof_rejected` | bearer replay of a bound token refused (RFC 9449) |
| P8 proof tampering | `test_dpop_wrong_htu_rejected`, `test_dpop_wrong_htm_rejected`, `test_dpop_stale_iat_rejected`, `test_dpop_wrong_ath_rejected`, `test_dpop_thumbprint_mismatch_rejected` | htu/htm/iat/ath/jkt binding enforced |
| P8 proof replay | `test_dpop_jti_replay_rejected` | single-use `jti` (DP shared dict) |
| P8 layered defense | `test_dpop_server_revalidates_without_gateway` | server `requireDpop` holds with the DP bypassed |
| P8 bearer unaffected | `test_bearer_client_unaffected` | claude-code bearer path untouched |

## Findings (filed as issues)

- **#1** (High, **closed**) — broker RFC 9207 mix-up defense was bypassed when
  the callback omitted `iss`; the guard now rejects omission when the vendor
  advertised `authorization_response_iss_parameter_supported`.
- **#2** (Medium, **closed**) — mass-STALE / page signal on org-app uninstall
  now emitted when ≥3 STALEs for one vendor land within a minute.
- **#3** (Low, open tracked gap) — external-tier CIMD origin-allowlist control
  is not implemented; URL-form `client_id`s are refused only as unknown clients.

## Notes

- `test_internal_token_admitted_at_internal_dp` asserts the token is *admitted*
  by the wall (not 401/403); the FHIR upstream (HAPI) may be OOM-down in a tight
  Docker VM (`Exited 137`), which surfaces as 5xx after the wall — see
  `compose/phase5/README.md` for recovery. It does not affect the security
  assertions, which resolve at the DP before any upstream.
- Probes that need a clean consent state revoke the sub's grant first
  (`new_consent_state`), so the suite is re-runnable against a persistent broker
  vault.
