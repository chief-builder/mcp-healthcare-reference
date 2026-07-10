# Phase 7 — red-team weekend (plan §3)

Adversarial probes against the running phase-5 stack + phase-6 audit spine.
The arch-doc §13 acceptance list plus the named probes: cross-tier replay,
scope-ceiling, broker `state` replay, RFC 9207 `iss` tampering/omission,
STALE-storm, token-in-log grep, and the CIMD external-tier experiment.

Run against the same target as `tests/phase6.sh` (phase-5 stack up):

```sh
../../tests/phase7.sh
```

A passing test means the defense held. Two probes are `xfail(strict)` —
they assert the behavior the design requires but the lab does not yet meet,
each tied to a filed issue. If one flips to XPASS, the gap was fixed and the
marker should be removed.

## Probe → property map

| Probe | Test(s) | Property |
|---|---|---|
| Cross-tier replay | `test_internal_token_replayed_at_external_dp` | tier audience wall (arch §13) |
| Scope-ceiling | `test_wildcard_tool_scope_is_not_grantable`, `test_scope_string_alone_is_not_authorization`, `test_broker_never_requests_beyond_registry_ceiling` | scope grammar / registry ceiling / defense in depth |
| Broker `state` replay | `test_state_replay_is_a_security_event` | consent CSRF/binding (design §4.3) |
| RFC 9207 `iss` tamper | `test_iss_tampering_is_rejected_and_alerts` | mix-up defense (holds) |
| RFC 9207 `iss` omission | `test_iss_omission_...` **(xfail — issue #1)** | mix-up defense (gap) |
| STALE-storm | `test_stale_storm_marks_each_entry_and_audits` | per-entry STALE + audit (holds) |
| STALE-storm mass signal | `test_stale_storm_raises_mass_stale_signal` **(xfail — issue #2)** | anomaly paging (gap) |
| Token-in-log grep | `test_no_token_material_in_any_log` | no secrets on logs/spine |
| CIMD non-allowlisted | `test_cimd_url_form_client_id_is_refused` | refused (control absent — issue #3) |
| Broker no-issuance | `test_broker_exposes_no_issuance_endpoint[*]`, `test_broker_resolve_requires_valid_hub_token` | custodian-not-issuer (design §11) |

## Findings (filed as issues)

- **#1** (High) — broker RFC 9207 mix-up defense is bypassed when the callback
  omits `iss`; the guard only validates a *present* `iss`.
- **#2** (Medium) — no mass-STALE / page signal on org-app uninstall; only
  per-entry `broker.stale` is emitted.
- **#3** (Low, tracked gap) — external-tier CIMD origin-allowlist control is not
  implemented; URL-form `client_id`s are refused only as unknown clients.

## Notes

- `test_internal_token_admitted_at_internal_dp` asserts the token is *admitted*
  by the wall (not 401/403); the FHIR upstream (HAPI) may be OOM-down in a tight
  Docker VM (`Exited 137`), which surfaces as 5xx after the wall — see
  `compose/phase5/README.md` for recovery. It does not affect the security
  assertions, which resolve at the DP before any upstream.
- Probes that need a clean consent state revoke the sub's grant first
  (`new_consent_state`), so the suite is re-runnable against a persistent broker
  vault.
