# Compliance Mapping (Workstream C)

**Evidence, not certification.** Nothing in this directory claims that a
deployment "is HIPAA compliant," "is SOC 2 compliant," or "is HITRUST
certified." What the kit provides is narrower and more useful: for each
control the platform enforces, a pointer to the executable test that produces
the evidence an assessor asks for. Compliance determinations belong to the
customer's compliance function and their assessors.

```
compliance/
  control-mapping.md        C9 — the control catalog mapped to HIPAA Security
                            Rule citations, SOC 2 TSC criteria, and HITRUST
                            assessment domains, with the proving test per row.
  shared-responsibility.md  C10 — what the platform enforces vs what the
                            customer must supply.
```

## Status and external dependencies (C11)

- **Compliance SME review: pending.** This mapping was produced by the
  engineering side of the house and desk-checked against the public texts of
  the cited frameworks. It MUST be reviewed by a qualified compliance SME
  before first customer use; treat every citation as a proposal until then.
- **HITRUST licensing: dispositioned.** The HITRUST CSF is licensed —
  redistribution and derivative works are prohibited without written
  permission (per the CSF license agreement, verified 2026-07-16). This kit
  therefore maps only to HITRUST's **publicly documented assessment domains**
  (the 19-domain taxonomy) and reproduces no CSF requirement text.
  Requirement-level mapping happens inside the customer's licensed MyCSF
  subscription during an engagement, where it is both permitted and
  assessor-visible.
- The HIPAA Security Rule citations target the rule as in force. The
  2024/2025 NPRM (proposed updates: mandatory MFA, encryption, asset
  inventories) is noted inline where a control anticipates it, and the
  mapping should be revisited when a final rule publishes.

## How to read the mapping

A row asserts: *this enforced control produces evidence relevant to this
citation*, nothing stronger. Several citations (e.g. §164.312(a)(2)(iii)
automatic logoff) are mapped as **closest analogue** and marked as such —
regulatory text written for interactive sessions does not always name
token-lifetime discipline, but assessors accept the evidence under the
analogous safeguard. Where the mapping leans on the Privacy Rule
(minimum-necessary, §164.502(b)) rather than the Security Rule, that is
stated explicitly.

Evidence pointers name the lab phase-gate tests (the reference
implementation's proof) and, where the control is portable, the
`kit/acceptance/` probe family a customer runs against their own deployment
(see `acceptance/conformance-profile.md` for the probe→control map). For a
customer engagement, the evidence column is satisfied by *their* acceptance
run, not the lab's.
