# Conformance Profile

**Kit Workstream D14** · Companion to `kit/blueprints/control-catalog.md`

What the acceptance framework proves, which probe proves which control, and —
crucially — what a green run does and does not let a deployment claim.

## What "conformant" means here

A deployment is **conformant to a control** when that control's probes pass
against it. Conformance is *per control*, not global: a deployment that runs
no egress has nothing to prove for EG-* and is neither conformant nor
non-conformant there — those probes **skip**, and the report says so. This is
deliberate. A single pass/fail number would hide exactly the coverage gaps a
customer needs to see.

Three probe outcomes, three meanings:

- **pass** — the control held against this deployment.
- **fail** — the control did **not** hold. This is the only outcome that
  blocks a conformance claim. The framework is built so a fail always means a
  control genuinely broke, never that an endpoint was unreachable or a section
  was undeclared (those skip).
- **skip** — not applicable or not exercisable here: the descriptor omits the
  section, the identity is undeclared/unavailable, or the deployment is
  unreachable. Every skip carries its reason in the report.

## Probe → control map

Each probe module is tagged with its control family (pytest markers in
`pytest.ini`). The mapping to `control-catalog.md` IDs:

| Probe module | Controls | Requires (descriptor) |
|---|---|---|
| `test_claim_vectors.py` | IDN-01/02/04/05/06/07, TIER-01, SC-01/02, AZ-04/05 (schema-expressible half) | nothing — runs offline |
| `test_identity.py` | IDN-01, IDN-02, IDN-03, IDN-04, IDN-05, IDN-07 | a workforce identity |
| `test_tier.py` | TIER-01, TIER-02, AZ-06 | `probe_endpoints.acl_resource`, both gateways |
| `test_sender_constraint.py` | SC-02, SC-03, SC-04 | `workforce_dpop` identity (scripted, dpop) + `scheduling_mcp` |
| `test_authorization.py` | AZ-01, AZ-04, TIER-02 | `workforce_nonclinical` and/or `patient` identity |
| `test_statelessness.py` | ST-01 | `scheduling_mcp` endpoint |
| `test_egress.py` | EG-01, EG-02, EG-04, EG-05 | `egress` section (+ `broker` for EG-04/05) |
| `test_audit.py` | AU-01, AU-03 | `audit` section with a reachable backend |

### Coverage notes and boundaries

- **The unit layer proves the schema; the component probes prove the
  deployment.** `test_claim_vectors.py` validates that the canonical-JWT schema
  encodes the contract (structural rules). Vectors labelled
  `schema_catches=false` (upstream-issuer, RS256, patient-missing-compartment,
  wildcard-scope-external) need a live issuer/validator and are covered by the
  component probes instead — the unit layer reports them as skips, not passes.
- **SC-01 (mTLS certificate binding)** is intentionally *not* a portable probe.
  It needs a client certificate and an mTLS listener that vary per deployment;
  the framework covers the DPoP half of sender-constraint (SC-02/03/04) and
  leaves mTLS to a deployment-specific extension. The reference lab proves
  SC-01 in `tests/phase4`.
- **SC-05 (secretless workload identity)**, **OPS-01/02 (declarative config,
  control-plane isolation)**, and **AU-02 (outcome-accurate audit)** are
  properties of the deployment topology and provisioning, not of a request the
  framework can send. They stay in the lab's phase-4/2/6 suites and in a
  deployment review, not here.
- **The red-team probes** (adversarial replay, scope-ceiling abuse, consent
  CSRF, `state` replay, token-in-log sweep) live in the lab's `tests/phase7`.
  Pointed at customer infrastructure they require written authorization —
  see `RULES-OF-ENGAGEMENT.md`. They are not run by `pytest` here without the
  `redteam` marker and an accepted RoE.

## Reporting a run

Run and capture a machine-readable report:

```
pip install -r requirements.txt
pytest --environment environments/<deployment>.yaml -ra \
       --junitxml=report.xml
```

- `-ra` prints the reason for every skip and fail — read it; a wall of skips
  means low coverage, which is a finding in itself.
- `report.xml` is the artifact to attach to a conformance record. Pair it with
  the descriptor used (it names exactly what was and wasn't exercised).

A defensible conformance statement reads: *"Controls IDN-\*, TIER-\*, SC-02/03/04,
AZ-01/04, ST-01, EG-01/02/04/05, AU-01/03 passed against `<deployment>` on
`<date>` at config commit `<sha>`; SC-01 and OPS-\* verified by deployment
review; EG/AU not exercised where the descriptor omits them."* Never *"the
deployment is conformant"* without the qualifier list.

## What a green run does NOT establish

Carried forward from the walkthrough's honesty framing — a full green here is
evidence, not certification. It does not establish MCP 2026-07-28 wire
conformance, RFC 9728 HTTPS-resource conformance, OAuth 2.1 production
certification, or a HIPAA determination. Those require the deltas in the
technical walkthrough to be closed and separately assessed.
