# Rules of Engagement — Acceptance & Red-Team Probes

**Kit Workstream D15** · Template — complete and sign before running against any
environment you do not own.

The conformance probes are mostly read-only, but several are adversarial by
construction: they replay tokens across tiers, plant identifier-shaped samples
in outbound payloads, drive OAuth consent flows, force concurrent refreshes,
and sweep logs for secrets. Against a customer deployment that activity needs
the same written authorization as a penetration test. This document is that
authorization. Do not run adversarial probes (the lab's `tests/phase7`, or
any probe ported into this kit under the `redteam` marker — none ships today),
or point any probe at production, until it is completed and signed.

---

## 1. Authorization

- **Target deployment:** _______________________________ (name, environment)
- **In-scope hosts / URLs:** ______________________________________________
  (gateway tiers, MCP servers, broker, audit backend — exactly the descriptor)
- **Explicitly out of scope:** ____________________________________________
  (any host not listed above is out of scope by default)
- **Authorizing owner:** ______________________ (name, role, org)
- **Window:** from ______________ to ______________ (timezone: ______)
- **Change freeze / notification:** who is told before the run, and how.

Signed authorization from the deployment owner is required. A green checkmark
in a ticket is not a signature.

## 2. Test data — no real identifiers, ever

- The DLP probes plant **synthetic** samples from the descriptor's
  `egress.dlp_patterns[].sample`. These MUST be manufactured values
  (`MRN-1234567`, `000-12-3456`), never a real patient's identifier. Planting a
  real identifier to "make the test realistic" is itself a PHI disclosure —
  prohibited.
- Test identities MUST be dedicated test principals (test patients, service
  accounts), never real users' credentials. The `patient` identity must resolve
  to a synthetic patient record.
- The consent probes connect **test** vendor accounts. Do not authorize a
  probe run to attach a real user's SaaS account.

## 3. Blast radius

- **Consent / grant probes** create and revoke broker grants for the test
  identity. Confirm the run leaves no residual grant (the probes revoke, but
  verify).
- **Refresh-race probe** issues ~20 concurrent resolves; confirm the vendor
  (or its stand-in) tolerates the burst, or run it only against a mock vendor.
- **Rate-limit interaction:** the probes can trip abuse ceilings. Coordinate so
  the source is not blocked mid-run, and so the run is distinguishable from a
  real attack in the deployment's monitoring.
- **No destructive tools.** Probes call read/list tools and create/revoke their
  own grants only. They must not invoke booking-confirm, write, or delete tools
  against real records. If a deployment's only exercisable tool is destructive,
  exclude it and note the coverage gap.

## 4. Handling of findings

- Probe output (`report.xml`, logs) may contain token *identifiers* (jti, sub)
  but MUST NOT contain token *material* — AU-03 exists to guarantee this. If a
  run surfaces a token secret in any log, that is a P1 finding: stop, report to
  the owner, and treat the captured output as sensitive.
- A `fail` is a control that did not hold. Report fails to the owner through the
  agreed channel before wider distribution; some are exploitable.
- Store the descriptor, `report.xml`, and this signed RoE together as the
  engagement record.

## 5. Monitoring & abort

- **Point of contact during the run:** ____________________ (reachable live)
- **Abort trigger:** any unexpected production impact, any real-identifier
  exposure, any control failure with active-exploitation risk.
- **Abort action:** stop the run, preserve output, notify the contact.

## 6. Sign-off

| Role | Name | Signature | Date |
|---|---|---|---|
| Deployment owner (authorizes) | | | |
| Test lead (executes) | | | |
| Security reviewer (witnesses) | | | |

---

*Non-adversarial conformance runs (everything except the `redteam` marker,
against a non-production environment you own) do not require this form, but
Sections 2 and 3 still apply: synthetic data only, dedicated test identities,
and confirm no residual grants.*
