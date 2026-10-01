# Rollout Sequence

**Kit playbook E16** · Stages mirror the lab's proven phase order — identity
before tiers, tiers before tools, workload identity before egress, audit
before red team. Each stage names entry criteria, activities, owners, and
**exit criteria = acceptance probes against the customer deployment**
(`acceptance/` parameterized on their environment descriptor). Do not
advance on red.

Owner vocabulary (the walkthrough's stakeholder split): **IDN** = identity
team · **PLT** = platform/gateway team · **SEC** = security · **CMP** =
compliance. The customer names people against these at kickoff.

---

## Stage 0 — Foundations

- **Entry:** production-choices worksheet filled; shared-responsibility
  owners named; environments and network paths provisioned; BAAs in flight
  (CMP — they gate stage 5's real vendor, start now).
- **Activities:** stand up the hub AS (per `adapters/hub-requirements.md` and
  the chosen posture), the FHIR sandbox with synthetic data, the
  observability base; write the environment descriptor
  (`acceptance/environments/TEMPLATE.yaml`).
- **Owners:** PLT leads; IDN for the hub; CMP observing.
- **Exit:** descriptor validates against `environment.schema.json`; the hub
  mints a token that passes the offline claim vectors
  (`probes/test_claim_vectors.py`); synthetic FHIR reads work.

## Stage 1 — Identity hub

- **Entry:** stage 0 green; upstream IdP admin access; claim/group mapping
  table drafted from the relevant `adapters/idp-*.md` guide.
- **Activities:** broker the workforce IdP (and customer IdP if in scope)
  behind the hub; claim normalization to the contract vocabulary; token
  exchange for any legacy issuer; MFA policy at the IdP (customer-side,
  verify it surfaces in `amr`).
- **Owners:** IDN leads; SEC reviews the mapping table; CMP records the MFA
  compensating control if `amr` fidelity is limited (see the Entra guide).
- **Exit:** **IDN probe family green** (`test_identity.py` + vectors) for
  every in-scope login path.

## Stage 2 — Gateway tiers

- **Entry:** stage 1 green; gateway platform chosen via
  `adapters/gateway-capability-matrix.md` (red flags dispositioned in
  writing); ingress paths (private/public) exist.
- **Activities:** two tier deployments per `blueprints/gateway-policy.md`
  §0/P1 (tier walls, both auth schemes), P4 header injection, P8 verified
  routes, rate ceilings; config lands in git from day one (OPS-01).
- **Owners:** PLT leads; SEC signs the tier catalog (what the external tier
  exposes is a security decision).
- **Exit:** **TIER probe family green** (`test_tier.py`), including
  cross-tier replay rejection and the anonymous/garbage-token challenges.

## Stage 3 — First-party MCP servers

- **Entry:** stage 2 green; tool inventory agreed (which servers, which
  tools, which scopes, which roles see them).
- **Activities:** deploy first-party servers meeting the blueprint's
  validation requirements (contract §7: own-audience, alg pin, contract pin,
  scope-per-tool, compartment both directions); PRM documents; connect the
  pilot client population through the internal tier.
- **Owners:** PLT + the app teams owning each server; IDN for scope/role
  policy; SEC reviews the step-up scope list.
- **Exit:** **AZ and ST probe families green** (`test_authorization.py`,
  `test_statelessness.py`): role-shaped visibility, step-up 403, compartment
  filtering, replica-loss survival.

## Stage 4 — Workload identity

- **Entry:** stage 3 green; workload-identity plane chosen (worksheet:
  SPIFFE/SPIRE, Athenz, or platform-native) and its CA trusted by the hub.
- **Activities:** attested short-lived certs to the pilot agent workload;
  `tls_client_auth` + cert-bound tokens at the hub; cnf enforcement at the
  gateway (P2); rotation without restart.
- **Owners:** PLT leads; SEC owns the trust-root ceremony.
- **Exit:** **SC-01/05 evidence and SC-03 green**: bound-token replay
  without/with the wrong cert refused and zero secrets in workload manifests
  (SC-01/05 are not portable probes — evidence comes from the lab's
  `tests/phase4` suite or a deployment review, see
  `acceptance/conformance-profile.md`); plain-bearer clients unaffected
  (`test_sender_constraint.py::test_plain_bearer_identity_unaffected`). (SC-02/04 DPoP lands with its client population —
  stage 3 if in pilot scope, else deferred and recorded.)

## Stage 5 — Governed egress + broker

- **Entry:** stage 4 green; vendor(s) selected; **BAAs/DPAs executed**
  (CMP gate — a real vendor leg without them is a compliance incident, not a
  milestone); vendor app registrations owned by the customer org.
- **Activities:** deploy the broker per `blueprints/broker.md` (custody
  backend from the worksheet, replica profile decided); egress routes with
  the P5 ordered chain (verify → DLP → swap); DLP pattern set extended from
  the shipped exemplars to the customer's data classes (SEC owns the
  pattern catalog); consent flows to the real vendor.
- **Owners:** PLT + SEC jointly; CMP for vendor risk.
- **Exit:** **EG probe family green** (`test_egress.py`) — DLP block +
  clean-pass audit, no-issuance, consent binding, ceiling enforcement — plus
  the lab-proven concurrency drills (single-flight, revocation) replayed
  against the customer broker.

## Stage 6 — Audit spine

- **Entry:** stage 5 green; the customer's SIEM (their responsibility —
  immutable, retention-managed) reachable from the collector.
- **Activities:** wire every emitter (gateway plugins, servers, broker) to
  the customer SIEM; provision the tuple dashboard or its SIEM-native
  equivalent; verify retention policy is applied.
- **Owners:** PLT wires it; SEC owns queries/alerts; CMP verifies retention.
- **Exit:** **AU probe family green** (`test_audit.py`): one query walks a
  vendor call and a DLP block end to end by `jti`; token-material grep is
  clean. Evidence exports attach to `compliance/control-mapping.md` rows.

## Stage 7 — Red team

- **Entry:** stages 0–6 green; **signed rules of engagement**
  (`acceptance/RULES-OF-ENGAGEMENT.md`): authorization scope, safe test
  identities, data-handling rules; comms channel for kill-switch.
- **Activities:** the full adversarial suite against the customer
  deployment — replay, scope-ceiling, consent-state, iss-tampering, STALE
  storm, DPoP probe pack where in scope, token-in-log sweep.
- **Owners:** SEC leads; PLT on standby; CMP receives the findings register.
- **Exit:** full acceptance suite green or every finding dispositioned as an
  accepted, documented risk with an owner. Findings become tracked issues in
  the customer's system — the honesty-ledger convention transfers with the
  kit.

---

## After stage 7

Hand CMP the filled evidence matrix: `compliance/control-mapping.md` with
each row's evidence pointer replaced by the customer's own acceptance-run
artifacts, plus the shared-responsibility matrix with owners. That package —
not a certificate — is what the kit promises.
