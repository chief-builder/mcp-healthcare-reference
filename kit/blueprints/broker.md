# Vendor Token Broker — Portability Profile

**Kit blueprint A4** · The normative design is `docs/vendor-token-broker-design.md`
(v1.0-draft) — this document does not restate it. It adds the three things a
customer deployment needs beyond the design: a custody-backend abstraction, a
multi-replica deployment profile, and the vendor registry as a normative
schema. Controls: EG-04..10.

## 1. What is fixed vs. pluggable

Fixed (from the design doc, non-negotiable anywhere the broker runs):

- **No issuance** (design §1, EG-04): the broker is an OAuth client and
  custodian; it never mints, signs, or transforms tokens. No signing keys, no
  JWKS, no token endpoint. Verified by route/dependency audit in CI.
- Independent hub-JWT re-validation on every call (§3, EG-05).
- PKCE S256, single-use sub-bound `state`, RFC 9207 `iss` validation
  including the omission case (§2/§4, EG-05/08).
- Single-flight refresh with generation CAS (§9, EG-06).
- Fail-closed custody: backend unavailable → 503, no grace beyond the short
  in-memory cache (§10, EG-07).
- Scope ceilings at authorize time; 409 re-consent, never silent escalation
  (§4.1, EG-09).
- Revoke-at-vendor before delete; STALE lifecycle with mass-STALE paging
  (§4.4/§8/§10, EG-10).
- No token material in logs, errors, or traces (§11, AU-03).

Pluggable: the custody backend (§2), the lock implementation (§3), the vendor
set (§4), and the runtime stack (design §14 — the lab's FastAPI/Python is one
choice, not a requirement).

## 2. Custody backend interface

The lab binds to OpenBao KV v2 (`broker/app/vault_store.py`). Any backend
satisfying this contract can substitute (HashiCorp Vault KV v2 is drop-in;
cloud secret managers need the CAS shim noted below):

```
read(vendor, sub)          -> {entry, version} | None
write(vendor, sub, entry, expected_version)   # MUST fail if the stored
                                              # version != expected (CAS)
delete(vendor, sub)                           # including all versions/metadata
list_subjects(vendor)      -> [sub]           # for sweeper + mass-STALE
read_client(vendor)        -> {client_id, credential}   # separate mount/path,
                                              # separate (tighter) read policy
```

Required properties, in order of how often substitutes get them wrong:

1. **Versioned compare-and-swap.** The refresh race defense (EG-06) rests on
   it. KV-v2 `cas` maps directly. AWS Secrets Manager / GCP Secret Manager
   have no native CAS — a substitute MUST add an external version guard
   (e.g. a conditional-write row in DynamoDB/Firestore holding
   `refresh_generation`) and treat guard failure exactly as a CAS failure:
   discard the local result, re-read, never write the older pair.
2. **Fail closed, distinguishably.** Backend errors surface as
   "custody unavailable" (→ 503), never as "entry absent" (→ consent flow).
   Conflating them turns an outage into a mass re-consent stampede.
3. **Two mounts, two policies.** Grant entries (`vendor-tokens/*`:
   broker read/write) and vendor client credentials (`vendor-clients/*`:
   broker read-only, admin write-only). No human read path to token material;
   every read audited.
4. **Encryption at rest under a dedicated key** (envelope/KMS per design §5).

## 3. Deployment profiles

### Single replica (the lab profile)

In-process `asyncio` lock scoped per `{vendor, sub}`; `REFRESHING` never
persisted; fixed-interval sweeper. Correct **only** while replicas = 1 —
this is a documented delta (design §16), not an oversight to copy.

### Multi-replica (the production profile)

Anything beyond one replica changes four things, all mandatory together:

1. **Distributed single-flight lock** per `{vendor, sub}`: short TTL bounded
   by the vendor round-trip (a few seconds), hard timeout, holder-death →
   waiters retry with a fresh read. Any fencing-capable store works (Redis
   SET NX PX, Postgres advisory locks, DynamoDB conditional writes). The CAS
   (§2) remains the backstop — the lock is an optimization to avoid burning
   rotating refresh-token families; the CAS is the correctness guarantee.
2. **Persisted `REFRESHING` state** (design §5/§8) so other replicas can
   distinguish in-flight from stale.
3. **Jittered sweeper** with a leader lease (or per-entry lock reuse) so N
   replicas don't proactively refresh the same expiring entries.
4. **Cache honesty**: the ≤ 60 s in-memory token cache is per-replica;
   after a revocation the worst-case serve-stale window is the cache TTL.
   If that window is unacceptable, broadcast invalidation or drop the cache.

Consent transactions and `state` records may stay replica-local **only**
behind session-affinity ingress; otherwise move them to a shared store with
the same TTL/single-use semantics.

### Sizing

Design §13 holds at enterprise scale: the hot path is cache-served resolves;
vendor traffic is ~tens of refreshes per user per day. One modest replica
pair is HA, not throughput, engineering.

## 4. Vendor registry (normative artifact)

Schema: `schemas/vendor-registry.schema.json` (extracted from
`broker/registry.json` + design §4.5). The registry is the vendor allowlist
and per-vendor policy: endpoints or RFC 8414 metadata URL, client auth
method, **scope ceiling**, refresh-rotation flag, revocation strategy, EMA
sunset status.

Rules that travel with it:

- Registry changes are reviewed changes with the same sign-off as a token
  contract change (the ceiling is a security boundary, EG-09). Git-reviewed
  mutation (the lab's mode) is acceptable and often stronger than an admin
  API.
- Endpoints are hardcoded **only** where the vendor publishes no RFC 8414
  metadata (e.g. GitHub); where metadata exists, hardcoding is forbidden.
- `client_id` and credentials never live in the registry — they live in the
  custody backend's `vendor-clients` mount (§2.3).
- `ema_status` is the sunset tracker (design §15): a vendor exits the broker
  when its AS advertises ID-JAG support, the IdP issues ID-JAGs, and a 30-day
  dual-run shows parity. The broker's success metric is a shrinking registry.

## 5. Onboarding a vendor (checklist)

1. Registry entry (schema-valid, reviewed): metadata URL or endpoints,
   auth method, scope ceiling, rotation flag, revocation strategy.
2. Confidential client registered at the vendor; credential written to
   `vendor-clients/{vendor}` (admin write path only).
3. Egress route added at the gateway pinned to the vendor endpoint
   (gateway-policy P5 — the route is the allowlist), with DLP + credential
   swap in the load-bearing order.
4. Acceptance probes green: consent dance, DLP block, single-flight refresh,
   revocation → STALE → re-consent, no-issuance route audit (EG-01..10).
5. Sunset criteria recorded (`ema_status`, review date).
