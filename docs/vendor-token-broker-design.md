# Vendor Token Broker — Design Document

**Version:** 1.0-draft &nbsp;|&nbsp; **Status:** For architecture review &nbsp;|&nbsp; **Owner:** API Gateway Platform
**Related:** MCP Platform Token Claims Contract v1.0 · SaaS Connector Onboarding Standard (TBD) · ADR-xxx "Broker as standalone service"

---

## 1. Role definition

The Vendor Token Broker acquires, custodies, refreshes, and revokes OAuth credentials issued by third-party SaaS authorization servers (GitHub, Notion, Atlassian, ...) on behalf of individual enterprise users, and resolves them per-request for the Kong egress tier.

**The broker is an OAuth client and credential custodian. It is not an authorization server and MUST NOT mint, sign, or transform tokens.** Keycloak remains the sole issuer for the MCP plane (Claims Contract §2). Any future requirement that appears to need broker-issued tokens is a design error to be escalated, not implemented.

The broker exists because most SaaS vendors' authorization servers do not yet accept the Identity Assertion JWT Authorization Grant (ID-JAG) on which MCP Enterprise-Managed Authorization (EMA, stable extension) is built. It is deliberately transitional: Section 15 defines per-vendor sunset criteria. Architect every vendor integration as a removable module.

## 2. Standards basis

| Leg | Standard | Broker obligation |
|---|---|---|
| Acquisition | RFC 6749 authorization code + OAuth 2.1 discipline | PKCE (S256) on every flow; exact redirect-URI match; no implicit/password grants |
| Acquisition | RFC 7636 PKCE | Verifier generated and held server-side per transaction |
| Discovery | RFC 8414 AS metadata | Vendor endpoints resolved from `.well-known`; hardcoding forbidden where metadata exists |
| Acquisition | RFC 9126 PAR | Used where the vendor advertises support |
| Acquisition | RFC 9207 issuer identification | Callback validates `iss` (when present or advertised) against the issuer recorded at transaction creation — strict string comparison, no URI normalization; applies to error responses too |
| Hardening | RFC 9700 OAuth 2.0 Security BCP | Normative checklist for the whole client stack; deviations documented per vendor |
| Lifecycle | RFC 6749 §6 refresh | Single-flight refresh per entry (Section 9) |
| Lifecycle | RFC 7009 revocation | Offboarding calls the vendor revocation endpoint before deleting the vault entry |
| Lifecycle | RFC 7662 introspection | Optional health probe where offered |
| Exchange (future) | MCP Enterprise-Managed Authorization (stable extension): ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant, profiling draft-ietf-oauth-identity-chaining) via RFC 8693 token exchange at the IdP + RFC 7523 JWT authorization grant at the vendor's Resource Authorization Server | The standardized replacement; drives Section 15 sunset |

The custodial pattern itself ("store foreign-domain tokens keyed by local identity") has no RFC; it is the token-handler/BFF pattern applied at gateway scale. RFC 9700 discipline plus Sections 10–12 substitute for the missing standard.

## 3. Architecture and trust boundaries

Deployment: Kubernetes (EKS in this reference), inside the PHI-boundary cloud accounts, egress-restricted to registered vendor AS/API hostnames. Workload identity: an attested SVID from the workload identity system (e.g., Athenz), used for (a) mTLS on every inbound API call and (b) `tls_client_auth` if the broker ever needs hub tokens of its own. All crypto on FIPS 140-3 validated modules.

Callers and trust:

- **Kong egress DP → broker** (`/v1/tokens/resolve`): mTLS with SVID allowlist pinned to the egress DP service identity; request carries the end-user hub JWT, which the broker independently re-validates (issuer, `exp`, tier audience, `cnf` where present) — defense in depth, never trust-the-gateway.
- **User browser → broker** (`/v1/authorize`, `/v1/callback`): via the private ingress only; the callback host is VPN-reachable, never on the public tier. Third-party/external-tier users have no route to the broker by construction.
- **Broker → vendor AS**: outbound TLS; broker authenticates with its per-vendor confidential client credential (from `vendor-clients/{vendor}`), preferring `private_key_jwt` over client secrets where the vendor supports it.
- **Broker → Vault**: the only role with read on `vendor-tokens/*`; every read is an audited event.

## 4. API specification

All endpoints: mTLS required; JSON; errors follow RFC 9457 problem details; no token material ever appears in an error body or log line.

### 4.1 `POST /v1/tokens/resolve`
Caller: Kong egress DP only.
Request: `{ "vendor": "github", "sub": "wf-user-8842", "hub_jti": "…", "min_ttl_s": 120, "required_scopes": ["repo"] }` plus the hub JWT in `Authorization`. `required_scopes` is derived by the caller from the authenticated MCP tool; the broker caps it at the registry `scope_ceiling` and answers `409 needs-reconsent-scope` when the held grant is narrower.
Responses:
- `200 { "access_token": "…", "expires_at": …, "granted_scopes": […] }` — token guaranteed live for ≥ `min_ttl_s` (refresh performed inline if needed).
- `404 { "type": "…/needs-consent", "authorize_uri": "https://broker…/v1/authorize/github?txn=…" }` — no entry or STALE entry; Kong translates this into the MCP authorization-required response so the client opens the consent flow.
- `409 needs-reconsent-scope` — entry exists but granted scopes < requested tool's required scopes.
- `503 vendor-unavailable` — retriable; entry state unchanged.
SLO: p99 ≤ 25 ms on cache hit; ≤ 400 ms when an inline refresh is required.

### 4.2 `GET /v1/authorize/{vendor}?txn=…`
Builds the vendor authorization URL: `state` = opaque handle to a server-side transaction record `{sub, vendor, nonce, pkce_verifier, created_at, requested_scopes}` (TTL 10 min, single use). `state` is never a JWT and never decodable client-side. Scopes requested = min(tool requirement, vendor scope ceiling from the registry). Redirects the browser to the vendor.

### 4.3 `GET /v1/callback/{vendor}?code=…&state=…`
Validates `state` (exists, unexpired, unconsumed, vendor matches); validates RFC 9207 `iss` against the issuer recorded in the transaction (mix-up defense — a mismatch is a security alert and the code is never redeemed); exchanges `code` + PKCE verifier at the vendor token endpoint; captures the vendor account id from the token response or userinfo; writes the vault entry; marks the transaction consumed; renders a "connection complete — return to your client" page. A `state` mismatch or reuse returns a 4xx to the browser **and** raises a security alert (possible CSRF/binding attack, §10) — the alert is the point; the status code alone is not an adequate response.

### 4.4 `DELETE /v1/grants/{vendor}/{sub}`
Callers: the user themself (sub match) or the offboarding automation (admin SVID). Order of operations: RFC 7009 revoke at vendor → delete vault entry → emit audit. Vendor revocation failure leaves the entry in `REVOKE_PENDING` with retry; the entry is unusable for resolve while pending.

### 4.5 `GET /v1/grants` (self-service) · `GET/PUT /v1/admin/vendors/{vendor}` (registry)
Registry record: `{ vendor_id, auth_metadata_url | endpoints, token_endpoint_auth_method, scope_ceiling: […], refresh_rotation: true|false, ema_status: none|announced|available }` plus operational fields (`enabled_env`, `vendor_user_endpoint`, `revocation`). Per-request scope needs travel in the resolve body (`required_scopes`, §4.1), not the registry — the registry holds only the ceiling. The vendor `client_id` lives with its credential in `vendor-clients/{vendor}` (Section 5), never in the registry. Changing `scope_ceiling` requires the same sign-off as a Claims Contract change. Lab delta: only the authenticated `GET` is implemented — registry mutation is a reviewed git change to `broker/registry.json`, which is the stronger control for a lab; the `PUT` leg is production intent (Section 16).

## 5. Vault schema

```
vendor-tokens/{vendor}/{sub}   {access_token, refresh_token, expires_at,
                                granted_scopes[], vendor_user_id,
                                state: ACTIVE|REFRESHING|STALE|REVOKE_PENDING,
                                refresh_generation, last_refresh_at, created_at}
vendor-clients/{vendor}        {client_id, private_key | client_secret}
```

Envelope encryption via KMS CMK dedicated to the broker; vault policy: broker role read/write on `vendor-tokens/*`, admin role write-only on `vendor-clients/*`; no human read path to token material. `refresh_generation` is a monotonic counter supporting the rotation-race detection in Section 9.

## 6. Sequence — first-time consent dance

```mermaid
sequenceDiagram
    autonumber
    participant UA as Browser
    participant C as MCP Client
    participant K as Kong egress DP
    participant B as Broker
    participant V as Vault
    participant G as GitHub Authorization Server
    participant M as GitHub MCP server (Resource Server)

    C->>K: MCP tool call (hub JWT, sub=wf-user-8842)
    K->>B: POST /v1/tokens/resolve {github, sub}
    B->>V: read vendor-tokens/github/wf-user-8842
    V-->>B: not found
    B-->>K: 404 needs-consent + authorize_uri(txn)
    K-->>C: MCP authorization-required
    C->>UA: open authorize_uri
    UA->>B: GET /v1/authorize/github?txn=…
    Note over B: create state txn {sub, nonce,<br/>PKCE verifier, scopes≤ceiling}, TTL 10m
    B-->>UA: 302 → GitHub authorize (client_id, PKCE S256, state)
    UA->>G: consent as themself (org-owned GitHub App)
    G-->>UA: 302 → broker /v1/callback?code&state
    UA->>B: GET /v1/callback/github?code&state
    Note over B: validate state: exists, unexpired,<br/>unconsumed, vendor match — else ALERT
    B->>G: token endpoint: code + PKCE verifier + client auth
    G-->>B: access (≈8h) + refresh (rotating) tokens
    B->>V: write vendor-tokens/github/{sub} state=ACTIVE gen=1
    B-->>UA: "connected — return to your client"
    C->>K: retry MCP tool call
    K->>B: resolve → 200 access_token
    K->>M: upstream MCP call, vendor token injected, hub JWT stripped
```

Properties enforced by the design: the PKCE verifier and `state` never leave the broker in decodable form; `state` binds the callback to the initiating `sub` so a stolen callback URL cannot attach someone else's GitHub account to your identity (login-CSRF / account-binding attack); scopes are capped by the registry ceiling regardless of what the tool asked for.

## 7. Sequence — steady-state resolve

```mermaid
sequenceDiagram
    autonumber
    participant K as Kong egress DP
    participant B as Broker
    participant V as Vault
    K->>B: resolve {github, sub, min_ttl_s:120}
    B->>B: in-memory cache hit? (TTL ≤ 60s)
    alt cache miss
        B->>V: read entry (audited)
        V-->>B: ACTIVE, expires_at
    end
    alt expires_at - now > min_ttl
        B-->>K: 200 token
    else inside refresh buffer
        Note over B: inline single-flight refresh (Section 9)
        B-->>K: 200 refreshed token
    end
```

## 8. Refresh state machine

```
            resolve/sweep hits buffer            success
  ACTIVE ─────────────────────────────► REFRESHING ─────► ACTIVE (gen+1)
    ▲                                        │
    │  re-consent (Section 6)                │ invalid_grant
    │                                        ▼
  (new entry, gen=1) ◄──────────────────── STALE
                                             │ admin uninstall detected
  REVOKE_PENDING ◄── DELETE /grants          ▼  (mass event → page)
```

Triggers: lazy (a resolve inside the buffer, `buffer = max(2 × max_clock_skew, 5 min)`) and proactive (sweeper refreshing entries expiring within 15 min, jittered). `invalid_grant` on refresh → STALE (user revoked at vendor, refresh token expired from 6-month disuse, or org App uninstalled — three+ simultaneous STALEs for one vendor within a minute is treated as the uninstall case and pages).

## 9. Sequence — refresh race (rotating refresh tokens)

GitHub-class vendors rotate the refresh token on every use: the old refresh token is consumed by the first successful refresh. Two concurrent refreshes for the same entry therefore burn the token family — the second caller presents an already-consumed refresh token, the vendor treats it as replay, and may revoke the whole grant. The broker prevents this with a per-entry single-flight lock and generation check:

```mermaid
sequenceDiagram
    autonumber
    participant K1 as Kong DP node A
    participant K2 as Kong DP node B
    participant B as Broker
    participant L as Lock (per-entry)
    participant V as Vault
    participant G as GitHub Authorization Server

    par concurrent resolves inside buffer
        K1->>B: resolve {github, sub}
    and
        K2->>B: resolve {github, sub}
    end
    B->>L: acquire github/sub (K1's request wins)
    Note over B: K2's request parks on the lock —<br/>it does NOT start a second refresh
    B->>V: read entry (gen=41)
    B->>G: refresh_token grant (RT gen41)
    G-->>B: new AT + new RT (rotated)
    B->>V: CAS write gen 41→42 (fails if gen moved)
    B->>L: release — wake parked waiters
    B-->>K1: 200 AT(gen42)
    B-->>K2: 200 AT(gen42)  — same token, zero extra vendor calls
```

Rules: the lock is per `{vendor, sub}`, held only for the refresh round-trip, with a hard timeout (lock holder death ⇒ waiters retry, re-read entry, and find either gen42 or ACTIVE-unexpired). The compare-and-swap on `refresh_generation` makes a split-brain double-refresh detectable: a CAS failure means another writer won — discard local result, re-read, never write the older pair. If the broker runs multi-replica (it should), the lock is a short-TTL distributed lock, not process-local. A vendor `invalid_grant` here transitions to STALE exactly as in Section 8; waiters receive the 404 needs-consent rather than an error.

## 10. Failure modes

| Failure | Detection | Behavior |
|---|---|---|
| User revoked grant at vendor | `invalid_grant` on refresh, or 401 from vendor API surfaced by Kong | Entry → STALE; next resolve returns needs-consent |
| Org App uninstalled at vendor | Burst of STALEs for one vendor | Mass-stale event; page platform on-call; registry `ema_status` unchanged |
| Refresh token 6-month disuse expiry | `invalid_grant` on first resolve after dormancy | STALE → re-consent; expected, not an incident |
| Vault unavailable | Read/write errors | **Fail closed.** No grace beyond in-memory cache TTL (≤ 60 s); resolve returns 503 |
| Vendor AS outage | Timeouts/5xx on token endpoint | 503 vendor-unavailable; entries untouched; circuit breaker per vendor |
| `state` replay / mismatch on callback | Transaction store check | 4xx to browser + security alert (possible CSRF/binding attack) |
| Clock skew | expires_at math | Buffer ≥ 2× measured skew; NTP-alarmed hosts |
| Broker replica death mid-refresh | Lock timeout | Waiters retry; CAS prevents stale write |

## 11. Security requirements

No issuance: the broker holds no signing keys and exposes no token or JWKS endpoint (lab: checked by the phase 5 route audit `test_no_issuance_rule_route_audit` and phase 7 `test_broker_exposes_no_issuance_endpoint` against the live stack). Token material never logged, never in errors, never in traces; resolve responses are excluded from any body-capturing middleware. Per-user entries only — no shared vendor service accounts through this path. Registry scope ceilings enforced at authorize time. Callback host on the private tier only. Annual pen test includes the consent dance (CSRF, mix-up, code injection per RFC 9700 §4) explicitly. The broker is in HIPAA risk-analysis scope as a system adjacent to PHI paths, though it stores no PHI — vendor tokens are credentials, and DLP at the Kong egress tier (not the broker) is the control preventing PHI reaching vendors.

## 12. Audit events

Emitted per Claims Contract §9 vocabulary: `broker.resolve` (hub jti, sub, vendor, decision, cache/refresh path), `broker.consent.start|complete|fail`, `broker.refresh` (gen transition), `broker.stale`, `broker.revoke`, `broker.registry.change`. Every vendor-side action is joinable: hub jti → resolve → Kong tool-call record → vendor audit log via `vendor_user_id`.

## 13. SLOs and capacity

resolve p99 ≤ 25 ms (cache hit) / 400 ms (inline refresh); availability 99.9% (it is on the egress hot path; Kong treats 503 as retriable with short backoff). Sizing intuition: 100 GitHub users × 8 h token lifetime ⇒ ~12 refreshes/user/day ≈ 1,200 vendor token calls/day — trivial; the hot path is cache-served resolves.

## 14. Delivery

Owner: a platform team with OAuth-client experience, as a new service — the legacy in-house AS continues its sunset per Claims Contract §6.2. Stack: the owner's choice; the mandatory ingredients are a certified OAuth client library, vault SDK, distributed lock, and the workload-identity agent/sidecar. Pre-build spike (2 days): evaluate Keycloak identity brokering's stored-external-token retrieval against the vendor list; record findings in the ADR even if (as expected) it falls short on refresh rotation and non-login-brokered vendors.

## 15. Sunset criteria (per vendor)

A vendor exits the broker when all hold: the vendor's Resource Authorization Server advertises `urn:ietf:params:oauth:grant-profile:id-jag` in `authorization_grant_profiles_supported` (EMA §6 discovery), the workforce IdP issues ID-JAGs, and a 30-day dual-run shows EMA-path parity in the SIEM. Exit = registry flag flips, consent flow disabled for the vendor, existing entries revoked per RFC 7009 on a drain schedule. The broker's success metric is its own shrinking registry.

## 16. Lab implementation deltas

The lab broker (`broker/`) realizes every security-critical mechanic of this design — single-flight + generation-CAS refresh, RFC 9207 `iss` and `iss`-omission defense, single-use `state` with TTL, PKCE S256, 409 needs-reconsent-scope, hub-JWT re-validation with PS256/ES256 pinning, mass-STALE paging, fail-closed vault behavior, and the no-issuance rule. Known deltas from the production design, accepted for the single-replica lab:

- **`REFRESHING` is never persisted.** Single-flight uses an in-process `asyncio` lock (single-replica scoping); the persisted `REFRESHING` state in §5/§8 is a multi-replica production construct. The state machine's observable transitions (`ACTIVE`, `STALE`, `REVOKE_PENDING`) match §8.
- **Client authentication is `client_secret_post` only.** The registry records `token_endpoint_auth_method` but the code does not yet branch on it; `private_key_jwt` (§3) and the `private_key` credential shape (§5) are unimplemented. RFC 9126 PAR and RFC 7662 introspection (§2, both conditional) are likewise not yet wired.
- **Registry mutation is git, not API.** `GET /v1/admin/vendors/{vendor}` is authenticated and read-only; there is no `PUT` (§4.5).
- **The proactive sweeper runs on a fixed interval** rather than jittered (§8) — jitter matters at fleet scale, not for one replica.
