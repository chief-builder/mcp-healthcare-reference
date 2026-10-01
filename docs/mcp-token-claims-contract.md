# MCP Platform Token Claims Contract

**Version:** 1.0-draft &nbsp;|&nbsp; **Status:** For platform team review &nbsp;|&nbsp; **Owner:** API Gateway Platform
**Applies to:** All tokens presented to the MCP plane (Kong DP internal and external tiers, all MCP servers)

---

## 1. Purpose and scope

This contract defines the single canonical JWT shape that every component of the MCP plane validates against and codes to. Keycloak is the sole token authority for the plane: no token minted by the workforce IdP, the legacy in-house auth server, the workload identity system, or Auth0 is ever presented directly to a Kong data plane or an MCP server. Those systems authenticate their populations; Keycloak normalizes the result into the schema below.

The contract exists so that Kong ACLs, MCP server permission logic, and SIEM audit parsing are written once against one claim vocabulary, regardless of which of the five grant paths produced the token. Any change to this schema is a versioned, reviewed change (Section 11), because every consumer of these tokens is coupled to it.

Out of scope: browser session cookies, Konnect admin authentication, and tokens used by MCP servers to reach FHIR backends (those are downstream service credentials governed by their own contract).

## 2. Token authority

| Property | Value |
|---|---|
| Issuer (`iss`) | `https://auth.mcp.<org>.com/realms/mcp-plane` |
| JWKS | `<issuer>/protocol/openid-connect/certs` — DPs and MCP servers cache with ≤ 5 min TTL |
| Signing algorithms | `PS256` primary, `ES256` permitted. `RS256` and all HMAC forbidden. Modules must be FIPS 140-3 validated per the 2025 Security Rule amendments |
| Access token lifetime | 300 s (m2m paths), 600 s (interactive paths). No refresh tokens on the external tier for third parties beyond 8 h session |
| Token type | JWT access tokens only. Opaque tokens are not used on the MCP plane (DPs validate locally; no introspection round trip on the request path) |
| Clock skew | Validators allow ≤ 30 s |

Rationale for short lifetimes: MCP tool calls are bursty and short-lived; a 5-minute token bounds the blast radius of any leak, and the cert-bound workload path (§6.3) makes re-acquisition cheap (mTLS client auth, no human).

## 3. Canonical claim schema

Every MCP-plane access token carries the claims below. `M` = mandatory on all paths, `C` = conditional (mandatory on the paths noted), `F` = forbidden.

| Claim | Req | Type | Semantics |
|---|---|---|---|
| `iss` | M | string | Exactly the issuer in Section 2. Any other value is rejected before all other checks. |
| `sub` | M | string | Stable Keycloak subject of the *effective principal* — the human on interactive paths, the workload service identity on m2m paths. Never an email; emails rotate. |
| `aud` | M | array | Tier audience **plus** per-server resource URIs (Section 4). Minimum two entries. |
| `azp` | M | string | The Keycloak client that requested the token — i.e., which application/agent is acting. For the workload-identity path (§6.3) this equals the workload's service identity (Section 6.3). |
| `exp`, `iat` | M | number | Standard. `nbf` optional; if present, enforced. |
| `jti` | M | string | Unique, opaque token identifier. Logged in every audit record; enables replay tracing across DP and MCP server logs. (Lab finding, Phase 1: Keycloak 26 emits a short type prefix plus UUID, e.g. `trrtcc:<uuid>` — consumers MUST treat `jti` as opaque, not parse it as a bare UUID.) |
| `mcp_tier` | M | string | `internal` \| `external`. Redundant with `aud` by design — belt and suspenders for policy engines that match on simple claims. |
| `idp_origin` | M | string | `ping` \| `athenz` \| `homegrown` \| `keycloak` \| `auth0`. Which upstream system authenticated the principal: `ping` = the brokered workforce IdP (§6.1), `athenz` = the attested workload-identity path (§6.3; the lab's SPIRE-issued agent carries it), `homegrown` = the legacy in-house AS (§6.2). Drives audit and anomaly detection (e.g., an `auth0` token at the internal tier is always an incident). |
| `scope` | M | string | Space-delimited, per the grammar in Section 5. |
| `act` | C | object | Delegation chain per RFC 8693 §4.1. Mandatory whenever the requesting party is not the effective principal — all on-behalf-of flows (Section 7). |
| `cnf` | C | object | Sender-constraint confirmation. `{"x5t#S256": "<thumbprint>"}` binds to an mTLS client cert (RFC 8705, workload-identity path §6.3 — mandatory there, forbidden absent mTLS). `{"jkt": "<thumbprint>"}` binds to a client-held DPoP key (RFC 9449, `workforce-dpop` path §6.6). A `cnf` the validator cannot satisfy is a rejection, not a no-op. |
| `fhir_patient` | C | string | FHIR Patient resource id. Mandatory on the Auth0 end-customer path; forbidden on all others. MCP servers MUST compartment-filter every FHIR query by it when present. |
| `groups` | C | array | Normalized role names (Section 3.1). Mandatory on workforce path; the *only* group vocabulary any consumer may reference. |
| `amr` | C | array | Authentication methods from the upstream IdP (e.g., `["mfa","swk"]`). Mandatory on interactive paths; policy MAY require `mfa` for designated tool scopes (lab: the FHIR server requires it for the scopes in `MCP_MFA_SCOPES`, default `mcp:fhir-clinical:everything:read`, answering `401 insufficient_user_authentication` per RFC 9470 when absent). |
| `email`, `name`, PII claims | F | — | Access tokens carry no directory PII. Consumers needing display data resolve `sub` out of band. Keeps tokens out of PHI/PII scope when they land in logs. |

### 3.1 Normalized group vocabulary

Upstream group formats (e.g., the workforce IdP's `memberOf` DNs, Auth0 permissions, workload-identity roles) are mapped by Keycloak protocol mappers into flat names with the prefix `mcp-`:

```
mcp-platform-admin      mcp-clinical-tools      mcp-scheduling-tools
mcp-analytics-readonly  mcp-external-curated    mcp-agent-operators
```

No consumer may match on raw upstream group strings. Adding a group to this vocabulary is a contract change.

## 4. Audiences and resource indicators

Two-level audience discipline per RFC 8707:

```
Tier audiences:        mcp://tier/internal          mcp://tier/external
Server resource URIs:  mcp://srv/scheduling         mcp://srv/fhir-clinical
                       mcp://srv/formulary          mcp://srv/claims-status
```

A token's `aud` MUST contain exactly one tier audience and one or more server URIs. Kong DPs reject any token whose tier audience does not match the DP's own tier — this is the cryptographic wall that makes an external-tier token useless against the internal tier even if replayed. MCP servers additionally reject tokens whose `aud` lacks their own URI, so a token minted for the scheduling server cannot be redirected at the clinical server by a compromised client.

Clients request server URIs via the `resource` parameter at the token endpoint; Keycloak client policy caps which URIs each client may request.

> **Lab deviation (documented, GitHub #13).** RFC 8707 / the MCP authorization
> spec expect the resource indicator to be the server's canonical **HTTPS
> endpoint URL** (e.g. `https://fhir.example/mcp`), and RFC 9728 metadata to be
> served at the path-inserted well-known URI. This reference implementation uses
> opaque `mcp://tier/*` and `mcp://srv/*` URIs as the two-level audience instead.
> The property under test — a token minted for one tier/server failing
> cryptographic validation at another — is fully preserved; what is consciously
> lost is out-of-the-box interop with clients that derive the `resource`
> parameter from the endpoint URL. The MCP servers now serve their PRM at the
> path-inserted URI (`/.well-known/oauth-protected-resource/mcp`, with the root
> path kept as an alias) so discovery is spec-shaped even though the resource
> value is not an HTTPS URL. The deviation also touches Enterprise-Managed
> Authorization adoption: EMA §4 requires the token-exchange `resource`
> parameter (and the ID-JAG `resource` claim) to be the RFC 9728 Resource
> Identifier of the MCP Server, so the EMA upgrade path (§6.1) presumes the
> endpoint-URL migration. Migrating to endpoint-URL resources is a major
> contract version (Section 11); issue #13 records this as a documented
> deviation (closed as documented).

## 5. Scope grammar

```
mcp:<server>:<tool>:<verb>            e.g.  mcp:scheduling:find-slots:read
mcp:<server>:*:<verb>                 server-wide, verb-limited (admin review required)
patient/<Resource>.<verb>             SMART-style, Auth0 path only
                                      e.g.  patient/Observation.read
```

Verbs are `read` | `write` | `execute`. Wildcards on `<tool>` require platform-admin approval and are forbidden on the external tier. The Kong MCP ACL layer and the MCP server both enforce scopes; the server is the authoritative check, the DP is the cheap early rejection.

## 6. Grant-path profiles

Five paths produce contract-conformant tokens. Each profile lists the front-leg mechanics and the claim deltas; everything not mentioned follows Section 3.

### 6.1 Workforce — brokered workforce IdP, e.g. Ping (Claude Code, Codex CLI, VS Code)

Front leg: OIDC authorization code + PKCE at Keycloak, with Keycloak brokering the workforce IdP for authentication (the lab stands in a second Keycloak realm, `fake-ping`). When the IdP ships Identity Assertion JWT Authorization Grant (ID-JAG) issuance, the front leg becomes the MCP Enterprise-Managed Authorization flow: the client exchanges its IdP identity assertion for an ID-JAG at the IdP (RFC 8693 token exchange, EMA §4), then presents the ID-JAG at Keycloak — the Resource Authorization Server — as a JWT authorization grant (RFC 7523, EMA §5); **no claim in this contract changes** — that is the point of the hub.

| Claim | Value on this path |
|---|---|
| `sub` | Workforce user (brokered IdP subject, stabilized by Keycloak) |
| `azp` | `claude-code` \| `codex-cli` \| `vscode-copilot` (pre-registered clients) |
| `idp_origin` | `ping` |
| `mcp_tier` / `aud` | `internal` + requested server URIs |
| `amr` | Propagated from the IdP; `mfa` required for clinical step-up scopes (lab: `MCP_MFA_SCOPES`, enforced by the FHIR server) |
| `act`, `cnf`, `fhir_patient` | Absent |

### 6.2 Legacy in-house AS (`homegrown`) — token exchange (transitional, sunset target)

Front leg: RFC 8693 exchange at Keycloak; the legacy AS is registered as a trusted external issuer. `subject_token` = a service token from the legacy AS.

| Claim | Value on this path |
|---|---|
| `sub` | Keycloak-registered service account for the workload |
| `azp` | The exchanging client |
| `idp_origin` | `homegrown` |
| `act` | Present iff the exchange included user context (on-behalf-of) |
| `cnf` | Absent (bearer) — one reason this path sunsets |

This path is frozen: no new services onboard to it. Each service migrating to 6.3 removes its issuer-trust mapping; the profile is deleted from this contract when the last mapping is removed.

### 6.3 Workload identity (e.g., Athenz; SPIRE in the lab) — mTLS client credentials (target state for all m2m)

Front leg: workload holds a short-lived X.509 SVID from the workload identity system (attested issuance, automatic rotation). Client credentials grant at Keycloak with `tls_client_auth`; Keycloak matches the SAN/SPIFFE URI to the client registration. Tokens are certificate-bound.

| Claim | Value on this path |
|---|---|
| `sub` | Workload service identity, e.g. `mcp-agents.prior-auth-agent` |
| `azp` | Same as `sub` (the workload is the client) |
| `idp_origin` | `athenz` |
| `cnf` | `{"x5t#S256": <thumbprint of the presenting cert>}` — mandatory |
| `act` | Present on on-behalf-of exchanges (agent token + user context → combined token; user becomes `sub`, agent moves to `act.sub`) |

Validators MUST verify `cnf` against the client certificate on the mTLS connection (Section 8). A 6.3 token presented without mTLS, or with a non-matching cert, is rejected and alerted, not merely rejected.

### 6.4 Third parties — Keycloak native (ChatGPT, B2B partners)

Front leg: authorization code + PKCE directly at Keycloak. Clients are individually pre-registered with pinned redirect URIs; Dynamic Client Registration is disabled (and is deprecated by the MCP 2026-07-28 authorization spec). Client ID Metadata Documents are accepted only from origin-allowlisted metadata URLs per Reference Architecture §5.1. Per-user consent screens are retained deliberately. (Lab delta: no third-party client is committed in the realm — the external tier is exercised by `patient-agent` (§6.5) and test clients; this profile is the production target.)

| Claim | Value on this path |
|---|---|
| `sub` | The consenting user |
| `azp` | `openai-chatgpt` \| partner client id |
| `idp_origin` | `keycloak` |
| `mcp_tier` / `aud` | `external` only; server URIs limited to the curated external catalog |
| `groups` | `mcp-external-curated` only |

### 6.5 End customers — Auth0 broker (patient-facing agents)

Front leg: Keycloak brokers Auth0. Auth0's forthcoming native ID-JAG issuance may later replace the broker leg; claims unchanged.

| Claim | Value on this path |
|---|---|
| `sub` | Customer identity (brokered Auth0 subject) |
| `idp_origin` | `auth0` |
| `mcp_tier` / `aud` | `external` + patient-facing server URIs |
| `scope` | SMART-style `patient/...` scopes only; `mcp:` scopes forbidden |
| `fhir_patient` | Mandatory — resolved by Keycloak mapper from the customer↔patient linkage store |

MCP servers MUST apply `fhir_patient` as a hard compartment filter on every FHIR interaction. A missing or unresolvable linkage means no token is issued, not a token without the claim.

### 6.6 Workforce — DPoP sender-constrained (`workforce-dpop`)

Front leg: identical to 6.1 (authorization code + PKCE, brokered Ping), but the client carries `dpop.bound.access.tokens=true`, so it presents a DPoP proof (RFC 9449) at the token endpoint and Keycloak stamps `cnf.jkt` — the RFC 7638 thumbprint of the client's key. This is the public-client analogue of 6.3's cert binding: the token is useless without the private key that signs a fresh proof per request, closing the "token lifted from the credential store" replay.

| Claim | Value on this path |
|---|---|
| `sub`, `azp`, `idp_origin`, `mcp_tier`/`aud`, `groups`, `amr` | As 6.1; `azp` = `workforce-dpop` |
| `cnf` | `{"jkt": <thumbprint of the client's DPoP key>}` — mandatory |
| `act`, `fhir_patient` | Absent |

`claude-code` (6.1) stays bearer until real Claude Code ships DPoP — a tracked gap (arch doc gap register); this profile proves the path end-to-end. Every request MUST carry a valid, matching, single-use DPoP proof (§8).

## 7. Delegation semantics (`act`)

On-behalf-of tokens follow RFC 8693 §4.1: the effective principal is `sub`; the acting party chain nests in `act`.

```json
{
  "sub": "wf-user-8842",
  "azp": "prior-auth-agent",
  "act": { "sub": "mcp-agents.prior-auth-agent" }
}
```

Rules: chains are at most two levels deep (`act.act` requires platform-admin approval per workflow); audit records log both identities (Section 9); scopes on a delegated token MUST be a subset of both parties' allowed scopes — Keycloak exchange policy computes the intersection.

## 8. Validation requirements (normative)

**Kong DP (both tiers), on every request:** verify signature against cached JWKS; `iss` exact match; `exp/nbf/iat` with ≤ 30 s skew; tier audience matches the DP's tier; `jti` present; if `cnf` present, mTLS client cert thumbprint MUST match, and absence of a client cert is a hard failure; map `groups`/`scope` through MCP ACLs to tool visibility; inject `jti`, `sub`, `azp`, `act.sub`, `idp_origin` as upstream headers for the MCP server and strip any client-supplied copies of those headers. (Lab delta: on the first-party MCP routes the DP tier wall in `deck/internal.yaml` enforces the tier audience without signature verification — signature verification there is carried by the servers' §8 re-validation, and by `openid-connect` on the egress routes. Full DP-side JWT verification on every route is the production target.)

**DPoP sender-constraint (RFC 9449), when `cnf.jkt` present:** the token MUST be presented as `Authorization: DPoP <token>` with exactly one `DPoP` proof header; the proof is a `dpop+jwt`/`ES256` JWS whose embedded public key's RFC 7638 thumbprint equals `cnf.jkt`, with `htm`/`htu` matching the request, `iat` within ±60 s, `ath` = `base64url(SHA-256(token))`, and a single-use `jti`. Gateway-first: the `dpop-check` DP plugin is early rejection (structure + binding + request match + `jti` replay via a shared dict, the DP being the single entry point); the MCP servers' `requireDpop` is the authoritative re-check and additionally verifies the proof signature (jose `EmbeddedJWK`). Consistent with §8's "servers re-validate, never trust the gateway," and mirroring the cnf/mTLS split, a `cnf.jkt` token without a valid matching proof is a rejection, not a no-op. Server-side `jti` dedup is absent by design (stateless replicas); the DP is authoritative for replay (arch doc gap register).

**MCP servers, on every tool call:** re-verify signature and `iss` (do not trust the DP blindly — defense in depth); `aud` contains this server's URI; scope authorizes this specific tool + verb; when `fhir_patient` present, compartment-filter; when absent on a path that requires it, reject. (Lab: the per-tool check runs at the HTTP layer for the challenge and again inside every tool handler, and JSON-RPC batch requests are refused, so no request shape reaches a tool unchecked.)

**Both:** rejections return RFC 6750 `WWW-Authenticate` errors without echoing token contents; all rejections are audit events. 401 challenges include `resource_metadata` and, when the attempted operation requires one, the operation's `scope` (floor tools advertise none); insufficient-permission cases return 403 `error="insufficient_scope"` with the complete required scope set in one challenge (single-shot, never incremental), enabling the spec's step-up flow. PRM `scopes_supported` lists the minimal baseline only; `offline_access` never appears in PRM or challenges.

**All OAuth clients on the plane (interactive clients, broker):** validate RFC 9207 `iss` on authorization responses — including error responses — against the issuer recorded from validated AS metadata, using strict string comparison without URI normalization, before any use of the authorization code. Keycloak advertises `authorization_response_iss_parameter_supported: true`.

## 9. Audit record mapping

Every DP and MCP-server audit record carries, at minimum:

| SIEM field | Source |
|---|---|
| `token_id` | `jti` |
| `principal` | `sub` |
| `acting_agent` | `act.sub` (null if none) |
| `client` | `azp` |
| `origin_idp` | `idp_origin` |
| `tier` | `mcp_tier` |
| `patient_compartment` | `fhir_patient` (null if none) |
| `tool`, `verb`, `server`, `decision`, `ts` | Gateway/server context |

This tuple answers the HIPAA questions directly: which human (or on whose behalf), through which agent, touched which tool, in which patient compartment, when, and with what outcome. Records never contain the token itself or request/response bodies.

Lab note: the first-party servers' audit records (`servers/shared/src/audit.ts`) emit `tool` but no separate `verb` field — the verb is recoverable as the suffix of the tool's required scope (`mcp:<server>:<tool>:<verb>`). A production implementation should emit it explicitly.

## 10. Keys, rotation, FIPS

Keycloak realm keys rotate every 90 days with a 7-day overlap (old key remains in JWKS for verification only). Workload certs: ≤ 30 day lifetime, rotated by the workload identity system. All signing and TLS on the plane runs on FIPS 140-3 validated modules; the DP fleet runs FIPS-mode builds. Key ceremonies and rotations are change-managed and logged to the same SIEM pipeline as config changes.

## 11. Contract versioning

Tokens carry `mcp_contract: "1.0"`. Additive optional claims = minor version; any change to mandatory claims, audience scheme, or scope grammar = major version with a dual-validation migration window. The contract file lives in the platform repo; changes require API Gateway Platform + Security sign-off.

---

## Appendix A — Pilot agent, end to end

Registering one internal agent (`prior-auth-agent`) on the 6.3 path — a worked example using Athenz as the workload identity system (the lab's equivalent uses SPIRE; see `compose/phase4/`).

**A.1 Athenz domain and service (ZMS):**

```bash
zms-cli -d mcp-agents add-service prior-auth-agent
zms-cli -d mcp-agents add-provider-role-member \
    eks.us-east-1 prior-auth-agent   # Copper Argos launch authorization
```

SIA on the EKS pod (sidecar or init) attests via the EKS instance provider and receives the X.509 with SAN URI `spiffe://athenz/sa/mcp-agents.prior-auth-agent`, rotating well inside the 30-day cap.

**A.2 Keycloak client (realm `mcp-plane`):**

```json
{
  "clientId": "mcp-agents.prior-auth-agent",
  "protocol": "openid-connect",
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "clientAuthenticatorType": "client-x509",
  "attributes": {
    "x509.subjectdn": "",
    "x509.allow.san.uri": "spiffe://athenz/sa/mcp-agents.prior-auth-agent",
    "tls.client.certificate.bound.access.tokens": "true"
  },
  "defaultClientScopes": ["mcp-tier-internal"],
  "optionalClientScopes": ["mcp:prior-auth:*:execute", "mcp:fhir-clinical:coverage-check:read"]
}
```

Plus realm client policy: this client may request `resource` values `mcp://srv/prior-auth` and `mcp://srv/fhir-clinical` only. Protocol mappers stamp `idp_origin=athenz`, `mcp_tier=internal`, `mcp_contract=1.0`.

**A.3 Token request from the pod:**

```bash
curl --cert /var/run/sia/certs/svc.cert.pem \
     --key  /var/run/sia/keys/svc.key.pem \
     -d grant_type=client_credentials \
     -d scope="mcp:prior-auth:submit-case:execute" \
     -d resource=mcp://srv/prior-auth \
     https://auth.mcp.<org>.com/realms/mcp-plane/protocol/openid-connect/token
```

**A.4 Kong (declarative, internal tier control plane via decK):**

```yaml
routes:
  - name: mcp-prior-auth
    paths: ["/mcp/prior-auth"]
    plugins:
      - name: mtls-auth            # client cert required on this route
      - name: jwt-validation       # iss, exp, aud: mcp://tier/internal
      - name: pre-function         # cnf x5t#S256 == presented cert thumbprint
      - name: request-transformer  # inject sub/azp/act/jti headers, strip inbound copies
      - name: opentelemetry        # audit tuple → collector → SIEM
```

**A.5 Acceptance tests before promotion:** token without mTLS → 401 + alert; token replayed at external tier → 401 (aud); scope for an unapproved tool → 403 at DP; expired cert → SIA renews without pod restart; SIEM shows the full Section 9 tuple for one successful `submit-case` call.

