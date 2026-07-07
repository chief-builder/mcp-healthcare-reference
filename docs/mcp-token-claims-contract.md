# MCP Platform Token Claims Contract

**Version:** 1.0-draft &nbsp;|&nbsp; **Status:** For platform team review &nbsp;|&nbsp; **Owner:** API Gateway Platform
**Applies to:** All tokens presented to the MCP plane (Kong DP internal and external tiers, all MCP servers)

---

## 1. Purpose and scope

This contract defines the single canonical JWT shape that every component of the MCP plane validates against and codes to. Keycloak is the sole token authority for the plane: no token minted by PingID, the homegrown auth server, Athenz ZTS, or Auth0 is ever presented directly to a Kong data plane or an MCP server. Those systems authenticate their populations; Keycloak normalizes the result into the schema below.

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

Rationale for short lifetimes: MCP tool calls are bursty and short-lived; a 5-minute token bounds the blast radius of any leak, and the Athenz path makes re-acquisition cheap (mTLS client auth, no human).

## 3. Canonical claim schema

Every MCP-plane access token carries the claims below. `M` = mandatory on all paths, `C` = conditional (mandatory on the paths noted), `F` = forbidden.

| Claim | Req | Type | Semantics |
|---|---|---|---|
| `iss` | M | string | Exactly the issuer in Section 2. Any other value is rejected before all other checks. |
| `sub` | M | string | Stable Keycloak subject of the *effective principal* — the human on interactive paths, the workload service identity on m2m paths. Never an email; emails rotate. |
| `aud` | M | array | Tier audience **plus** per-server resource URIs (Section 4). Minimum two entries. |
| `azp` | M | string | The Keycloak client that requested the token — i.e., which application/agent is acting. For the Athenz path this equals the Athenz service identity (Section 6.3). |
| `exp`, `iat` | M | number | Standard. `nbf` optional; if present, enforced. |
| `jti` | M | string | UUID. Logged in every audit record; enables replay tracing across DP and MCP server logs. |
| `mcp_tier` | M | string | `internal` \| `external`. Redundant with `aud` by design — belt and suspenders for policy engines that match on simple claims. |
| `idp_origin` | M | string | `ping` \| `athenz` \| `homegrown` \| `keycloak` \| `auth0`. Which upstream system authenticated the principal. Drives audit and anomaly detection (e.g., an `auth0` token at the internal tier is always an incident). |
| `scope` | M | string | Space-delimited, per the grammar in Section 5. |
| `act` | C | object | Delegation chain per RFC 8693 §4.1. Mandatory whenever the requesting party is not the effective principal — all on-behalf-of flows (Section 7). |
| `cnf` | C | object | `{"x5t#S256": "<thumbprint>"}`. Mandatory on the Athenz path; forbidden absent mTLS (a `cnf` the DP cannot verify is a rejection, not a no-op). |
| `fhir_patient` | C | string | FHIR Patient resource id. Mandatory on the Auth0 end-customer path; forbidden on all others. MCP servers MUST compartment-filter every FHIR query by it when present. |
| `groups` | C | array | Normalized role names (Section 3.1). Mandatory on workforce path; the *only* group vocabulary any consumer may reference. |
| `amr` | C | array | Authentication methods from the upstream IdP (e.g., `["mfa","swk"]`). Mandatory on interactive paths; DP policy MAY require `mfa` for designated tool scopes. |
| `email`, `name`, PII claims | F | — | Access tokens carry no directory PII. Consumers needing display data resolve `sub` out of band. Keeps tokens out of PHI/PII scope when they land in logs. |

### 3.1 Normalized group vocabulary

Upstream group formats (Ping `memberOf` DNs, Auth0 permissions, Athenz roles) are mapped by Keycloak protocol mappers into flat names with the prefix `mcp-`:

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

### 6.1 Workforce — PingID broker (Claude Code, Codex CLI, VS Code)

Front leg: OIDC authorization code + PKCE at Keycloak, with Keycloak brokering PingID for authentication. When Ping ships ID-JAG/XAA support, the front leg becomes the EMA exchange (ID-JAG presented as grant at Keycloak); **no claim in this contract changes** — that is the point of the hub.

| Claim | Value on this path |
|---|---|
| `sub` | Workforce user (brokered Ping subject, stabilized by Keycloak) |
| `azp` | `claude-code` \| `codex-cli` \| `vscode-copilot` (pre-registered clients) |
| `idp_origin` | `ping` |
| `mcp_tier` / `aud` | `internal` + requested server URIs |
| `amr` | Propagated from Ping; `mfa` required for `mcp-clinical-tools` scopes |
| `act`, `cnf`, `fhir_patient` | Absent |

### 6.2 Homegrown AS — token exchange (transitional, sunset target)

Front leg: RFC 8693 exchange at Keycloak; the homegrown AS is registered as a trusted external issuer. `subject_token` = homegrown service token.

| Claim | Value on this path |
|---|---|
| `sub` | Keycloak-registered service account for the workload |
| `azp` | The exchanging client |
| `idp_origin` | `homegrown` |
| `act` | Present iff the exchange included user context (on-behalf-of) |
| `cnf` | Absent (bearer) — one reason this path sunsets |

This path is frozen: no new services onboard to it. Each service migrating to 6.3 removes its issuer-trust mapping; the profile is deleted from this contract when the last mapping is removed.

### 6.3 Athenz — mTLS client credentials (target state for all m2m)

Front leg: workload holds a short-lived X.509 from ZTS (Copper Argos attestation, SIA rotation). Client credentials grant at Keycloak with `tls_client_auth`; Keycloak matches the SAN/SPIFFE URI to the client registration. Tokens are certificate-bound.

| Claim | Value on this path |
|---|---|
| `sub` | Athenz service identity, e.g. `mcp-agents.prior-auth-agent` |
| `azp` | Same as `sub` (the workload is the client) |
| `idp_origin` | `athenz` |
| `cnf` | `{"x5t#S256": <thumbprint of the presenting cert>}` — mandatory |
| `act` | Present on on-behalf-of exchanges (agent token + user context → combined token; user becomes `sub`, agent moves to `act.sub`) |

Validators MUST verify `cnf` against the client certificate on the mTLS connection (Section 8). A 6.3 token presented without mTLS, or with a non-matching cert, is rejected and alerted, not merely rejected.

### 6.4 Third parties — Keycloak native (ChatGPT, B2B partners)

Front leg: authorization code + PKCE directly at Keycloak. Clients are individually pre-registered with pinned redirect URIs; dynamic client registration is disabled on this realm. Per-user consent screens are retained deliberately.

| Claim | Value on this path |
|---|---|
| `sub` | The consenting user |
| `azp` | `openai-chatgpt` \| partner client id |
| `idp_origin` | `keycloak` |
| `mcp_tier` / `aud` | `external` only; server URIs limited to the curated external catalog |
| `groups` | `mcp-external-curated` only |

### 6.5 End customers — Auth0 broker (patient-facing agents)

Front leg: Keycloak brokers Auth0. Auth0's forthcoming native XAA/ID-JAG support may later replace the broker leg; claims unchanged.

| Claim | Value on this path |
|---|---|
| `sub` | Customer identity (brokered Auth0 subject) |
| `idp_origin` | `auth0` |
| `mcp_tier` / `aud` | `external` + patient-facing server URIs |
| `scope` | SMART-style `patient/...` scopes only; `mcp:` scopes forbidden |
| `fhir_patient` | Mandatory — resolved by Keycloak mapper from the customer↔patient linkage store |

MCP servers MUST apply `fhir_patient` as a hard compartment filter on every FHIR interaction. A missing or unresolvable linkage means no token is issued, not a token without the claim.

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

**Kong DP (both tiers), on every request:** verify signature against cached JWKS; `iss` exact match; `exp/nbf/iat` with ≤ 30 s skew; tier audience matches the DP's tier; `jti` present; if `cnf` present, mTLS client cert thumbprint MUST match, and absence of a client cert is a hard failure; map `groups`/`scope` through MCP ACLs to tool visibility; inject `jti`, `sub`, `azp`, `act.sub`, `idp_origin` as upstream headers for the MCP server and strip any client-supplied copies of those headers.

**MCP servers, on every tool call:** re-verify signature and `iss` (do not trust the DP blindly — defense in depth); `aud` contains this server's URI; scope authorizes this specific tool + verb; when `fhir_patient` present, compartment-filter; when absent on a path that requires it, reject.

**Both:** rejections return RFC 6750 `WWW-Authenticate` errors without echoing token contents; all rejections are audit events.

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

## 10. Keys, rotation, FIPS

Keycloak realm keys rotate every 90 days with a 7-day overlap (old key remains in JWKS for verification only). Athenz service certs: ≤ 30 day lifetime, SIA-rotated. All signing and TLS on the plane runs on FIPS 140-3 validated modules; the DP fleet runs FIPS-mode builds. Key ceremonies and rotations are change-managed and logged to the same SIEM pipeline as config changes.

## 11. Contract versioning

Tokens carry `mcp_contract: "1.0"`. Additive optional claims = minor version; any change to mandatory claims, audience scheme, or scope grammar = major version with a dual-validation migration window. The contract file lives in the platform repo; changes require API Gateway Platform + Security sign-off.

---

## Appendix A — Pilot agent, end to end

Registering one internal agent (`prior-auth-agent`) on the 6.3 path.

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

