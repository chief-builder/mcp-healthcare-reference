# Token Claims Contract — Portable Blueprint

**Kit blueprint A2** · Derived from `docs/mcp-token-claims-contract.md` v1.0-draft
· Machine-readable shape: `schemas/canonical-jwt.schema.json` · Fixtures: `vectors/`

One canonical JWT shape that every component of the MCP plane validates
against, regardless of which grant path produced the token. Gateway ACLs,
server permission logic, and SIEM parsing are written once against this
vocabulary. Controls: IDN-01..09, TIER-01..03 (see `control-catalog.md`).

## 1. Deployment parameters

A deployment binds these before anything else is configured. Everything below
is stated in terms of them.

| Parameter | Meaning | Lab value (reference) |
|---|---|---|
| `HUB_ISSUER` | The single token authority for the plane | `http://keycloak:8080/realms/mcp-plane` (production: HTTPS) |
| `TIER_AUD(internal)`, `TIER_AUD(external)` | Tier audience URIs | `mcp://tier/internal`, `mcp://tier/external` |
| `SRV_AUD(<server>)` | Per-server resource URIs | `mcp://srv/scheduling`, `mcp://srv/fhir-clinical`, … |
| `CONTRACT_VERSION` | Value of the `mcp_contract` pin | `"1.0"` |
| `IDP_ORIGINS` | Enumeration of upstream identity systems | `ping, athenz, homegrown, keycloak, auth0` |
| `GROUPS` | Normalized role vocabulary (prefix required) | `mcp-platform-admin`, `mcp-clinical-tools`, … |

> **Resource-URI note.** RFC 8707 / RFC 9728 / MCP EMA expect the resource
> indicator to be the server's canonical **HTTPS endpoint URL**. New
> deployments SHOULD use endpoint-URL resources from day one; the lab's opaque
> `mcp://` URIs are a documented deviation (issue #13) that preserves the
> two-level-audience property but costs out-of-the-box client interop.

## 2. Token authority (normative)

- Exactly one issuer mints every plane token (IDN-01). Upstream IdPs
  authenticate their populations; the hub normalizes the result. No upstream
  token is ever presented to a gateway, server, or broker.
- JWT access tokens only (no introspection round trip on the request path).
  JWKS cached ≤ 5 min.
- Algorithms: PS256 primary, ES256 permitted; RS256 and all HMAC rejected
  (IDN-02). Production: FIPS 140-3 validated modules.
- Lifetimes: ≤ 300 s m2m, ≤ 600 s interactive (IDN-03). Clock skew ≤ 30 s.

## 3. Claim registry

`M` mandatory on all paths · `C` conditional (mandatory where noted, forbidden
elsewhere unless stated) · `F` forbidden.

| Claim | Req | Rule |
|---|---|---|
| `iss` | M | Exactly `HUB_ISSUER`; checked before all other claims. |
| `sub` | M | Stable identifier of the *effective principal* (human on interactive paths, workload on m2m). Never an email. |
| `aud` | M | Exactly one tier audience **plus** ≥ 1 server resource URI (TIER-01). |
| `azp` | M | The client that requested the token (which application/agent is acting). |
| `exp`, `iat` | M | Standard; `nbf` optional but enforced if present. |
| `jti` | M | Unique, **opaque** token ID; the audit join key (AU-01). Consumers MUST NOT parse its structure. |
| `mcp_tier` | M | `internal` \| `external`; deliberately redundant with `aud` for simple policy engines. |
| `idp_origin` | M | One of `IDP_ORIGINS`; drives audit and anomaly detection (a customer-origin token at the internal tier is always an incident). |
| `mcp_contract` | M | Exactly `CONTRACT_VERSION` (IDN-06). |
| `scope` | M | Space-delimited, per §5 grammar. |
| `act` | C | RFC 8693 §4.1 delegation chain. Mandatory whenever requester ≠ effective principal; chains ≤ 2 deep; delegated scope = intersection of both parties' ceilings (IDN-09). |
| `cnf` | C | Sender-constraint. `{"x5t#S256": …}` on the mTLS m2m path (SC-01); `{"jkt": …}` on the DPoP path (SC-02). A `cnf` the validator cannot satisfy is a rejection, never a no-op. Forbidden where no binding exists. |
| `fhir_patient` | C | Patient resource id. **Mandatory** on the customer path; **forbidden** on all others. Enforced in both directions (AZ-04). |
| `groups` | C | Normalized `GROUPS` names only; mandatory on workforce paths (IDN-05). |
| `amr` | C | Upstream authentication methods; mandatory on interactive paths; policy MAY require `mfa` for designated scopes (IDN-08). |
| `email`, `name`, any directory PII | F | Access tokens carry no PII (IDN-04); display data resolves from `sub` out of band. |

## 4. Audiences

Two-level discipline (RFC 8707): the tier audience is the cryptographic wall
between gateway tiers (TIER-02); the server URI stops a token minted for one
server being redirected at another (TIER-03). Clients request server URIs via
the `resource` parameter; issuer client policy caps which URIs each client may
request (AZ-05).

## 5. Scope grammar

```
mcp:<server>:<tool>:<verb>       verb ∈ read | write | execute
mcp:<server>:*:<verb>            admin-approved only; forbidden on external tier
patient/<Resource>.<verb>        SMART-style; customer path only
```

The server is the authoritative scope check; the gateway is cheap early
rejection (AZ-01). Under-scoped calls get one complete `insufficient_scope`
challenge (AZ-02).

## 6. Grant-path profiles (generalized)

Five path shapes produce contract-conformant tokens. The hub exists so that
**no claim changes when a front leg upgrades** (e.g. brokered SSO → EMA/ID-JAG).

| Path | Front leg | Claim deltas from §3 baseline |
|---|---|---|
| Workforce (interactive) | Auth code + PKCE at the hub, brokering the workforce IdP | `idp_origin` = workforce IdP; internal tier; `groups`, `amr` present |
| Workforce, sender-constrained | As above + DPoP-bound client | `cnf.jkt` mandatory; every request needs a proof (SC-02) |
| Workload m2m | mTLS client credentials; cert from the workload-identity system (SPIFFE/attested) | `sub` = `azp` = service identity; `cnf.x5t#S256` mandatory (SC-01); `act` on on-behalf-of exchanges |
| Legacy issuer (transitional) | RFC 8693 token exchange at the hub | `idp_origin` = legacy; bearer (one reason it sunsets); frozen — no new onboarding |
| Customer / patient | Auth code + PKCE, hub brokering the customer IdP | External tier only; SMART scopes only; `fhir_patient` mandatory — no linkage means **no token**, never a token without the claim |
| Third party / partner | Auth code + PKCE directly at the hub; pre-registered, pinned redirects, consent retained | External tier; curated catalog; `groups` = external-curated only |

## 7. Validation requirements (normative)

**Gateway, every request:** tier audience matches the DP's tier (TIER-02);
sender-constraint checks when `cnf` present (SC-01/02), claim-driven so plain
bearer passes (SC-03); inject `jti`/`sub`/`azp`/`act.sub`/`idp_origin` as
upstream headers and strip client-supplied copies. Production target: full
signature verification at the DP on every route (the lab carries it on egress
routes and defers first-party routes to the servers — a documented delta).

**MCP servers, every tool call:** re-verify signature, `iss`, own `aud` —
never trust the gateway (defense in depth); algorithm pin; contract pin;
exactly one tier audience; scope for this tool+verb; `fhir_patient`
compartment when present, rejection when absent on a path that requires it.

**Broker:** independent hub-JWT validation with the same pins plus internal
tier audience (EG-05).

**All rejections:** RFC 6750 `WWW-Authenticate` without echoing token
contents; every rejection is an audit event (AU-01). 401 challenges carry
`resource_metadata`; insufficient scope is single-shot 403 with the complete
required set. `offline_access` never appears in PRM or challenges.

**All OAuth clients on the plane:** validate RFC 9207 `iss` on authorization
responses — including error responses — strict string compare, before any use
of the code (EG-08).

## 8. Audit mapping

Every audit record carries: `token_id`(=`jti`), `principal`(=`sub`),
`acting_agent`(=`act.sub`), `client`(=`azp`), `origin_idp`, `tier`,
`patient_compartment`, plus `server`/`tool`/`verb`/`decision`/`ts` from
context. Records never contain the token or bodies (AU-03). This tuple
answers the regulator's question — which human, through which agent, touched
which tool, in which compartment, when, with what outcome — in one query.

## 9. Versioning

Additive optional claims = minor version. Any change to mandatory claims, the
audience scheme, or the scope grammar = major version with a dual-validation
migration window. Changing the normalized group vocabulary or a registry
scope ceiling is a contract change with the same sign-off.

## 10. Conformance

A deployment conforms when the Workstream-D acceptance probes for IDN-*,
TIER-*, SC-*, and AZ-* pass against it. The claim-shape fixtures in
`vectors/` are the unit-level input: every `valid/` fixture (signed with the
deployment's issuer) MUST be accepted and every `invalid/` fixture rejected by
each validating component.
