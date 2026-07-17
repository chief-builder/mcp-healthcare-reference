# Hub Authorization Server — Requirements

**Kit adapter B5** · Status: **normative** (derived from the lab's Keycloak hub,
all gates green) · Controls: IDN-*, TIER-01, SC-01/02, AZ-04/05, EG-08, OPS-01

The platform's identity pattern is: **upstream IdPs vary; one hub issuer
normalizes** (IDN-01). Every adapter guide in this directory assumes a hub AS
exists. A customer has two honest postures:

- **Dedicated hub AS** — a purpose-run AS (lab reference: Keycloak) brokers
  the enterprise IdP(s). The enterprise IdP keeps authentication, MFA, and
  lifecycle; the hub owns token shape. This is the shape the lab proves.
- **Enterprise IdP as hub** — the corporate IdP mints plane tokens directly.
  Only honest if the IdP meets *every* requirement below; the per-IdP guides
  score this. A miss on HUB-08/09 is disqualifying for the sender-constraint
  controls, not a documented delta.

## Requirements

`M` = MUST to claim the associated controls; `S` = SHOULD.

| ID | Req | Requirement | Controls | Keycloak reference (lab) |
|---|---|---|---|---|
| HUB-01 | M | Single token authority: all plane tokens minted here; upstream tokens never accepted by gateway/server/broker. | IDN-01 | realm `mcp-plane`; consumers pin `iss` |
| HUB-02 | M | Brokered OIDC login legs per upstream IdP, with upstream claim ingestion into the hub's session. | IDN-01 | identity brokering (`realm/mcp-plane.json`, fake-ping + Auth0 legs) |
| HUB-03 | M | Claim shaping at issuance: inject `mcp_contract`, `mcp_tier`, `idp_origin`; suppress all directory PII from access tokens. | IDN-04/06 | protocol mappers per client scope |
| HUB-04 | M | Normalize upstream group/role vocabularies to the contract `GROUPS` names; raw upstream strings never reach a token. | IDN-05 | broker mappers → realm groups |
| HUB-05 | M | Propagate upstream authentication methods into `amr` on interactive paths. | IDN-08 | broker `amr` passthrough mapper |
| HUB-06 | M | RFC 8707 `resource` indicators with per-client audience ceilings: exactly one tier audience + requested server URIs, capped by client policy. | TIER-01, AZ-05 | client scopes `srv-*`, `mcp-tier-*`; `fullScopeAllowed=false` |
| HUB-07 | M | RFC 8693 token exchange: legacy-issuer subject tokens in, contract tokens out; `act` stamped on delegation, delegated scope = intersection of ceilings. | IDN-09 | token-exchange policy (homegrown-issuer leg) |
| HUB-08 | M | mTLS client auth (`tls_client_auth`) with certificate-bound access tokens (`cnf.x5t#S256`, RFC 8705), trusting the workload-identity CA. | SC-01 | `client-x509` on :8443, SPIRE-issued SVIDs |
| HUB-09 | M | DPoP-bound token issuance (`cnf.jkt`, RFC 9449) for designated public clients. | SC-02 | `workforce-dpop` client, `dpop.bound.access.tokens` |
| HUB-10 | M | Algorithm pinning: PS256 primary / ES256 permitted; RS256 and HMAC never issued. Published JWKS. | IDN-02 | realm token settings |
| HUB-11 | M | Lifetimes ≤ 300 s m2m / ≤ 600 s interactive. | IDN-03 | realm token policy |
| HUB-12 | M | PKCE S256 required for public clients; **exact-match** redirect URIs (RFC 9700 §2.1) — no wildcards. | — | realm client policy (issue #15 closed) |
| HUB-13 | M | Stable non-email `sub`; unique opaque `jti` on every token. | IDN-07 | realm defaults + mappers |
| HUB-14 | M | Customer-path linkage: inject `fhir_patient` from the account-linkage store on the customer clients only; **no linkage → no token**; claim never present on other paths. | AZ-04 | patient mapper on `patient-agent` |
| HUB-15 | M | RFC 9207 `iss` on authorization responses (clients on the plane validate it, including error responses). | EG-08 | Keycloak emits `iss` natively |
| HUB-16 | M | Declarative, exportable, re-importable configuration so identity config is git-authoritative. | OPS-01 | `realm/*.json` exports |
| HUB-17 | S | Accept ID-JAG assertions (Identity Assertion JWT Authorization Grant) as a grant, so upstream IdPs that ship MCP EMA replace the interactive brokered leg without any claim change (contract §6 invariant). | IDN-01 | not yet in the lab; EMA went stable as an MCP extension 2026-06; Okta (XAA) is the first shipping issuer |

## Evaluating "our IdP as the hub"

Summary scorecard against the requirements that most often fail; the per-IdP
guides carry the detail and citations. **Desk-checked** — see the validation
rule in `README.md`.

| Candidate | HUB-06 two-level aud | HUB-07 RFC 8693 | HUB-08 cert-bound | HUB-09 DPoP | HUB-16 declarative config | Verdict |
|---|---|---|---|---|---|---|
| Keycloak (reference) | ✅ | ✅ | ✅ | ✅ | ✅ realm export | The lab proof |
| PingFederate | ✅ attribute contracts | ✅ native | ✅ native | ✅ (11.3+, verify at engagement) | ◐ admin API / bulk export | **Closest full-fidelity candidate** |
| Okta (custom AS) | ◐ single AS audience; needs per-tier AS + claim-level server audiences | ◐ native token exchange — verify feature tier | ❌ not offered | ✅ GA | ◐ Terraform provider | Hub only with the HUB-06 workaround documented; no SC-01 path |
| Entra ID | ◐ resource-per-token model, no multi-resource `aud` | ❌ OBO is proprietary-wire, not RFC 8693 | ❌ (mTLS-bound "under investigation") | ❌ (SHR only, proprietary) | ◐ Graph/Terraform, no full round-trip | **Broker it behind the hub; do not make it the hub** if SC-01/02 are in scope |

The scorecard is deliberately harsh: a ❌ on HUB-08/09 means the deployment
cannot claim SC-01/SC-02 with that IdP as hub — that is a fidelity-contract
property, not a nice-to-have. Brokered-behind-the-hub sidesteps every ❌
because sender constraint is a hub function.
