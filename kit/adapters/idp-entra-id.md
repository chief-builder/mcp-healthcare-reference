# Microsoft Entra ID — Adapter Guide

**Kit adapter B6** · Status: **desk-checked** (not validated; the planned
real-tenant validation leg — plan item B8 — targets an Entra dev tenant first)

## Shape 1 — Brokered behind the hub (supported today)

The shape the lab already proves with fake-ping and the real Auth0 leg:
Entra authenticates the workforce; the hub brokers the OIDC leg and mints
every plane token. Entra tokens never reach a gateway, server, or broker
(IDN-01).

### Entra side

- App registration for the hub broker: web platform, redirect =
  `HUB_ISSUER`'s broker endpoint (exact URI), `openid profile` only.
- Emit group membership: **app roles are preferred over the groups claim.**
  The `groups` claim carries object-ID GUIDs (and overflows past 200 groups
  into a Graph link — silently breaking mapping); app roles emit stable
  developer-chosen strings in `roles`. Assign roles to the directory groups
  that correspond to plane roles.
- Conditional Access: require MFA for the hub-broker app. This is the
  enforcement backstop for `amr` (below).

### Hub side (Keycloak reference)

Identity-provider entry (OIDC, discovery from the tenant's
`v2.0/.well-known` document) plus broker mappers:

| Entra claim | Contract claim | Mapper rule |
|---|---|---|
| `oid` (not `sub`) | linked hub user → stable `sub` | `oid` is tenant-stable; Entra's `sub` is *per-app pairwise* — using it breaks cross-client identity. Never map `email`/`preferred_username` to `sub` (IDN-07). |
| `roles` (app roles) | `groups` → `mcp-*` | explicit table, e.g. `Clinical.Tools` → `mcp-clinical-tools`; unmapped roles drop (IDN-05) |
| `amr` | `amr` | passthrough. **Caveat:** on some Entra flows `amr` reports only `["pwd"]` even after CA-enforced MFA, or the claim needs the claims-mapping opt-in. If the tenant cannot surface `mfa` in `amr`, do not fake it — record the CA policy ID as the compensating control and gate clinical scopes on group membership instead (IDN-08 delta, documented). |
| — | `idp_origin` | constant `entra` (extend `IDP_ORIGINS`) |
| `email`, `name`, … | **dropped** | hub mappers must not forward directory PII into access tokens (IDN-04) |

### MFA propagation

Belt and braces: (1) CA policy requires MFA at Entra for the broker app;
(2) the hub forwards `amr` when the tenant emits it truthfully. Acceptance
probe IDN-08 must be run against the *hub's* token, which is what the plane
consumes.

### Known limitations (brokered shape)

- `groups`-claim GUIDs and the 200-group overage — use app roles (above).
- `amr` fidelity varies by flow and tenant config (above).
- Guest (B2B) accounts surface a different `oid`/`iss` pairing per tenant;
  decide the linkage rule before onboarding guests.

## Shape 2 — EMA / ID-JAG issuer (target state; **not available**)

MCP Enterprise-Managed Authorization (stable extension since 2026-06) lets
the enterprise IdP issue an **ID-JAG** identity assertion that the hub
accepts as a grant — replacing the interactive brokered redirect with a
silent, policy-controlled exchange. Contract §6's invariant applies: when
this front leg upgrades, **no claim in the canonical token changes**.

As of July 2026 Microsoft has not shipped ID-JAG issuance (Okta is the first
mover). Track it; when it lands, the hub-side change is accepting the
assertion as a grant (HUB-17) plus the same mapping table above.

## Entra as the hub itself — not recommended where SC-* is in scope

Scored against `hub-requirements.md` (desk-checked, July 2026):

| Req | Entra status |
|---|---|
| HUB-06 two-level `aud` | ❌ one resource per access token (`.default` model); no RFC 8707 multi-resource `aud` |
| HUB-07 RFC 8693 | ❌ OBO flow is functionally similar but not the RFC 8693 wire protocol; no `act` chain semantics |
| HUB-08 cert-bound (RFC 8705) | ❌ mTLS-bound tokens "under investigation" for confidential clients; nothing shipped |
| HUB-09 DPoP (RFC 9449) | ❌ not supported; MSAL offers proprietary Signed HTTP Request (SHR) PoP instead — gateways and servers in this kit validate RFC 9449, not SHR |
| HUB-03 claim shaping | ◐ claims-mapping policies + custom claims providers exist but cannot produce the full contract shape (e.g. suppressing standard claims, opaque `jti` guarantees) |
| HUB-16 declarative config | ◐ Graph/Terraform automation, no full-fidelity export/re-import round trip |

Consequence: with Entra as hub, SC-01 and SC-02 cannot be claimed, TIER-01
needs an emulation, and IDN-09 delegation is out. **Broker Entra behind the
hub.** Revisit if Microsoft ships DPoP/RFC 8705.
