# Okta — Adapter Guide

**Kit adapter B6** · Status: **desk-checked** (not validated; see the
validation rule in `README.md`)

## Shape 1 — Brokered behind the hub (supported today)

Okta authenticates the workforce; the hub brokers the OIDC leg and mints
every plane token (IDN-01). Mirrors the lab's fake-ping leg one-for-one.

### Okta side

- OIDC web app for the hub broker; redirect = the hub's broker endpoint
  (exact URI); `openid profile groups` scopes.
- Groups claim with a **filter** (regex/starts-with) so only plane-relevant
  Okta groups are emitted — never `.*` (group lists leak org structure and
  bloat the token before the hub even sees it).
- Sign-on policy: require MFA for the broker app (per-app policy or global).

### Hub side (Keycloak reference)

| Okta claim | Contract claim | Mapper rule |
|---|---|---|
| `sub` (Okta user ID, `00u…`) | linked hub user → stable `sub` | org-stable and non-email — usable directly for linkage (IDN-07); never map `email` |
| `groups` (filtered) | `groups` → `mcp-*` | explicit table, e.g. `SG-Clinical` → `mcp-clinical-tools`; unmapped names drop (IDN-05) |
| `amr` | `amr` | Okta emits `amr` on ID tokens (`pwd`, `mfa`, `otp`, `swk`, …); passthrough (IDN-08) |
| — | `idp_origin` | constant `okta` (extend `IDP_ORIGINS`) |
| `email`, `name`, … | **dropped** | IDN-04 |

### Known limitations (brokered shape)

- `amr` granularity depends on the org's authenticator setup; verify the
  `mfa` mark appears for the enrolled factors during onboarding.
- Group filter changes in Okta are invisible to the hub until a login
  carries the new claim — treat the filter as identity config under change
  control (OPS-01 spirit).

## Shape 2 — EMA / ID-JAG issuer (**shipping — first mover**)

Okta's **Cross App Access (XAA)** is the productized ID-JAG leg, and MCP
Enterprise-Managed Authorization went stable 2026-06-18 with Okta as the
first supported IdP (Anthropic and VS Code clients at launch). Flow, mapped
to this platform:

1. The MCP client, already SSO'd, requests an identity assertion (ID-JAG)
   from Okta; admin policy decides silently — no user consent screen.
2. The client presents the assertion at the **hub's** token endpoint
   (JWT-bearer-style grant per the draft profile).
3. The hub validates it against the existing Okta trust, applies the *same
   mapping table as Shape 1*, and mints the canonical token. No claim
   changes (contract §6 invariant); tier walls, scopes, and audit are
   untouched.

Deployment notes:

- The hub must accept the ID-JAG grant (HUB-17). Keycloak has no native
  support yet — budget a custom grant SPI, or front the exchange with the
  RFC 8693 endpoint where the assertion is the subject token; either way
  the acceptance probes for IDN-* must pass unchanged.
- XAA connections are managed in Okta per app pair; the hub is registered
  once as the "requesting app" side.
- Do **not** point XAA directly at MCP servers, bypassing the hub — that
  would re-introduce a second issuer and break IDN-01.

## Okta as the hub itself

Scored against `hub-requirements.md` (desk-checked, July 2026):

| Req | Okta status |
|---|---|
| HUB-09 DPoP | ✅ GA for OAuth clients |
| HUB-07 RFC 8693 | ◐ native token exchange exists — verify feature tier/EA status and `act` semantics for the org |
| HUB-06 two-level `aud` | ◐ a custom authorization server has **one** audience; two-level discipline needs one AS per tier plus server URIs as custom claims — an emulation the acceptance probes (TIER-01/03) must be re-pointed at, and a real divergence from the contract's `aud` semantics |
| HUB-08 cert-bound (RFC 8705) | ❌ certificate-bound access tokens not offered → no SC-01 |
| HUB-03/04 claim shaping | ✅ custom claims with expression language (API Access Management required) |
| HUB-16 declarative config | ◐ Terraform provider covers most; no single-file export/import |

Consequence: Okta-as-hub can carry the DPoP path but not the workload
mTLS path (SC-01) and needs a documented `aud` emulation. For deployments
with the m2m fidelity property in scope, broker Okta behind the hub;
without it, Okta-as-hub is defensible with the deltas written down.
