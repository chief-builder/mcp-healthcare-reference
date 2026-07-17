# Ping (PingFederate / PingOne) — Adapter Guide

**Kit adapter B6** · Status: **desk-checked** (not validated — note that the
lab's `fake-ping` leg is a stand-in for exactly this IdP, so the *brokered
pattern* is lab-proven even though no real Ping tenant has been wired up)

Two distinct products; be precise in engagements:

- **PingFederate** — self-hosted federation server; the standards-dense one.
- **PingOne** — the SaaS platform; narrower OAuth surface, closer to Okta's
  shape. This guide's hub scoring is for PingFederate; treat PingOne like
  the Okta guide's posture until scored separately.

## Shape 1 — Brokered behind the hub (supported today)

Ping authenticates the workforce; the hub brokers the OIDC leg (IDN-01).
This is the leg `realm/fake-ping.json` emulates — same mapper layout.

### Ping side

- OIDC client (or SP connection with an OIDC adapter) for the hub broker;
  exact redirect URI; authorization code + PKCE.
- Attribute contract exposing the directory groups (filtered to
  plane-relevant ones) and the authentication context.
- Enforce MFA in the authentication policy for this connection.

### Hub side (Keycloak reference)

| Ping claim | Contract claim | Mapper rule |
|---|---|---|
| `sub` (per attribute contract — pin it to an immutable directory ID, not mail/UPN) | linked hub user → stable `sub` | IDN-07; PingFederate lets the contract choose the subject attribute — choose once, never re-map |
| group attribute | `groups` → `mcp-*` | explicit table; unmapped drop (IDN-05) |
| `amr` / `acr` | `amr` | PingFederate emits per policy; passthrough, verify the `mfa` mark during onboarding (IDN-08) |
| — | `idp_origin` | constant `ping` (already in the lab's `IDP_ORIGINS`) |
| `email`, `name`, … | **dropped** | IDN-04 |

### Known limitations (brokered shape)

- Attribute contracts are powerful enough to emit *anything* — including
  PII; the discipline that access-token-bound attributes stay minimal lives
  on the Ping side too, not just the hub mappers.
- OGNL-based mapping logic is code; keep it in the connection export under
  version control (OPS-01 spirit).

## Shape 2 — EMA / ID-JAG issuer (target state; **not shipped**)

As of July 2026 Ping has not shipped ID-JAG issuance (Okta is first; the
spec is a stable MCP extension since 2026-06). Given PingFederate's history
of fast RFC adoption, expect it; the hub-side landing is identical to the
Okta guide's Shape 2 — assertion in, same mapping table, no claim changes
(contract §6 invariant, HUB-17).

## PingFederate as the hub itself — the strongest candidate

Scored against `hub-requirements.md` (desk-checked, July 2026):

| Req | PingFederate status |
|---|---|
| HUB-07 RFC 8693 | ✅ native token-exchange grant with processor policies (delegation semantics supported) |
| HUB-08 cert-bound (RFC 8705) | ✅ `tls_client_auth` + certificate-bound access tokens |
| HUB-09 DPoP | ✅ supported (11.3+; **verify the deployed version** at engagement) |
| HUB-02 brokering | ✅ IdP connections (OIDC/SAML) with attribute contracts |
| HUB-03/04/05 claim shaping | ✅ attribute contracts + OGNL; full custom claim control |
| HUB-06 two-level `aud` | ✅ resource indicators / audience restriction per access-token manager — confirm multi-value `aud` shape against the JSON Schema during validation |
| HUB-16 declarative config | ◐ admin API + bulk config export; round-trippable with tooling, not a single flat file |

Consequence: PingFederate is the one enterprise IdP that plausibly meets
the full table — the honest framing for a Ping shop is "PingFederate *is*
your hub" rather than running a second AS. The acceptance framework
(Workstream D) runs unchanged against it; that run is the proof, not this
document.
