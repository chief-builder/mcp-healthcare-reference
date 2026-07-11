# plugins/

Bespoke Kong plugins on the production critical path (reference
architecture §12). All are loaded from this directory by the phase
compose files (`KONG_PLUGINS`), with schemas registered on the Konnect CP
by the setup scripts and wired declaratively in `deck/internal.yaml`.

- `cnf-check/` — RFC 8705 certificate-bound token enforcement (phase 4):
  binds `cnf.x5t#S256` tokens to the mTLS channel at the internal DP.
- `dlp-egress/` — outbound DLP at the egress routes (phase 5): PCRE
  screening of tool arguments (MRN/SSN-grade patterns) before anything
  leaves for a vendor; blocks + audits by pattern NAME (never the matched
  text); fail-closed on unscannable bodies. Clean passes get an `allow`
  verdict too (phase 6): the audit tuple must show content WAS screened.
- `vendor-token/` — per-sub vendor credential injection (phase 5): calls
  the broker's resolve, swaps the upstream Authorization to the vendor
  token (the hub JWT never transits), and translates needs-consent into
  the MCP authorization-required challenge.
- `dpop-check/` — RFC 9449 DPoP sender-constraint enforcement: binds
  `cnf.jkt` tokens to a client-held key at the internal DP (structure +
  thumbprint + htm/htu/iat/ath + `jti` replay via a shared dict). The
  public-client analogue of `cnf-check`; the servers' `requireDpop`
  middleware is the authoritative signature re-check.
