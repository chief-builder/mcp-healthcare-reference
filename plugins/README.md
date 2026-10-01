# plugins/

Bespoke Kong plugins on the production critical path (reference
architecture §12). All are loaded from this directory by the phase
compose files (`KONG_PLUGINS`), with schemas registered on the Konnect CP
by the setup scripts and wired declaratively in `deck/internal.yaml`.

- `cnf-check/` — RFC 8705 certificate-bound token enforcement (phase 4):
  binds `cnf.x5t#S256` tokens to the mTLS channel at the internal DP.
- `dlp-egress/` — outbound DLP at the egress routes (phase 5): PCRE
  screening of tool arguments (MRN/SSN-grade patterns) before anything
  leaves for a vendor — the raw body AND, for JSON, every decoded string
  value and key (so `\u002d`-style escapes cannot hide a match); blocks +
  audits by pattern NAME (never the matched text); fail-closed on
  unscannable bodies, declared-JSON bodies that do not parse, and JSON
  nested deeper than 64 levels. Clean passes get an `allow`
  verdict too (phase 6): the audit tuple must show content WAS screened.
- `vendor-token/` — per-sub vendor credential injection (phase 5): calls
  the broker's resolve, swaps the upstream Authorization to the vendor
  token (the hub JWT never transits), and translates needs-consent into
  the MCP authorization-required challenge. Egress is bearer-only: a
  `DPoP`-scheme token is refused with a 401 rather than forwarded (the
  broker does not check proofs, so forwarding would downgrade it to bearer).
- `dpop-check/` — RFC 9449 DPoP sender-constraint enforcement: binds
  `cnf.jkt` tokens to a client-held key at the internal DP (structure +
  thumbprint + htm/htu/iat/ath + `jti` replay via a shared dict). The
  public-client analogue of `cnf-check`; the servers' `requireDpop`
  middleware is the authoritative signature re-check.

## Testing

`make test-plugins` (or `plugins/tests/run.sh`) runs luacheck, then starts a
DB-less `kong/kong-gateway` in Docker with these four plugins, the tier-wall
pre-function lifted from `deck/internal.yaml`, and stub upstreams
(`plugins/tests/stubs/stub.py` plays both an echo upstream and the broker).
`plugins/tests/test_gateway.py` drives every plugin's allow and reject
branches and checks that no token material reaches the gateway logs;
`test_deck_config.py` checks the committed deck routes. No Konnect account is
needed. `openid-connect` is an Enterprise plugin and is not part of this
suite; the live gates (`tests/phase2.sh`–`phase7.sh`) cover it.

Kong 3.14 changed the default route `protocols` to `https` only, so every
route in `deck/*.yaml` sets `protocols: [http, https]` explicitly.
