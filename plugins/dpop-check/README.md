# dpop-check — DPoP sender-constraint enforcement (RFC 9449)

The public-client analogue of `cnf-check`. Where `cnf-check` binds a token to a
TLS client certificate (`cnf.x5t#S256`), this binds a token to a client-held key
(`cnf.jkt`): every request must carry a fresh DPoP proof signed by that key, so a
stolen access token is useless without the private key. It is the early-rejection
layer for the workforce `workforce-dpop` client; the MCP servers' `requireDpop`
middleware is the authoritative re-check (contract §8: servers re-validate).

What it does, in the `access` phase, when the access token carries `cnf.jkt`:

- The token MUST be presented under the `DPoP` authorization scheme (RFC 9449
  §7.1) → else 401, reason `wrong_auth_scheme`.
- Exactly one `DPoP` proof header → else `missing_proof` / `multiple_proofs`.
- Proof header is a well-formed `dpop+jwt` with `alg=ES256` and a public EC
  P-256 `jwk` (no private `d` member) → else `bad_proof_header` / `bad_proof_jwk`.
- RFC 7638 thumbprint of the proof's key equals the token's `cnf.jkt` → else
  `thumbprint_mismatch`.
- `htm` equals the request method; `htu` equals this request's URL (query and
  fragment stripped); `iat` within ±60 s; `ath` equals `base64url(SHA-256(token))`
  → else `htm_mismatch` / `htu_mismatch` / `stale_proof` / `ath_mismatch`.
- `jti` is present and single-use — replay is caught in an nginx shared dict
  (`dpop_jti`), authoritative because the internal DP is the single entry point
  → else `proof_replay`.
- Tokens without `cnf.jkt` pass through untouched (the `claude-code` bearer path
  is unaffected).
- Every rejection emits a one-line JSON audit record (contract §9 field names,
  joinable by `token_id`/`jti`) for the Phase 6 audit spine.

## Scope boundary — this layer does not verify the proof signature

Consistent with the repo doctrine that the DP performs no cryptographic token
validation on first-party routes (the tier wall base64-decodes the access token
without verifying its signature), this plugin does **not** verify the proof's
ECDSA signature. It verifies structure, key-to-token binding, and request
binding. The authoritative signature check is the servers' `requireDpop`
(jose `EmbeddedJWK`, `plugins`… see `servers/*/src/dpop.ts`).

The only attack this split leaves for the server to catch is a proof carrying the
correct public key but an invalid signature — which requires possessing the
(public, derivable) key yet not the private key. Every cheaper attack shape
(no proof, wrong key, replay, wrong htu/htm/ath, stale) is rejected here, at the
edge, before the request reaches a server. Adding OpenSSL EC verification in Lua
would close the residual at the DP too, at the cost of a fragile hot-path
dependency; deferred deliberately.

## Deployment (see `compose/phase5/`)

Mounted into the internal DP at `/opt/kong-plugins/kong/plugins/dpop-check`,
enabled via `KONG_PLUGINS=bundled,cnf-check,dlp-egress,vendor-token,dpop-check`,
with `KONG_NGINX_HTTP_LUA_SHARED_DICT="dpop_jti 5m"` for the replay cache. Schema
registered with the Konnect CP by `setup-phase5.sh` (`ensure_plugin_schema
dpop-check`), applied globally in `deck/internal.yaml` next to `cnf-check`.
