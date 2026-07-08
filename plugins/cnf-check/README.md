# cnf-check — certificate-bound token enforcement (RFC 8705)

The bespoke DP plugin from the prototype plan (§3 Phase 4) and reference
architecture §12 — small surface, hot path, production critical path.

What it does, per claims-contract §8:

- `certificate` phase: requests a client certificate on every TLS handshake
  (no CA allowlist — the token's `cnf` claim is the authority).
- `access` phase: if the bearer token carries `cnf.x5t#S256`, the SHA-256
  thumbprint of the presented leaf certificate must match it exactly.
  - no client certificate (including any request on a plaintext listener) →
    401 `invalid_token`, reason `no_client_certificate`
  - thumbprint mismatch → 401 `invalid_token`, reason `thumbprint_mismatch`
- Tokens without `cnf` pass through untouched (bearer paths are governed by
  openid-connect + the tier wall, not this plugin).
- Every rejection emits a one-line JSON audit record (contract §9 field
  names, joinable by `token_id`/`jti`) on the proxy log for the Phase 6
  audit spine.

Deployment (see `compose/phase4/`): mounted into the internal DP at
`/opt/kong-plugins/kong/plugins/cnf-check`, enabled via
`KONG_PLUGINS=bundled,cnf-check`, schema registered with the Konnect CP by
`setup-phase4.sh`, and applied globally in `deck/internal.yaml`.
