# Vendor Token Broker

Implementation of `docs/vendor-token-broker-design.md` — the lab's OAuth
credential custodian for third-party SaaS vendors. **Custodian, not issuer**
(§1/§11): no signing keys, no token or JWKS endpoints; the phase 5 suite
audits the route table for exactly that.

What's faithful to the design doc:

- §4 API: `POST /v1/tokens/resolve`, `GET /v1/authorize/{vendor}`,
  `GET /v1/callback/{vendor}`, `DELETE /v1/grants/{vendor}/{sub}`,
  `GET /v1/grants`, `GET /v1/admin/vendors/{vendor}` (RFC 9457 problems).
- §5 custody: OpenBao KV v2 `vendor-tokens/{vendor}/{sub}` +
  `vendor-clients/{vendor}`, policy-scoped broker token, KV v2 CAS as the
  `refresh_generation` write guard.
- §6 consent: server-side single-use `state` bound to the initiating `sub`,
  PKCE S256 verifier held server-side, scopes capped by the registry
  ceiling, RFC 9207 `iss` validated (strict string compare) before any code
  redemption; replay/mismatch raise `security_event` audit alerts.
- §8/§9: ACTIVE→REFRESHING→ACTIVE(gen+1)/STALE/REVOKE_PENDING; per-entry
  single-flight lock with hard timeout, generation CAS, waiters receive the
  winner's token with zero extra vendor calls; `invalid_grant` → STALE →
  needs-consent.
- §10: vault loss fails CLOSED (503, no grace beyond the ≤60s memory cache).
- §12: `broker.resolve|consent.*|refresh|stale|revoke` JSON audit events,
  hub-jti joinable, no token material ever logged.

Registry (`registry.json`, git-committed — a scope-ceiling change is a
reviewed commit, the lab's §4.5 sign-off): real **github** (endpoints
hardcoded, no RFC 8414 metadata; revocation via GitHub's grant-deletion
API — both documented deviations) and **mockhub**
(`compose/phase5/mock-vendor`, RFC 8414 + RFC 7009, 60s tokens, rotating
refresh tokens) so every gate runs headless.

Lab substitutions vs §3 (conscious losses, per prototype-plan §2): SVID
mTLS ingress → hub-JWT re-validation + compose-network isolation; single
replica → asyncio per-entry locks (multi-replica needs the distributed
lock; the CAS already guards split-brain); KMS envelope encryption →
OpenBao dev mode.

## Configuration

All settings are read once by `app/config.py` and validated at startup; a
bad value stops the container with the variable name in the error.

| Variable | Default | Meaning |
|---|---|---|
| `BROKER_PUBLIC_URL` | `http://localhost:8300` | Base URL for `authorize_uri` and the vendor `redirect_uri` |
| `HUB_ISSUER` | `http://localhost:8080/realms/mcp-plane` | Required `iss` of hub JWTs |
| `HUB_JWKS_URI` | `http://keycloak:8080/realms/mcp-plane/protocol/openid-connect/certs` | Hub signing keys |
| `HUB_TIER_AUDIENCE` | `mcp://tier/internal` | Required tier audience (must start `mcp://tier/`) |
| `VAULT_ADDR` | `http://vault:8200` | OpenBao address |
| `VAULT_TOKEN` | *(empty)* | Policy-scoped broker token (set by `compose/phase5/setup-phase5.sh`) |
| `VAULT_TIMEOUT_S` | `3` | Vault call timeout; expiry fails closed (503) |
| `REGISTRY_PATH` | `/app/registry.json` | Vendor registry; must exist and parse |
| `REFRESH_BUFFER_S` | `300` | Resolve refreshes lazily inside this window (§8) |
| `PROACTIVE_REFRESH_S` | `900` | Sweeper refreshes between the buffer and this (≥ buffer) |
| `SWEEP_INTERVAL_S` | `60` | Background sweeper period; `0` disables it |
| `MASS_STALE_THRESHOLD` | `3` | STALEs per vendor per minute that trigger a page (≥ 1) |
| `GITHUB_CLIENT_ID` | *(unset)* | Enables the `github` registry entry when set |

## Tests

Offline, no stack needed: vault is an in-memory KV v2 fake with real CAS,
vendor HTTP is mocked with respx, and hub keys are generated per run.

```sh
make test-broker          # from the repo root
# or: cd broker && ../.venv/bin/python -m pytest --cov=app
```

The live behaviour (real OpenBao, mockhub, Kong) is still gated by
`tests/phase5.sh`–`tests/phase7.sh`.
