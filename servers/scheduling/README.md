# scheduling — hand-built scheduling MCP server

Stateless (2026-07-28) OAuth 2.1 resource-server MCP server on the MCP SDK —
**hand-built**, not generated; see `../README.md` for the authorization model
and the phase 3 walkthrough. There is no API-key auth: every request must
carry a hub JWT, validated in-server (issuer, `aud mcp://srv/scheduling`,
per-tool scope with 403 `insufficient_scope` step-up). Continuity is stateless
by design — a hold returns an explicit `slot_hold_id` handle and hold state
lives in Postgres (held-only partial-unique index, migrated under a pg advisory
lock), so either replica can confirm or release the hold. DPoP-bound tokens
(`cnf.jkt`) are authoritatively re-validated in-server by `requireDpop`
(`src/dpop.ts`), with `dpopSchemeShim` normalizing the `DPoP` auth scheme
first; bearer tokens are unaffected.

Tools: `find-slots`, `hold-slot`, `confirm-hold`, `release-hold`. `find-slots`
is the floor (no scope); `hold-slot` needs `mcp:scheduling:hold-slot:execute`,
and `confirm-hold`/`release-hold` need `mcp:scheduling:confirm:execute` — a
missing scope returns a single-shot 403 `insufficient_scope` step-up.

Run: `npm install && npm run build && npm start` (the phase 3+ compose stacks
build it via the Dockerfile). Key env vars, with lab defaults: `PORT` (3000),
`HOST`, `DATABASE_URL` (Postgres hold store), `HOLD_TTL_S` (300),
`MCP_RESOURCE_URI`, `MCP_ISSUER`, `MCP_AUTHORIZATION_SERVERS`, `MCP_JWKS_URI`,
`PUBLIC_BASE_URL`, `DPOP_HTU`.
