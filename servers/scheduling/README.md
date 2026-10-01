# scheduling — scheduling MCP server

Hand-built, stateless MCP 2026-07-28 OAuth 2.1 resource server on
`@mcp-lab/shared` — see `../README.md` for the authorization model,
configuration table, and tests. Every request must carry a hub JWT, validated
in-server (issuer, `aud mcp://srv/scheduling`, contract claims, per-tool scope
with 403 `insufficient_scope` step-up). Continuity is stateless by design: a
hold returns an explicit `slot_hold_id` handle and hold state lives in Postgres
(held-only partial-unique index, migrated under a pg advisory lock), so either
replica can confirm or release the hold.

Tools: `find-slots`, `hold-slot`, `confirm-hold`, `release-hold`. `find-slots`
is the floor (no scope); `hold-slot` needs `mcp:scheduling:hold-slot:execute`,
and `confirm-hold`/`release-hold` need `mcp:scheduling:confirm:execute`. Holds
expire after `HOLD_TTL_S` (300 s) unless confirmed or released; only the
subject that placed a hold can confirm or release it.

| File            | Role                                                      |
| --------------- | --------------------------------------------------------- |
| `src/index.ts`  | Load and validate config, migrate the hold table, listen  |
| `src/config.ts` | Every setting and its default (`DATABASE_URL` required)   |
| `src/server.ts` | Per-request McpServer: tools, policy, audit               |
| `src/holds.ts`  | Slot catalogue and hold persistence over an injected `Db` |

Run locally: from `servers/`, `npm ci && npm run build && node scheduling/dist/index.js`
with `DATABASE_URL`, `MCP_AUTHORIZATION_SERVERS`, and `MCP_JWKS_URI` set.
