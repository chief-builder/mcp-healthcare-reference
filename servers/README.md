# First-party MCP servers (Phase 3)

Two OAuth 2.1 resource-server MCP servers, fronted by the internal Kong tier.
Both speak **MCP 2026-07-28** (the current spec revision) on the official
TypeScript SDK v2 — no `initialize` handshake, no sessions, every request
self-describing — and fall back to stateless 2025-11-25 serving for clients
that have not migrated. Each validates its own resource audience, per-tool
scope, and (FHIR) patient compartment; the DP adds the tier wall and early
rejection, but the server is authoritative (arch doc §6).

| Server          | Resource URI              | Endpoint (internal)                     | Built                                                                          |
| --------------- | ------------------------- | --------------------------------------- | ------------------------------------------------------------------------------ |
| `fhir-clinical` | `mcp://srv/fhir-clinical` | http://localhost:8100/fhir-clinical/mcp | tool catalogue generated from `fhir-clinical/openapi.json`; runtime hand-built |
| `scheduling`    | `mcp://srv/scheduling`    | http://localhost:8100/scheduling/mcp    | hand-built; Postgres-backed slot holds                                         |

The directory is an npm workspace. `shared/` (`@mcp-lab/shared`) holds
everything the two servers have in common, so a security fix lands once:

| Module                         | Responsibility                                                                                             |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `shared/src/app.ts`            | Express host: Host/Origin guard, PRM routes, middleware order, SDK `createMcpHandler` mounting             |
| `shared/src/token-verifier.ts` | JWT validation against the claims contract (PS256/ES256, audience, tier, mandatory claims, `fhir_patient`) |
| `shared/src/dpop.ts`           | RFC 9449 proof re-validation for `cnf.jkt`-bound tokens                                                    |
| `shared/src/tool-policy.ts`    | Per-tool step-up scope, per-resource patient scope, MFA requirement                                        |
| `shared/src/audit.ts`          | One JSON audit line per `tools/call` (contract §9), no token material                                      |
| `shared/src/config.ts`         | Environment readers; every problem reported together at startup                                            |

## Authorization model

Request pipeline for `POST /mcp`: Host/Origin guard → `DPoP` scheme shim →
bearer validation → DPoP proof → batch rejection → per-tool policy → MCP handler.

- **Visibility (group):** `tools/list` returns only tools whose required group
  the token's `groups` include. `patientEverything` is `mcp-clinical-tools`-only.
- **Execution (scope):** a tool's required scope must be held or the server
  returns **403 `insufficient_scope`** naming the scope (single-shot step-up).
  Floor read tools need no scope; `$everything` and scheduling writes are step-up.
- **MFA (clinical scopes):** scopes listed in `MCP_MFA_SCOPES` (default
  `mcp:fhir-clinical:everything:read`) also require the token's `amr` to
  include `mfa`; otherwise **401 `insufficient_user_authentication`**
  (RFC 9470) so the client re-authenticates with MFA (contract §3 `amr`).
- **Defense in depth:** the same policy runs again inside every tool handler,
  and JSON-RPC batch arrays are refused (`-32600`) — batching is not part of
  MCP since 2025-06-18, and a batch must never carry a call past the HTTP-layer
  check.
- **Compartment (FHIR):** when the token carries `fhir_patient` (Auth0 patients),
  `fhir-clinical/src/authz-hook.ts` hard-scopes every query to that patient and
  blocks by-id reads of anyone else (contract §6.5). Patient tokens also need
  the per-resource scope (`patient/Observation.read`, …).
- **Sender-constraint (DPoP):** DPoP-bound tokens (`cnf.jkt`) are re-validated
  in-server (`shared/src/dpop.ts`); bearer tokens are unaffected.

## Configuration

Read once at startup; an invalid value stops the server with a list of every
problem. Defaults are the lab's.

| Variable                                                        | Server     | Default                                                                   |
| --------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------- |
| `HOST` / `PORT`                                                 | both       | `127.0.0.1` / `3000` (loopback bind turns on the Host check)              |
| `PUBLIC_BASE_URL`                                               | both       | `http://HOST:PORT` — what clients and DPoP proofs name                    |
| `MCP_RESOURCE_URI`                                              | both       | `mcp://srv/fhir-clinical` / `mcp://srv/scheduling`                        |
| `MCP_AUTHORIZATION_SERVERS`                                     | both       | fhir: `http://localhost:8080/realms/mcp-plane`; scheduling: **required**  |
| `MCP_JWKS_URI`                                                  | both       | fhir: Keycloak `…/certs` on the compose network; scheduling: **required** |
| `MCP_ISSUER`                                                    | both       | first authorization server                                                |
| `ALLOWED_ORIGINS`                                               | both       | none (any browser `Origin` is refused)                                    |
| `DPOP_HTU`                                                      | both       | `PUBLIC_BASE_URL/mcp`                                                     |
| `MCP_MFA_SCOPES`                                                | both       | fhir: `mcp:fhir-clinical:everything:read`; scheduling: none               |
| `MCP_REQUIRED_SCOPES`                                           | fhir       | none                                                                      |
| `UPSTREAM_BASE_URL`                                             | fhir       | `http://hapi:8081/fhir`                                                   |
| `UPSTREAM_API_KEY`                                              | fhir       | unset (server-owned credential; the caller's token is never forwarded)    |
| `MAX_FHIR_COUNT` / `UPSTREAM_TIMEOUT_MS` / `MAX_UPSTREAM_BYTES` | fhir       | `100` / `10000` / `2000000`                                               |
| `DATABASE_URL`                                                  | scheduling | **required** (`postgres://…`)                                             |
| `HOLD_TTL_S`                                                    | scheduling | `300`                                                                     |

## Develop and test

```sh
npm ci                  # Node 24 (see ../.nvmrc)
npm test                # vitest, offline: in-memory issuer, PGlite for Postgres
npm run test:coverage
npm run lint && npm run format:check && npm run typecheck
npm run build
docker build -f fhir-clinical/Dockerfile .   # images build from this directory
```

The tests drive the servers over real HTTP with the SDK's own v2 client pinned
to 2026-07-28, plus raw requests for the attack shapes (batches, wrong
audience, missing MFA, bad DPoP proofs). Live, end-to-end coverage through
Kong is `tests/phase3/` and `tests/phase7/`.

## The FHIR tool catalogue

`fhir-clinical/src/tools.ts` was generated from `fhir-clinical/openapi.json`
(tools + `x-mcp-scope`/`x-mcp-group`) by `openapi-mcp-generator`. Since the SDK
v2 migration the server runtime is hand-maintained: to change tools, edit
`openapi.json` and update `tools.ts` to match (regenerate only the catalogue —
running the generator over the whole server would replace the 2026-07-28
runtime). `src/authz-hook.ts` is hand-written.

## Connecting real Claude Code (manual demo)

`mcp.json.example` points Claude Code at the internal DP. Copy it to `.mcp.json`
in a workspace; Claude Code discovers Protected Resource Metadata from the
server, brokers login through Keycloak → fake-Ping (sign in as `dr-alice`), and
lists tools.

1. Add Claude Code's OAuth callback (printed on first connect) to the
   `claude-code` client's redirect URIs in `realm/mcp-plane.json`.
2. **Lists only role-permitted tools:** `dr-alice` (clinical) sees the FHIR
   tools incl. `patientEverything`; a non-clinical login would not.
3. **Step-up:** invoking `patientEverything` on a floor token returns 403
   `insufficient_scope`; Claude Code re-authorizes for
   `mcp:fhir-clinical:everything:read` and retries — a consented step-up.

The automated equivalents live in `tests/phase3/`.
