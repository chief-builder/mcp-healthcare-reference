# First-party MCP servers (Phase 3)

Two OAuth 2.1 resource-server MCP servers, fronted by the internal Kong tier.
Both are stateless (2026-07-28 model) and validate their own resource audience,
per-tool scope, and (FHIR) patient compartment — the DP only enforces the tier
wall (server is authoritative, DP is the cheap early rejection; arch doc §6).

| Server | Resource URI | Endpoint (internal) | Built |
|---|---|---|---|
| `fhir-clinical` | `mcp://srv/fhir-clinical` | http://localhost:8100/fhir-clinical/mcp | **generated** from `fhir-clinical/openapi.json` via `openapi-mcp-generator` |
| `scheduling` | `mcp://srv/scheduling` | http://localhost:8100/scheduling/mcp | **hand-built** on the MCP SDK; Postgres-backed slot holds |

## Authorization model

- **Visibility (group):** `tools/list` returns only tools whose `x-mcp-group` the
  token's `groups` include. `patientEverything` is `mcp-clinical-tools`-only.
- **Execution (scope):** a tool's `x-mcp-scope` must be held or the server
  returns **403 `insufficient_scope`** naming the scope (single-shot step-up).
  Floor read tools need no scope; `$everything` and scheduling writes are step-up.
- **Compartment (FHIR):** when the token carries `fhir_patient` (Auth0 patients),
  `fhir-clinical/src/authz-hook.ts` hard-scopes every query to that patient and
  blocks by-id reads of anyone else (contract §6.5).
- **Sender-constraint (DPoP):** DPoP-bound tokens (`cnf.jkt`) are authoritatively
  re-validated in-server by `requireDpop` (`src/dpop.ts`), with `dpopSchemeShim`
  normalizing the `DPoP` auth scheme first; bearer tokens are unaffected.

## Regenerating the FHIR server

Edit `fhir-clinical/openapi.json` (tools + `x-mcp-scope`/`x-mcp-group`), then run
`openapi-mcp-generator` (sibling repo) with `--provider generic --authz-hook`,
`--resource-uri mcp://srv/fhir-clinical`,
`--auth-server http://localhost:8080/realms/mcp-plane`,
`--jwks-uri http://keycloak:8080/realms/mcp-plane/protocol/openid-connect/certs`,
`--upstream-auth none`. `src/authz-hook.ts` is hand-written and preserved.

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
