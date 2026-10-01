# fhir-clinical — FHIR MCP server

Stateless MCP 2026-07-28 OAuth 2.1 resource server over HAPI FHIR. The tool
catalogue (`src/tools.ts`) was generated from `openapi.json`; the runtime is
built on `@mcp-lab/shared` — see `../README.md` for the authorization model,
configuration table, tests, and the Claude Code walkthrough. Every request must
carry a hub JWT, validated in-server (issuer, `aud mcp://srv/fhir-clinical`,
contract claims, per-tool scope with 403 `insufficient_scope` step-up, MFA on
the clinical step-up scope, `groups` visibility). The hand-written
`src/authz-hook.ts` hard-scopes queries to the token's `fhir_patient`
compartment when present.

Tools: `getPatient`, `patientEverything`, `searchObservation`,
`searchCondition`, `searchMedicationRequest`. `patientEverything` is
`mcp-clinical-tools`-only and requires the step-up scope
`mcp:fhir-clinical:everything:read` plus `amr` containing `mfa`.

| File                | Role                                                          |
| ------------------- | ------------------------------------------------------------- |
| `src/index.ts`      | Load and validate config, listen                              |
| `src/config.ts`     | Every setting and its default                                 |
| `src/mcp-server.ts` | Per-request McpServer: visibility, policy, audit, upstream    |
| `src/tools.ts`      | Tool catalogue (generated from `openapi.json`)                |
| `src/upstream.ts`   | FHIR call with `_count` clamp, timeout, and response-size cap |
| `src/authz-hook.ts` | Patient compartment filter                                    |

Run locally: from `servers/`, `npm ci && npm run build && node fhir-clinical/dist/index.js`.
The phase 3+ compose stacks build the image with context `servers/`.
