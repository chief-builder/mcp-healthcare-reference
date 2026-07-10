# fhir-clinical — generated FHIR MCP server

Stateless (2026-07-28) OAuth 2.1 resource-server MCP server over HAPI FHIR,
**generated** from `openapi.json` by `openapi-mcp-generator` — see
`../README.md` for the exact generator flags, the authorization model, and
the Claude Code walkthrough. There is no API-key auth: every request must
carry a hub JWT, validated in-server (issuer, `aud mcp://srv/fhir-clinical`,
per-tool scope with 403 `insufficient_scope` step-up, `groups` visibility).
The hand-written `src/authz-hook.ts` (preserved across regeneration)
hard-scopes queries to the token's `fhir_patient` compartment when present.

Tools (from `openapi.json`): `getPatient`, `patientEverything`,
`searchObservation`, `searchCondition`, `searchMedicationRequest`.
`patientEverything` is `mcp-clinical-tools`-only and requires the step-up
scope `mcp:fhir-clinical:everything:read`.

Run: `npm install && npm run build && npm start` (the phase 3+ compose
stacks build it via the Dockerfile). Key env vars, with lab defaults:
`PORT` (3000), `UPSTREAM_BASE_URL` (`http://hapi:8081/fhir`),
`MCP_RESOURCE_URI`, `MCP_AUTHORIZATION_SERVERS`, `MCP_JWKS_URI`.
