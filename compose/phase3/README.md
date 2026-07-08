# Phase 3 — First-party MCP servers

Phase 2 gateway tiers + two first-party MCP servers: the **generated**
FHIR-clinical server and the **hand-built** stateless scheduling server (2
replicas, for the statelessness test). Reuses the phase 2 Konnect control
planes and phase 1 Keycloak setup.

## Bring-up

```sh
cp .env.example .env          # or reuse compose/phase2/.env (same creds)
./setup-phase3.sh             # Konnect CPs + certs + stack + keycloak + deck sync
FHIR_BASE=http://localhost:8081/fhir ../phase0/seed-synthea.sh
../../tests/phase3.sh         # acceptance gate
```

All four earlier gates still pass on this stack:
`../../tests/phase0.sh`, `phase1.sh`, `phase2.sh`, `phase3.sh`.

## Endpoints (new vs phase 2)

| URL | What |
|---|---|
| http://localhost:8100/fhir-clinical/mcp | FHIR clinical MCP (workforce, internal tier) |
| http://localhost:8200/fhir-clinical/mcp | FHIR clinical MCP (patients, external tier) |
| http://localhost:8100/scheduling/mcp | scheduling MCP (workforce) |

See `../../servers/README.md` for the authorization model and the Claude Code
walkthrough.

## Notes

- Kong routes for the MCP servers carry only the **global tier pre-function**
  (the cheap tier wall). Everything else — resource audience, per-tool scope
  (step-up), group visibility, patient compartment — is enforced **in-server**.
- The tier pre-function returns early for token-less requests, so unauthenticated
  Protected Resource Metadata discovery works; the server issues the challenge.
- Scheduling holds live in Postgres (`scheduling` db), shared across replicas —
  that is what makes the kill-a-replica statelessness test pass.
