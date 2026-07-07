# Phase 0 — Skeleton stack

Keycloak 26 (realm `mcp-plane`, imported from `realm/mcp-plane.json`) + Postgres,
HAPI FHIR JPA (R4), and the observability spine (OTel collector → Loki + Tempo → Grafana).

## Bring-up

```sh
cp .env.example .env        # then change every value
docker compose up -d
./seed-synthea.sh           # ~50 synthetic patients into HAPI
../../tests/phase0.sh       # acceptance checks — must be green
```

## Endpoints

| Service | URL |
|---|---|
| Keycloak | http://localhost:8080 |
| HAPI FHIR | http://localhost:8081/fhir |
| Grafana | http://localhost:3000 |
| OTLP (gRPC / HTTP) | localhost:4317 / localhost:4318 |

Keycloak exports its own traces to Tempo (via the collector), so the spine
carries real data from first boot — check Grafana → Explore → Tempo.

## Notes

- The realm export references `${PHASE0_CLIENT_SECRET}`; Keycloak substitutes
  it from the container environment at import. No secrets in git.
- Realm changes go through the export in `realm/`, never hand-edits to live
  state (see CLAUDE.md). To re-import after editing the export:
  `docker compose down && docker compose up -d` re-imports only if the realm
  does not exist — for phase 0, wipe with `down -v` and re-seed.
- Reset everything: `docker compose down -v`.
