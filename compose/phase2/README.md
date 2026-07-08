# Phase 2 — Gateway tiers (Konnect hybrid, two DPs)

Everything from phase 1 plus the real Kong Konnect hybrid split: two cloud
control planes (`mcp-internal`, `mcp-external`), two local data-plane
containers, and git-tracked gateway config in `deck/`.

| Endpoint | Tier | Enforces |
|---|---|---|
| http://localhost:8100 | internal | `aud: mcp://tier/internal` + `mcp-clinical-tools` ACL |
| http://localhost:8200 | external | `aud: mcp://tier/external` + `mcp-external-curated` ACL |

## Bring-up

```sh
cp .env.example .env          # fill in; needs KONNECT_REGION + KONNECT_TOKEN
brew install kong/deck/deck   # NOT homebrew-core 'deck' (a slides tool)
./setup-phase2.sh             # Konnect CPs + certs + stack + keycloak + deck sync
FHIR_BASE=http://localhost:8081/fhir ../phase0/seed-synthea.sh
../../tests/phase2.sh         # acceptance gate — must be green
```

`setup-phase2.sh` provisions everything via the Konnect API — control planes,
pinned DP client certificates (gitignored `certs/`), generated DP env
(`generated/`), and the four uplink alias vars it maintains in `.env`.
**Never click in the Konnect UI**; the UI is read-only by convention here.

## Gateway config workflow (config-as-git)

```sh
vi deck/internal.yaml                 # or deck/external.yaml
deck gateway sync deck/internal.yaml \
  --konnect-addr https://us.api.konghq.com \
  --konnect-control-plane-name mcp-internal   # DECK_KONNECT_TOKEN in env
git commit deck/
```

`tests/phase2/test_resilience_and_git.py` fails if live config drifts from
git. Pass the token via the `DECK_KONNECT_TOKEN` env var, never `--konnect-token`
(argv leaks into process lists and stack traces).

## How the CP-severance test works

DPs point at the real Konnect hostnames, but those hostnames are network
aliases of the `cp-uplink` container — a generic SNI-passthrough nginx that
forwards to the real endpoints via public DNS (`uplink.conf`). SNI and Host
stay honest end-to-end, and `docker compose stop cp-uplink` deterministically
severs the uplink: the phase 2 acceptance test proves the DPs keep serving
their cached config.

## Two design notes

- **Cross-tier replay is 401, not 403.** The openid-connect plugin treats an
  audience mismatch as an authorization failure (403 `insufficient_scope`).
  Per RFC 6750 a token minted for another tier is `invalid_token` → 401, and
  the prototype-plan gate says 401. A small `pre-function` in each deck file
  enforces the tier audience with correct semantics (signature is still
  verified by openid-connect on every request). Same pattern as the
  production `cnf` check (arch doc §A.4). Requires
  `KONG_UNTRUSTED_LUA_SANDBOX_REQUIRES=cjson.safe` on the DPs.
- **Issuer alias.** Tokens are minted via `http://localhost:8080` but DPs
  fetch discovery/JWKS in-network via `http://keycloak:8080`; the plugin's
  `issuers_allowed` lists the localhost form explicitly (exact string match).
