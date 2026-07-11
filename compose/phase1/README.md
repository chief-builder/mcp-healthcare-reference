# Phase 1 — Identity hub

Everything from phase 0 (infra configs are bind-mounted from `../phase0` —
single source of truth) plus the three brokered identity legs of
`docs/mcp-token-claims-contract.md` §6:

| Leg | Upstream | Contract path |
|---|---|---|
| workforce | `fake-ping` realm (same Keycloak, git-committed) | §6.1, `idp_origin=ping` |
| legacy m2m | `homegrown-issuer` (toy FastAPI AS) + RFC 8693 exchange | §6.2, `idp_origin=homegrown` |
| end customer | **real Auth0 free tenant**, brokered | §6.5, `idp_origin=auth0` |

## Bring-up

```sh
cp .env.example .env        # fill in; Auth0 block optional (tests skip without it)
docker compose up -d --build
./setup-phase1.sh           # post-import setup a realm import can't express
FHIR_BASE=http://localhost:8081/fhir ../phase0/seed-synthea.sh
../../tests/phase1.sh       # acceptance gate — must be green
```

`setup-phase1.sh` is part of the canonical identity config: `realm/*.json`
(imported at first boot, env placeholders substituted from `.env`) plus this
script reproduce the entire live state from scratch. Verify anytime with
`docker compose down -v` and the sequence above.

## Auth0 tenant (one-time)

1. Free tenant at auth0.com; note the domain.
2. Applications → Create → **Regular Web Applications** → callback URL
   `http://localhost:8080/realms/mcp-plane/broker/auth0/endpoint`.
3. Create a database test user (email + password).
4. Security → Attack Protection → **Bot Detection off** (pytest scripts the
   Universal Login form).
5. Fill the `AUTH0_*` block in `.env`. If the stack was already imported
   before the credentials existed, either `docker compose down -v && up` to
   re-import, or update the IdP live (see git history for the kcadm call).

## Endpoints (new vs phase 0)

| Service | URL |
|---|---|
| homegrown issuer | http://localhost:7001 (host) / http://homegrown-issuer:7000 (in-network; macOS AirPlay squats on host 7000) |
| fake-ping realm | http://localhost:8080/realms/fake-ping |

## The linkage store (contract §6.5)

`fhir_patient` is a Keycloak user attribute on the federated Auth0 user —
the lab's customer↔patient linkage store. The pytest fixture links the test
user to a seeded Synthea patient via the admin API on first run; the
`mcp-fhir-patient` client scope maps the attribute into the claim.

## Notes

- Keycloak runs with
  `KC_FEATURES=token-exchange:v1,admin-fine-grained-authz:v1,dpop`
  (explicit `:v1` — unversioned names resolve to V2 on KC 26.2+, and the
  external→internal exchange leg needs the V1 pair). `dpop` enables the
  DPoP sender-constraint (RFC 9449) used by the `workforce-dpop` client,
  whose tokens carry `cnf.jkt`.
- Keycloak validates homegrown subject tokens via the issuer's `/userinfo`
  (that is how V1 external exchange validates `access_token` subject types).
- The two test users in `fake-ping` (`dr-alice` clinical, `bob-analyst`
  analytics) share `FAKE_PING_PASSWORD`; their raw `hospital-*` groups must
  never appear in an mcp-plane token — `tests/phase1/test_normalization.py`
  enforces exactly that.
