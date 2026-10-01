# Changelog

Notable changes to this repository. Dates are UTC. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.1] — 2026-10-01 — hardening, second pass

### Fixed

- **Phases 2–4 could not start on their own.** `deck/internal.yaml`, shared by
  every phase, references the four custom plugins added in phases 4–5; the
  phase 2–4 data planes did not load them and rejected the whole config, so
  every route returned 404 (the phase 2 gate failed 6 of 11 from a clean
  clone). Every internal data plane now loads all four plugins and every setup
  registers all four schemas (one shared helper, `compose/lib/konnect.sh`).
- Phases 4 and 5 had no `.env.example` or bring-up command block; their setup
  scripts silently copied the previous phase's `.env`. Setup scripts 2–5 now
  fail fast with a clear message on a missing `.env` or placeholder token.
- The k3d `host.k3d.internal` check could fail or hang from a clean clone; it
  now polls with a bounded probe pod.

### Added

- CI smoke tests that run the phase 0 and phase 1 quickstarts from a clean
  checkout and their gates.
- Measured per-phase resource needs (memory, disk, ports, time) and pinned
  versions in `compose/README.md`; all phases verified from a clean clone.

### Verified

- All eight live gates green on 2026-10-01 on `main` (`0638fdf`): 159 of 159,
  nothing skipped, including the real-GitHub egress leg (`list_issues` against
  GitHub's MCP server through DLP, the broker, and Kong) and the Auth0 leg.

### Changed

- Synthetic data made unambiguous: the DLP sample SSN is now `000-12-3456`
  (area 000 is never issued) and the fake-Ping personas are "Alice Clinician"
  and "Bob Analyst".
- `mirror-docs`: runs in a `docs-mirror` environment (so the deploy key can be
  scoped to `main`), publishes the docs repo's README from
  `.github/docs-mirror/README.md` (the old one said the source repo was
  private), and can be re-run manually.
- Dependabot holds Node, `@types/node`, and TypeScript majors (it had proposed
  Node 26 before its LTS date).
- Architecture §5.1 and issue #3: Keycloak has native but experimental CIMD
  since 26.6; not enabled while PKCE is unenforced for CIMD clients
  (keycloak#52795). #3 stays open with a trigger and an implementation plan.

## [2.0.0] — 2026-09-30 — hardening

A repository-wide audit ([`AUDIT.md`](AUDIT.md)) followed by fixes, an MCP
protocol migration, current dependencies, offline tests, and hardened CI.

### Security

- **Per-tool scope bypass via JSON-RPC batch (high).** Both MCP servers checked
  the step-up scope only when the request body was a single object; the SDK
  accepted a batch array and ran each call, so a token without
  `mcp:fhir-clinical:everything:read` could call `patientEverything` (and
  scheduling writes) by wrapping the call in `[...]`, audited as `allow`.
  Batches are now refused (`-32600`) and every tool handler re-checks the same
  policy.
- **Egress DLP bypass by JSON escaping (medium).** `dlp-egress` matched the raw
  body only, so `"MRN-1234567"` passed and reached the vendor as an MRN.
  It now also scans every JSON-decoded string and key; a declared-JSON body
  that does not parse is denied.
- `dpop-check` never saw a second `DPoP` header (`kong.request.get_header`
  returns the first), so "exactly one proof" was enforced only by the servers;
  it now reads all values.
- `vendor-token` refuses DPoP-scheme tokens with a clear 401 instead of
  forwarding a sender-constrained token as a bearer token, and returns 502 on
  malformed broker replies.
- Dependency advisories cleared: npm 2 high + 3 moderate (via MCP SDK 1.29) →
  0; PyJWT 2.10 (20 advisories) → 2.15; starlette 0.46 (14) → 1.7 via FastAPI
  0.142; requests and pytest in the test toolchain.
- Homegrown issuer: constant-time client-secret comparison; runs as non-root.
- Token verifiers now require every contract-mandatory claim (`sub`, `azp`,
  `exp`, `iat`, `jti`).

### Added

- **MFA for clinical scopes.** Scopes in `MCP_MFA_SCOPES` (default
  `mcp:fhir-clinical:everything:read`) require `amr` to include `mfa`;
  otherwise 401 `insufficient_user_authentication` (RFC 9470). Previously
  documented but not enforced.
- Offline test suites, one command (`make test`): MCP servers (vitest, 89
  tests), broker (pytest, 97 tests), kit claim vectors, and the four Kong
  plugins against a DB-less Kong 3.16 (47 tests). Live phase 3 probes for the
  2026-07-28 wire, legacy fallback, batch rejection, and the MFA mark; a live
  phase 5 probe for the escaped-MRN bypass.
- CI: lint, format, type check, tests with coverage, build, image builds,
  link check, shellcheck, actionlint, decK validation, blocking npm/pip audits;
  CodeQL; Dependabot; SHA-pinned actions with least-privilege permissions.
- `SECURITY.md`, `CONTRIBUTING.md`, issue and PR templates, `.editorconfig`,
  `Makefile`, `.nvmrc`, `.python-version`.

### Changed

- **MCP 2026-07-28.** The servers move from `@modelcontextprotocol/sdk` 1.29
  (wire protocol 2025-11-25) to `@modelcontextprotocol/server` 2.2: no
  `initialize`, no sessions, per-request `_meta`, `Mcp-Method`/`Mcp-Name`
  headers, `server/discover`. 2025-era clients are still served by the SDK's
  stateless fallback. The acceptance clients, kit harness, and loop agent speak
  2026-07-28. Resolves #8.
- Duplicated server modules (token verifier, DPoP, audit, host guard) moved into
  one npm workspace package, `servers/shared`. Configuration is centralized per
  component and validated at startup.
- Broker: validated settings, injectable clients, 4xx problems instead of 500s
  on malformed input, vendor network errors mapped to 502/503.
- Runtimes and images: Node 22.14 → 24.21 LTS, TypeScript 6.0, Python 3.12 →
  3.14.7, Kong Gateway 3.9 → 3.16.0.0 (routes declare `protocols` after 3.14's
  default change), Keycloak 26.3 → 26.7.5, Postgres 16 → 18.6, HAPI FHIR
  v8.0.0 → v8.12.0-1, Grafana 11.4 → 13.2.3, Loki 3.7.8, Tempo 3.1.0, OTel
  collector 0.161.0, Alloy v1.20.1, nginx 1.30.5, OpenBao 2.7.0 (pinned),
  SPIRE 1.15.3, spiffe-helper 0.12.1, k3s v1.37.0-k3s1 (pinned), Synthea v4.0.0.
- README rewritten; docs corrected where they had drifted from the code (see
  the PR's claims table).

### Fixed

- Phase 0 quickstart failed from a clean clone: the shared realm export needs
  Auth0 placeholders that only phases 1–4 defaulted.
- `setup-phase1.sh` failed on first run because it did not wait for Keycloak.
- IPv6 loopback `Host: [::1]:port` was rejected by the rebinding guard.
- `confirm-hold` could confirm a hold that expired between its read and write.
- The Synthea jar cache ignored the version, so upgrades kept the old jar.

### Upgrade notes

- Postgres 16 data volumes are not readable by 18: `docker compose down -v`
  (or dump and restore) before bringing an existing stack up.
- Server images now build with context `servers/`
  (`docker build -f servers/fhir-clinical/Dockerfile servers`); compose files
  are updated.
- `scheduling` refuses to start without `MCP_AUTHORIZATION_SERVERS`,
  `MCP_JWKS_URI`, and `DATABASE_URL`.

## [1.0.0] — 2026-07-16

Phases 0–7 of the prototype plan: Keycloak identity hub with fake-Ping, Auth0,
and homegrown-issuer federation; Kong Konnect internal/external data planes with
the tier wall; first-party FHIR and scheduling MCP servers; SPIRE
certificate-bound m2m; vendor token broker on OpenBao with DLP and
vendor-token egress plugins; the `jti` audit spine; the red-team suite with
DPoP sender-constraint; remediation of review issues #1, #2, #4–#7, #9–#16;
and the enterprise rollout kit (workstreams A–E).
