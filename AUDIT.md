# Repository audit — 2026-09-30

Branch `hardening/2026-09-30`, audited at commit `5366956`. Phase 1 of the
hardening pass: findings only, no code changes.

> **Point-in-time record.** Everything below describes the repository *before*
> the fixes. How each finding was resolved (or why it was deferred) is in
> [`CHANGELOG.md`](CHANGELOG.md) under 2.0.0 and in the pull request's claims
> table. Every "Verified" item cites a
file, a test, or a command that was actually run on 2026-09-30; anything that
could not be checked is marked Unverifiable with what would check it.

Method: full read of servers/, broker/, plugins/, deck/, realm/, compose/,
tests/, kit/, docs/ and every README; a fresh clone of this branch was built
and exercised (npm ci/build/audit, pip-audit, gitleaks over the tree and all
94 commits, shellcheck, actionlint, the phase 0 and phase 1 quickstarts and
gates on a real Docker stack, and a live exploit reproduction of finding S1).
Version facts come from the npm/PyPI registries, GitHub release APIs, Docker
Hub, and modelcontextprotocol.io as of today.

---

## 1. What the project does (from the code)

It is a Docker Compose lab (plus a k3d cluster for phase 4) that stands up
Keycloak as a single token issuer brokering three upstream identity sources,
two Kong Konnect data planes enforcing tier audiences with custom Lua plugins
(mTLS `cnf` binding, DPoP proof checking, egress DLP, vendor-token injection),
and two TypeScript MCP servers (a FHIR read server over HAPI/Synthea data and
a Postgres-backed scheduling server) that re-validate every token themselves.
A FastAPI "vendor token broker" keeps third-party OAuth tokens in OpenBao and
hands them to the egress gateway with single-flight refresh, and every
component emits JSON audit lines keyed by the hub token's `jti` into Loki.
Acceptance is a per-phase pytest/shell suite (`tests/phaseN.sh`) that drives
the live stack; there are no offline unit tests.

---

## 2. Accuracy of claims

Full per-claim tables from the three review passes are summarized here; only
the claims that are **Wrong**, **stale**, or **Unverifiable** need action, so
they are listed individually. Everything else (≈150 claims: token alg
pinning, tier-audience checks, PRM path, DPoP re-check, broker routes, KV v2
CAS, rate limits, non-root images, port maps, tool lists, issue states, …)
was **Verified** against code; representative evidence is in the table.

### 2.1 Wrong or stale

| # | Where | Claim | Status | Evidence / what is true |
|---|---|---|---|---|
| A1 | README.md:5, servers/README.md:4, servers/*/README.md:3, arch.md:16, repo description context | "stateless MCP servers (2026-07-28)" | **Wrong (version)** | Stateless *mode* is real (`sessionIdGenerator: undefined`, fhir `mcp-server.ts:504`, scheduling `server.ts:264`). The wire protocol is **2025-11-25**: SDK 1.29.0 `types.js` `LATEST_PROTOCOL_VERSION='2025-11-25'`; servers still perform `initialize`. Issue #8 open. |
| A2 | README.md:46 | "Conformance is to the **draft** MCP 2026-07-28 model" | **Stale** | 2026-07-28 is the released, current revision (`gh api repos/modelcontextprotocol/modelcontextprotocol/releases/latest` → `2026-07-28`, prerelease=false; modelcontextprotocol.io/specification/versioning). |
| A3 | CLAUDE.md status | #8 "deferred off an unstable 12h-old beta" | **Stale** | `@modelcontextprotocol/server` 2.0.0 shipped 2026-07-27; 2.2.0 is `latest` (`npm view`). |
| A4 | Repo description, README.md:3-4 | "three-tier Kong gateway" | **Imprecise** | Two DPs (`kong-internal`, `kong-external`, compose/phase5:132,176); egress is a route set on the internal DP (deck/internal.yaml:141,178; prototype-plan.md:53). "Three tiers on two data planes" is accurate. |
| A5 | overview.html:401 | "3 bespoke Kong plugins" | **Wrong** | 4: cnf-check, dlp-egress, dpop-check, vendor-token (same page lists 4 at :477-480). |
| A6 | compose/phase5/README.md:20 | "registers the three custom plugin schemas" | **Wrong** | setup-phase5.sh:147-150 registers 4. |
| A7 | overview.html:570, prototype-plan.md:79 | plugin enumeration / "two bespoke components" | **Stale** | dpop-check missing. |
| A8 | tests/README.md:5 | "phases 1–6 each create a venv in `phaseN/`" | **Wrong** | Only phase1.sh creates one; phase2–7 reuse `../phase1/.venv`. |
| A9 | tests/README.md:8 | "phases 0–6 all pass" | **Stale** | Everything else says 0–7. |
| A10 | one-pager.md:28; enterprise-rollout-kit-plan.md:99-101; claims-contract:92 | #13/#15/#16 listed as open gaps / "tracked in #13" | **Stale** | All three CLOSED (`gh issue list`); fixes in realm export and scheduling `server.ts:213-227`. |
| A11 | modules-technical.html:127; modules-functional.html:178; overall-functional.html:106 | scheduling lacks Origin validation | **Stale** | Guard present (`servers/scheduling/src/server.ts:219-234`, fix 0435462). |
| A12 | modules-functional.html:182 | "illustrations created with OpenAI image generation" | **Stale** | Commit 2681383 replaced them with hand-authored SVGs. |
| A13 | technical-overview.html:358; kit/playbook/production-choices.md:15 | "Dex-as-Ping" | **Wrong** | Ping stand-in is a second Keycloak realm (`realm/fake-ping.json`); no Dex anywhere. |
| A14 | product.html:451,499-501; one-pager.md:21 | lab "follows" EMA / ID-JAG ("sign in once… no per-app consent") | **Overstated** | No ID-JAG / jwt-bearer grant in realm, servers, or broker; arch.md:43 and contract:111 call EMA a deferred upgrade. |
| A15 | token-lifecycle.html:318-321; overall-functional.html:62; product persona; control-catalog IDN-08; shared-responsibility.md:70 | clinical scopes require the `mfa` amr mark | **Wrong (not enforced)** | `git grep mfa` in servers/plugins/deck/tests: nothing. `realm/fake-ping.json:103-104` hardcodes `amr=["pwd","mfa"]`; the test only checks `amr` presence. |
| A16 | technical-overview.html:311 | MCP clients "Claude Code, Codex CLI, VS Code, loop agent, ChatGPT, patient apps — In place" | **Overstated** | Realm clients: phase0-smoke, claude-code, workforce-dpop, patient-agent, legacy-exchange, loop-agent. |
| A17 | overview.html:447 | "MCP servers use their own backend credentials for FHIR calls" | **Wrong for the lab** | `UPSTREAM_AUTH_MODE = 'none'` hardcoded (mcp-server.ts:40); HAPI is called unauthenticated. (The "hub token never forwarded" half is true.) |
| A18 | overview.html:405 | "Ping, Auth0, Athenz, and homegrown identity paths normalize" | **Overstated** | No Athenz implementation; m2m uses SPIRE. |
| A19 | overview.html:534 | Phase 1 gate includes "a DPoP sender-constrained workforce path" | **Wrong** | Phase 1 legs are workforce/legacy/customer/smoke (tests/phase1/conftest.py:26); DPoP is tested only in phase 7 (P8). |
| A20 | compose/phase2/README.md:56-57 | DP verifies signature "on every request" | **Stale after phase 3** | MCP routes carry only the unverified tier wall (contract:204). |
| A21 | kit/acceptance/README.md "How it degrades"; conformance-profile.md | unreachable endpoints skip, never fail | **Wrong** | Descriptor pointed at a dead port → 16 failed, 17 errors, 15 passed, 10 skipped; only `probes/test_tier.py` catches `ConnectionError`. |
| A22 | kit/blueprints/control-catalog.md:41,62,79-83 | test → phase attributions | **Wrong** | Several swapped (e.g. `test_sub_mismatch_is_rejected` is phase 5, not 7; `test_fhir_patient_compartment` is phase 1, not 3). |
| A23 | kit/playbook/rollout-sequence.md:78 | "`test_sender_constraint.py` mTLS subset" | **Wrong** | That module has no mTLS probes; conformance-profile says SC-01/05 are not portable. |
| A24 | broker-design.md:204 | no-issuance rule "checked in CI" | **Wrong** | Checked in live gates (test_egress_broker.py:224, test_redteam.py:226), not CI. |
| A25 | mirror-docs.yml:2-4; .claude/skills/docs-sync/SKILL.md:79,86; technical-overview.html:401; modules-*.html; enterprise-rollout-kit-plan.md:9; published docs-repo README | source repo is "private" | **Wrong** | `gh repo view` → `visibility: PUBLIC`. |
| A26 | one-pager "Five invariants" vs arch.md:14-18 | two different "five invariants" lists | **Inconsistent** | README points to arch.md's list. |
| A27 | CLAUDE.md "P8 = … (11 probes)" | 11 | **Minor** | 12 functions in P8; 11 `test_dpop_*` + a bearer control. Total 32 is right. |
| A28 | prototype-plan.md:35-36,47; platform-landscape.svg; token-lifecycle.html:267 | tailnet / cloudflared / Caddy ingress | **Not implemented** | No such config in compose/ or deck/; never marked as a deviation. |
| A29 | SKILL.md:7 | "single-file HTML pages … inline CSS/JS/SVG only" | **Partly wrong** | Walkthrough pages load `assets/*.svg`. |
| A30 | kit/blueprints/token-claims-contract.md:146-147 | `valid/` / `invalid/` fixture dirs | **Wrong (minor)** | Files are `vectors/valid.json` / `vectors/invalid.json`. |
| A31 | plugins/dpop-check/README.md:37 | — | **Garbled sentence** | Editorial. |

### 2.2 Numbers and status that are true in count but not re-provable here

| # | Claim | Status | Evidence |
|---|---|---|---|
| U1 | "tests/phase7.sh green at 32 passed, 0 xfail" | Count **Verified**; green **Unverifiable** | 26 functions + 1 parametrized ×6 = 32 collected; no xfail markers. Running it needs Konnect + k3d. |
| U2 | "all eight acceptance gates green (154 tests)" (index, product, one-pager) | Count **Verified**; green **Unverifiable** | Collect-only: 72+11+8+9+16+6+32 = 154 pytest items (phases 1–7) + 4 shell checks in phase 0. 18 of the 72 phase-1 items skip without Auth0; the GitHub leg skips without an App. |
| U3 | Phases 0 and 1 green | **Verified today** | Fresh clone: `tests/phase1.sh` → `54 passed, 18 skipped in 1.29s`; `tests/phase0.sh` → `ALL CHECKS GREEN` (against the phase 1 stack — see §8 for why not against phase 0's own). |
| U4 | Phases 2–7 green | **Unverifiable** | Require a Kong Konnect account/PAT (phases 2+), k3d + SPIRE (4), GitHub App optional (5). |
| U5 | "58 portable probes", "42 controls" (kit) | **Verified** | `pytest kit/acceptance --collect-only` → 58; 42 unique control IDs. Offline vector layer: 15 passed, 4 skipped. |
| U6 | "npm zero vulns 2026-07-10", "last full run 2026-07-12" | **Unverifiable / now false** | No artifact; today's `npm audit` shows 2 high + 3 moderate (§7). |
| U7 | GitHub MCP "47 tools", real issue created/closed end to end | **Unverifiable** | Needs a GitHub App + live run. |
| U8 | Keycloak jti shape `trrtcc:<uuid>` | **Unverifiable** | Needs a live client-credentials token (phase 0 check passes but does not assert shape). |

### 2.3 Links, paths, employer references

- **Relative links:** none broken across README, docs/, kit/, component READMEs, and the HTML site (every `href`/`src`/anchor resolves). The site mirror is byte-identical to `docs/` and the live Pages URL returns 200.
- **External links:** very few real ones (Konnect API host, GitHub Pages URL, json-schema.org, w3.org namespaces); the rest are placeholders (`*.example`) or lab-internal (`localhost`, `keycloak:8080`) and must be excluded from a link checker.
- **Absolute local paths:** none in tracked files (`git grep "/Users/|/home/"` empty).
- **Employer references:** none found by name; all 94 commits are authored by you. One judgment call for you: the design docs repeatedly describe a very specific target estate (PingID workforce IdP, **Athenz** named as "the actual target" in prototype-plan.md:27, a "homegrown AS" with its own owning team, customer AWS/EKS). It names no organization, but the combination could read as a fingerprint of a real employer. I will not change it without your say-so.
- Personal project names `ClaWeb` and "your `openapi-mcp-generator`" appear in prototype-plan.md:30,79 — harmless, noted for completeness.

---

## 3. Currency

Latest-stable values were read from registries/release APIs on 2026-09-30.

| Component | Pinned (where) | Latest stable | Supported? | Upgrade risk |
|---|---|---|---|---|
| **MCP spec** | 2025-11-25 in practice (SDK 1.29) | **2026-07-28** (current) | previous revision | See §3.1 — a protocol migration, not a bump. |
| @modelcontextprotocol/sdk | ^1.29.0 → 1.29.0 (both package.json) | 1.31.0 (1.x) / `@modelcontextprotocol/server` **2.2.0** | 1.x maintained | 1.31 = low risk, fixes the npm-audit findings; still 2025-11-25. v2 = issue #8. |
| Node (runtime) | `node:22.14.0-slim`; `engines >=20`; CI `22` | 22.23.3 / **24.x Active LTS** / 26 current | 22 = maintenance LTS to 2027-04; 22.14 is many security patches behind; **20 is EOL** (engines floor) | 22.14→24: low for express/jose/pg; verify build + tests. |
| TypeScript | ^5.7 → 5.9.3 | 7.0.2 (Go-native) | 5.9 fine | TS 7 is a major; hold. |
| zod | ^3.24 → 3.25.76 | 4.6.5 | 3.x superseded | Major; required only by MCP v2. |
| express / jose / pg | 5.2.1 / 6.2.3 / 8.22.0 | 5.2.1 / 6.2.12 / 8.23.1 | yes | patch-level. |
| Python (images, CI) | `python:3.12-slim` (floating), CI 3.12 | 3.14.7 | 3.12 = security-only to 2028-10 | 3.13/3.14: low risk for this code. |
| fastapi / uvicorn | 0.115.* / 0.32.* | 0.142.2 / 0.54.0 | old 0.x | 0.x minors can break; covered once broker unit tests exist. **Pulls vulnerable starlette 0.46.2.** |
| PyJWT | 2.10.* (broker, tests, issuer) | 2.15.1 | behind | Same major; **20 advisories in 2.10.1** — security-relevant (hub-token validation). |
| hvac / httpx / requests / pytest | 2.3 / 0.28 / 2.32 / 8.3 | 2.4 / 0.28.1 / 2.34.2 / 9.1.1 | ok / ok / advisories / advisories | low. |
| kit/acceptance deps | floors only (`>=`) | — | unpinned | not reproducible; pin. |
| Keycloak | 26.3 | 26.7.5 | 26.3 line no longer patched | Same major; DPoP no longer a preview feature since 26.4. Re-run phases 1/3/4/7. |
| **Kong Gateway** | 3.9 | 3.16; LTS 3.10 / 3.14 | **3.9 out of full support since 2025-12-12** | Custom Lua plugins + pre-function need the Konnect stack to re-verify. |
| OpenBao | `2` (floating) | 2.7.0 | yes | pin for reproducibility. |
| HAPI FHIR | v8.0.0 | v8.12.0-1 | unclear | DB migrations; memory already tight. |
| Postgres | 16-alpine | 18.6 | 16 supported to 2028-11 | no action. |
| nginx | 1.27-alpine | 1.30.x stable | **1.27 mainline superseded** | low. |
| Grafana | 11.4.0 | 13.2.3 | **11.4 EOL 2025-09** | two majors; re-check provisioning. |
| Tempo | 2.6.1 | 3.1.0 | — | 3.0 has breaking config (migration tool exists). |
| Loki / Alloy / OTel collector | 3.3.2 / 1.5.1 / 0.115.1 | 3.7.8 / 1.20.1 / 0.162.0 | pre-1.0 collector renames | medium. |
| SPIRE / spiffe-helper | 1.11.2 / 0.10.0 | 1.15.3 / 0.12.1 | — | one-minor-at-a-time upgrades. |
| k3s (via k3d) | unpinned | — | drifts with host | pin `--image`. |
| GitHub Actions | checkout@v4, setup-node@v4, setup-python@v5 (tags, not SHAs) | v7 / v7 / v7 | run today only because GitHub force-runs them on Node 24 (deprecation annotation on run 36705391839) | low; pin SHAs. |

### 3.1 MCP revision gap

The repo's fidelity contract says "stateless MCP (2026-07-28)". What 2026-07-28
actually changed (modelcontextprotocol.io/specification/2026-07-28/changelog):
`initialize` handshake removed; per-request `_meta` protocol version +
capabilities; `Mcp-Session-Id` removed; `Mcp-Method`/`Mcp-Name` headers
required on POST; GET stream replaced by `subscriptions/listen`; `resultType`
required; error codes renumbered; DCR deprecated in favour of Client ID
Metadata Documents (relevant to open issue #3). The servers implement the
2026-07-28 *architecture* (no sessions, explicit `slot_hold_id` handles) on
the 2025-11-25 *wire*. Migrating means `@modelcontextprotocol/server` 2.x +
`@modelcontextprotocol/express` + zod 4, replacing `metadataHandler` /
`InvalidTokenError` imports, and re-verifying every gateway plugin and the
phase 3/7 harnesses (which send `initialize`) against a live Konnect stack.

---

## 4. Design

**Module boundaries — mostly good.** Each component has one job and a README.
The token verifier, DPoP middleware, and audit writer are separate modules;
the broker splits hub validation / vault custody / vendor legs / HTTP.

Problems:

- **D1 Duplication (TS).** `audit.ts`, `dpop.ts`, `oauth-resource-server.ts` are byte-identical copies in both servers (`diff` → identical); `isLoopbackHost`, `securityGuard`, and the `enforceToolScope` pattern are duplicated inline. The scheduling header claims it "reuses their oauth-resource-server module" — it is a copy. A security fix (e.g. S1) has to be made twice.
- **D2 Configuration scattered and unvalidated.** Each server reads `process.env` at module load with inline defaults; there is no startup validation (e.g. scheduling starts with `jwksUri: ''` and fails on the first request; `parseInt` of a bad value silently yields `NaN`). `issuer: process.env.MCP_ISSUER || '' || undefined` (mcp-server.ts:55) is a no-op expression. Broker config is spread over `main.py`, `hub.py`, `vault_store.py`, `vendors.py` as module globals.
- **D3 Import-time side effects block testing.** Broker modules build the JWKS client, the vault client, and read `registry.json` at import (`hub.py:18`, `vault_store.py:18`, `vendors.py:19`); servers build their pg pool at import. No seam for injecting fakes → no unit tests exist.
- **D4 Dead code.** `UPSTREAM_AUTH_MODE` is a hardcoded constant (`'none'`), so the `env-credential`/`passthrough` branches and `callerToken` plumbing are unreachable (mcp-server.ts:40,296-306,408); `vendors.now()` unused; broker `nonce` in consent state generated but never used.
- **D5 Error handling (broker).** Malformed/non-object JSON, non-integer `min_ttl_s`, or a non-list `required_scopes` produce unhandled 500s or wrong behaviour (a string is iterated char by char) in `/v1/tokens/resolve`; `vendors.endpoints()` and `vendor_user_id()` raise raw `httpx` errors that escape the `VendorError` handler (500 after the state is consumed); `CasConflict` on the REVOKE_PENDING write in `delete_grant` is unhandled. Scheduling returns raw DB error messages to the client (server.ts:171).
- **D6 Logging.** Audit lines are structured JSON and carry no token material (verified by reading every audit call). Operational logs are ad-hoc `console.error` / `print`; no log level control. Acceptable for the lab; worth one small shared logger per language.
- **D7 Config that belongs in config.** Egress DLP patterns and rate limits are in deck (fine — that is config-as-code). The FHIR tool catalogue is embedded in `mcp-server.ts` alongside `openapi.json` (generated-code artifact; acceptable, noted).

---

## 5. Tests

| Suite | What it covers | Runs from clean clone? |
|---|---|---|
| `tests/phase0.sh` | 3 contract claims on a client-credentials token; `$everything` returns data | **No, as documented** (phase 0 Keycloak crashes — §8 O1). Yes against the phase 1 stack. |
| `tests/phase1` (72 items) | Claims contract per leg, IdP-vocabulary normalization | **Yes: 54 passed, 18 skipped** (Auth0 leg). |
| `tests/phase2`–`phase7` (82 items) | Tier wall, CP-severance resilience, config drift, tool visibility/step-up, compartment, statelessness, cert-bound m2m, egress DLP + broker single-flight, audit spine, 32 red-team probes | **No** — need a Kong Konnect account (+ k3d for 4). |
| `kit/acceptance` (58) | Portable probes; offline claim-vector layer | Offline layer **yes** (15 passed, 4 skipped); rest need a live environment. |
| Unit tests | — | **None** in any language. |

Coverage cannot be measured: no unit-test runner exists and the live gates
exercise containers, not instrumented code.

Most important untested paths (offline):
1. Server per-tool scope enforcement for **batched** JSON-RPC (see S1 — the live gates only ever send single requests, which is why it was never caught).
2. `createTokenVerifier` negative cases (wrong alg, two tier audiences, `fhir_patient` on a non-Auth0 token, Auth0 token without it).
3. `requireDpop` (each rejection branch) and `authorize` compartment filter.
4. Broker `hub.validate`, `_consent_scopes`, scope-ceiling denial, the RFC 9207 iss checks in `callback`, `_mark_stale` mass-page threshold, CAS-lost path.
5. Scheduling hold lifecycle (`isCatalogueSlot`, ownership checks, expiry).
6. dlp-egress behaviour on JSON-escaped input (S2) — no test.

---

## 6. CI/CD

Existing: `ci.yml` (push to main + PRs) — `npm ci && npm run build` per server,
`npm audit … continue-on-error: true`, `py_compile` of broker/agent/mock-vendor,
`pip install` broker deps, JSON/YAML parse of realm/registry/deck.
`mirror-docs.yml` — rsyncs the published pages to the public docs repo using
a deploy key.

Gaps:
- No lint, format check, type check (beyond `tsc` during build), or tests; no coverage; no link check; no shellcheck/actionlint.
- `npm audit` is non-blocking, so the current 2 high advisories pass CI green.
- `ci.yml` has **no top-level `permissions`** (defaults to the repo's token permissions); no `concurrency`; no job `timeout-minutes`.
- All actions pinned by mutable tag, not SHA; all target the deprecated Node 20 runtime.
- The broker "import" step is misnamed: it `ast.parse`s a file (a second syntax check), it does not import the app.
- `mirror-docs.yml`: has `permissions: contents: read` (good) but no concurrency (two quick pushes can race the mirror push), no timeout, unpinned actions, and `ssh-keyscan` trust-on-first-use instead of GitHub's published host keys. Its header comment is now wrong (repo is public).
- Kit's offline vector layer and schema validations (which pass) are not run in CI.

---

## 7. Security

| # | Severity | Finding | Evidence |
|---|---|---|---|
| **S1** | **High** | **Per-tool scope / step-up bypass via JSON-RPC batch.** `enforceToolScope` in both servers reads only `req.body.method`; the SDK 1.29 transport accepts a batch array and executes each call. The gateway defers per-tool scope to the servers (deck/internal.yaml:102). A clinical-group token **without** `mcp:fhir-clinical:everything:read` gets `403` for a single `patientEverything` call but `200` + the full `$everything` Bundle when the same call is wrapped in `[ … ]` — and the audit line records `decision: allow`. Same bypass for scheduling `hold-slot`/`confirm-hold`/`release-hold` scopes and for patient tokens' per-resource `patient/*.read` scopes (compartment filter still applies). | Live repro today against the built server + seeded HAPI (throwaway local JWKS, test-only key): `SINGLE → 403 insufficient_scope`, `BATCH → 200 {"result":{"content":[… "resourceType": "Bundle" …`. |
| **S2** | **Medium** | **Egress DLP bypass by JSON escaping.** `dlp-egress` regex-matches the *raw* request body; `"MRN-1234567"` does not match `MRN-\d{7}` but decodes to `MRN-1234567` at the vendor. Same for SSN. | plugins/dlp-egress/handler.lua:59-73; deck patterns :159-163. By construction; no test covers it. |
| S3 | Medium (dependency) | npm: **2 high** (`ip-address` ≤10.7.0 — SSRF classification bugs; `fast-uri` host confusion) + 3 moderate (`hono`, `@hono/node-server`, `qs`) in both servers — all transitive via the MCP SDK, all in production deps, all fixable (`npm audit fix` / SDK 1.31). Reachability in this code is low (the servers don't use express-rate-limit or hono paths directly), but CI hides them. | `npm audit` on clean clone. |
| S4 | Medium (dependency) | pip: broker pins **PyJWT 2.10.1 (20 advisories, fixed ≤2.15)** — used for hub-token validation incl. `PyJWKClient`; **starlette 0.46.2 (14 advisories, fixed ≥0.49/1.x)** via fastapi 0.115. tests/phase1: requests 2.32.5, pytest 8.3.5 advisories. kit deps clean. | `pip-audit -r …` |
| S5 | Low | `vendor-token` plugin only parses `Bearer`; a DPoP-scheme token on an egress route is 401'd rather than handled. Egress routes are bearer-only by config, so this is a consistency gap, not a bypass. | handler.lua:43-45 |
| S6 | Low | Broker `/v1/tokens/resolve` returns 500 on malformed input (D5) — no data exposure, but noisy and unaudited. | main.py:259-272 |
| S7 | Low | Homegrown issuer (lab legacy stand-in) runs as root and compares the client secret with `!=` (not constant-time). | homegrown-issuer/Dockerfile (no USER); main.py:103 |
| S8 | Info | `ci.yml` lacks explicit least-privilege `permissions`. | §6 |

Verified good: no secrets in the tree or in any of the 94 commits (gitleaks);
`.env*` gitignored with `.env.example` placeholders only; realm secrets are
env-substituted at import; algorithm pinning (PS256/ES256) in servers and
broker; audience + exactly-one-tier-audience checks; `fhir_patient`
both-directions rule; DPoP re-verification with `EmbeddedJWK`; PKCE S256 +
server-side single-use state + RFC 9207 checks in the broker; XSS-safe
callback pages; non-root Node/broker images; Origin/Host guard on both
servers; FHIR `_count`/timeout/size caps; no token material in audit lines.

.gitignore gaps: no `.env.*` pattern (only `.env`), no `coverage/`,
`.pytest_cache/` (one exists untracked at repo root), editor dirs (`.idea/`,
`.vscode/`), `*.log`.

---

## 8. Onboarding (clean clone, following the docs exactly)

README has **no quickstart**; it points to `compose/phaseN/README.md`. I
followed phase 0, then phase 1, on a fresh clone of this branch.

| # | Step | Result |
|---|---|---|
| O1 | phase 0: `cp .env.example .env` → `docker compose up -d` | **Fails.** Keycloak exits: `The url [authorization_url] is malformed … Illegal character found in host: '{'`. `realm/mcp-plane.json:487-495` references `${AUTH0_DOMAIN}`/`${AUTH0_CLIENT_ID}`/`${AUTH0_CLIENT_SECRET}`; phases 1–4 compose files give them defaults (`auth0-not-configured.invalid`), phase 0 does not. Phase 0 has been broken from a clean clone since the Auth0 IdP was added to the shared realm export. |
| O2 | phase 0: `./seed-synthea.sh` | Works (6m46s; "60 patient bundles loaded" for the default `PATIENT_COUNT=50`, so "~50 patients" is approximate). Downloads the Synthea jar and a JRE image on first run; the time cost is not mentioned. |
| O3 | phase 1: `docker compose up -d --build` → `./setup-phase1.sh` | **Fails on first run**: `Connect to localhost:8080 … Connection refused` — the script does not wait for Keycloak (ready ~20 s later). Re-running succeeds. |
| O4 | phase 1: seed → `../../tests/phase1.sh` | **Green**: `54 passed, 18 skipped in 1.29s`. Phase 0 gate against this stack: `ALL CHECKS GREEN`. |
| O5 | phase 2+ | Blocked for anyone without a **Kong Konnect** account + PAT (and `brew install kong/deck/deck`). Not stated in the README; a reader discovers it in `compose/phase2/README.md`. |
| O6 | phase 5 | Host ports 8300/8310 are commonly used; no override variables. (They collided with another local project here — environment-specific, noted only as a portability point.) |
| O7 | Prereqs | Never listed in one place: Docker (+ ~8 GB for HAPI — CLAUDE.md notes OOM), `jq`, `python3`, `openssl`, Node for local builds, `deck`, `k3d`/`kubectl` for phase 4. |
| O8 | Tests | No single command; no offline suite. |

---

## 9. Prioritized plan for Phase 2

Ordered by risk to a reader or user of the repo. Each line is one or a few
small conventional commits.

**P0 — correctness & security (do first)**
1. **Fix S1**: enforce per-tool scope for every `tools/call` in a request (reject batch arrays outright — 2025-06-18+ removed JSON-RPC batching, and 2026-07-28 does not reintroduce it — *or* check each element). Plan: reject arrays with a JSON-RPC `-32600` + audit, in one shared guard. Regression tests (single, batch, mixed) for both servers.
2. **Fix S2**: have `dlp-egress` scan the JSON-decoded body (decode with cjson, walk string values, scan each) in addition to the raw body; unparseable JSON on a JSON content-type → fail closed. Add an escaped-MRN probe to `tests/phase5` (live-stack only; I cannot run it without Konnect, so it will be marked as not yet executed).
3. **Fix O1/O3**: add the Auth0 defaults to `compose/phase0/docker-compose.yml`; add a Keycloak readiness wait to `setup-phase1.sh` (and the other setup scripts that call kcadm immediately).
4. **Dependency highs (S3/S4)**: SDK → 1.31.x (lockfile), PyJWT → 2.15.x, fastapi/starlette to a fixed release, requests/pytest bumps; make `npm audit --audit-level=high` blocking in CI.

**P1 — accuracy**
5. Fix every Wrong/stale claim in §2.1 (A1–A31), including "private" wording (A25) and the docs-site pages (regenerated in place, same design); reword unverifiable status claims to "last recorded run on <date>; phases 0–1 re-verified in CI-equivalent run on 2026-09-30" rather than asserting green.
6. Fix the kit's degradation behaviour (A21) in `harness/` so unreachable endpoints skip as documented (small, makes the claim true), and correct the control-catalog attributions (A22).

**P2 — tests, CI, design seams**
7. Extract the duplicated server modules into one shared local package (`servers/shared`, npm workspace) with centralized, validated config; remove dead passthrough code (D1, D2, D4). Dockerfiles adjusted to the new build context.
8. Broker: a `config.py` validated at startup, lazy clients with injection points, input validation on resolve, httpx errors mapped to `VendorUnavailable` (D2, D3, D5).
9. Offline test suite, one command (`make test`): vitest + coverage for both servers (verifier, DPoP, compartment, scope guard incl. batch, scheduling tools against pg via a test double), pytest + coverage for the broker (hub validation with generated keys, resolve/consent/callback/revoke with fake vault + vendor), kit offline vectors + schema validation. Report coverage.
10. CI: one hardened workflow (lint: eslint + ruff; format: prettier + ruff format; type: tsc + mypy on broker; tests with coverage; build; lychee link check; shellcheck; actionlint), top-level `permissions: contents: read`, SHA-pinned actions, concurrency, timeouts, badge. Harden `mirror-docs.yml` the same way. CodeQL workflow (JS/TS + Python). Dependabot for npm ×2, pip, docker, github-actions.

**P3 — currency & hygiene**
11. Node 24 LTS (images, `.nvmrc`, `engines`, CI); Python 3.13 (images, `.python-version`, CI); pin OpenBao and kit deps; bump patch-level images I can verify locally (Keycloak 26.7, HAPI, OTel/Loki/Grafana only if phases 0–1 stay green).
12. SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, .editorconfig, issue/PR templates, .gitignore additions, README restructure (summary, why, Mermaid architecture, prereqs + working quickstart, config table, tests, status/limitations, license).

**Proposed, not done in this PR (need your call or a live Konnect stack)**
- **MCP 2026-07-28 wire migration (#8)** — SDK v2 + zod 4 + gateway re-verification. It is a protocol migration touching every harness; it cannot be verified without the Konnect stack. I will document the gap precisely instead.
- **Kong 3.9 → 3.14 LTS, Grafana 13, Tempo 3, SPIRE 1.15** — out of support or majors, but only verifiable on the full stack; I will document and leave pinned.
- Enforcing the `mfa` amr mark (A15) is a feature, not a fix — I will reword the claim rather than add enforcement unless you want it.
