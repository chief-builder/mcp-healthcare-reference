# Home-Lab Prototype Plan — Enterprise MCP Reference Implementation

**Goal:** a running, end-to-end reference implementation of the architecture in `docs/mcp-e2e-reference-architecture.md`, on home hardware, substituting external/commercial dependencies without losing the properties that make the design worth proving.

## 1. Fidelity contract — what must survive simulation

The prototype is only useful if these seven properties are *actually enforced*, not stubbed:

1. **Single issuer:** every token the gateway or an MCP server validates is minted by the lab Keycloak, regardless of which upstream "IdP" authenticated the principal.
2. **Two-level audiences:** tier audience + per-server resource URI (RFC 8707); a token replayed across tiers must fail cryptographic validation, and the acceptance suite proves it.
3. **Cert-bound m2m:** the internal-agent path uses X.509 client auth at Keycloak and `cnf.x5t#S256` verification at the gateway (RFC 8705). No client secrets on the m2m path.
4. **Stateless MCP (2026-07-28):** no protocol session; any request to any replica; continuity via explicit handles.
5. **Egress DLP:** outbound tool arguments to the real SaaS vendor are screened; a planted fake-MRN string must be blocked and audited.
6. **Broker correctness:** one-time consent dance with server-side `state`/PKCE, vault custody keyed by hub `sub`, and single-flight refresh proven under forced concurrency.
7. **Audit joinability:** one `jti` traceable from client call → gateway decision → MCP server → (vendor action or FHIR read) in a single dashboard.

Everything else is negotiable.

## 2. Substitution map

| Production component | Home-lab substitute | What's preserved / consciously lost |
|---|---|---|
| Kong Konnect hybrid (CP in Kong's AWS) | **Konnect free/dev tier CP + local data planes in Docker** | Preserves the real hybrid split: cloud CP, DPs on your hardware, decK-driven config, cached-config resilience (kill your uplink and watch DPs keep serving). Fallback: Kong Gateway OSS DB-less if Konnect free limits bite — loses the CP/DP boundary demo |
| PingID (workforce) | **Dex** (or a second Keycloak realm) as a fake upstream OIDC IdP, brokered into the hub realm | Preserves the brokered-login leg and claim normalization; loses nothing architectural — Ping is just another OIDC broker |
| Auth0 (customers) | **Auth0 free tier (real)** — generous and permanent | Real product, real broker leg, and a front-row seat when Auth0 ships native XAA/ID-JAG |
| Homegrown AS | **~150-line FastAPI/Node token issuer** registered as a trusted external issuer | Preserves the RFC 8693 exchange leg and the "frozen, sunsetting" migration story |
| Athenz (ZMS/ZTS, Copper Argos, SIA) | **Phase 4a: step-ca or SPIRE** issuing short-lived SPIFFE-SAN certs; **Phase 4b (stretch): real Athenz OSS** via its docker-compose | 4a preserves the property that matters (short-lived X.509 → `tls_client_auth` → cert-bound token); loses provider attestation. 4b adds real ZMS/ZTS + role model — valuable since Athenz is the actual target, but it's the heaviest lift; do it second |
| EKS | **k3d or kind** (Phase ≥4); plain docker-compose for Phases 0–3 | k8s enters exactly when workload identity does |
| Epic/Cerner FHIR | **HAPI FHIR JPA server + Synthea synthetic patients** | Real FHIR R4 semantics, patient-compartment filtering, zero PHI by construction |
| First-party MCP servers | Generate from HAPI's OpenAPI with **your `openapi-mcp-generator`**, plus one hand-built stateless server; PRM (RFC 9728) on both | Dogfoods your own project; statelessness and discovery are real |
| MCP clients | **Claude Code** (workforce), **MCP Inspector** (external/third-party), a small containerized loop agent (internal m2m) | Three genuinely different client classes |
| SaaS vendor + MCP | **Real GitHub** — org-owned GitHub App against github.com, GitHub's remote MCP endpoint | The best part of the lab: real rotating refresh tokens, real revocation, real consent screens. Notion optional second vendor |
| Vault + KMS | **OpenBao or HashiCorp Vault** (dev mode Phase 5, file storage after) | Real policies and audit device; loses HSM/KMS envelope — noted, not simulated |
| SIEM | **OTel Collector → Grafana Loki + Tempo + Grafana** | The audit-tuple dashboard is a first-class deliverable |
| WAF + public ALB | **Caddy/nginx with rate limits + cloudflared or Tailscale Funnel** for the public tier | Preserves the tier separation and public exposure; consciously drops managed WAF rules (documented gap, see Appendix A of the arch doc) |
| Client VPN | **Tailscale** — the private ingress is your tailnet | Surprisingly faithful: identity-gated network path vs. public path |
| FIPS 140-3 | Skipped | Documented gap; irrelevant to the properties under test |

## 3. Phases

Each phase ends with named acceptance checks; don't advance on red.

**Phase 0 — Skeleton (a weekend).** This repo; `compose/` with Keycloak, Postgres, HAPI FHIR, Grafana stack; Synthea generates ~50 patients into HAPI; hub realm `mcp-plane` created by a realm-export checked into git. ✅ Keycloak issues a token with `mcp_contract`, `mcp_tier`, `idp_origin` via protocol mappers; HAPI serves `Patient/$everything` for a synthetic patient.

**Phase 1 — Identity hub (1–2 weekends).** Dex as fake-Ping, brokered; Auth0 free tenant, brokered; the toy homegrown issuer + token-exchange policy; claim normalization to the Claims Contract vocabulary. ✅ Three differently-authenticated logins all yield contract-conformant JWTs from the single issuer; a pytest suite validates every claim in `docs/mcp-token-claims-contract.md` §3.

**Phase 2 — Gateway tiers (1–2 weekends).** Konnect free CP; two local DP containers (internal on the tailnet, external via cloudflared); decK state in git; JWT validation + tier-audience enforcement; route-level ACLs from `groups`. ✅ Internal-tier token replayed at the external DP → 401; DPs keep proxying with CP uplink severed; all config changes are git commits.

**Phase 3 — First-party MCP (2 weekends).** Generate the FHIR MCP server from HAPI's OpenAPI; hand-build a stateless `scheduling` server (explicit `slot_hold_id` handles); PRM documents pointing at Keycloak; scope-per-tool checks in-server; connect Claude Code through the internal tier. ✅ Claude Code lists only role-permitted tools; a deliberately under-scoped token triggers the 403 `insufficient_scope` challenge and a working step-up re-authorization (draft-spec scope flow); a patient-scoped (Auth0-origin) token retrieves exactly its own compartment; kill one server replica mid-conversation and the next tool call succeeds on the other (statelessness).

**Phase 4 — Cert-bound m2m (2 weekends).** k3d; step-ca/SPIRE issuing ≤24h SPIFFE-SAN certs to the loop agent; Keycloak `client-x509` + certificate-bound tokens; the `cnf`-thumbprint check as a small Kong serverless/Lua plugin (this bespoke plugin is a deliverable — it's on the production critical path too). Stretch 4b: swap step-ca for real Athenz. ✅ Agent obtains tokens with zero secrets in its manifest; token presented without mTLS or with a different cert → 401 + audit event; cert rotation happens without pod restart.

**Phase 5 — Egress + broker (3 weekends, the centerpiece).** Org-owned GitHub App; the Vendor Token Broker built to `docs/vendor-token-broker-design.md` (resolve/authorize/callback/grants, vault schema, state machine); egress route on the internal DP with allowlist + regex-grade DLP plugin (fake-MRN patterns like `MRN-\d{7}` seeded in test prompts); per-`sub` vendor token injection. ✅ First call → consent dance → GitHub MCP tool works; planted MRN in a `create_issue` argument → blocked + audited; forced concurrent refresh (set a 60s access-token TTL, hammer with 20 parallel resolves) → exactly one vendor refresh call (single-flight + generation CAS proven); `DELETE /grants` revokes at GitHub for real (RFC 7009).

**Phase 6 — Audit spine (1 weekend).** OTel from DPs, servers, broker → Loki/Tempo; the Grafana "tuple" dashboard keyed by `jti`. ✅ Pick any GitHub issue created in Phase 5 and walk it back to the human, client, gateway decision, and DLP verdict in one query.

**Phase 7 — Red-team weekend.** Run the acceptance list from the arch doc §13 plus: cross-tier replay, scope-ceiling probes, `state` replay on the broker callback (expect the security alert), STALE-storm simulation (uninstall the GitHub App), token in a log grep (expect zero hits). Also probe: RFC 9207 `iss` tampering on the broker callback (expect rejection + alert), and a CIMD experiment — attempt a URL-form `client_id` from a non-allowlisted origin at the external tier (expect refusal). Findings become GitHub issues in this repo.

## 4. Hardware and cost

Fits one box: 16 GB RAM minimum (32 GB comfortable with Athenz), any recent mini-PC or a spare MacBook with Docker Desktop. External spend: $0 — Konnect free tier, Auth0 free tier, Tailscale free, GitHub App on your existing account, everything else OSS.

## 5. Repo layout (this repository)

```
docs/         architecture package (claims contract, broker design, e2e reference, this plan)
compose/      phase 0–5 docker-compose stacks (phase4/ also carries the k3d/SPIRE manifests; phase5/ the mock vendor)
realm/        keycloak realm exports (git-tracked identity config)
deck/         Konnect/Kong declarative state
plugins/      cnf-check + DLP Lua plugins
broker/       vendor token broker service
servers/      first-party MCP servers (generated + hand-built)
agents/       the internal loop agent
tests/        acceptance suites per phase
```

## 6. What this prototype earns you

Beyond the fun: a working demo of every contested design decision before the production review (single-flight refresh, cnf enforcement, DLP-at-egress), the two bespoke components (cnf plugin, broker) substantially de-risked, and — given the overlap with `ClaWeb` and `openapi-mcp-generator` — probable upstream improvements to your own OSS projects. Findings that change the production design get folded back into the docs in this repo, which is the point of keeping architecture and lab in one place.
