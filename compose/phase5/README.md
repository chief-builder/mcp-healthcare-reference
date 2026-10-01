# Phase 5 — egress + broker (plan §3, the centerpiece)

The phase 4 stack (cert-bound m2m, k3d/SPIRE side included) plus:

```
vault (OpenBao dev, host :8210)   vendor-tokens/ + vendor-clients/ KV v2
broker (broker/, host :8300)      resolve / authorize / callback / grants
mock-vendor (host :8310)          mockhub AS + fake vendor MCP endpoint
kong-internal                     + cnf-check + dpop-check + dlp-egress + vendor-token plugins
```

Egress routes (deck/internal.yaml): `/egress/github` →
api.githubcopilot.com/mcp, `/egress/mockhub` → mock-vendor. The route
upstream is the vendor allowlist; plugin order is openid-connect
(egress audience) → dlp-egress (nothing unscreened leaves) → vendor-token
(broker resolve, vendor credential injected, hub JWT stripped).

Bring-up: `./setup-phase5.sh` (idempotent; inherits the phase 4 lab CA so
the running SPIRE side keeps chaining to the same root; provisions OpenBao
mounts/policy/scoped token; registers the four custom plugin schemas).
Gate: `tests/phase5.sh` — fully headless against mockhub.

GitHub leg (optional, real): create a GitHub App on your account —
callback URL `http://localhost:8300/v1/callback/github`, "Expire user
authorization tokens" ON (that's the rotating-refresh behavior §9 exists
for), Issues read/write permission, then install it on your account. Put
`GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` in `.env`, re-run
`./setup-phase5.sh`, and complete the one-time consent from the
`authorize_uri` that `tests/phase5.sh`'s GitHub test prints when skipping.

Real GitHub MCP tool names differ from mockhub's — the broker/DLP/injection
machinery is vendor-agnostic, but tool contracts are per-vendor. GitHub's
remote MCP server (`api.githubcopilot.com/mcp`; 47 tools when the lab's live run listed them) uses:

| Intent | mockhub (lab) | real GitHub |
|---|---|---|
| create an issue | `create_issue` | `issue_write` with `method: "create"` |
| update / close an issue | — | `issue_write` with `method: "update"`, `state: "closed"` |
| read one issue | — | `issue_read` with `method: "get"` |
| list issues | `list_issues` | `list_issues` (matches) |

`issue_write`/`issue_read` require `method`, `owner`, `repo`; discover the
full set with a `tools/list` call through `/egress/github`. Confirmed end to
end in the lab's July 2026 live run: a real issue created and closed through resolve → DLP → vendor-token
injection → GitHub, with one hub `jti` joining every hop (contract §9).

Vault note: OpenBao runs in dev mode (in-memory, per plan §2 — file
storage is a later hardening). Any vault restart wipes the broker token,
vendor client creds, and all grants; re-run `./setup-phase5.sh` to
re-provision (it is idempotent). The fail-closed gate therefore *pauses*
vault rather than stopping it, so provisioning survives the test.

Memory note: same 8 GB Docker VM squeeze as phase 4 — seed with
`PATIENT_COUNT=10`, or stop the k3d cluster during seeding. Under load the
loop agent or HAPI can OOM-restart; `docker start mcp-phase5-hapi-1` and a
loop-agent rollout restart recover them.

## Phase 6 — audit spine (rides this stack)

No new stack: phase 6 is telemetry wiring + the tuple dashboard on top of
the phase 5 services.

- **Kong DPs → OTLP**: a global `opentelemetry` plugin on both tiers
  (deck/*.yaml) exports traces and the bespoke plugins' `kong.log` audit
  records (cnf-check / dpop-check / dlp-egress / vendor-token) to the collector →
  Tempo/Loki, unwrapped from the nginx error log. Needs
  `KONG_TRACING_INSTRUMENTATIONS=all` (compose).
- **Everything else → Alloy**: `alloy/config.alloy` tails every container
  in this project over the Docker API and pushes to Loki. The broker, MCP
  servers, and mock vendor emit one JSON audit line per event on stdout by
  design, so a `service_name` label plus LogQL `| json` is the whole
  parsing story.
- **Grafana**: the "MCP Audit Tuple" dashboard is provisioned from
  `compose/phase0/grafana/provisioning/dashboards/` — paste a token `jti`
  and walk the human → client → gateway decision → DLP verdict → broker →
  vendor/server action chain in one query.

Bring-up: re-run `./setup-phase5.sh` (rebuilds servers, syncs deck, starts
Alloy). Gate: `tests/phase6.sh`.
