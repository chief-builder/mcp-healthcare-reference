# deck/

Declarative Kong Konnect gateway state — the canonical gateway config.
Config-as-git: `tests/phase2/test_resilience_and_git.py` fails if live
state drifts from these files.

- `internal.yaml` — internal-tier DP: global opentelemetry + cnf-check +
  dpop-check + tier pre-function (the pre-function accepts both `Bearer`
  and `DPoP` auth schemes); first-party MCP routes; egress routes
  (`/egress/github`, `/egress/mockhub`) with openid-connect → dlp-egress →
  vendor-token.
- `external.yaml` — external-tier DP: curated catalog behind the external
  tier wall.

Sync workflow (and why the token goes via `DECK_KONNECT_TOKEN`, never
argv): `compose/phase2/README.md`. Custom plugin schemas must be
registered on the Konnect CPs first — the phase setup scripts do that.
