# realm/

Keycloak realm exports — the canonical identity config, imported at first
boot with `${ENV}` placeholders substituted from the phase `.env` (no
secrets in git).

- `mcp-plane.json` — the hub realm: single issuer for the MCP plane,
  brokered IdPs (fake-ping, Auth0), clients, and the protocol mappers that
  stamp the claims-contract vocabulary (`mcp_contract`, `mcp_tier`,
  `idp_origin`, …).
- `fake-ping.json` — the fake workforce IdP realm (stands in for an enterprise workforce IdP such as Ping).

State a realm import can't express (token-exchange policy, x509 client
auth, live IdP credential updates) lives in the phase setup scripts,
starting with `compose/phase1/setup-phase1.sh`. Never hand-edit live realm
state without exporting back here (CLAUDE.md).
