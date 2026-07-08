# agents/

Internal autonomous workloads (the m2m client population).

- `loop-agent/` — the phase 4 pilot agent (contract §6.3, Appendix A):
  containerized loop that gets its X.509 SVID from SPIRE via a spiffe-helper
  sidecar, performs `tls_client_auth` client-credentials at Keycloak, and
  drives scheduling MCP tools through the internal DP over mTLS with a
  certificate-bound token. No secrets in image, manifest, or env — that is
  the acceptance gate. Deployed by `compose/phase4/setup-phase4.sh` into the
  `mcp-lab` k3d cluster (`compose/phase4/k8s/loop-agent.yaml`).
