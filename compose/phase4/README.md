# Phase 4 — cert-bound m2m (plan §3)

The phase 3 stack plus the workload-identity layer: no client secrets on the
m2m path, anywhere.

```
lab CA (certs/lab-ca.*, generated once by setup-phase4.sh, gitignored)
 ├── SPIRE server intermediate (UpstreamAuthority disk) ── SVIDs (180s TTL)
 ├── Keycloak server cert + truststore (KC_HTTPS_CLIENT_AUTH=request, :8443)
 └── Kong internal server cert (TLS proxy listener, host :8143)

k3d cluster "mcp-lab"
 ├── spire (k8s/spire.yaml): server StatefulSet (PSAT node attestation),
 │   agent DaemonSet (k8s workload attestation)
 └── mcp-agents (k8s/loop-agent.yaml): loop agent + spiffe-helper sidecar
     — manifest contains zero secrets; identity = ns/sa attestation
```

Flow, per contract §6.3 / Appendix A: spiffe-helper keeps the SVID
(CN `loop-agent.mcp-agents.svc`, SPIFFE SAN) on a shared volume → the agent
does `tls_client_auth` client-credentials at Keycloak :8443 (`client-x509`,
subject-DN match, certificate-bound token with `cnf.x5t#S256`) → calls
scheduling MCP tools through Kong :8143, where the bespoke `cnf-check`
plugin (plugins/cnf-check, schema registered on the Konnect CP by the setup
script) binds token to channel. `KC_HOSTNAME` pins the issuer to
`http://localhost:8080/realms/mcp-plane` so every existing validator keeps
working; the phase 0–3 listeners and ports are unchanged.

Bring-up: `./setup-phase4.sh` (idempotent; stops the phase 3 stack — same
host ports; re-seed HAPI afterwards if you need the FHIR tests:
`FHIR_BASE=http://localhost:8081/fhir ../phase0/seed-synthea.sh`).
Gate: `tests/phase4.sh`. Teardown of the workload side:
`k3d cluster delete mcp-lab`.

Memory note: this stack + k3d + a Synthea run is tight in an 8 GB Docker
VM (the two Kong Enterprise DPs alone hold ~3.5 GB) — the Synthea JVM or
HAPI can get OOM-killed mid-seed. Seed with `PATIENT_COUNT=10`, or
`k3d cluster stop mcp-lab` during seeding and `start` it after.
