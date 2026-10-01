# Production Choices Worksheet

**Kit playbook E16** · The lab's substitution map restated as decisions.
Every row the lab substituted for cost or convenience is a choice the
customer must make deliberately — with the property that must survive the
choice spelled out. Fill this at stage 0; the answers parameterize the
descriptor, the gateway config, and the broker deployment.

Rule of thumb: **the property column is non-negotiable; the component column
never is.**

| Decision | Lab reference | Production options | The property that must survive |
|---|---|---|---|
| Hub AS posture | Keycloak | Dedicated Keycloak/PingFederate hub · "IdP as hub" only if it clears `adapters/hub-requirements.md` | Single issuer; claim shaping; both `cnf` bindings (HUB-01..17) |
| Workforce IdP leg | A second Keycloak realm (`fake-ping`) standing in for Ping | Entra ID / Okta / Ping brokered per `adapters/idp-*.md`; ID-JAG leg when the vendor ships it | Brokered normalization; MFA surfaced in `amr` (IDN-05/08) |
| Customer/patient IdP leg | Auth0 free tenant (real) | Auth0 / other CIAM | External tier only; `fhir_patient` linkage: no linkage → no token (AZ-04) |
| Legacy issuer sunset | Toy FastAPI issuer | The org's actual legacy AS via RFC 8693, frozen | Exchange-only, no new onboarding; `idp_origin` marks it (IDN-09) |
| Gateway platform | Kong Konnect hybrid | Kong / Envoy-Istio / Apigee / APIM per `adapters/gateway-capability-matrix.md` | Tier walls, claim-driven cnf checks, **fail-closed body DLP, ordered egress chain** — the matrix's red flags are disqualifiers, not notes |
| Gateway management plane | Konnect free tier CP | Konnect / self-hosted CP / GitOps-only | PHI, tokens, audit records never reach the management plane (OPS-02); BAA question for any SaaS CP |
| Workload identity | SPIRE in k3d | SPIRE on the real cluster · Athenz (the lab's 4b stretch) · cloud-native attestation | ≤24 h attested certs → `tls_client_auth` → cert-bound tokens; zero secrets in manifests (SC-01/05) |
| Clinical data plane | HAPI FHIR + Synthea | Epic / Cerner / other FHIR R4 | Patient-compartment semantics identical (AZ-04); synthetic data until the compliance owner signs PHI exposure |
| Vendor custody | OpenBao dev mode | Vault/OpenBao HA with **HSM/KMS envelope** (the lab's declared absence), or cloud secret manager per `blueprints/broker.md` custody interface | Fail-closed on custody loss (EG-07); audit device on |
| Broker replicas | Single replica | Single (documented ceiling) or multi with the distributed lock profile from `blueprints/broker.md` | Single-flight refresh still provably single-flight (EG-06) |
| SaaS vendor(s) | GitHub + mockhub | The org's sanctioned vendors | Registry ceilings per vendor; RFC 7009 revocation actually works; BAA/DPA before first real call (EG-09/10) |
| DLP pattern set | MRN/SSN exemplar regexes | Customer data-class catalog (SEC-owned, versioned) | Fail-closed on unscannable bodies; pattern names never values in audit (EG-01) |
| SIEM | Loki/Tempo/Grafana, local | The org's SIEM, immutable + retention-managed | `jti`-joinable tuple; 6-year documentation retention is customer-side (AU-01..03) |
| Public ingress + WAF | cloudflared, no WAF rules | Managed WAF + LB (the lab's documented gap) | Tier separation preserved; WAF is additive, never a substitute for the tier wall |
| Private ingress | Tailscale | Client VPN / ZTNA | Internal tier reachable only via the identity-gated path |
| TLS posture | HTTP-first lab | TLS everywhere, real PKI, HTTPS issuer/resource URLs | Exact-match redirect URIs stay exact; HTTPS resource identifiers (the lab's issue-#13 deviation) SHOULD be adopted from day one |
| FIPS 140-3 | Skipped, documented | Validated modules where mandated | Alg pinning unchanged (IDN-02); module validation is customer policy |
| MCP client population | Claude Code, Inspector, loop agent, DPoP harness | The org's sanctioned clients | DPoP for public interactive clients where supported; the bearer gap is recorded per client, never silent (SC-02 gap register) |

## Recording the answers

Keep the filled worksheet in the engagement repo next to the environment
descriptor. Every deviation from a "property that must survive" is not a
worksheet answer — it is a risk acceptance that belongs in the stage-7
findings register with a named owner.
