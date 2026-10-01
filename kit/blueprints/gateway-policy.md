# Gateway Policy — Portable Blueprint

**Kit blueprint A3** · Derived from `deck/internal.yaml`, `deck/external.yaml`,
`plugins/` (Kong 3.x reference implementation)

Vendor-neutral specification of the gateway-tier policy set. Each policy is
stated as behavior (trigger, algorithm, failure mode, audit obligation) so it
can be re-implemented on another gateway (Envoy/Istio, Apigee, Azure APIM,
AWS API Gateway); the Kong artifacts are the conforming implementation.
Controls: TIER-02/04, SC-01..04, EG-01..03, AZ-06, AU-01/03, OPS-01..03.

## 0. Estate shape

Two (or more) gateway tiers, each its own deployment with its own route
catalog and tier audience — never one gateway with path rules:

| Tier | Reaches | Routes | Notes |
|---|---|---|---|
| Internal | VPN/private ingress only | Full first-party MCP catalog + governed egress | mTLS-capable listener for the workload path |
| External | Public (or partner) ingress | Curated catalog only; **no egress routes** (TIER-04) | Tighter rate ceilings |

Configuration is declarative and git-authoritative (OPS-01): edits land in
the repo and are synced; live state never drifts silently. The management/
control plane sees configuration and aggregate telemetry only — PHI, tokens,
and audit records stay on the data path (OPS-02).

## P1 — Tier wall (TIER-02)

Applied globally on every route, before routing decisions.

```
on request:
  token = bearer_or_dpop_token(Authorization)   # accept BOTH schemes —
                                                # matching only "Bearer" lets
                                                # DPoP-scheme requests bypass
  if no token: pass                             # unauthenticated PRM discovery
                                                # must still reach the server,
                                                # which owns the 401 challenge
  claims = decode_payload_unverified(token)     # see trust note below
  if claims.aud does not contain THIS_TIER_AUD: reject 401 invalid_token
```

Trust note: the wall may parse without signature verification **only** when a
downstream component on every route performs full verification (in the lab:
the MCP servers, and `openid-connect` on egress routes). If a route has no
verifying upstream, the wall MUST verify signatures itself. Production
target: full JWT verification at the DP on all routes.

Failure mode: malformed/undecodable token with a scheme present → reject.
Audit: rejection emits a tier-mismatch event with the request context.

## P2 — Certificate binding, `cnf.x5t#S256` (SC-01)

Applied globally (the TLS client-certificate phase precedes routing).

```
if token.cnf["x5t#S256"] exists:
  cert = tls_client_certificate()
  if no cert: reject 401 + audit(alert)
  if SHA256(cert.leaf_DER) != cnf value: reject 401 + audit(alert)
else: pass untouched                            # claim-driven (SC-03)
```

The plugin only locates the thumbprint; signature verification belongs to the
verifying component (P1 trust note). A binding failure is an alert, not just
a 401 — replay of a bound token is an attack signature, never user error.

## P3 — DPoP sender-constraint, `cnf.jkt` (SC-02, SC-04)

Applied globally; claim-driven.

```
if token.cnf.jkt exists:
  require Authorization scheme == DPoP and exactly one DPoP proof header
  proof = parse(dpop_header)                    # typ dpop+jwt, ES256
  require RFC7638_thumbprint(proof.jwk) == cnf.jkt
  require proof.htm == request.method
  require proof.htu == request.url (normalized)
  require |now - proof.iat| <= 60s
  require proof.ath == b64url(SHA256(access_token))
  require replay_cache.insert_if_absent(proof.jti)   # single use
  # replay cache unavailable or insert error → reject 503 (fail closed)
else: pass untouched
```

Division of labor (deliberate): the gateway is early rejection — structure,
binding, request match, replay — and MAY skip proof-signature verification
when the resource server authoritatively re-checks the proof **including the
signature** (SC-04; in the lab, `servers/shared/src/dpop.ts`). A deployment whose
servers cannot re-check MUST verify the signature at the gateway. The replay
cache is per-entry single-use with TTL ≥ the `iat` window; cache pressure
(evictions) is a degraded-mode audit event.

## P4 — First-party MCP routes

Route → MCP server; the server is authoritative for its own audience, scope,
group visibility, and compartment (AZ-01..04). Gateway obligations on these
routes: P1–P3 plus a rate ceiling (OPS-03). Identity context
(`jti`, `sub`, `azp`, `act.sub`, `idp_origin`) is injected as upstream headers
with client-supplied copies stripped.

## P5 — Governed egress routes (EG-01..03)

Only on the internal tier. The route's upstream **is** the allowlist: each
registered vendor gets its own route/service pinned to that vendor's endpoint;
there is no generic proxy route (EG-03). Plugin order is load-bearing:

```
1. full token verification        (signature, issuer, egress-resource audience)
2. DLP screen                     (P6 — nothing unscreened leaves)
3. credential swap                (P7 — vendor token in, hub token out)
4. rate ceiling
```

## P6 — Egress DLP (EG-01)

```
on request (non-GET/HEAD):
  body = read_raw_body()
  if body unreadable: reject 400 (fail closed)
  for pattern in configured_patterns:           # e.g. MRN, SSN regexes
    if pattern matches body: reject 403 + audit(block, pattern.name)
  audit(allow)                                  # clean passes are audited too
```

Audit records carry the **pattern name only**, never the matched value (the
audit trail must not itself become the leak). Pattern execution error →
block. Clean-pass records are required — AU-01's join must show the screen
ran, not merely that nothing was caught.

## P7 — Vendor credential swap (EG-02)

```
resp = broker.resolve(vendor, sub, hub_jti, min_ttl, required_scopes)
                                # authenticated with the caller's hub JWT
case 200: set Authorization = "Bearer " + resp.access_token   # hub JWT never
          forward upstream                                    # reaches vendor
case 404 needs-consent:   map to the MCP authorization-required response
case 409 needs-reconsent: map likewise (scope escalation requires consent)
otherwise: reject 502/503 (fail closed — never forward the hub token)
```

`required_scopes` derives from the authenticated MCP tool, not from client
input. See `broker.md` for the resolve contract.

## P8 — Legacy/JWT-verified routes (external curated surface)

Where the upstream is not an MCP server that self-validates (e.g. a plain
FHIR proxy route), the gateway carries full OIDC verification plus a
group ACL (normalized `GROUPS` only, IDN-05) — deny without the required
group is 403, not 401 (AZ-06 challenge semantics preserved).

## P9 — Observability (AU-01, AU-03)

Every tier exports traces and the policy plugins' audit records to the
customer-side collector (OTLP in the lab). No token material in any span,
log, or record (AU-03). Gateway records join the spine on the token's `jti`.

## Portability red flags

Evaluate these before committing to a gateway platform; they are where
re-implementations fail quietly:

1. **Fail-closed body inspection** (P6): the platform must be able to buffer
   and inspect the raw body *and* reject when it cannot. Platforms that skip
   inspection on streaming/large bodies fail open — disqualifying unless
   bounded by a hard body-size limit.
2. **Single-use proof cache** (P3): needs an atomic insert-if-absent shared
   across workers of one gateway node (lab: nginx shared dict). Multi-node
   estates need either node-sticky routing at the LB or a shared cache;
   document which.
3. **Claim-driven activation** (P2/P3): the checks trigger on token *claims*,
   not route config. Platforms that can only enable checks per-route need
   route duplication or script-level branching — budget for it.
4. **Plugin ordering guarantees** (P5): verification → DLP → swap must be
   provably ordered. If ordering is implicit (priority numbers, filter
   chains), pin it in config and cover it with an acceptance probe.
5. **TLS client-cert phase** (P2): the gateway must expose the presented
   leaf certificate to policy code on non-mTLS-terminating LB topologies
   this often breaks first.

## Reference implementation map

| Policy | Kong artifact |
|---|---|
| P1 | `pre-function` global plugin in `deck/{internal,external}.yaml` |
| P2 | `plugins/cnf-check/handler.lua` (global, internal tier) |
| P3 | `plugins/dpop-check/handler.lua` + `dpop_jti` shared dict |
| P5–P7 | egress services in `deck/internal.yaml`: `openid-connect` → `plugins/dlp-egress` → `plugins/vendor-token` |
| P8 | `openid-connect` + `acl` on the placeholder FHIR routes |
| P9 | global `opentelemetry` plugin |
