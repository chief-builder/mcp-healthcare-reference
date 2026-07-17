# Gateway Capability Matrix

**Kit adapter B7** · Status: **desk-checked** (no non-Kong gateway has run
the acceptance suite; see the validation rule in `README.md`)

Maps each policy in `blueprints/gateway-policy.md` (P1–P9) to its
implementation mechanism on the major gateway platforms, with the
portability red flags called out where a platform cannot honestly carry a
policy. Kong 3.x is the reference implementation (rightmost column of the
blueprint); this matrix is for the "customer already standardized on X"
conversation.

Legend: ✅ native/straightforward · ◐ buildable with scripting/sidecars —
budget it · ❌ cannot meet the policy's failure mode → compensating design
required.

| Policy | Envoy / Istio | Apigee (X/hybrid) | Azure APIM | AWS API Gateway |
|---|---|---|---|---|
| P1 tier wall (TIER-02) | ✅ `jwt_authn` per-tier `audiences` (full signature verify — exceeds the lab's parse-only wall) | ✅ `VerifyJWT` policy with audience check | ✅ `validate-jwt` with `<audience>` | ◐ HTTP-API JWT authorizer checks `iss`/`aud` only; both-scheme (Bearer+DPoP) acceptance needs a Lambda authorizer |
| P2 cnf.x5t#S256 (SC-01) | ◐ downstream mTLS + claim/cert compare in Lua/ext_authz (cert via XFCC or connection API) | ◐ mTLS northbound; cert in flow variables; compare in JS/Java callout | ◐ client certs supported; `context.Request.Certificate` in policy expressions | ◐ mTLS truststore supported; leaf cert reaches a **Lambda authorizer** via request context — compare there |
| P3 DPoP checks (SC-02/04) | ◐ ext_authz service (or WASM) + shared replay cache (Redis); fail closed by `failure_mode_allow: false` | ◐ JS/Java callout + `PopulateCache`/`LookupCache` for proof `jti` — verify cache atomicity and per-region scope | ◐ policy expressions can parse/compare; replay cache via built-in cache or external Redis; proof-signature verify is awkward — prefer the blueprint's server-side authoritative re-check | ◐ Lambda authorizer + DynamoDB/ElastiCache conditional write for `jti`; same server-side re-check posture |
| P4 first-party routes + header injection | ✅ route config + header mutation (strip client copies) | ✅ AssignMessage per flow | ✅ set-header policies | ◐ header mapping exists; stripping client-supplied copies needs care in every integration mapping |
| P5 ordered egress chain (verify → DLP → swap) | ✅ filter-chain order is explicit config | ✅ policy order is the proxy flow — explicit | ✅ policy document order — explicit | ❌ no in-gateway ordered chain; the whole egress pipeline moves into a Lambda/sidecar (see below) |
| P6 fail-closed body DLP (EG-01) | ◐ ext_authz `with_request_body` (`max_request_bytes` + reject-on-overflow) or WASM; pair with a hard body-size limit | ✅ `RegularExpressionProtection` / JS callout on the buffered body; message-size cap ~10 MB | ◐ `context.Request.Body` with `preserveContent`; enforce an explicit size cap and reject unreadable bodies | ❌ authorizers never see the body. AWS WAF regex rules inspect only the first 8–64 KB and the oversize action defaults matter — **fail-open trap**. Body DLP must run in a Lambda proxy or a fronting service |
| P7 credential swap (EG-02) | ◐ ext_proc/Lua HTTP call to broker `resolve`, rewrite `Authorization`; fail closed on non-200 | ✅ `ServiceCallout` to broker + AssignMessage rewrite | ✅ `send-request` to broker + set-header rewrite | ◐ only inside the same Lambda that does P6 |
| P8 verified non-MCP routes + group ACL | ✅ `jwt_authn` + RBAC filter on normalized groups | ✅ VerifyJWT + condition flows | ✅ validate-jwt + `<required-claims>` | ◐ Lambda authorizer policy generation |
| P9 OTel + audit records, no token material (AU-01/03) | ✅ native OTel tracing + access-log filters | ✅ distributed trace + MessageLogging (scrub config reviewed against AU-03) | ✅ App Insights/OTel; scrub review | ◐ X-Ray + access logs; joining on `jti` requires logging it explicitly from the Lambda layers |

## Per-platform verdicts and red flags

Keyed to the blueprint's five portability red flags (RF1 fail-closed body,
RF2 replay cache, RF3 claim-driven activation, RF4 ordering, RF5 client-cert
exposure).

### Envoy / Istio
The strongest port target. RF3 (claim-driven activation) is the main cost:
`jwt_authn`/RBAC are route-scoped, so the cnf/DPoP branching lives in one
global ext_authz/WASM layer — effectively re-writing the two Kong plugins as
one service, which then also owns RF2's shared cache. RF5: on sidecar
topologies the client cert must survive to the policy point (XFCC config);
on LB-terminated TLS it often doesn't — verify first.

### Apigee
Comfortable fit; policies buffer bodies and ordering is explicit (RF1/RF4
green within the message-size cap — pin the cap and reject above it).
RF2: `LookupCache`/`PopulateCache` are not a guaranteed atomic
insert-if-absent and caches can be region-local — for multi-region estates
back the proof-`jti` cache with an external store or accept documented
region-sticky routing.

### Azure APIM
Workable throughout, all in policy expressions (C#). The honest caveats:
proof-signature verification in-gateway is impractical (lean on the
blueprint's division of labor — server re-checks signature, SC-04), and
RF1 requires deliberately configured size caps so `preserveContent`
buffering can't be bypassed by oversized bodies.

### AWS API Gateway
**Disqualifying as the enforcement point for governed egress (P5–P7)
unless the design accepts that the "gateway" policy actually runs in a
Lambda.** Authorizers cannot read bodies (RF1 ❌ at the gateway layer), WAF
body inspection is size-capped with configurable-but-defaulted oversize
handling (the classic fail-open), and there is no ordered policy chain.
The viable AWS shape: API Gateway (mTLS truststore + JWT/Lambda authorizer)
as the front door for P1/P2, with P3 and the whole P5–P7 egress chain in a
dedicated service (Lambda or ECS sidecar) that the acceptance probes then
target directly. Cost that shape honestly — it is a re-implementation, not
a configuration exercise.

## Validation status

No cell in this matrix has run the Workstream-D acceptance suite. Per the
kit's validation rule, a platform column may be promoted from desk-checked
only by pointing `kit/acceptance/` at a deployment on that platform and
recording the run.
