# Claim-shape test vectors

Fixtures for the canonical JWT contract (`../token-claims-contract.md`,
`../schemas/canonical-jwt.schema.json`). Input to the Workstream-D acceptance
framework's unit layer: every `valid.json` entry, once signed, MUST be
accepted by each validating component (gateway verification, MCP servers,
broker); every `invalid.json` entry MUST be rejected.

**Unsigned by policy.** This repo never commits token material, so fixtures
are claim sets, not JWTs. The test harness signs them at run time with an
ephemeral key it registers (or with the deployment issuer's test realm) —
signing is the harness's job, never a committed artifact.

Fixture format:

```json
{
  "name": "kebab-case id",
  "description": "what this proves",
  "header": { "alg": "PS256" },          // harness applies when signing
  "claims": { ... },                     // ${HUB_ISSUER} substituted by harness
  "expect": "accept" | "reject",
  "reason": "why rejection is required (reject only)",
  "controls": ["IDN-02", ...],           // control-catalog IDs exercised
  "schema_catches": true | false         // false = beyond JSON Schema; only
}                                        //   component validators catch it
```

Harness conventions: substitute `${HUB_ISSUER}`; stamp `iat = now` and
`exp = now + 300` unless the fixture sets them; validate against the JSON
Schema **after** stamping. Fixtures with `schema_catches: false` exist
because some rules need issuance context (e.g. "customer path requires
`fhir_patient`") — they still bind the component validators.

Presentation-level cases (expired token, `cnf` without the matching
certificate/proof, cross-tier replay) are not claim-shape vectors — they live
in the acceptance probes (phases 2/4/7 in the lab).
