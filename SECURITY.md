# Security policy

## Scope

This repository is a home-lab **reference implementation**, not production
software. It runs on synthetic data only (Synthea-generated patients); no
real PHI is ever used or needed. Even so, its value is in getting the
security controls right — token validation, audience binding, sender
constraint, egress DLP, credential custody — so reports about weaknesses in
those controls are welcome.

## Supported versions

Only the latest `main` (and the most recent tagged release, if any) receives
fixes.

## Reporting a vulnerability

Please report privately through GitHub's **private vulnerability reporting**:
go to the repository's **Security** tab →
**Report a vulnerability**
(<https://github.com/chief-builder/mcp-healthcare-reference/security/advisories/new>).
Do not open a public issue for a suspected vulnerability.

Helpful details:

- the component (`servers/`, `broker/`, `plugins/`, `deck/`, `realm/`, …)
  and commit you tested;
- what an attacker needs (which token, tier, or network position) and what
  they gain;
- reproduction steps or a minimal proof of concept.

This is maintained on a best-effort basis. I aim to acknowledge reports
within about a week and will credit reporters in the fix unless asked not to.

## Keys and credentials in this repository

- No real secrets are committed. Each compose phase ships a `.env.example`
  with placeholder values; the real `.env` files, certificates, and keys are
  gitignored.
- Test-only keys are generated at run time: the offline suites create their
  signing and DPoP keys in memory, and the phase setup scripts write lab
  certificates into gitignored `compose/phaseN/certs/` directories. None are
  stored in the tree.
