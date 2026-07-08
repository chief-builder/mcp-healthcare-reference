# plugins/

Bespoke Kong plugins — the two custom components on the production critical
path (reference architecture §12).

- `cnf-check/` — RFC 8705 certificate-bound token enforcement (phase 4):
  binds `cnf.x5t#S256` tokens to the mTLS channel at the internal DP.
  See its README for semantics and deployment.
- DLP egress plugin — phase 5, not started.
