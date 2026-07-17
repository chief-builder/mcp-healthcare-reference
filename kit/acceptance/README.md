# Acceptance Framework

**Kit Workstream D** · Portable conformance probes a customer can run against
their own deployment.

The reference lab's `tests/phaseN` suites prove the invariants against the lab.
This framework extracts the *portable* half of those probes and parameterizes
them on an environment descriptor, so the same assertions run against any
deployment — and reports coverage honestly (see `conformance-profile.md`).

## Layout

```
acceptance/
  environment.schema.json      Descriptor schema (validated at load).
  environments/
    lab.yaml                   The reference lab — the framework's own fixture.
    TEMPLATE.yaml              Annotated starting point for a customer.
  harness/                     Reusable mechanics (descriptor, oidc, dpop, mcp,
                               identities, audit) — self-contained, no import
                               from the lab's tests/.
  probes/                      The probes, one module per control family.
  conftest.py  pytest.ini  requirements.txt
  conformance-profile.md       What green means; probe → control-catalog map.
  RULES-OF-ENGAGEMENT.md       Authorization template for adversarial runs.
```

## Run it

```bash
pip install -r requirements.txt

# Offline: the claim-shape unit layer needs nothing running.
pytest probes/test_claim_vectors.py

# Against the reference lab (bring up compose/phase5 + the phase6 spine first,
# and export the secrets the lab descriptor names, e.g. FAKE_PING_PASSWORD):
set -a; . ../../compose/phase5/.env; set +a
pytest --environment environments/lab.yaml -ra

# Against your deployment:
cp environments/TEMPLATE.yaml environments/mine.yaml   # then edit
pytest --environment environments/mine.yaml -ra --junitxml=report.xml
```

## How it degrades

- A descriptor section you omit **skips** its probes (no egress section → EG
  probes skip). Coverage, not correctness, shrinks.
- An identity you don't declare — or one whose `command`/`env`/`scripted`
  acquisition fails — **skips** the probes that need it, with the reason shown.
- An unreachable endpoint **skips** (it's an environment problem), it does not
  fail.
- A **fail** therefore always means a control genuinely did not hold. That is
  the only outcome that blocks a conformance claim.

## Getting tokens into a run

Each identity in the descriptor picks an acquisition mode:

- `scripted` — the built-in auth-code+PKCE (or client-credentials) driver.
  Suits dev/lab IdPs with a scriptable login form (the lab uses this). Set
  `dpop: true` to mint a key-bound token for the sender-constraint probes.
- `command` — run a shell command that prints a fresh access token to stdout.
  The realistic path for a production IdP: wrap your own SSO/CI login.
- `env` — read a token from an environment variable.

Secrets are never inline in a descriptor: `password_env` / `client_secret_env`
/ `env` name environment variables.

## Extending

- New control probe → add to the right `probes/test_<family>.py`, tag it with
  the control-catalog ID in the assertion message, and add the mapping row to
  `conformance-profile.md`.
- New deployment shape → a new `environments/<name>.yaml`. The lab descriptor
  is the worked example.
- Adversarial probes ported from `tests/phase7` belong under the `redteam`
  marker and require an accepted `RULES-OF-ENGAGEMENT.md` before running against
  anything you don't own.
