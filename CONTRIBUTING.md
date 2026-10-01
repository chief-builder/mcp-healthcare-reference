# Contributing

## Prerequisites

- Node.js 24 (`.nvmrc`) and Python 3.14 (`.python-version`)
- Docker (the gateway plugin suite runs a DB-less Kong container)
- `make`; for the live stacks also `jq`, `openssl`, and — for phases 2–7 —
  a Kong Konnect account plus `deck`, `k3d`, `kubectl`

## Offline checks (what CI runs)

```sh
make install                       # Python venv + servers/ npm workspace
make test                          # all offline suites, with coverage
make lint format-check typecheck   # ruff, eslint, prettier, shellcheck, tsc, mypy
make build                         # compile the MCP servers
```

## Live acceptance gates

`tests/phaseN.sh` drives a running `compose/phaseN` stack (see each
`compose/phaseN/README.md`). Phases 0–1 run locally with Docker only;
phases 2–7 need the Kong Konnect control planes. Re-run the gates a change
touches before opening a PR.

## Conventions

- One focused pull request per change.
- [Conventional Commits](https://www.conventionalcommits.org/) for commit
  messages and PR titles (`fix(broker): …`, `feat(servers): …`).
- Never commit secrets: copy `compose/phaseN/.env.example` to `.env` (gitignored)
  and fill in local values. Report vulnerabilities privately — see
  [SECURITY.md](SECURITY.md).
