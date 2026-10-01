# One-command entry points. `make test` runs every offline suite from a clean
# clone (needs Node 24, Python 3.14, and Docker for the gateway plugin suite).
# The live acceptance gates stay in tests/phaseN.sh (see tests/README.md).

PY_VENV := .venv
PY := $(PY_VENV)/bin/python

.PHONY: help install test test-servers test-broker test-kit test-plugins \
        lint format format-check typecheck build clean

help:
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-14s %s\n", $$1, $$2}'

$(PY_VENV)/.installed: requirements-dev.txt broker/requirements.txt kit/acceptance/requirements.txt
	python3 -m venv $(PY_VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -r requirements-dev.txt
	touch $@

servers/node_modules/.package-lock.json: servers/package.json servers/package-lock.json
	cd servers && npm ci

install: $(PY_VENV)/.installed servers/node_modules/.package-lock.json ## Install all dev dependencies

test: test-servers test-broker test-kit test-plugins ## Run every offline test suite with coverage

test-servers: servers/node_modules/.package-lock.json ## MCP servers: vitest + coverage
	cd servers && npm run test:coverage

test-broker: $(PY_VENV)/.installed ## Vendor token broker: pytest + coverage
	cd broker && ../$(PY) -m pytest --cov=app --cov-report=term-missing

test-kit: $(PY_VENV)/.installed ## Kit: offline claim vectors + schema validation
	cd kit/acceptance && ../../$(PY) -m pytest probes/test_claim_vectors.py -q

test-plugins: ## Kong plugins against a DB-less gateway in Docker
	plugins/tests/run.sh

lint: $(PY_VENV)/.installed servers/node_modules/.package-lock.json ## Lint Python, TypeScript, shell
	$(PY_VENV)/bin/ruff check .
	cd servers && npm run lint
	shellcheck -S warning tests/*.sh compose/*/*.sh plugins/tests/*.sh

format: $(PY_VENV)/.installed servers/node_modules/.package-lock.json ## Apply formatters
	$(PY_VENV)/bin/ruff format .
	cd servers && npm run format

format-check: $(PY_VENV)/.installed servers/node_modules/.package-lock.json ## Check formatting
	$(PY_VENV)/bin/ruff format --check .
	cd servers && npm run format:check

typecheck: $(PY_VENV)/.installed servers/node_modules/.package-lock.json ## Type-check TS and the broker
	cd servers && npm run typecheck
	cd broker && ../$(PY_VENV)/bin/mypy app

build: servers/node_modules/.package-lock.json ## Compile the MCP servers
	cd servers && npm run build

clean:
	rm -rf $(PY_VENV) servers/node_modules servers/*/dist coverage .coverage
