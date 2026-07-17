"""Acceptance-framework fixtures.

Loads the environment descriptor (--environment, default environments/lab.yaml),
exposes it plus token/claim helpers, and provides an identity() factory that
skips a probe cleanly when the descriptor does not declare the identity it needs.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from harness import audit as audit_mod
from harness import descriptor as descriptor_mod
from harness import identities as id_mod

HERE = Path(__file__).resolve().parent


def pytest_addoption(parser):
    parser.addoption(
        "--environment",
        action="store",
        default=str(HERE / "environments" / "lab.yaml"),
        help="Path to the environment descriptor (YAML or JSON).",
    )


@pytest.fixture(scope="session")
def descriptor(request):
    return descriptor_mod.load(request.config.getoption("--environment"))


@pytest.fixture(scope="session")
def audit(descriptor):
    return audit_mod.build(descriptor.section("audit"))


@pytest.fixture(scope="session")
def identity(descriptor):
    """Factory: identity('workforce_clinical') → harness.identities.Identity,
    or pytest.skip if the descriptor doesn't declare it (or it can't be
    acquired). Cached per name within the session."""
    cache: dict[str, id_mod.Identity] = {}

    def get(name: str) -> id_mod.Identity:
        if name not in cache:
            try:
                cache[name] = id_mod.resolve(descriptor, name)
            except id_mod.MissingIdentity as exc:
                pytest.skip(f"identity {name!r} unavailable: {exc}")
        return cache[name]

    return get


def decode_claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


@pytest.fixture(scope="session")
def claims():
    return decode_claims


def require(descriptor, *sections):
    """Skip the calling probe unless every named descriptor section is present."""
    for s in sections:
        if not descriptor.section(s):
            pytest.skip(f"descriptor has no '{s}' section — probe not applicable")
