"""Claim-shape unit layer — the A2 token-contract vectors.

Loads kit/blueprints/vectors/{valid,invalid}.json, substitutes the deployment
issuer, stamps iat/exp, and validates each claim set against the canonical-JWT
JSON Schema. This is the unit-level half of conformance: it proves the *schema*
encodes the contract. Vectors marked schema_catches=false need issuance context
or signature inspection and are covered by the live component probes (identity /
tier / authorization / egress) instead — they are reported here as expected
deferrals, not failures.

No network and no running deployment required — this module runs anywhere.
"""

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.vectors

BLUEPRINTS = Path(__file__).resolve().parents[2] / "blueprints"
SCHEMA_PATH = BLUEPRINTS / "schemas" / "canonical-jwt.schema.json"
VECTORS_DIR = BLUEPRINTS / "vectors"


def _load(name):
    return json.loads((VECTORS_DIR / name).read_text())


def _stamp(claims, issuer):
    c = dict(claims)
    c.setdefault("iat", 1000)
    c.setdefault("exp", 1300)
    c["iss"] = c["iss"].replace("${HUB_ISSUER}", issuer)
    return c


@pytest.fixture(scope="module")
def validator():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_schema_is_valid():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("vec", _load("valid.json"), ids=lambda v: v["name"])
def test_valid_vector_accepted(validator, descriptor, vec):
    errors = list(validator.iter_errors(_stamp(vec["claims"], descriptor.issuer)))
    assert not errors, f"valid vector {vec['name']} rejected by schema: {errors[0].message}"


@pytest.mark.parametrize("vec", _load("invalid.json"), ids=lambda v: v["name"])
def test_invalid_vector_behaves_as_labeled(validator, descriptor, vec):
    caught = bool(list(validator.iter_errors(_stamp(vec["claims"], descriptor.issuer))))
    if not vec["schema_catches"]:
        assert not caught, (
            f"{vec['name']} is labeled schema_catches=false but the schema caught "
            "it — update the label or the schema"
        )
        pytest.skip(
            f"{vec['name']} needs a live validator ({', '.join(vec['controls'])}); "
            "covered by component probes"
        )
    assert caught, f"invalid vector {vec['name']} was NOT caught by the schema"
