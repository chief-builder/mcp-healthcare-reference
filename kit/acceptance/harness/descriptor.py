"""Load and validate an environment descriptor.

YAML is preferred for readability; JSON is accepted too. Validation against
environment.schema.json runs when jsonschema is installed (it is in
requirements.txt) — a descriptor that fails validation stops the run early
with a clear message rather than surfacing as confusing probe errors.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SCHEMA = Path(__file__).resolve().parent.parent / "environment.schema.json"


def _load_mapping(path: Path) -> dict[str, Any]:
    text = path.read_text()
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise SystemExit(
                f"{path} is YAML but PyYAML is not installed — "
                "pip install -r requirements.txt (or use a .json descriptor)"
            ) from exc
        return yaml.safe_load(text)
    return json.loads(text)


def _validate(doc: dict[str, Any], path: Path) -> None:
    try:
        import jsonschema
    except ImportError:  # pragma: no cover - validation is best-effort
        return
    schema = json.loads(_SCHEMA.read_text())
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(doc),
        key=lambda e: list(e.path),
    )
    if errors:
        loc = "/".join(str(p) for p in errors[0].path) or "(root)"
        raise SystemExit(
            f"{path} is not a valid environment descriptor:\n"
            f"  at {loc}: {errors[0].message}"
        )


@dataclass
class Descriptor:
    path: Path
    doc: dict[str, Any]

    @property
    def name(self) -> str:
        return self.doc["name"]

    @property
    def issuer(self) -> str:
        return self.doc["issuer"]

    @property
    def jwks_uri(self) -> str:
        return self.doc.get(
            "jwks_uri", f"{self.issuer}/protocol/openid-connect/certs"
        )

    def audience(self, tier: str) -> str:
        return self.doc["audiences"][f"tier_{tier}"]

    def gateway(self, tier: str) -> str:
        return self.doc["gateways"][tier].rstrip("/")

    def endpoint(self, tier: str, key: str) -> str | None:
        path = self.doc.get("probe_endpoints", {}).get(key)
        return f"{self.gateway(tier)}{path}" if path else None

    def section(self, key: str) -> dict[str, Any] | None:
        return self.doc.get(key)

    def identity(self, name: str) -> dict[str, Any] | None:
        return self.doc.get("identities", {}).get(name)


def load(path: str | Path) -> Descriptor:
    path = Path(path)
    if not path.exists():
        raise SystemExit(f"environment descriptor not found: {path}")
    doc = _load_mapping(path)
    _validate(doc, path)
    return Descriptor(path=path, doc=doc)
