"""Write the DB-less Kong config for plugins/tests to the path in argv[1].

The tier-wall pre-function and the DLP patterns are lifted from
deck/internal.yaml at build time, so the suite exercises exactly what the
lab deploys rather than a copy that can drift. openid-connect (Enterprise,
license-gated) is left out: these routes test the bespoke plugins only.
"""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
STUB = "http://stub:8080"


def route(name: str, path: str) -> dict:
    # Kong 3.14+ defaults routes to https only; the suite (like the lab DPs) speaks
    # plain HTTP, so the protocols are explicit, as they are in deck/*.yaml.
    return {"name": name, "paths": [path], "strip_path": True, "protocols": ["http", "https"]}


def deck_internal() -> dict:
    return yaml.safe_load((ROOT / "deck" / "internal.yaml").read_text())


def tier_wall(deck: dict) -> dict:
    (plugin,) = [p for p in deck["plugins"] if p["name"] == "pre-function"]
    return plugin


def dlp_patterns(deck: dict) -> list[dict]:
    for service in deck["services"]:
        for plugin in service.get("plugins", []):
            if plugin["name"] == "dlp-egress":
                return plugin["config"]["patterns"]
    raise SystemExit("no dlp-egress plugin in deck/internal.yaml")


def vendor_route(name: str, vendor: str, broker_url: str = STUB) -> dict:
    return {
        "name": f"vt-{name}",
        "url": f"{STUB}/echo",
        "routes": [route(f"vt-{name}", f"/vt/{name}")],
        "plugins": [{
            "name": "vendor-token",
            "config": {"broker_url": broker_url, "vendor": vendor, "min_ttl_s": 30,
                       "timeout_ms": 2000, "required_scopes": ["issues:read"]},
        }],
    }


def build() -> dict:
    deck = deck_internal()
    return {
        "_format_version": "3.0",
        # Same global chain as the internal DP (minus opentelemetry: no collector).
        "plugins": [{"name": "cnf-check"}, {"name": "dpop-check"}, tier_wall(deck)],
        "services": [
            {
                "name": "echo",
                "url": f"{STUB}/echo",
                "routes": [route("echo", "/echo")],
            },
            {
                "name": "dlp",
                "url": f"{STUB}/echo",
                "routes": [route("dlp", "/dlp")],
                "plugins": [{"name": "dlp-egress", "config": {"patterns": dlp_patterns(deck)}}],
            },
            vendor_route("ok", "ok"),
            vendor_route("consent", "consent"),
            vendor_route("reconsent", "reconsent"),
            vendor_route("pending", "pending"),
            vendor_route("down", "down"),
            vendor_route("malformed", "malformed"),
            # Nothing listens on port 9 inside the Kong container.
            vendor_route("unreachable", "ok", broker_url="http://127.0.0.1:9"),
        ],
    }


if __name__ == "__main__":
    Path(sys.argv[1]).write_text(yaml.safe_dump(build(), sort_keys=False))
