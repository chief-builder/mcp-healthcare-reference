"""Static checks on the committed gateway config (no Kong needed)."""

from pathlib import Path

import pytest
import yaml

DECK = Path(__file__).resolve().parents[2] / "deck"


def routes():
    for path in sorted(DECK.glob("*.yaml")):
        for service in yaml.safe_load(path.read_text()).get("services", []):
            for route in service.get("routes", []):
                yield path.name, route


@pytest.mark.parametrize("deck_file,route", list(routes()),
                         ids=lambda v: v if isinstance(v, str) else v["name"])
def test_every_route_declares_http(deck_file, route):
    # Kong 3.14+ defaults a route without `protocols` to https only, which
    # would 426 every request on the DPs' plain-HTTP :8000 listener.
    assert "http" in route.get("protocols", []), f"{deck_file}: {route['name']}"
