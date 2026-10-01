import pytest

from app.config import ConfigError, Settings, load_settings
from tests.conftest import REGISTRY


def env(**kw):
    return {"REGISTRY_PATH": str(REGISTRY), **kw}


def test_defaults_match_the_design_doc():
    s = load_settings(env())
    assert s == Settings(registry_path=REGISTRY)
    assert (s.refresh_buffer_s, s.proactive_refresh_s, s.mass_stale_threshold) == (300, 900, 3)


def test_public_url_trailing_slash_is_trimmed():
    assert (
        load_settings(env(BROKER_PUBLIC_URL="http://b:8300/")).broker_public_url == "http://b:8300"
    )


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"HUB_ISSUER": "localhost:8080"}, "HUB_ISSUER must be an http(s) URL"),
        ({"VAULT_ADDR": "ftp://vault"}, "VAULT_ADDR must be an http(s) URL"),
        ({"SWEEP_INTERVAL_S": "soon"}, "SWEEP_INTERVAL_S must be an integer"),
        ({"MASS_STALE_THRESHOLD": "0"}, "MASS_STALE_THRESHOLD must be >= 1"),
        ({"VAULT_TIMEOUT_S": "0"}, "VAULT_TIMEOUT_S must be >= 1"),
        ({"REFRESH_BUFFER_S": "1000"}, "PROACTIVE_REFRESH_S must be >= REFRESH_BUFFER_S"),
        ({"HUB_TIER_AUDIENCE": "mcp://srv/x"}, "HUB_TIER_AUDIENCE must be an mcp://tier/"),
    ],
)
def test_bad_values_fail_fast_with_the_variable_name(overrides, message):
    with pytest.raises(ConfigError, match=message.replace("(", r"\(").replace(")", r"\)")):
        load_settings(env(**overrides))


def test_missing_registry_fails_fast(tmp_path):
    with pytest.raises(ConfigError, match="is not readable"):
        load_settings({"REGISTRY_PATH": str(tmp_path / "nope.json")})


def test_unparseable_registry_fails_fast(tmp_path):
    bad = tmp_path / "registry.json"
    bad.write_text("{not json")
    with pytest.raises(ConfigError, match="is not valid JSON"):
        load_settings({"REGISTRY_PATH": str(bad)})


def test_empty_registry_fails_fast(tmp_path):
    empty = tmp_path / "registry.json"
    empty.write_text("{}")
    with pytest.raises(ConfigError, match="non-empty object"):
        load_settings({"REGISTRY_PATH": str(empty)})
