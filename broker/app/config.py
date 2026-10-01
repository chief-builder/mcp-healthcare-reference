"""Broker configuration: every environment input, read and validated once.

`load_settings()` is pure over a mapping so tests can build a Settings
without touching os.environ; `get_settings()` caches the process-wide one.
The FastAPI lifespan calls `get_settings()` at startup, so a bad value
fails the container immediately with a readable message instead of on the
first request.
"""

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    broker_public_url: str = "http://localhost:8300"
    hub_issuer: str = "http://localhost:8080/realms/mcp-plane"
    hub_jwks_uri: str = "http://keycloak:8080/realms/mcp-plane/protocol/openid-connect/certs"
    hub_tier_audience: str = "mcp://tier/internal"
    vault_addr: str = "http://vault:8200"
    vault_token: str = ""
    vault_timeout_s: int = 3
    registry_path: Path = Path("/app/registry.json")
    refresh_buffer_s: int = 300  # §8: lazy refresh band (0–5 min)
    proactive_refresh_s: int = 900  # §8: sweeper refreshes inside 5–15 min
    sweep_interval_s: int = 60  # 0 disables the background sweeper
    mass_stale_threshold: int = 3  # §8/§10: STALEs per vendor per minute → page


def _url(env: Mapping[str, str], name: str, default: str) -> str:
    value = env.get(name, default)
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ConfigError(f"{name} must be an http(s) URL, got {value!r}")
    return value.rstrip("/") if name == "BROKER_PUBLIC_URL" else value


def _int(env: Mapping[str, str], name: str, default: int, minimum: int) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def load_settings(env: Mapping[str, str]) -> Settings:
    d = Settings()
    registry_path = Path(env.get("REGISTRY_PATH", str(d.registry_path)))
    try:
        registry = json.loads(registry_path.read_text())
    except OSError as exc:
        raise ConfigError(f"REGISTRY_PATH {registry_path} is not readable: {exc}") from exc
    except ValueError as exc:
        raise ConfigError(f"REGISTRY_PATH {registry_path} is not valid JSON: {exc}") from exc
    if not isinstance(registry, dict) or not registry:
        raise ConfigError(f"REGISTRY_PATH {registry_path} must hold a non-empty object")

    s = Settings(
        broker_public_url=_url(env, "BROKER_PUBLIC_URL", d.broker_public_url),
        hub_issuer=_url(env, "HUB_ISSUER", d.hub_issuer),
        hub_jwks_uri=_url(env, "HUB_JWKS_URI", d.hub_jwks_uri),
        hub_tier_audience=env.get("HUB_TIER_AUDIENCE", d.hub_tier_audience),
        vault_addr=_url(env, "VAULT_ADDR", d.vault_addr),
        vault_token=env.get("VAULT_TOKEN", d.vault_token),
        vault_timeout_s=_int(env, "VAULT_TIMEOUT_S", d.vault_timeout_s, 1),
        registry_path=registry_path,
        refresh_buffer_s=_int(env, "REFRESH_BUFFER_S", d.refresh_buffer_s, 0),
        proactive_refresh_s=_int(env, "PROACTIVE_REFRESH_S", d.proactive_refresh_s, 0),
        sweep_interval_s=_int(env, "SWEEP_INTERVAL_S", d.sweep_interval_s, 0),
        mass_stale_threshold=_int(env, "MASS_STALE_THRESHOLD", d.mass_stale_threshold, 1),
    )
    if not s.hub_tier_audience.startswith("mcp://tier/"):
        raise ConfigError(
            f"HUB_TIER_AUDIENCE must be an mcp://tier/ audience, got {s.hub_tier_audience!r}"
        )
    if s.proactive_refresh_s < s.refresh_buffer_s:
        raise ConfigError("PROACTIVE_REFRESH_S must be >= REFRESH_BUFFER_S")
    return s


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings(os.environ)
    return _settings


def set_settings(settings: Settings | None) -> None:
    """Test seam: install a Settings (None → reload from env on next use)."""
    global _settings
    _settings = settings
