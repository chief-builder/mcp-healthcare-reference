"""Vault custody (design §5): KV v2 mounts vendor-tokens/ and vendor-clients/.

The entry's refresh_generation is the §9 monotonic counter; the KV v2
version doubles as the compare-and-swap handle (cas= on write fails if
another writer moved the entry). Vault unavailability fails CLOSED (§10):
callers translate VaultUnavailable into 503.
"""
import os

import hvac
from hvac import exceptions as hvac_exc

TOKENS_MOUNT = "vendor-tokens"
CLIENTS_MOUNT = "vendor-clients"

# Explicit timeout so an unreachable/frozen vault surfaces as VaultUnavailable
# (→ 503, §10 fail-closed) in bounded time instead of hanging the resolve.
_client = hvac.Client(
    url=os.environ.get("VAULT_ADDR", "http://vault:8200"),
    token=os.environ.get("VAULT_TOKEN", ""),
    timeout=int(os.environ.get("VAULT_TIMEOUT_S", "3")),
)


class VaultUnavailable(Exception):
    pass


class CasConflict(Exception):
    pass


def _path(vendor: str, sub: str) -> str:
    return f"{vendor}/{sub}"


def read_entry(vendor: str, sub: str) -> tuple[dict, int] | None:
    """Return (entry, kv_version) or None if absent."""
    try:
        resp = _client.secrets.kv.v2.read_secret_version(
            path=_path(vendor, sub), mount_point=TOKENS_MOUNT, raise_on_deleted_version=True)
    except hvac_exc.InvalidPath:
        return None
    except Exception as exc:
        raise VaultUnavailable(str(exc)) from exc
    return resp["data"]["data"], resp["data"]["metadata"]["version"]


def write_entry(vendor: str, sub: str, entry: dict, cas: int | None = None) -> int:
    """Write the entry; cas=N fails with CasConflict if the version moved.
    cas=0 requires the entry not to exist; cas=None overwrites (re-consent)."""
    try:
        resp = _client.secrets.kv.v2.create_or_update_secret(
            path=_path(vendor, sub), secret=entry, cas=cas, mount_point=TOKENS_MOUNT)
    except hvac_exc.InvalidRequest as exc:
        if "check-and-set" in str(exc):
            raise CasConflict(str(exc)) from exc
        raise VaultUnavailable(str(exc)) from exc
    except Exception as exc:
        raise VaultUnavailable(str(exc)) from exc
    return resp["data"]["version"]


def delete_entry(vendor: str, sub: str) -> None:
    try:
        _client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=_path(vendor, sub), mount_point=TOKENS_MOUNT)
    except hvac_exc.InvalidPath:
        pass
    except Exception as exc:
        raise VaultUnavailable(str(exc)) from exc


def read_client(vendor: str) -> dict | None:
    """Per-vendor confidential client credential (design §3/§5)."""
    try:
        resp = _client.secrets.kv.v2.read_secret_version(
            path=vendor, mount_point=CLIENTS_MOUNT, raise_on_deleted_version=True)
    except hvac_exc.InvalidPath:
        return None
    except Exception as exc:
        raise VaultUnavailable(str(exc)) from exc
    return resp["data"]["data"]
