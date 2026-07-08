"""Vendor registry and OAuth-client legs (design §2/§4.5).

Registry is git-committed JSON (registry.json): changing a scope ceiling is
a reviewed commit, which is the lab's version of the §4.5 sign-off rule.
Endpoints come from RFC 8414 metadata when the vendor publishes it
(mockhub); hardcoded registry endpoints are the documented deviation for
vendors without metadata (GitHub).
"""
import json
import os
import time
from pathlib import Path

import httpx

from .vault_store import read_client

REGISTRY_PATH = Path(os.environ.get("REGISTRY_PATH", "/app/registry.json"))
_registry: dict[str, dict] = json.loads(REGISTRY_PATH.read_text())
_metadata_cache: dict[str, dict] = {}


class VendorError(Exception):
    pass


class InvalidGrant(VendorError):
    """The vendor rejected the grant itself (revoked / rotated-away / expired)."""


class VendorUnavailable(VendorError):
    pass


def registry() -> dict[str, dict]:
    return _registry


def get_vendor(vendor: str) -> dict | None:
    spec = _registry.get(vendor)
    if spec is None:
        return None
    enabled_env = spec.get("enabled_env")
    if enabled_env and not os.environ.get(enabled_env):
        return None  # vendor present in registry but not configured in this lab
    return spec


async def endpoints(vendor: str) -> dict:
    """authorization_endpoint / token_endpoint / revocation_endpoint / issuer."""
    spec = _registry[vendor]
    if "auth_metadata_url" in spec:
        if vendor not in _metadata_cache:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(spec["auth_metadata_url"])
                r.raise_for_status()
                _metadata_cache[vendor] = r.json()
        return _metadata_cache[vendor]
    return spec["endpoints"]


def _client_auth(vendor: str) -> tuple[str, str]:
    creds = read_client(vendor)
    if not creds:
        raise VendorUnavailable(f"no client credential for {vendor} in vault")
    return creds["client_id"], creds["client_secret"]


async def _token_request(vendor: str, form: dict) -> dict:
    """POST to the vendor token endpoint with client auth; classify failures."""
    eps = await endpoints(vendor)
    client_id, client_secret = _client_auth(vendor)
    form = {**form, "client_id": client_id, "client_secret": client_secret}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(eps["token_endpoint"], data=form,
                             headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise VendorUnavailable(str(exc)) from exc
    if r.status_code >= 500:
        raise VendorUnavailable(f"vendor token endpoint {r.status_code}")
    body = r.json() if "json" in r.headers.get("content-type", "") else {}
    # GitHub answers 200 with an error field; RFC-shaped vendors answer 400.
    error = body.get("error")
    if r.status_code >= 400 or error:
        if error in ("invalid_grant", "bad_refresh_token"):
            raise InvalidGrant(error)
        raise VendorUnavailable(f"token endpoint error: {error or r.status_code}")
    return body


async def exchange_code(vendor: str, code: str, verifier: str, redirect_uri: str) -> dict:
    return await _token_request(vendor, {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
    })


async def refresh(vendor: str, refresh_token: str) -> dict:
    return await _token_request(vendor, {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    })


async def vendor_user_id(vendor: str, access_token: str) -> str:
    spec = _registry[vendor]
    url = spec.get("vendor_user_endpoint")
    if not url:
        eps = await endpoints(vendor)
        url = eps.get("userinfo_endpoint")
    if not url:
        return "unknown"
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(url, headers={"Authorization": f"Bearer {access_token}",
                                      "Accept": "application/json"})
        if r.status_code != 200:
            return "unknown"
        body = r.json()
        return str(body.get("id") or body.get("login") or body.get("sub") or "unknown")


async def revoke(vendor: str, entry: dict) -> None:
    """RFC 7009 where offered; GitHub's grant-deletion API as the documented
    per-vendor deviation (design §2 'deviations documented per vendor')."""
    spec = _registry[vendor]
    kind = spec.get("revocation", {}).get("type", "rfc7009")
    client_id, client_secret = _client_auth(vendor)
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            if kind == "github_grant":
                r = await c.request(
                    "DELETE",
                    f"https://api.github.com/applications/{client_id}/grant",
                    auth=(client_id, client_secret),
                    json={"access_token": entry["access_token"]},
                    headers={"Accept": "application/vnd.github+json"})
                if r.status_code not in (204, 404, 422):
                    raise VendorUnavailable(f"github grant delete {r.status_code}")
            else:
                eps = await endpoints(vendor)
                r = await c.post(eps["revocation_endpoint"],
                                 data={"token": entry["refresh_token"],
                                       "token_type_hint": "refresh_token",
                                       "client_id": client_id,
                                       "client_secret": client_secret})
                if r.status_code >= 400:
                    raise VendorUnavailable(f"revocation endpoint {r.status_code}")
    except httpx.HTTPError as exc:
        raise VendorUnavailable(str(exc)) from exc


def now() -> float:
    return time.time()
