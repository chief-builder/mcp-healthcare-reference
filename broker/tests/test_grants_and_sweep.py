"""Revocation (§4.4), the §8 background sweeper, grant listing, the admin
route, and the §11 no-issuance invariant."""

import time
from urllib.parse import parse_qs, urlparse

import pytest

from app import main
from tests.conftest import MOCK, active_entry, audit_lines, bearer


# ── DELETE /v1/grants/{vendor}/{sub} ─────────────────────────────────────────
def test_revocation_is_self_service_only(client, keys, kv):
    kv.put("mockhub", "bob-sub", active_entry())
    r = client.delete("/v1/grants/mockhub/bob-sub", headers=bearer(keys.mint()))
    assert r.status_code == 403
    assert kv.entry("mockhub", "bob-sub") is not None


def test_revocation_hits_the_vendor_first_then_deletes(client, keys, kv, mockhub):
    kv.put("mockhub", "alice-sub", active_entry())
    r = client.delete("/v1/grants/mockhub/alice-sub", headers=bearer(keys.mint()))
    assert r.status_code == 200 and r.json() == {"revoked": True}
    assert mockhub.revoked == ["vendor-rt-1"]
    assert kv.entry("mockhub", "alice-sub") is None


def test_revoking_nothing_is_404(client, keys):
    r = client.delete("/v1/grants/mockhub/alice-sub", headers=bearer(keys.mint()))
    assert r.status_code == 404 and r.json()["title"] == "no-grant"


def test_vendor_down_leaves_revoke_pending_then_sweep_finishes_it(client, keys, kv, mockhub):
    kv.put("mockhub", "alice-sub", active_entry())
    mockhub.revoke_mode = "down"
    r = client.delete("/v1/grants/mockhub/alice-sub", headers=bearer(keys.mint()))
    assert r.status_code == 502 and r.json()["title"] == "revoke-pending"
    assert kv.entry("mockhub", "alice-sub")["state"] == "REVOKE_PENDING"
    # Resolve refuses a pending entry rather than serving a token.
    r = client.post("/v1/tokens/resolve", json={"vendor": "mockhub"}, headers=bearer(keys.mint()))
    assert r.status_code == 409

    mockhub.revoke_mode = "ok"
    client.portal.call(main._sweep_once)
    assert kv.entry("mockhub", "alice-sub") is None
    assert mockhub.revoked == ["vendor-rt-1"]


def test_revoke_pending_cas_conflict_is_409_not_500(client, keys, kv, mockhub, monkeypatch):
    kv.put("mockhub", "alice-sub", active_entry())
    mockhub.revoke_mode = "down"
    real_revoke = main.vendors.revoke

    async def revoke_while_refresh_lands(vendor, entry):
        kv.put("mockhub", "alice-sub", active_entry(refresh_generation=2))
        await real_revoke(vendor, entry)

    monkeypatch.setattr(main.vendors, "revoke", revoke_while_refresh_lands)
    r = client.delete("/v1/grants/mockhub/alice-sub", headers=bearer(keys.mint()))
    assert r.status_code == 409 and r.json()["title"] == "grant-changed"
    assert kv.entry("mockhub", "alice-sub")["state"] == "ACTIVE"


def test_revocation_with_vault_down_is_503(client, keys, kv):
    kv.down = True
    r = client.delete("/v1/grants/mockhub/alice-sub", headers=bearer(keys.mint()))
    assert r.status_code == 503


# ── sweeper (§8) ─────────────────────────────────────────────────────────────
async def test_sweeper_refreshes_entries_in_the_proactive_band(kv, mockhub, capsys):
    kv.put("mockhub", "alice-sub", active_entry(expires_at=time.time() + 600))  # 5–15 min
    kv.put("mockhub", "fresh-sub", active_entry(expires_at=time.time() + 3600))
    await main._sweep_once()
    assert kv.entry("mockhub", "alice-sub")["refresh_generation"] == 2
    assert kv.entry("mockhub", "fresh-sub")["refresh_generation"] == 1
    refreshes = [a for a in audit_lines(capsys) if a["audit"] == "broker.refresh"]
    assert refreshes == [
        {**refreshes[0], "path": "proactive", "generation_from": 1, "generation_to": 2}
    ]


async def test_sweeper_marks_stale_on_invalid_grant(kv, mockhub):
    mockhub.refresh_mode = "invalid_grant"
    kv.put("mockhub", "alice-sub", active_entry(expires_at=time.time() + 600))
    await main._sweep_once()
    assert kv.entry("mockhub", "alice-sub")["state"] == "STALE"


async def test_sweeper_drops_expired_transactions(kv, mockhub):
    main._txns["old"] = {"created_at": time.time() - main.TXN_TTL_S - 1}
    main._txns["new"] = {"created_at": time.time()}
    await main._sweep_once()
    assert set(main._txns) == {"new"}


async def test_sweeper_survives_vault_outage(kv, mockhub):
    kv.down = True
    await main._sweep_once()  # must not raise


# ── listing, admin, no-issuance ──────────────────────────────────────────────
def test_grant_listing_shows_only_the_callers_grants_without_tokens(client, keys, kv):
    kv.put("mockhub", "alice-sub", active_entry())
    kv.put("mockhub", "bob-sub", active_entry())
    r = client.get("/v1/grants", headers=bearer(keys.mint()))
    grants = r.json()["grants"]
    assert [g["vendor"] for g in grants] == ["mockhub"]
    assert "access_token" not in r.text and "refresh_token" not in r.text


def test_admin_record_requires_the_platform_admin_group(client, keys, capsys):
    r = client.get("/v1/admin/vendors/mockhub", headers=bearer(keys.mint()))
    assert r.status_code == 403
    assert audit_lines(capsys)[-1]["audit"] == "broker.admin.deny"
    admin = keys.mint(groups=["mcp-platform-admin"])
    r = client.get("/v1/admin/vendors/mockhub", headers=bearer(admin))
    assert r.status_code == 200 and r.json()["vendor_id"] == "mockhub"
    assert client.get("/v1/admin/vendors/nope", headers=bearer(admin)).status_code == 404


@pytest.mark.parametrize("path", ["/v1/grants", "/v1/admin/vendors/mockhub"])
def test_authenticated_routes_reject_missing_tokens(client, path):
    assert client.get(path).status_code == 401


def test_no_issuance_endpoints_exist():
    """§11: custodian, not issuer — no token minting, JWKS, or discovery."""
    paths = {getattr(r, "path", "") for r in main.app.routes}
    forbidden = ("token", "jwks", "certs", ".well-known", "introspect", "keys")
    offending = [p for p in paths if any(f in p for f in forbidden) and p != "/v1/tokens/resolve"]
    assert offending == []


def test_no_token_material_in_any_audit_line(client, keys, kv, mockhub, capsys):
    """§12: run consent + refresh + revoke and grep every stdout line for the
    vendor tokens, the client secret, and the hub JWT."""
    hub_token = keys.mint()
    r = client.post("/v1/tokens/resolve", json={"vendor": "mockhub"}, headers=bearer(hub_token))
    path = urlparse(r.json()["authorize_uri"])
    loc = urlparse(
        client.get(f"{path.path}?{path.query}", follow_redirects=False).headers["location"]
    )
    state = parse_qs(loc.query)["state"][0]
    client.get(f"/v1/callback/mockhub?code=good-code&state={state}&iss={MOCK}")
    entry = kv.entry("mockhub", "alice-sub")
    kv.put("mockhub", "alice-sub", {**entry, "expires_at": time.time() + 60})
    main._cache.clear()
    assert (
        client.post(
            "/v1/tokens/resolve", json={"vendor": "mockhub"}, headers=bearer(hub_token)
        ).json()["access_token"]
        == "vendor-at-2"
    )
    client.delete("/v1/grants/mockhub/alice-sub", headers=bearer(hub_token))

    out = capsys.readouterr().out
    assert out.count('"audit"') >= 6
    for secret in (
        "vendor-at-1",
        "vendor-rt-1",
        "vendor-at-2",
        "vendor-rt-2",
        "test-client-secret",
        hub_token,
        "good-code",
    ):
        assert secret not in out, f"{secret!r} leaked into the audit stream"
