"""POST /v1/tokens/resolve (design §4.1, §7–§10): every state-machine path,
input validation, and the fail-closed rules."""

import asyncio
import time

import pytest

from app import main
from tests.conftest import active_entry, audit_lines, bearer


def resolve(client, token, **body):
    body.setdefault("vendor", "mockhub")
    return client.post("/v1/tokens/resolve", json=body, headers=bearer(token))


# ── authentication and input validation ──────────────────────────────────────
def test_missing_hub_token_is_401_problem(client):
    r = client.post("/v1/tokens/resolve", json={"vendor": "mockhub"})
    assert r.status_code == 401
    assert r.headers["content-type"] == "application/problem+json"
    assert r.json()["title"] == "invalid-hub-token"


@pytest.mark.parametrize(
    "body, detail",
    [
        (b"not json", "body must be a JSON object"),
        (b"[1, 2]", "body must be a JSON object"),
        (b"{}", "vendor is required"),
        (b'{"vendor": 7}', "vendor is required"),
        (b'{"vendor": "mockhub", "min_ttl_s": "soon"}', "min_ttl_s must be"),
        (b'{"vendor": "mockhub", "min_ttl_s": -1}', "min_ttl_s must be"),
        (b'{"vendor": "mockhub", "min_ttl_s": true}', "min_ttl_s must be"),
        (b'{"vendor": "mockhub", "required_scopes": "issues:read"}', "required_scopes must be"),
        (b'{"vendor": "mockhub", "required_scopes": [1]}', "required_scopes must be"),
    ],
)
def test_malformed_body_is_a_400_problem_and_audited(client, keys, capsys, body, detail):
    token = keys.mint()
    r = client.post(
        "/v1/tokens/resolve",
        content=body,
        headers={**bearer(token), "Content-Type": "application/json"},
    )
    assert r.status_code == 400
    assert r.json()["title"] == "invalid-request"
    assert detail in r.json()["detail"]
    deny = [a for a in audit_lines(capsys) if a.get("reason") == "bad_request"]
    assert deny and deny[0]["decision"] == "deny" and deny[0]["detail"].startswith(detail)


def test_empty_lua_table_scopes_are_accepted_as_none(client, keys, kv):
    # Kong's cjson encodes the plugin's default {} (empty Lua table) as an object.
    kv.put("mockhub", "alice-sub", active_entry())
    r = resolve(client, keys.mint(), required_scopes={})
    assert r.status_code == 200


def test_integral_float_min_ttl_is_accepted(client, keys, kv):
    kv.put("mockhub", "alice-sub", active_entry())
    assert resolve(client, keys.mint(), min_ttl_s=30.0).status_code == 200


def test_sub_mismatch_is_rejected_and_audited(client, keys, capsys):
    r = resolve(client, keys.mint(), sub="mallory-sub")
    assert r.status_code == 400 and r.json()["title"] == "sub-mismatch"
    assert any(a.get("reason") == "sub_mismatch" for a in audit_lines(capsys))


def test_unknown_or_unconfigured_vendor_is_404(client, keys):
    assert resolve(client, keys.mint(), vendor="nope").status_code == 404
    # github is registered but disabled unless GITHUB_CLIENT_ID is set.
    assert resolve(client, keys.mint(), vendor="github").status_code == 404


def test_required_scopes_beyond_ceiling_are_refused(client, keys, capsys):
    r = resolve(client, keys.mint(), required_scopes=["issues:read", "admin:org"])
    assert r.status_code == 403 and r.json()["title"] == "scope-exceeds-ceiling"
    assert any(a.get("path") == "scope-ceiling" for a in audit_lines(capsys))


# ── grant states ─────────────────────────────────────────────────────────────
def test_absent_grant_needs_consent_for_the_minimum_scopes(client, keys):
    r = resolve(client, keys.mint(), required_scopes=["issues:read"])
    assert r.status_code == 404 and r.json()["title"] == "needs-consent"
    uri = r.json()["authorize_uri"]
    assert uri.startswith("http://broker.test/v1/authorize/mockhub?txn=")
    txn = uri.split("txn=")[1]
    assert main._txns[txn]["scopes"] == ["issues:read"]
    assert main._txns[txn]["sub"] == "alice-sub"


def test_absent_grant_without_required_scopes_asks_for_the_ceiling(client, keys):
    r = resolve(client, keys.mint())
    txn = r.json()["authorize_uri"].split("txn=")[1]
    assert main._txns[txn]["scopes"] == ["issues:read", "issues:write"]


def test_consent_scopes_are_capped_by_the_ceiling():
    assert main._consent_scopes([], ["a", "b"]) == ["a", "b"]
    assert main._consent_scopes(["b"], ["a", "b"]) == ["b"]
    assert main._consent_scopes(["b", "z"], ["a", "b"]) == ["b"]


def test_stale_grant_needs_consent(client, keys, kv):
    kv.put("mockhub", "alice-sub", active_entry(state="STALE"))
    assert resolve(client, keys.mint()).json()["title"] == "needs-consent"


def test_revoke_pending_grant_is_refused(client, keys, kv):
    kv.put("mockhub", "alice-sub", active_entry(state="REVOKE_PENDING"))
    r = resolve(client, keys.mint())
    assert r.status_code == 409 and r.json()["title"] == "revoke-pending"


def test_grant_missing_a_required_scope_asks_for_reconsent(client, keys, kv):
    kv.put("mockhub", "alice-sub", active_entry(granted_scopes=["issues:read"]))
    r = resolve(client, keys.mint(), required_scopes=["issues:write"])
    assert r.status_code == 409 and r.json()["title"] == "needs-reconsent-scope"
    assert r.json()["missing_scopes"] == ["issues:write"]
    txn = r.json()["authorize_uri"].split("txn=")[1]
    assert main._txns[txn]["scopes"] == ["issues:read", "issues:write"]


def test_fresh_grant_is_served_from_cache_without_a_vendor_call(client, keys, kv, mockhub):
    kv.put("mockhub", "alice-sub", active_entry())
    r = resolve(client, keys.mint())
    assert r.status_code == 200
    assert r.json()["access_token"] == "vendor-at-1"
    assert mockhub.refresh_calls == 0


# ── refresh (§8/§9) ──────────────────────────────────────────────────────────
def test_refresh_inside_buffer_rotates_and_bumps_generation(client, keys, kv, mockhub):
    kv.put("mockhub", "alice-sub", active_entry(expires_at=time.time() + 60))
    r = resolve(client, keys.mint())
    assert r.status_code == 200 and r.json()["access_token"] == "vendor-at-2"
    stored = kv.entry("mockhub", "alice-sub")
    assert stored["refresh_generation"] == 2 and stored["refresh_token"] == "vendor-rt-2"
    assert mockhub.refresh_calls == 1


def test_non_rotating_vendor_keeps_the_old_refresh_token(client, keys, kv, mockhub, monkeypatch):
    async def no_rotation(vendor, rt):
        return {"access_token": "at-new", "expires_in": 3600}

    monkeypatch.setattr(main.vendors, "refresh", no_rotation)
    kv.put("mockhub", "alice-sub", active_entry(expires_at=time.time() + 60))
    assert resolve(client, keys.mint()).status_code == 200
    assert kv.entry("mockhub", "alice-sub")["refresh_token"] == "vendor-rt-1"


async def test_concurrent_resolves_single_flight_one_vendor_refresh(kv, keys, mockhub, monkeypatch):
    """§9: N concurrent resolves inside the buffer → exactly one vendor refresh;
    waiters get the winner's token. The vendor call yields to the event loop
    (like a real network round trip) so the requests genuinely overlap."""
    import httpx

    real_refresh = main.vendors.refresh

    async def slow_refresh(vendor, refresh_token):
        await asyncio.sleep(0.05)
        return await real_refresh(vendor, refresh_token)

    monkeypatch.setattr(main.vendors, "refresh", slow_refresh)
    kv.put("mockhub", "alice-sub", active_entry(expires_at=time.time() + 60))
    token = keys.mint()
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://broker.test") as c:
        rs = await asyncio.gather(
            *[
                c.post("/v1/tokens/resolve", json={"vendor": "mockhub"}, headers=bearer(token))
                for _ in range(10)
            ]
        )
    assert {r.status_code for r in rs} == {200}
    assert {r.json()["access_token"] for r in rs} == {"vendor-at-2"}
    assert mockhub.refresh_calls == 1


def test_invalid_grant_marks_stale_and_needs_consent(client, keys, kv, mockhub, capsys):
    mockhub.refresh_mode = "invalid_grant"
    kv.put("mockhub", "alice-sub", active_entry(expires_at=time.time() + 60))
    r = resolve(client, keys.mint())
    assert r.status_code == 404 and r.json()["title"] == "needs-consent"
    assert kv.entry("mockhub", "alice-sub")["state"] == "STALE"
    assert any(a["audit"] == "broker.stale" for a in audit_lines(capsys))


def test_mass_stale_pages_once_at_threshold(client, keys, kv, mockhub, capsys):
    mockhub.refresh_mode = "invalid_grant"
    for i in range(3):
        kv.put("mockhub", f"user-{i}", active_entry(expires_at=time.time() + 60))
        resolve(client, keys.mint(sub=f"user-{i}"))
    pages = [a for a in audit_lines(capsys) if a["audit"] == "broker.stale.mass"]
    assert len(pages) == 1
    assert pages[0]["count"] == 3 and pages[0]["page"] is True and pages[0]["security_event"]
    # A fourth STALE inside the window does not page again.
    kv.put("mockhub", "user-3", active_entry(expires_at=time.time() + 60))
    resolve(client, keys.mint(sub="user-3"))
    assert not [a for a in audit_lines(capsys) if a["audit"] == "broker.stale.mass"]


def test_vendor_down_during_refresh_is_503(client, keys, kv, mockhub):
    mockhub.refresh_mode = "down"
    kv.put("mockhub", "alice-sub", active_entry(expires_at=time.time() + 60))
    r = resolve(client, keys.mint())
    assert r.status_code == 503 and r.json()["title"] == "vendor-unavailable"
    assert kv.entry("mockhub", "alice-sub")["state"] == "ACTIVE"


def test_cas_lost_serves_the_winners_token(client, keys, kv, monkeypatch):
    """§9: if another writer moved the entry mid-refresh, our pair is
    discarded and the winner's stored token is served."""
    kv.put("mockhub", "alice-sub", active_entry(expires_at=time.time() + 60))

    async def racing_refresh(vendor, rt):
        kv.put("mockhub", "alice-sub", active_entry(access_token="winner-at", refresh_generation=2))
        return {"access_token": "loser-at", "refresh_token": "loser-rt", "expires_in": 3600}

    monkeypatch.setattr(main.vendors, "refresh", racing_refresh)
    r = resolve(client, keys.mint())
    assert r.status_code == 200 and r.json()["access_token"] == "winner-at"
    assert kv.entry("mockhub", "alice-sub")["access_token"] == "winner-at"


def test_vault_down_fails_closed(client, keys, kv, capsys):
    kv.down = True
    r = resolve(client, keys.mint())
    assert r.status_code == 503 and r.json()["title"] == "vault-unavailable"
    assert any(a.get("path") == "vault-unavailable" for a in audit_lines(capsys))


def test_cached_entry_is_served_within_cache_ttl_even_if_vault_drops(client, keys, kv):
    """§10: the only grace is the ≤60 s in-memory cache."""
    kv.put("mockhub", "alice-sub", active_entry())
    assert resolve(client, keys.mint()).status_code == 200
    kv.down = True
    assert resolve(client, keys.mint()).status_code == 200
    key = ("mockhub", "alice-sub")
    entry, ver, _ = main._cache[key]
    main._cache[key] = (entry, ver, time.time() - main.CACHE_TTL_S - 1)
    assert resolve(client, keys.mint()).status_code == 503


def test_rejected_hub_token_detail_hides_library_text(client, keys, capsys):
    """The client gets a fixed detail; the JWT library's reason is audited."""
    r = resolve(client, keys.mint(iss="http://evil.example/realms/x"), vendor="mockhub")
    assert r.status_code == 401
    assert r.json()["detail"] == "hub token rejected"
    denied = [a for a in audit_lines(capsys) if a.get("audit") == "broker.auth.deny"]
    assert denied and "issuer" in denied[0]["reason"].lower()
