"""Consent dance (design §4.2/§4.3/§6): authorize → vendor → callback, with
the PKCE, single-use state, and RFC 9207 iss mix-up defenses."""

from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from app import main
from tests.conftest import MOCK, audit_lines, bearer


def start_consent(client, keys, **body) -> dict:
    """resolve → needs-consent → GET authorize; returns the vendor redirect params."""
    r = client.post(
        "/v1/tokens/resolve", json={"vendor": "mockhub", **body}, headers=bearer(keys.mint())
    )
    path = urlparse(r.json()["authorize_uri"])
    redirect = client.get(f"{path.path}?{path.query}", follow_redirects=False)
    assert redirect.status_code == 307
    location = urlparse(redirect.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == f"{MOCK}/authorize"
    return {k: v[0] for k, v in parse_qs(location.query).items()}


def test_authorize_redirect_carries_pkce_s256_and_minimum_scopes(client, keys):
    params = start_consent(client, keys, required_scopes=["issues:read"])
    assert params["code_challenge_method"] == "S256"
    assert len(params["code_challenge"]) == 43  # base64url(SHA-256), unpadded
    assert params["scope"] == "issues:read"
    assert params["client_id"] == "broker-client"
    assert params["redirect_uri"] == "http://broker.test/v1/callback/mockhub"
    # The verifier stays server-side, bound to the initiating sub.
    record = main._states[params["state"]]
    assert record["sub"] == "alice-sub" and "pkce_verifier" in record
    assert "nonce" not in record


@pytest.mark.parametrize("txn", ["unknown", ""])
def test_authorize_with_bad_transaction_is_400_not_a_redirect(client, txn):
    r = client.get(f"/v1/authorize/mockhub?txn={txn}", follow_redirects=False)
    assert r.status_code == 400 and r.json()["title"] == "invalid-transaction"


def test_authorize_txn_is_bound_to_its_vendor(client, keys):
    r = client.post("/v1/tokens/resolve", json={"vendor": "mockhub"}, headers=bearer(keys.mint()))
    txn = r.json()["authorize_uri"].split("txn=")[1]
    assert client.get(f"/v1/authorize/github?txn={txn}").status_code == 400


def test_authorize_with_vendor_metadata_down_is_502_problem(client, keys, mockhub):
    r = client.post("/v1/tokens/resolve", json={"vendor": "mockhub"}, headers=bearer(keys.mint()))
    txn = r.json()["authorize_uri"].split("txn=")[1]
    mockhub.router["metadata"].mock(side_effect=httpx.ConnectError("refused"))
    r = client.get(f"/v1/authorize/mockhub?txn={txn}", follow_redirects=False)
    assert r.status_code == 502 and r.json()["title"] == "vendor-unavailable"


def test_authorize_with_vault_down_is_503_problem(client, keys, kv):
    r = client.post("/v1/tokens/resolve", json={"vendor": "mockhub"}, headers=bearer(keys.mint()))
    txn = r.json()["authorize_uri"].split("txn=")[1]
    kv.down = True
    r = client.get(f"/v1/authorize/mockhub?txn={txn}", follow_redirects=False)
    assert r.status_code == 503 and r.json()["title"] == "vault-unavailable"


def test_callback_success_stores_a_generation_one_grant(client, keys, kv, capsys):
    params = start_consent(client, keys)
    r = client.get(f"/v1/callback/mockhub?code=good-code&state={params['state']}&iss={MOCK}")
    assert r.status_code == 200 and "Connected" in r.text
    entry = kv.entry("mockhub", "alice-sub")
    assert entry["state"] == "ACTIVE" and entry["refresh_generation"] == 1
    assert entry["vendor_user_id"] == "octo-1"
    assert entry["granted_scopes"] == ["issues:read", "issues:write"]
    assert any(a["audit"] == "broker.consent.complete" for a in audit_lines(capsys))


def test_state_replay_is_a_security_event(client, keys, capsys):
    params = start_consent(client, keys)
    url = f"/v1/callback/mockhub?code=good-code&state={params['state']}&iss={MOCK}"
    assert client.get(url).status_code == 200
    capsys.readouterr()
    replay = client.get(url)
    assert replay.status_code == 400
    fails = [a for a in audit_lines(capsys) if a["audit"] == "broker.consent.fail"]
    assert fails and fails[0]["reason"] == "state_invalid_or_replayed"
    assert fails[0]["security_event"] is True


def test_unknown_state_is_a_security_event(client, capsys):
    assert client.get("/v1/callback/mockhub?code=x&state=forged").status_code == 400
    assert audit_lines(capsys)[-1]["security_event"] is True


def test_iss_mismatch_is_rejected_before_code_redemption(client, keys, kv, mockhub, capsys):
    params = start_consent(client, keys)
    r = client.get(
        f"/v1/callback/mockhub?code=good-code&state={params['state']}&iss=https://evil.example"
    )
    assert r.status_code == 400 and "mismatch" in r.text.lower()
    assert kv.entry("mockhub", "alice-sub") is None
    fail = audit_lines(capsys)[-1]
    assert fail["reason"] == "iss_mismatch" and fail["iss_present"] is True


def test_iss_omission_is_rejected_when_the_as_advertises_iss(client, keys, kv, capsys):
    params = start_consent(client, keys)
    r = client.get(f"/v1/callback/mockhub?code=good-code&state={params['state']}")
    assert r.status_code == 400 and "issuer" in r.text.lower()
    assert kv.entry("mockhub", "alice-sub") is None
    assert audit_lines(capsys)[-1]["iss_present"] is False


def test_iss_omission_is_tolerated_when_the_as_does_not_advertise_iss(client, keys, kv, mockhub):
    mockhub.iss_supported = False
    params = start_consent(client, keys)
    r = client.get(f"/v1/callback/mockhub?code=good-code&state={params['state']}")
    assert r.status_code == 200
    assert kv.entry("mockhub", "alice-sub")["state"] == "ACTIVE"


def test_vendor_error_gets_a_constant_page_with_no_reflection(client, keys, capsys):
    params = start_consent(client, keys)
    payload = "<script>alert(1)</script>"
    r = client.get(
        f"/v1/callback/mockhub?error={payload}&state={params['state']}&iss={MOCK}",
    )
    assert r.status_code == 400
    assert r.text == "<h1>Authorization failed.</h1>"
    assert audit_lines(capsys)[-1]["reason"] == payload  # audit only, never the page


def test_bad_code_exchange_is_502_and_nothing_stored(client, keys, kv):
    params = start_consent(client, keys)
    r = client.get(f"/v1/callback/mockhub?code=bad-code&state={params['state']}&iss={MOCK}")
    assert r.status_code == 502
    assert kv.entry("mockhub", "alice-sub") is None


def test_userinfo_outage_is_502_not_500(client, keys, kv, mockhub):
    params = start_consent(client, keys)
    mockhub.router["user"].mock(side_effect=httpx.ConnectError("refused"))
    r = client.get(f"/v1/callback/mockhub?code=good-code&state={params['state']}&iss={MOCK}")
    assert r.status_code == 502
    assert kv.entry("mockhub", "alice-sub") is None


def test_vault_down_at_callback_is_503(client, keys, kv):
    params = start_consent(client, keys)
    kv.down = True
    r = client.get(f"/v1/callback/mockhub?code=good-code&state={params['state']}&iss={MOCK}")
    assert r.status_code == 503
