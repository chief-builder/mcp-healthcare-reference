"""Offline gateway suite (run via plugins/tests/run.sh, not plain pytest).

Each section drives one bespoke plugin through a DB-less Kong: positive
paths prove the plugin lets legitimate traffic through untouched, negative
paths prove each rejection branch fires. Tokens are signed with a throwaway
test key; the plugins never verify hub-token signatures (that is the
openid-connect plugin's and the MCP servers' job), so any key will do.
"""

import base64
import hashlib
import http.client
import json
import os
import subprocess
import time
import uuid
from urllib.parse import urlparse

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import ec

KONG_URL = os.environ.get("KONG_URL", "")
KONG_CONTAINER = os.environ.get("KONG_CONTAINER", "")
pytestmark = pytest.mark.skipif(not KONG_URL, reason="run via plugins/tests/run.sh")

TIER = "mcp://tier/internal"
HUB_KEY = ec.generate_private_key(ec.SECP256R1())  # test-only signing key
MINTED: list[str] = []  # every token sent, for the no-token-in-logs check


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def mint(**claims) -> str:
    now = int(time.time())
    payload = {
        "iss": "http://localhost:8080/realms/mcp-plane",
        "sub": "user-1",
        "azp": "test-client",
        "jti": str(uuid.uuid4()),
        "aud": ["mcp://srv/test", TIER],
        "mcp_tier": "internal",
        "iat": now,
        "exp": now + 300,
        **claims,
    }
    token = jwt.encode(payload, HUB_KEY, algorithm="ES256")
    MINTED.append(token)
    return token


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- DPoP helpers -----------------------------------------------------------

class DpopKey:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key()))
        self.jwk = {k: jwk[k] for k in ("kty", "crv", "x", "y")}
        canonical = json.dumps(
            {k: self.jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"))
        self.jkt = b64url(hashlib.sha256(canonical.encode()).digest())

    def proof(self, token: str, htm: str = "POST", htu: str | None = None, *,
              iat: float | None = None, jti: str | None = None, typ: str = "dpop+jwt",
              ath: str | None = None, jwk: dict | None = None) -> str:
        payload = {
            "htm": htm,
            "htu": htu if htu is not None else f"{KONG_URL}/echo",
            "iat": int(iat if iat is not None else time.time()),
            "jti": jti or str(uuid.uuid4()),
            "ath": ath if ath is not None else b64url(hashlib.sha256(token.encode()).digest()),
        }
        return jwt.encode(payload, self.key, algorithm="ES256",
                          headers={"typ": typ, "jwk": jwk or self.jwk})


def dpop_call(token: str, proof: str | None, scheme: str = "DPoP") -> requests.Response:
    headers = {"Authorization": f"{scheme} {token}"}
    if proof is not None:
        headers["DPoP"] = proof
    return requests.post(f"{KONG_URL}/echo", headers=headers, json={}, timeout=10)


def reason_of(resp: requests.Response) -> str:
    return resp.json().get("message", "")


# --- tier wall (deck/internal.yaml global pre-function) ---------------------

def test_tier_wall_internal_audience_passes():
    r = requests.get(f"{KONG_URL}/echo", headers=bearer(mint()), timeout=10)
    assert r.status_code == 200


def test_tier_wall_external_audience_rejected():
    token = mint(aud=["mcp://srv/test", "mcp://tier/external"], mcp_tier="external")
    r = requests.get(f"{KONG_URL}/echo", headers=bearer(token), timeout=10)
    assert r.status_code == 401
    assert "tier audience mismatch" in r.headers["WWW-Authenticate"]


def test_tier_wall_garbage_token_rejected():
    r = requests.get(f"{KONG_URL}/echo", headers=bearer("not-a-jwt"), timeout=10)
    assert r.status_code == 401


def test_tier_wall_no_token_passes_through():
    # Token-less requests reach the upstream, which issues the 401 challenge.
    r = requests.get(f"{KONG_URL}/echo", timeout=10)
    assert r.status_code == 200
    assert r.json()["authorization"] is None


def test_tier_wall_checks_dpop_scheme_too():
    token = mint(aud=["mcp://srv/test", "mcp://tier/external"])
    r = requests.get(f"{KONG_URL}/echo", headers={"Authorization": f"DPoP {token}"}, timeout=10)
    assert r.status_code == 401
    assert "tier audience mismatch" in r.headers["WWW-Authenticate"]


# --- cnf-check ---------------------------------------------------------------

def test_cnf_bearer_token_passes():
    r = requests.get(f"{KONG_URL}/echo", headers=bearer(mint()), timeout=10)
    assert r.status_code == 200


def test_cnf_bound_token_over_plaintext_rejected():
    token = mint(cnf={"x5t#S256": b64url(hashlib.sha256(b"some-cert").digest())})
    r = requests.get(f"{KONG_URL}/echo", headers=bearer(token), timeout=10)
    assert r.status_code == 401
    assert "no_client_certificate" in r.json()["message"]


# --- dpop-check --------------------------------------------------------------

def test_dpop_plain_bearer_untouched():
    token = mint()
    r = requests.post(f"{KONG_URL}/echo", headers=bearer(token), json={}, timeout=10)
    assert r.status_code == 200
    assert r.json()["authorization"] == f"Bearer {token}"


def test_dpop_valid_proof_passes():
    k = DpopKey()
    token = mint(cnf={"jkt": k.jkt})
    r = dpop_call(token, k.proof(token))
    assert r.status_code == 200


def test_dpop_bound_token_with_bearer_scheme_rejected():
    k = DpopKey()
    token = mint(cnf={"jkt": k.jkt})
    r = dpop_call(token, k.proof(token), scheme="Bearer")
    assert r.status_code == 401
    assert reason_of(r) == "dpop: wrong_auth_scheme"


def test_dpop_missing_proof_rejected():
    k = DpopKey()
    token = mint(cnf={"jkt": k.jkt})
    r = dpop_call(token, None)
    assert r.status_code == 401
    assert reason_of(r) == "dpop: missing_proof"


def test_dpop_two_proofs_rejected():
    k = DpopKey()
    token = mint(cnf={"jkt": k.jkt})
    url = urlparse(KONG_URL)
    conn = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
    conn.putrequest("POST", "/echo")
    conn.putheader("Authorization", f"DPoP {token}")
    conn.putheader("DPoP", k.proof(token))
    conn.putheader("DPoP", k.proof(token))
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", "2")
    conn.endheaders(b"{}")
    resp = conn.getresponse()
    body = json.loads(resp.read())
    assert resp.status == 401
    assert body["message"] == "dpop: multiple_proofs"


def test_dpop_wrong_typ_rejected():
    k = DpopKey()
    token = mint(cnf={"jkt": k.jkt})
    r = dpop_call(token, k.proof(token, typ="JWT"))
    assert r.status_code == 401
    assert reason_of(r) == "dpop: bad_proof_header"


def test_dpop_htm_mismatch_rejected():
    k = DpopKey()
    token = mint(cnf={"jkt": k.jkt})
    r = dpop_call(token, k.proof(token, htm="GET"))
    assert reason_of(r) == "dpop: htm_mismatch"


def test_dpop_htu_mismatch_rejected():
    k = DpopKey()
    token = mint(cnf={"jkt": k.jkt})
    r = dpop_call(token, k.proof(token, htu=f"{KONG_URL}/elsewhere"))
    assert reason_of(r) == "dpop: htu_mismatch"


def test_dpop_stale_iat_rejected():
    k = DpopKey()
    token = mint(cnf={"jkt": k.jkt})
    r = dpop_call(token, k.proof(token, iat=time.time() - 600))
    assert reason_of(r) == "dpop: stale_proof"


def test_dpop_ath_mismatch_rejected():
    k = DpopKey()
    token = mint(cnf={"jkt": k.jkt})
    r = dpop_call(token, k.proof(token, ath=b64url(hashlib.sha256(b"other").digest())))
    assert reason_of(r) == "dpop: ath_mismatch"


def test_dpop_thumbprint_mismatch_rejected():
    k, other = DpopKey(), DpopKey()
    token = mint(cnf={"jkt": other.jkt})
    r = dpop_call(token, k.proof(token))
    assert reason_of(r) == "dpop: thumbprint_mismatch"


def test_dpop_jti_replay_rejected():
    k = DpopKey()
    token = mint(cnf={"jkt": k.jkt})
    proof = k.proof(token, jti="replayed-" + str(uuid.uuid4()))
    assert dpop_call(token, proof).status_code == 200
    r = dpop_call(token, proof)
    assert r.status_code == 401
    assert reason_of(r) == "dpop: proof_replay"


# --- dlp-egress --------------------------------------------------------------

def dlp_post(data, content_type: str = "application/json") -> requests.Response:
    body = data if isinstance(data, (str, bytes)) else json.dumps(data)
    return requests.post(f"{KONG_URL}/dlp", data=body, timeout=10,
                         headers={**bearer(mint()), "Content-Type": content_type})


def tool_call(text: str) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "create_issue", "arguments": {"body": text}}}


def test_dlp_clean_body_passes():
    r = dlp_post(tool_call("nothing sensitive here"))
    assert r.status_code == 200
    assert "nothing sensitive here" in r.json()["body"]


def test_dlp_raw_mrn_blocked():
    r = dlp_post(tool_call("patient MRN-1234567 follow-up"))
    assert r.status_code == 403
    assert r.json() == {"error": "dlp_blocked", "reason": "pattern_match", "pattern": "mrn"}


def test_dlp_json_escaped_mrn_blocked():
    # "MRN-1234567" is the raw-scan bypass (AUDIT.md S2): no literal hyphen
    # on the wire, but the vendor's JSON parser yields MRN-1234567.
    body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x",' \
           '"arguments":{"body":"MRN\\u002d1234567"}}}'
    assert "MRN-1234567" not in body
    r = dlp_post(body)
    assert r.status_code == 403
    assert r.json()["pattern"] == "mrn"


def test_dlp_ssn_blocked():
    r = dlp_post(tool_call("ssn 123-45-6789"))
    assert r.status_code == 403
    assert r.json()["pattern"] == "ssn"


def test_dlp_nested_string_blocked():
    deep = {"a": [{"b": {"c": ["ok", {"d": "MRN-7654321"}]}}]}
    r = dlp_post(tool_call("") | {"params": {"name": "x", "arguments": deep}})
    assert r.status_code == 403


def test_dlp_match_in_json_key_blocked():
    r = dlp_post('{"MRN\\u002d1111111": "value"}')
    assert r.status_code == 403


def test_dlp_non_json_body_scanned_raw():
    assert dlp_post("plain text MRN-1234567", "text/plain").status_code == 403
    assert dlp_post("plain text, clean", "text/plain").status_code == 200


def test_dlp_invalid_json_with_json_content_type_refused():
    r = dlp_post('{"body": "unterminated', "application/json")
    assert r.status_code == 403
    assert r.json()["reason"] == "unparseable_body"


def test_dlp_overly_deep_json_refused():
    body = "[" * 80 + "]" * 80
    r = dlp_post(body)
    assert r.status_code == 403
    assert r.json()["reason"] in ("body_too_deep", "unparseable_body")


def test_dlp_empty_post_body_passes():
    r = requests.post(f"{KONG_URL}/dlp", headers=bearer(mint()), timeout=10)
    assert r.status_code == 200


def test_dlp_get_passes():
    r = requests.get(f"{KONG_URL}/dlp", headers=bearer(mint()), timeout=10)
    assert r.status_code == 200


# --- vendor-token ------------------------------------------------------------

def vt(route: str, token: str | None = None, scheme: str = "Bearer") -> requests.Response:
    headers = {"Authorization": f"{scheme} {token}"} if token else {}
    return requests.post(f"{KONG_URL}/vt/{route}", headers=headers, json={}, timeout=10)


def test_vendor_token_swaps_hub_jwt_for_vendor_token():
    token = mint()
    r = vt("ok", token)
    assert r.status_code == 200
    seen = r.json()["authorization"]
    assert seen == "Bearer vendor-token-for-test"
    assert token not in json.dumps(r.json())


def test_vendor_token_needs_consent():
    r = vt("consent", mint())
    assert r.status_code == 401
    assert r.json()["error"] == "authorization_required"
    assert r.json()["authorize_uri"].startswith("http://broker.test/")
    assert 'error="invalid_token"' in r.headers["WWW-Authenticate"]


def test_vendor_token_needs_reconsent_scope():
    r = vt("reconsent", mint())
    assert r.status_code == 401
    assert 'error="insufficient_scope"' in r.headers["WWW-Authenticate"]
    assert r.json()["authorize_uri"]


def test_vendor_token_conflict_without_authorize_uri():
    r = vt("pending", mint())
    assert r.status_code == 403
    assert r.json()["error"] == "revoke-pending"


def test_vendor_token_broker_5xx_is_503():
    assert vt("down", mint()).status_code == 503


def test_vendor_token_broker_unreachable_is_502():
    r = vt("unreachable", mint())
    assert r.status_code == 502
    assert r.json()["error"] == "broker_unreachable"


def test_vendor_token_malformed_broker_response_is_502():
    r = vt("malformed", mint())
    assert r.status_code == 502


def test_vendor_token_missing_token_is_401():
    r = vt("ok")
    assert r.status_code == 401


def test_vendor_token_refuses_dpop_scheme():
    r = vt("ok", mint(), scheme="DPoP")
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_request"


# --- audit hygiene (keep last) -----------------------------------------------

def test_no_token_material_in_gateway_logs():
    logs = subprocess.run(["docker", "logs", KONG_CONTAINER], capture_output=True,
                          text=True, check=True)
    text = logs.stdout + logs.stderr
    assert '"audit":"dlp-egress"' in text  # the audit lines are actually there
    assert '"audit":"vendor-token"' in text
    leaked = [t for t in MINTED if t in text or t.split(".")[2] in text]
    assert not leaked, f"{len(leaked)} token(s) found in Kong logs"
    assert "MRN-1234567" not in text and "123-45-6789" not in text
