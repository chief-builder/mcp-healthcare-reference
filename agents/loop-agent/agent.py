#!/usr/bin/env python3
"""Internal m2m loop agent — the lab's contract §6.3 workload (plan phase 4).

Identity comes from the platform, not from configuration: a spiffe-helper
sidecar keeps a short-lived SPIFFE X.509 SVID on a shared volume. Every
iteration re-reads the files (so SIA-style rotation needs no restart),
performs tls_client_auth client-credentials at Keycloak to obtain a
certificate-bound token (cnf.x5t#S256), then drives the scheduling MCP
server through the internal DP over the same mTLS channel:
find-slots -> hold-slot -> release-hold.

There are no secrets here and none in the manifest — that is the point.
One JSON log line per iteration carries the presented-cert thumbprint and
token jti, which the phase 4 acceptance suite (and later the audit spine)
joins on.
"""
import base64
import hashlib
import json
import os
import sys
import time

import requests

KC_TOKEN_URL = os.environ["KC_TOKEN_URL"]
MCP_URL = os.environ["MCP_URL"]
CLIENT_ID = os.environ.get("CLIENT_ID", "mcp-agents.loop-agent")
SCOPE = os.environ.get("SCOPE", "mcp:scheduling:hold-slot:execute mcp:scheduling:confirm:execute")
SVID_DIR = os.environ.get("SVID_DIR", "/svid")
CA_BUNDLE = os.environ.get("CA_BUNDLE", "/lab-ca/lab-ca.crt")
INTERVAL = float(os.environ.get("INTERVAL", "15"))
# Book against the workload's own provider so its slot namespace never collides
# with the acceptance tests' (both otherwise default to the same catalogue slot).
PROVIDER = os.environ.get("SCHED_PROVIDER", "loop-agent")

CERT = (f"{SVID_DIR}/svid.pem", f"{SVID_DIR}/svid_key.pem")
ACCEPT = "application/json, text/event-stream"


def log(**fields):
    fields["ts"] = time.time()
    print(json.dumps(fields), flush=True)


def x5t_s256(cert_path: str) -> str:
    """RFC 8705 thumbprint of the leaf: base64url(SHA-256(DER)), unpadded."""
    pem = open(cert_path).read()
    body = pem.split("-----BEGIN CERTIFICATE-----", 1)[1].split("-----END CERTIFICATE-----", 1)[0]
    der = base64.b64decode("".join(body.split()))
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()


def jwt_payload(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def sse_json(text: str) -> dict:
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:"):].strip())
    return json.loads(text)


def get_token() -> str:
    r = requests.post(
        KC_TOKEN_URL,
        data={"grant_type": "client_credentials", "client_id": CLIENT_ID, "scope": SCOPE},
        cert=CERT,
        verify=CA_BUNDLE,
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def call_tool(token: str, name: str, arguments: dict) -> dict:
    r = requests.post(
        MCP_URL,
        headers={"Authorization": f"Bearer {token}", "Accept": ACCEPT},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": name, "arguments": arguments}},
        cert=CERT,
        verify=CA_BUNDLE,
        timeout=10,
    )
    r.raise_for_status()
    result = sse_json(r.text)["result"]
    if result.get("isError"):
        raise RuntimeError(f"{name}: {result}")
    return json.loads(result["content"][0]["text"])


def iteration() -> None:
    x5t = x5t_s256(CERT[0])
    token = get_token()
    claims = jwt_payload(token)
    bound = claims.get("cnf", {}).get("x5t#S256")
    if bound != x5t:
        raise RuntimeError(f"token cnf {bound} does not match presented cert {x5t}")

    slots = call_tool(token, "find-slots", {"provider": PROVIDER})
    hold = call_tool(token, "hold-slot", {"slot_id": slots[0]["slot_id"]})
    call_tool(token, "release-hold", {"slot_hold_id": hold["slot_hold_id"]})

    log(event="loop", ok=True, x5t=x5t, jti=claims.get("jti"),
        azp=claims.get("azp"), idp_origin=claims.get("idp_origin"),
        slot_hold_id=hold["slot_hold_id"])


def main() -> None:
    log(event="start", client_id=CLIENT_ID, kc=KC_TOKEN_URL, mcp=MCP_URL)
    while not (os.path.exists(CERT[0]) and os.path.exists(CERT[1])):
        log(event="waiting_for_svid")
        time.sleep(2)
    while True:
        try:
            iteration()
        except Exception as exc:  # keep looping; the gate reads the log stream
            log(event="loop", ok=False, error=str(exc))
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
