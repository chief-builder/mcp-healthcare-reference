"""Minimal MCP-over-Streamable-HTTP client for the Phase 3 acceptance suite.

The generated/hand-built servers run stateless: a single POST carries one
JSON-RPC request and the response comes back SSE-framed. We don't need a full
session — tools/list and tools/call work per-request — so this stays tiny.
"""
import json

import requests

ACCEPT = "application/json, text/event-stream"


def _parse_sse(text: str) -> dict:
    """Return the JSON payload of the first SSE `data:` line (or plain JSON)."""
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:"):].strip())
    return json.loads(text)  # some errors come back as plain JSON


def post(url: str, token: str | None, body: dict, dpop_key=None) -> requests.Response:
    """POST one JSON-RPC request. With dpop_key (RFC 9449), the token is sent
    under the DPoP scheme with a fresh proof bound to this method+url+token;
    default None keeps the plain-Bearer behaviour byte-for-byte."""
    headers = {"Content-Type": "application/json", "Accept": ACCEPT}
    if token and dpop_key is not None:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase1"))
        import dpop as _dpop
        headers["Authorization"] = f"DPoP {token}"
        headers["DPoP"] = _dpop.proof(dpop_key, "POST", url, access_token=token)
    elif token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.post(url, headers=headers, json=body)


def list_tools(url: str, token: str, dpop_key=None) -> list[str]:
    r = post(url, token, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, dpop_key=dpop_key)
    r.raise_for_status()
    return [t["name"] for t in _parse_sse(r.text)["result"]["tools"]]


def call_tool(url: str, token: str, name: str, arguments: dict, dpop_key=None) -> requests.Response:
    return post(url, token, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }, dpop_key=dpop_key)


def tool_result(response: requests.Response) -> dict:
    """Parse a successful tools/call result payload (the tool's text content)."""
    data = _parse_sse(response.text)
    content = data["result"]["content"][0]["text"]
    return json.loads(content)
