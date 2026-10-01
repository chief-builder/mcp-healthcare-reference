"""Minimal MCP 2026-07-28 Streamable-HTTP client for the acceptance suites.

2026-07-28 is stateless at the protocol level: there is no `initialize`
handshake and no session. Every POST carries one JSON-RPC request whose
`params._meta` names the protocol version and client, plus the
`MCP-Protocol-Version`, `Mcp-Method` and (for tools/call) `Mcp-Name` headers.
Responses are plain JSON or SSE-framed; `_parse_sse` handles both.
"""

import json

import requests

ACCEPT = "application/json, text/event-stream"
PROTOCOL_VERSION = "2026-07-28"
CLIENT_INFO = {"name": "mcp-lab-acceptance", "version": "2.0"}


def envelope(method: str, params: dict | None = None, request_id: int | str = 1) -> dict:
    """One 2026-07-28 JSON-RPC request with the per-request `_meta` envelope."""
    meta = {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": {**(params or {}), "_meta": meta},
    }


def headers_for(body: dict) -> dict:
    """The 2026-07-28 routing headers that must mirror the body."""
    h = {
        "Content-Type": "application/json",
        "Accept": ACCEPT,
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "Mcp-Method": body["method"],
    }
    if body["method"] == "tools/call":
        h["Mcp-Name"] = body["params"]["name"]
    return h


def _parse_sse(text: str) -> dict:
    """Return the JSON payload of the first SSE `data:` line (or plain JSON)."""
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:") :].strip())
    return json.loads(text)


def post(url: str, token: str | None, body: dict, dpop_key=None) -> requests.Response:
    """POST one JSON-RPC request. With dpop_key (RFC 9449), the token is sent
    under the DPoP scheme with a fresh proof bound to this method+url+token;
    default None keeps the plain-Bearer behaviour."""
    headers = headers_for(body)
    if token and dpop_key is not None:
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase1"))
        import dpop as _dpop

        headers["Authorization"] = f"DPoP {token}"
        headers["DPoP"] = _dpop.proof(dpop_key, "POST", url, access_token=token)
    elif token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.post(url, headers=headers, json=body, timeout=30)


def list_tools(url: str, token: str, dpop_key=None) -> list[str]:
    r = post(url, token, envelope("tools/list"), dpop_key=dpop_key)
    r.raise_for_status()
    return [t["name"] for t in _parse_sse(r.text)["result"]["tools"]]


def call_tool(url: str, token: str, name: str, arguments: dict, dpop_key=None) -> requests.Response:
    body = envelope("tools/call", {"name": name, "arguments": arguments}, request_id=2)
    return post(url, token, body, dpop_key=dpop_key)


def tool_result(response: requests.Response) -> dict:
    """Parse a successful tools/call result payload (the tool's text content)."""
    data = _parse_sse(response.text)
    content = data["result"]["content"][0]["text"]
    return json.loads(content)
