"""Minimal MCP-over-Streamable-HTTP client for the acceptance probes.

Portable copy of the reference lab's tests/phase3/mcp_http.py. Speaks MCP
2026-07-28: no initialize handshake, no session; every POST carries one
JSON-RPC request with the per-request `_meta` envelope and the
MCP-Protocol-Version / Mcp-Method / Mcp-Name headers. (A stateless 2025-era
server ignores the envelope, so the harness stays portable.) The response is
SSE-framed or plain JSON.
Supports the DPoP scheme (RFC 9449) so sender-constraint probes can present a
key-bound token with a fresh proof.
"""
from __future__ import annotations

import json

import requests

from . import dpop as dpop_lib

ACCEPT = "application/json, text/event-stream"
PROTOCOL_VERSION = "2026-07-28"
CLIENT_INFO = {"name": "mcp-acceptance-kit", "version": "2.0"}


def envelope(method: str, params: dict | None = None, request_id: int | str = 1) -> dict:
    """One 2026-07-28 JSON-RPC request with the per-request `_meta` envelope."""
    meta = {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    return {"jsonrpc": "2.0", "id": request_id, "method": method,
            "params": {**(params or {}), "_meta": meta}}


def headers_for(body: dict) -> dict:
    """The 2026-07-28 routing headers that must mirror the body."""
    h = {"Content-Type": "application/json", "Accept": ACCEPT,
         "MCP-Protocol-Version": PROTOCOL_VERSION, "Mcp-Method": body["method"]}
    if body["method"] == "tools/call":
        h["Mcp-Name"] = body["params"]["name"]
    return h


def parse_sse(text: str) -> dict:
    """The JSON payload of the first SSE `data:` line (or plain JSON)."""
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:"):].strip())
    return json.loads(text)


def post(url: str, token: str | None, body: dict, dpop_key=None, timeout: int = 15):
    headers = headers_for(body)
    if token and dpop_key is not None:
        headers["Authorization"] = f"DPoP {token}"
        headers["DPoP"] = dpop_lib.proof(dpop_key, "POST", url, access_token=token)
    elif token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.post(url, headers=headers, json=body, timeout=timeout)


def list_tools(url: str, token: str, dpop_key=None):
    r = post(url, token, envelope("tools/list"), dpop_key=dpop_key)
    r.raise_for_status()
    return [t["name"] for t in parse_sse(r.text)["result"]["tools"]]


def call_tool(url: str, token: str, name: str, arguments: dict, dpop_key=None):
    body = envelope("tools/call", {"name": name, "arguments": arguments}, request_id=2)
    return post(url, token, body, dpop_key=dpop_key)


def tool_result(response) -> dict:
    """Parse a successful tools/call payload (the tool's text content)."""
    data = parse_sse(response.text)
    return json.loads(data["result"]["content"][0]["text"])
