"""Minimal MCP-over-Streamable-HTTP client for the acceptance probes.

Portable copy of the reference lab's tests/phase3/mcp_http.py. Stateless: one
POST carries one JSON-RPC request; the response is SSE-framed or plain JSON.
Supports the DPoP scheme (RFC 9449) so sender-constraint probes can present a
key-bound token with a fresh proof.
"""
from __future__ import annotations

import json

import requests

from . import dpop as dpop_lib

ACCEPT = "application/json, text/event-stream"


def parse_sse(text: str) -> dict:
    """The JSON payload of the first SSE `data:` line (or plain JSON)."""
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:"):].strip())
    return json.loads(text)


def post(url: str, token: str | None, body: dict, dpop_key=None, timeout: int = 15):
    headers = {"Content-Type": "application/json", "Accept": ACCEPT}
    if token and dpop_key is not None:
        headers["Authorization"] = f"DPoP {token}"
        headers["DPoP"] = dpop_lib.proof(dpop_key, "POST", url, access_token=token)
    elif token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.post(url, headers=headers, json=body, timeout=timeout)


def list_tools(url: str, token: str, dpop_key=None):
    r = post(url, token, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, dpop_key=dpop_key)
    r.raise_for_status()
    return [t["name"] for t in parse_sse(r.text)["result"]["tools"]]


def call_tool(url: str, token: str, name: str, arguments: dict, dpop_key=None):
    return post(url, token, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }, dpop_key=dpop_key)


def tool_result(response) -> dict:
    """Parse a successful tools/call payload (the tool's text content)."""
    data = parse_sse(response.text)
    return json.loads(data["result"]["content"][0]["text"])
