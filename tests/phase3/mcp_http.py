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


def post(url: str, token: str | None, body: dict) -> requests.Response:
    headers = {"Content-Type": "application/json", "Accept": ACCEPT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.post(url, headers=headers, json=body)


def list_tools(url: str, token: str) -> list[str]:
    r = post(url, token, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    r.raise_for_status()
    return [t["name"] for t in _parse_sse(r.text)["result"]["tools"]]


def call_tool(url: str, token: str, name: str, arguments: dict) -> requests.Response:
    return post(url, token, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })


def tool_result(response: requests.Response) -> dict:
    """Parse a successful tools/call result payload (the tool's text content)."""
    data = _parse_sse(response.text)
    content = data["result"]["content"][0]["text"]
    return json.loads(content)
