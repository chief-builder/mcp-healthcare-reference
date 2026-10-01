"""Test-only upstream for plugins/tests: one process plays two roles.

- POST /v1/tokens/resolve  — a stand-in vendor token broker; the response is
  chosen by the `vendor` field the vendor-token plugin sends.
- anything else            — an echo upstream reporting what reached it
  (method, path, Authorization header, body), so tests can assert what the
  gateway forwarded.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AUTHORIZE_URI = "http://broker.test/v1/authorize/stub?txn=t1"

RESOLVE = {
    "ok": (200, {"access_token": "vendor-token-for-test", "expires_at": 0, "granted_scopes": []}),
    "consent": (404, {"title": "needs-consent", "authorize_uri": AUTHORIZE_URI}),
    "reconsent": (409, {"title": "needs-reconsent-scope", "authorize_uri": AUTHORIZE_URI}),
    "pending": (409, {"title": "revoke-pending"}),
    "down": (503, {"title": "vendor-unavailable"}),
    "malformed": (200, {"granted_scopes": []}),
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> str:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length).decode() if length else ""

    def _handle(self) -> None:
        body = self._body()
        if self.command == "POST" and self.path == "/v1/tokens/resolve":
            vendor = json.loads(body or "{}").get("vendor", "")
            status, payload = RESOLVE.get(vendor, (500, {"title": "unknown stub vendor"}))
            return self._send(status, payload)
        self._send(200, {
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "body": body,
        })

    do_GET = do_POST = do_DELETE = _handle

    def log_message(self, *_args) -> None:  # keep test output quiet
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # noqa: S104 (container-only)
