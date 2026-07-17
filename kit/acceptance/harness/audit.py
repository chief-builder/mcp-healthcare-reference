"""Audit-backend adapter for the AU-* probes.

The reference lab ships audit records to Loki; a customer SIEM differs. The
probes need two capabilities: join records by a token's jti, and grep the
whole log corpus for a needle (token-material leak check). This adapter
implements them for Loki; other backends implement the same two methods.
"""
from __future__ import annotations

import time

import requests


class NullAudit:
    """No audit backend declared — AU probes skip."""
    available = False

    def query_by_jti(self, jti, timeout=90):  # pragma: no cover
        raise RuntimeError("no audit backend")

    def grep(self, needle):  # pragma: no cover
        raise RuntimeError("no audit backend")


class LokiAudit:
    available = True

    def __init__(self, url: str):
        self.url = url.rstrip("/")

    def _query(self, logql: str, since: str = "15m") -> list[str]:
        r = requests.get(
            f"{self.url}/loki/api/v1/query_range",
            params={"query": logql, "since": since, "limit": "2000"},
            timeout=20,
        )
        r.raise_for_status()
        lines = []
        for stream in r.json()["data"]["result"]:
            for _ts, line in stream["values"]:
                lines.append(line)
        return lines

    def query_by_jti(self, jti: str, timeout: int = 90) -> list[str]:
        """All shipped log lines mentioning this jti, polling until some
        appear or the timeout elapses (the spine is eventually consistent)."""
        deadline = time.time() + timeout
        logql = '{service_name=~".+"} |= "%s"' % jti
        while time.time() < deadline:
            lines = self._query(logql)
            if lines:
                return lines
            time.sleep(2)
        return []

    def grep(self, needle: str) -> int:
        """Count log lines anywhere on the spine containing needle."""
        return len(self._query('{service_name=~".+"} |= "%s"' % needle))


def build(section: dict | None):
    if not section or section.get("backend") == "none":
        return NullAudit()
    if section["backend"] == "loki":
        return LokiAudit(section["loki_url"])
    return NullAudit()
