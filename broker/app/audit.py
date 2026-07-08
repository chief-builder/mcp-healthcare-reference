"""Audit events per claims-contract §9 / broker design §12.

One JSON line per event on stdout (the phase 6 audit spine ships container
logs). Token material MUST never be passed to audit() — callers log ids,
states, and generations only.
"""
import json
import time


def audit(event: str, **fields) -> None:
    print(json.dumps({"audit": event, "ts": time.time(), **fields}), flush=True)
