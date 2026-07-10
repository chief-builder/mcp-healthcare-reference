"""Vendor Token Broker — implements docs/vendor-token-broker-design.md.

Custodian, not issuer (§1/§11): this service holds no signing keys and
exposes no token-minting or JWKS endpoint — tests/phase5 audits the route
table for exactly that.

Lab substitutions (documented, per prototype-plan §2):
- §3 SVID-mTLS ingress → hub-JWT re-validation + compose-network isolation.
- Single replica → per-entry asyncio locks; a multi-replica deployment must
  swap in the short-TTL distributed lock of §9 (the CAS already guards it).
- §5 KMS envelope encryption → OpenBao dev-mode storage (noted, not simulated).
"""
import asyncio
import base64
import hashlib
import os
import secrets
import time

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from contextlib import asynccontextmanager

from .audit import audit
from .hub import HubAuthError, validate
from . import vendors
from .vault_store import (CasConflict, VaultUnavailable, delete_entry,
                          list_subs, read_entry, write_entry)

BROKER_PUBLIC_URL = os.environ.get("BROKER_PUBLIC_URL", "http://localhost:8300")
REFRESH_BUFFER_S = int(os.environ.get("REFRESH_BUFFER_S", "300"))
CACHE_TTL_S = 60          # §7: in-memory cache TTL ≤ 60s (also the §10 grace cap)
TXN_TTL_S = 600           # §4.2: transaction TTL 10 min
LOCK_TIMEOUT_S = 10       # §9: hard timeout; waiters re-read on expiry
SWEEP_INTERVAL_S = int(os.environ.get("SWEEP_INTERVAL_S", "60"))
PROACTIVE_REFRESH_S = int(os.environ.get("PROACTIVE_REFRESH_S", "900"))  # §8: <15 min
MASS_STALE_WINDOW_S = 60  # §8/§10: ≥3 STALEs for one vendor within a minute…
MASS_STALE_THRESHOLD = int(os.environ.get("MASS_STALE_THRESHOLD", "3"))  # …→ page

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_sweep_loop()) if SWEEP_INTERVAL_S > 0 else None
    try:
        yield
    finally:
        if task is not None:
            task.cancel()


app = FastAPI(title="vendor-token-broker", version="1.0", lifespan=lifespan)

_locks: dict[tuple[str, str], asyncio.Lock] = {}
_cache: dict[tuple[str, str], tuple[dict, int, float]] = {}  # (entry, ver, fetched_at)
_txns: dict[str, dict] = {}   # txn_id -> {sub, vendor, scopes, created_at, ...}
_states: dict[str, dict] = {} # state -> {txn_id, pkce_verifier, issuer, consumed}
_stale_events: dict[str, list[float]] = {}  # vendor -> recent STALE timestamps
_paged_vendors: dict[str, float] = {}       # vendor -> last mass-stale page ts


def _problem(status: int, type_: str, detail: str = "", **extra) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"type": f"urn:mcp-lab:broker:{type_}", "title": type_,
                 "detail": detail, **extra},
        media_type="application/problem+json")


def _lock(vendor: str, sub: str) -> asyncio.Lock:
    return _locks.setdefault((vendor, sub), asyncio.Lock())


def _new_txn(sub: str, vendor: str, scopes: list[str]) -> str:
    txn_id = secrets.token_urlsafe(24)
    _txns[txn_id] = {"sub": sub, "vendor": vendor, "scopes": scopes,
                     "created_at": time.time()}
    return txn_id


def _needs_consent(sub: str, vendor: str, spec: dict,
                   scopes: list[str] | None = None) -> JSONResponse:
    txn = _new_txn(sub, vendor,
                   scopes if scopes is not None else spec.get("scope_ceiling", []))
    return _problem(
        404, "needs-consent", f"no usable grant for {vendor}",
        authorize_uri=f"{BROKER_PUBLIC_URL}/v1/authorize/{vendor}?txn={txn}")


def _get_entry(vendor: str, sub: str):
    key = (vendor, sub)
    cached = _cache.get(key)
    if cached and time.time() - cached[2] < CACHE_TTL_S:
        return cached[0], cached[1]
    found = read_entry(vendor, sub)
    if found is None:
        _cache.pop(key, None)
        return None
    _cache[key] = (found[0], found[1], time.time())
    return found


def _put_cache(vendor: str, sub: str, entry: dict, ver: int) -> None:
    _cache[(vendor, sub)] = (entry, ver, time.time())


def _mark_stale(vendor: str, sub: str, generation: int) -> None:
    """Emit the per-entry broker.stale record and, when STALEs for one vendor
    burst past the threshold within a minute, a mass-stale page (§8/§10 —
    the org-App-uninstall anomaly)."""
    audit("broker.stale", sub=sub, vendor=vendor, generation=generation)
    now = time.time()
    events = [t for t in _stale_events.get(vendor, []) if now - t < MASS_STALE_WINDOW_S]
    events.append(now)
    _stale_events[vendor] = events
    if len(events) >= MASS_STALE_THRESHOLD and \
            now - _paged_vendors.get(vendor, 0) > MASS_STALE_WINDOW_S:
        _paged_vendors[vendor] = now
        audit("broker.stale.mass", vendor=vendor, count=len(events),
              window_s=MASS_STALE_WINDOW_S, page=True, security_event=True)


def _consent_scopes(required: list[str], ceiling: list[str]) -> list[str]:
    """§4.2/§6: request the minimum — the tool's required scopes capped by the
    registry ceiling. No required_scopes (legacy caller) → the full ceiling."""
    if not required:
        return list(ceiling)
    return [s for s in required if s in ceiling]


def _entry_from_token_response(tok: dict, gen: int, vendor_uid: str,
                               scopes: list[str]) -> dict:
    return {
        "access_token": tok["access_token"],
        "refresh_token": tok.get("refresh_token", ""),
        "expires_at": time.time() + float(tok.get("expires_in", 8 * 3600)),
        "granted_scopes": (tok.get("scope") or " ".join(scopes)).split(),
        "vendor_user_id": vendor_uid,
        "state": "ACTIVE",
        "refresh_generation": gen,
        "last_refresh_at": time.time(),
        "created_at": time.time(),
    }


def _ok_response(entry: dict) -> JSONResponse:
    return JSONResponse({"access_token": entry["access_token"],
                         "expires_at": entry["expires_at"],
                         "granted_scopes": entry["granted_scopes"]})


async def _sweep_once() -> None:
    """One §8 maintenance pass: drop abandoned in-memory transactions/state,
    retry pending revocations, and proactively refresh entries approaching
    expiry (the 5–15 min band; the 0–5 min band is served lazily by resolve)."""
    now = time.time()
    for store in (_txns, _states):
        for key in [k for k, v in store.items()
                    if now - v["created_at"] > TXN_TTL_S]:
            store.pop(key, None)
    for vendor in list(_stale_events):
        kept = [t for t in _stale_events[vendor] if now - t < MASS_STALE_WINDOW_S]
        if kept:
            _stale_events[vendor] = kept
        else:
            _stale_events.pop(vendor, None)

    for vendor in vendors.registry():
        if vendors.get_vendor(vendor) is None:
            continue
        try:
            subs = list_subs(vendor)
        except VaultUnavailable:
            continue
        for sub in subs:
            try:
                await _sweep_entry(vendor, sub)
            except Exception as exc:  # a bad entry must never kill the loop
                audit("broker.sweep.error", vendor=vendor, sub=sub, error=str(exc))


async def _sweep_entry(vendor: str, sub: str) -> None:
    found = read_entry(vendor, sub)
    if found is None:
        return
    entry, ver = found
    if entry["state"] == "REVOKE_PENDING":
        try:
            await vendors.revoke(vendor, entry)
        except vendors.VendorUnavailable:
            return  # still down; retry next pass
        delete_entry(vendor, sub)
        _cache.pop((vendor, sub), None)
        audit("broker.revoke", sub=sub, vendor=vendor, outcome="revoked",
              path="sweep-retry")
        return
    if entry["state"] != "ACTIVE":
        return
    remaining = entry["expires_at"] - time.time()
    if not (REFRESH_BUFFER_S < remaining <= PROACTIVE_REFRESH_S):
        return
    lock = _lock(vendor, sub)
    if lock.locked():
        return  # a resolve is already refreshing this entry
    await lock.acquire()
    try:
        found = read_entry(vendor, sub)
        if found is None or found[0]["state"] != "ACTIVE":
            return
        entry, ver = found
        try:
            tok = await vendors.refresh(vendor, entry["refresh_token"])
        except vendors.InvalidGrant:
            try:
                write_entry(vendor, sub, {**entry, "state": "STALE"}, cas=ver)
            except CasConflict:
                return
            _cache.pop((vendor, sub), None)
            _mark_stale(vendor, sub, entry["refresh_generation"])
            return
        except vendors.VendorUnavailable:
            return
        new_gen = entry["refresh_generation"] + 1
        new_entry = _entry_from_token_response(
            tok, new_gen, entry["vendor_user_id"], entry["granted_scopes"])
        if not new_entry["refresh_token"]:
            new_entry["refresh_token"] = entry["refresh_token"]
        try:
            new_ver = write_entry(vendor, sub, new_entry, cas=ver)
        except CasConflict:
            _cache.pop((vendor, sub), None)
            return
        _put_cache(vendor, sub, new_entry, new_ver)
        audit("broker.refresh", sub=sub, vendor=vendor, path="proactive",
              generation_from=entry["refresh_generation"], generation_to=new_gen)
    finally:
        lock.release()


async def _sweep_loop() -> None:
    while True:
        await asyncio.sleep(SWEEP_INTERVAL_S)
        try:
            await _sweep_once()
        except Exception as exc:
            audit("broker.sweep.error", error=str(exc))


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.post("/v1/tokens/resolve")
async def resolve(request: Request):
    try:
        claims = validate(request.headers.get("authorization"))
    except HubAuthError as exc:
        return _problem(401, "invalid-hub-token", str(exc))
    body = await request.json()
    vendor = body.get("vendor", "")
    sub = claims["sub"]  # the JWT is authoritative; the field is advisory
    if body.get("sub") and body["sub"] != sub:
        audit("broker.resolve", decision="deny", reason="sub_mismatch",
              hub_jti=claims.get("jti"), sub=sub, claimed_sub=body["sub"], vendor=vendor)
        return _problem(400, "sub-mismatch", "request sub does not match hub token")
    min_ttl = int(body.get("min_ttl_s", 120))
    spec = vendors.get_vendor(vendor)
    if spec is None:
        return _problem(404, "unknown-vendor", f"vendor {vendor} not registered/enabled")

    ceiling = spec.get("scope_ceiling", [])
    required = [s for s in body.get("required_scopes", []) if isinstance(s, str)]
    if not set(required) <= set(ceiling):
        # A caller can never widen past the registry ceiling (§4.2).
        audit("broker.resolve", decision="deny", path="scope-ceiling",
              hub_jti=claims.get("jti"), sub=sub, vendor=vendor,
              required=required, ceiling=ceiling)
        return _problem(403, "scope-exceeds-ceiling",
                        "required_scopes exceed the vendor registry ceiling",
                        required=required, ceiling=ceiling)
    consent_scopes = _consent_scopes(required, ceiling)

    def _audit(decision: str, path: str, **kw):
        audit("broker.resolve", decision=decision, path=path, hub_jti=claims.get("jti"),
              sub=sub, vendor=vendor, **kw)

    def _insufficient_scope(entry: dict) -> JSONResponse | None:
        """§4.1: an ACTIVE grant that doesn't cover the tool's required scopes
        returns 409 needs-reconsent-scope with an authorize_uri that re-consents
        for the union of held and required scopes (capped by the ceiling)."""
        missing = [s for s in required if s not in entry["granted_scopes"]]
        if not missing:
            return None
        reconsent = [s for s in ceiling
                     if s in set(entry["granted_scopes"]) | set(required)]
        txn = _new_txn(sub, vendor, reconsent)
        _audit("deny", "insufficient-scope", missing=missing)
        return _problem(409, "needs-reconsent-scope",
                        "grant does not cover the required scopes",
                        missing_scopes=missing,
                        authorize_uri=f"{BROKER_PUBLIC_URL}/v1/authorize/{vendor}?txn={txn}")

    try:
        found = _get_entry(vendor, sub)
        if found is None:
            _audit("needs-consent", "absent")
            return _needs_consent(sub, vendor, spec, consent_scopes)
        entry, ver = found
        if entry["state"] == "STALE":
            _audit("needs-consent", "stale")
            return _needs_consent(sub, vendor, spec, consent_scopes)
        if entry["state"] == "REVOKE_PENDING":
            _audit("deny", "revoke-pending")
            return _problem(409, "revoke-pending", "entry is being revoked")

        insufficient = _insufficient_scope(entry)
        if insufficient is not None:
            return insufficient

        remaining = entry["expires_at"] - time.time()
        if remaining >= max(min_ttl, REFRESH_BUFFER_S):
            _audit("allow", "cache")
            return _ok_response(entry)

        # Inside the refresh buffer: single-flight per {vendor, sub} (§9).
        gen_before = entry["refresh_generation"]
        lock = _lock(vendor, sub)
        try:
            await asyncio.wait_for(lock.acquire(), timeout=LOCK_TIMEOUT_S)
        except asyncio.TimeoutError:
            # Lock-holder death path: re-read and serve if usable (§9 rules).
            _cache.pop((vendor, sub), None)
            found = _get_entry(vendor, sub)
            if found and found[0]["state"] == "ACTIVE" and \
                    found[0]["expires_at"] - time.time() >= min_ttl:
                _audit("allow", "lock-timeout-reread")
                return _ok_response(found[0])
            return _problem(503, "vendor-unavailable", "refresh lock timeout")
        try:
            _cache.pop((vendor, sub), None)
            found = _get_entry(vendor, sub)
            if found is None:
                _audit("needs-consent", "absent")
                return _needs_consent(sub, vendor, spec, consent_scopes)
            entry, ver = found
            if entry["state"] == "STALE":
                _audit("needs-consent", "stale")
                return _needs_consent(sub, vendor, spec, consent_scopes)
            if entry["refresh_generation"] != gen_before and \
                    entry["expires_at"] - time.time() >= min_ttl:
                # A concurrent refresh already won — same token, no vendor call.
                _audit("allow", "refresh-waited", generation=entry["refresh_generation"])
                return _ok_response(entry)

            try:
                tok = await vendors.refresh(vendor, entry["refresh_token"])
            except vendors.InvalidGrant:
                stale = {**entry, "state": "STALE"}
                try:
                    write_entry(vendor, sub, stale, cas=ver)
                except CasConflict:
                    pass
                _cache.pop((vendor, sub), None)
                _mark_stale(vendor, sub, entry["refresh_generation"])
                _audit("needs-consent", "stale-on-refresh")
                return _needs_consent(sub, vendor, spec, consent_scopes)
            except vendors.VendorUnavailable as exc:
                _audit("deny", "vendor-unavailable", error=str(exc))
                return _problem(503, "vendor-unavailable", str(exc))

            new_gen = entry["refresh_generation"] + 1
            new_entry = _entry_from_token_response(
                tok, new_gen, entry["vendor_user_id"], entry["granted_scopes"])
            if not new_entry["refresh_token"]:
                new_entry["refresh_token"] = entry["refresh_token"]  # non-rotating vendor
            try:
                new_ver = write_entry(vendor, sub, new_entry, cas=ver)
            except CasConflict:
                # Another writer won (§9): discard our pair, never write the older one.
                _cache.pop((vendor, sub), None)
                found = _get_entry(vendor, sub)
                _audit("allow", "cas-lost")
                if found and found[0]["state"] == "ACTIVE":
                    return _ok_response(found[0])
                return _problem(503, "vendor-unavailable", "refresh race lost; retry")
            _put_cache(vendor, sub, new_entry, new_ver)
            audit("broker.refresh", sub=sub, vendor=vendor,
                  generation_from=gen_before, generation_to=new_gen)
            _audit("allow", "refreshed", generation=new_gen)
            return _ok_response(new_entry)
        finally:
            lock.release()
    except VaultUnavailable as exc:
        # §10: fail closed — no grace beyond the in-memory cache TTL.
        _audit("deny", "vault-unavailable", error=str(exc))
        return _problem(503, "vault-unavailable", str(exc))


@app.get("/v1/authorize/{vendor}")
async def authorize(vendor: str, txn: str):
    record = _txns.get(txn)
    if (record is None or record["vendor"] != vendor
            or time.time() - record["created_at"] > TXN_TTL_S):
        audit("broker.consent.fail", vendor=vendor, reason="bad_txn", security_event=False)
        return _problem(400, "invalid-transaction", "unknown or expired transaction")
    spec = vendors.get_vendor(vendor)
    if spec is None:
        return _problem(404, "unknown-vendor", vendor)

    eps = await vendors.endpoints(vendor)
    creds = vendors.read_client(vendor) or {}
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(32)
    _states[state] = {"txn_id": txn, "sub": record["sub"], "vendor": vendor,
                      "pkce_verifier": verifier, "nonce": secrets.token_urlsafe(16),
                      "issuer": eps.get("issuer"), "created_at": time.time(),
                      "consumed": False,
                      # RFC 9207 §2.4: if the AS advertises iss support, a
                      # callback that omits iss is a mix-up signal (see callback).
                      "iss_required": bool(
                          eps.get("authorization_response_iss_parameter_supported")),
                      "scopes": record["scopes"]}  # ≤ registry ceiling (§4.2)
    audit("broker.consent.start", sub=record["sub"], vendor=vendor)
    from urllib.parse import urlencode
    params = {
        "client_id": creds.get("client_id", ""),
        "response_type": "code",
        "redirect_uri": f"{BROKER_PUBLIC_URL}/v1/callback/{vendor}",
        "scope": " ".join(record["scopes"]),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{eps['authorization_endpoint']}?{urlencode(params)}")


@app.get("/v1/callback/{vendor}")
async def callback(vendor: str, request: Request):
    q = request.query_params
    state = q.get("state", "")
    record = _states.get(state)
    if (record is None or record["consumed"] or record["vendor"] != vendor
            or time.time() - record["created_at"] > TXN_TTL_S):
        # §4.3/§10: state replay or mismatch is a SECURITY EVENT, not a plain 400.
        audit("broker.consent.fail", vendor=vendor, reason="state_invalid_or_replayed",
              security_event=True)
        return HTMLResponse("<h1>Invalid or expired authorization state.</h1>",
                            status_code=400)
    # RFC 9207 mix-up defense: strict string comparison against the issuer
    # recorded at transaction creation; applies before any code redemption.
    # When the vendor AS advertises authorization_response_iss_parameter_supported
    # (RFC 8414), an authorization response with no iss is itself a mix-up
    # signal (RFC 9207 §2.4) and is rejected exactly like a mismatched one.
    iss = q.get("iss")
    if record["issuer"] is not None and (
            iss is None and record["iss_required"] or
            iss is not None and iss != record["issuer"]):
        audit("broker.consent.fail", vendor=vendor, reason="iss_mismatch",
              security_event=True, iss_present=iss is not None)
        return HTMLResponse("<h1>Issuer mismatch.</h1>", status_code=400)
    record["consumed"] = True
    _txns.pop(record["txn_id"], None)
    if "error" in q:
        # The raw vendor error goes to the audit line only; the browser gets a
        # constant page (no reflected, attacker-controllable value → no XSS).
        audit("broker.consent.fail", vendor=vendor, sub=record["sub"],
              reason=q.get("error"), security_event=False)
        return HTMLResponse("<h1>Authorization failed.</h1>", status_code=400)
    try:
        tok = await vendors.exchange_code(
            vendor, q.get("code", ""), record["pkce_verifier"],
            f"{BROKER_PUBLIC_URL}/v1/callback/{vendor}")
        vendor_uid = await vendors.vendor_user_id(vendor, tok["access_token"])
        entry = _entry_from_token_response(tok, 1, vendor_uid, record["scopes"])
        write_entry(vendor, record["sub"], entry, cas=None)  # re-consent = fresh gen=1
        _cache.pop((vendor, record["sub"]), None)
    except vendors.VendorError as exc:
        audit("broker.consent.fail", vendor=vendor, sub=record["sub"],
              reason=str(exc), security_event=False)
        return HTMLResponse("<h1>Token exchange failed.</h1>", status_code=502)
    except VaultUnavailable:
        return HTMLResponse("<h1>Credential store unavailable.</h1>", status_code=503)
    audit("broker.consent.complete", sub=record["sub"], vendor=vendor,
          vendor_user_id=vendor_uid)
    return HTMLResponse("<h1>Connected — return to your client.</h1>")


@app.delete("/v1/grants/{vendor}/{sub}")
async def delete_grant(vendor: str, sub: str, request: Request):
    try:
        claims = validate(request.headers.get("authorization"))
    except HubAuthError as exc:
        return _problem(401, "invalid-hub-token", str(exc))
    if claims["sub"] != sub:
        return _problem(403, "forbidden", "grants are self-service (sub must match)")
    if vendors.get_vendor(vendor) is None:
        return _problem(404, "unknown-vendor", vendor)
    try:
        found = read_entry(vendor, sub)
        if found is None:
            return _problem(404, "no-grant", "nothing to revoke")
        entry, ver = found
        try:
            await vendors.revoke(vendor, entry)   # §4.4: revoke at vendor FIRST
        except vendors.VendorUnavailable as exc:
            write_entry(vendor, sub, {**entry, "state": "REVOKE_PENDING"}, cas=ver)
            _cache.pop((vendor, sub), None)
            audit("broker.revoke", sub=sub, vendor=vendor, outcome="pending",
                  error=str(exc))
            return _problem(502, "revoke-pending", "vendor revocation failed; will retry")
        delete_entry(vendor, sub)
        _cache.pop((vendor, sub), None)
    except VaultUnavailable as exc:
        return _problem(503, "vault-unavailable", str(exc))
    audit("broker.revoke", sub=sub, vendor=vendor, outcome="revoked",
          hub_jti=claims.get("jti"))
    return JSONResponse({"revoked": True})


@app.get("/v1/grants")
async def list_grants(request: Request):
    try:
        claims = validate(request.headers.get("authorization"))
    except HubAuthError as exc:
        return _problem(401, "invalid-hub-token", str(exc))
    grants = []
    for vendor in vendors.registry():
        if vendors.get_vendor(vendor) is None:
            continue
        try:
            found = read_entry(vendor, claims["sub"])
        except VaultUnavailable as exc:
            return _problem(503, "vault-unavailable", str(exc))
        if found:
            entry, _ = found
            grants.append({"vendor": vendor, "state": entry["state"],
                           "granted_scopes": entry["granted_scopes"],
                           "vendor_user_id": entry["vendor_user_id"],
                           "created_at": entry["created_at"]})
    return {"grants": grants}


ADMIN_GROUP = "mcp-platform-admin"


@app.get("/v1/admin/vendors/{vendor}")
async def vendor_record(vendor: str, request: Request):
    try:
        claims = validate(request.headers.get("authorization"))
    except HubAuthError as exc:
        return _problem(401, "invalid-hub-token", str(exc))
    if ADMIN_GROUP not in (claims.get("groups") or []):
        audit("broker.admin.deny", sub=claims.get("sub"), vendor=vendor,
              reason="not_platform_admin")
        return _problem(403, "forbidden", f"requires the {ADMIN_GROUP} group")
    spec = vendors.registry().get(vendor)
    if spec is None:
        return _problem(404, "unknown-vendor", vendor)
    return {k: v for k, v in spec.items() if "secret" not in k}
