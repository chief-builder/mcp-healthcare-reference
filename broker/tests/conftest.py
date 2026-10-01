"""Offline fixtures: an in-memory KV v2 fake, locally generated hub signing
keys (test-only, never leave the process), and the mockhub vendor AS mocked
with respx. Nothing here touches a network or a real vault."""

import json
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient
from hvac import exceptions as hvac_exc

from app import config, hub, main, vault_store, vendors

ISSUER = "http://localhost:8080/realms/mcp-plane"
TIER_AUD = "mcp://tier/internal"
MOCK = "http://mock-vendor:8310"
REGISTRY = Path(__file__).resolve().parent.parent / "registry.json"


# ── in-memory OpenBao KV v2 ──────────────────────────────────────────────────
class FakeKV:
    """The slice of hvac's secrets.kv.v2 API the broker uses, with real CAS."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], tuple[dict, int]] = {}
        self.down = False

    def _check(self) -> None:
        if self.down:
            raise ConnectionError("vault unreachable")

    def read_secret_version(self, path, mount_point, raise_on_deleted_version=True):
        self._check()
        if (mount_point, path) not in self.store:
            raise hvac_exc.InvalidPath()
        data, ver = self.store[(mount_point, path)]
        return {"data": {"data": dict(data), "metadata": {"version": ver}}}

    def create_or_update_secret(self, path, secret, cas=None, mount_point=None):
        self._check()
        cur = self.store.get((mount_point, path))
        cur_ver = cur[1] if cur else 0
        if cas is not None and cas != cur_ver:
            raise hvac_exc.InvalidRequest("check-and-set parameter did not match")
        self.store[(mount_point, path)] = (dict(secret), cur_ver + 1)
        return {"data": {"version": cur_ver + 1}}

    def delete_metadata_and_all_versions(self, path, mount_point):
        self._check()
        if (mount_point, path) not in self.store:
            raise hvac_exc.InvalidPath()
        del self.store[(mount_point, path)]

    def list_secrets(self, path, mount_point):
        self._check()
        prefix = f"{path}/"
        paths = [p for (m, p) in self.store if m == mount_point and p.startswith(prefix)]
        keys = [p[len(prefix) :] for p in paths]
        if not keys:
            raise hvac_exc.InvalidPath()
        return {"data": {"keys": keys}}

    # helpers for tests
    def entry(self, vendor: str, sub: str) -> dict | None:
        found = self.store.get((vault_store.TOKENS_MOUNT, f"{vendor}/{sub}"))
        return found[0] if found else None

    def put(self, vendor: str, sub: str, entry: dict) -> None:
        self.create_or_update_secret(f"{vendor}/{sub}", entry, mount_point=vault_store.TOKENS_MOUNT)


@pytest.fixture
def kv():
    fake = FakeKV()
    fake.create_or_update_secret(
        "mockhub",
        {"client_id": "broker-client", "client_secret": "test-client-secret"},
        mount_point=vault_store.CLIENTS_MOUNT,
    )
    vault_store.set_client(SimpleNamespace(secrets=SimpleNamespace(kv=SimpleNamespace(v2=fake))))
    yield fake
    vault_store.set_client(None)


# ── hub signing keys (test-only) ─────────────────────────────────────────────
class Keys:
    def __init__(self) -> None:
        self.private = {
            "ps": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "es": ec.generate_private_key(ec.SECP256R1()),
        }

    def get_signing_key_from_jwt(self, token: str):
        kid = jwt.get_unverified_header(token)["kid"]
        return SimpleNamespace(key=self.private[kid].public_key())

    def mint(self, alg: str = "PS256", kid: str | None = None, drop=(), **overrides) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": [TIER_AUD, "mcp://egress/mockhub"],
            "sub": "alice-sub",
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 300,
            "mcp_contract": "1.0",
            "azp": "claude-code",
        }
        claims.update(overrides)
        for k in drop:
            claims.pop(k, None)
        kid = kid or ("es" if alg == "ES256" else "ps")
        return jwt.encode(claims, self.private[kid], algorithm=alg, headers={"kid": kid})


_KEYS = Keys()  # RSA generation is slow; one set per test session


@pytest.fixture
def keys():
    hub.set_jwks_client(_KEYS)
    yield _KEYS
    hub.set_jwks_client(None)


# ── settings, module state, mock vendor ──────────────────────────────────────
@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    s = config.load_settings(
        {
            "REGISTRY_PATH": str(REGISTRY),
            "SWEEP_INTERVAL_S": "0",
            "BROKER_PUBLIC_URL": "http://broker.test",
        }
    )
    config.set_settings(s)
    vendors.set_registry(None)
    for store in (main._locks, main._cache, main._txns, main._states, main._stale_events):
        store.clear()
    main._paged_vendors.clear()
    yield s
    config.set_settings(None)


class MockHub:
    """State behind the respx routes standing in for compose/phase5/mock-vendor."""

    def __init__(self) -> None:
        self.refresh_calls = 0
        self.refresh_mode = "ok"  # ok | invalid_grant | down
        self.revoke_mode = "ok"  # ok | down
        self.revoked: list[str] = []
        self.issuer = MOCK
        self.iss_supported = True

    def metadata(self, request):
        return httpx.Response(
            200,
            json={
                "issuer": self.issuer,
                "authorization_endpoint": f"{MOCK}/authorize",
                "token_endpoint": f"{MOCK}/token",
                "revocation_endpoint": f"{MOCK}/revoke",
                "userinfo_endpoint": f"{MOCK}/user",
                "authorization_response_iss_parameter_supported": self.iss_supported,
            },
        )

    def token(self, request):
        form = dict(httpx.QueryParams(request.content.decode()))
        if form["grant_type"] == "authorization_code":
            if form.get("code") != "good-code" or not form.get("code_verifier"):
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(
                200,
                json={
                    "access_token": "vendor-at-1",
                    "refresh_token": "vendor-rt-1",
                    "expires_in": 3600,
                    "scope": "issues:read issues:write",
                },
            )
        self.refresh_calls += 1
        if self.refresh_mode == "down":
            return httpx.Response(503)
        if self.refresh_mode == "invalid_grant":
            return httpx.Response(400, json={"error": "invalid_grant"})
        n = self.refresh_calls + 1
        return httpx.Response(
            200,
            json={
                "access_token": f"vendor-at-{n}",
                "refresh_token": f"vendor-rt-{n}",
                "expires_in": 3600,
            },
        )

    def revoke(self, request):
        if self.revoke_mode == "down":
            return httpx.Response(503)
        self.revoked.append(dict(httpx.QueryParams(request.content.decode()))["token"])
        return httpx.Response(200)


@pytest.fixture
def mockhub():
    hubstate = MockHub()
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{MOCK}/.well-known/oauth-authorization-server", name="metadata").mock(
            side_effect=hubstate.metadata
        )
        router.post(f"{MOCK}/token", name="token").mock(side_effect=hubstate.token)
        router.post(f"{MOCK}/revoke", name="revoke").mock(side_effect=hubstate.revoke)
        router.get(f"{MOCK}/user", name="user").mock(
            return_value=httpx.Response(200, json={"sub": "octo-1"})
        )
        hubstate.router = router  # tests override a named route, e.g. router["user"]
        yield hubstate


@pytest.fixture
def client(kv, keys, mockhub):
    with TestClient(main.app) as c:
        yield c


def active_entry(**overrides) -> dict:
    now = time.time()
    entry = {
        "access_token": "vendor-at-1",
        "refresh_token": "vendor-rt-1",
        "expires_at": now + 3600,
        "granted_scopes": ["issues:read", "issues:write"],
        "vendor_user_id": "octo-1",
        "state": "ACTIVE",
        "refresh_generation": 1,
        "last_refresh_at": now,
        "created_at": now,
    }
    entry.update(overrides)
    return entry


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def audit_lines(capsys) -> list[dict]:
    """The JSON audit records printed since the last capture."""
    lines = capsys.readouterr().out.splitlines()
    return [json.loads(line) for line in lines if line.startswith("{")]
