"""Resolve a named identity from the descriptor into an access token.

Three acquisition modes (environment.schema.json → identities.*.acquire):

  scripted  built-in auth-code+PKCE (or client_credentials) driver — dev/lab
            IdPs with a scriptable login page. Mints a DPoP-bound token when
            the identity sets dpop: true.
  command   run a shell command that prints a fresh access token to stdout —
            the realistic path for a production IdP (wrap your own login/CI).
  env       read a token from an environment variable.

A DPoP identity also carries an EC key so probes can mint matching proofs;
resolve() returns an Identity holding both.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Any

from . import dpop as dpop_lib
from . import oidc


class MissingIdentity(Exception):
    """The descriptor does not declare this identity — the probe should skip."""


@dataclass
class Identity:
    name: str
    token: str
    tier: str | None = None
    dpop_key: Any = None
    expects_compartment: bool = False
    _spec: dict = field(default_factory=dict)

    def fresh(self, descriptor) -> "Identity":
        """A newly minted token for the same identity (some probes need two,
        e.g. DPoP jti-replay or a second login). Falls back to self when the
        acquire mode cannot re-mint on demand."""
        try:
            return resolve(descriptor, self.name, _key=self.dpop_key)
        except Exception:
            return self


def _env(name: str, spec_key: str, spec: dict) -> str:
    var = spec.get(spec_key)
    if not var:
        raise MissingIdentity(f"{spec_key} not set for identity")
    value = os.environ.get(var)
    if value is None:
        raise MissingIdentity(f"env var {var} is unset")
    return value


def resolve(descriptor, name: str, _key=None) -> Identity:
    spec = descriptor.identity(name)
    if spec is None:
        raise MissingIdentity(name)

    mode = spec["acquire"]
    tier = spec.get("tier")
    expects = bool(spec.get("expects_compartment"))

    if mode == "env":
        var = spec.get("env")
        token = os.environ.get(var) if var else None
        if not token:
            raise MissingIdentity(f"{name}: env var {var} is unset")
        return Identity(name, token, tier, None, expects, spec)

    if mode == "command":
        cmd = spec["command"]
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if out.returncode != 0 or not out.stdout.strip():
            raise MissingIdentity(f"{name}: command failed: {out.stderr.strip()[:200]}")
        return Identity(name, out.stdout.strip(), tier, None, expects, spec)

    # scripted
    s = spec["scripted"]
    issuer = descriptor.issuer
    grant = s.get("grant", "authorization_code")
    if grant == "client_credentials":
        token = oidc.client_credentials(
            issuer, s["client_id"], _env(s, "client_secret_env", s))
        return Identity(name, token, tier, None, expects, spec)

    username = s.get("username") or (os.environ.get(s["username_env"]) if s.get("username_env") else None)
    if not username:
        raise MissingIdentity(f"{name}: no username / username_env")
    password_var = s.get("password_env")
    password = os.environ.get(password_var) if password_var else None
    if password is None:
        raise MissingIdentity(f"{name}: env var {password_var} is unset")

    key = None
    if spec.get("dpop"):
        key = _key or dpop_lib.make_key()
    token = oidc.authorization_code(
        issuer, s["client_id"], s["redirect_uri"], username, password,
        idp_hint=s.get("idp_hint"), scope=s.get("scope", "openid"), dpop_key=key,
    )
    return Identity(name, token, tier, key, expects, spec)
