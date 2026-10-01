"""Scripted OAuth flows for the acceptance harness (acquire: scripted).

Adapted from the reference lab's tests/phase1/oidc_flows.py. Drives a real
authorization-code + PKCE login (including brokered legs) by scripting the
HTML login forms — suitable for dev/lab IdPs with a scriptable login page.
Validates the RFC 9207 `iss` on the authorization response (contract §8).

For production IdPs whose login cannot be scripted (real MFA, WebAuthn), use
acquire: command or acquire: env instead — see harness/identities.py.
"""

from __future__ import annotations

import base64
import hashlib
import html
import re
import secrets
from urllib.parse import parse_qs, urljoin, urlparse

import requests

REDIRECT_CODES = (301, 302, 303, 307, 308)
FORM_BLOCK_RE = re.compile(r"<form[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
FORM_ACTION_RE = re.compile(r'<form[^>]+action="([^"]+)"', re.IGNORECASE)
FIELD_TAG_RE = re.compile(r"<(?:input|button)[^>]+>", re.IGNORECASE)
NAME_ATTR_RE = re.compile(r'name="([^"]+)"', re.IGNORECASE)
VALUE_ATTR_RE = re.compile(r'value="([^"]*)"', re.IGNORECASE)


def _primary_form(text: str) -> str:
    forms = FORM_BLOCK_RE.findall(text)
    assert forms, f"no form found: {text[:400]}"
    for form in forms:
        if 'data-form-primary="true"' in form or (
            NAME_ATTR_RE.search(form)
            and any(f'name="{m}"' in form for m in ("password", "username", "firstName"))
        ):
            return form
    return forms[0]


def _form_fields(form_block: str) -> dict[str, str]:
    fields = {}
    for tag in FIELD_TAG_RE.findall(form_block):
        name = NAME_ATTR_RE.search(tag)
        if not name:
            continue
        value = VALUE_ATTR_RE.search(tag)
        fields[name.group(1)] = html.unescape(value.group(1)) if value else ""
    return fields


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


def _request(session, method, url, **kwargs):
    response = session.request(method, url, allow_redirects=False, **kwargs)
    for cookie in session.cookies:
        cookie.secure = False  # Keycloak marks cookies Secure even over HTTP
    return response


def _follow(session, response, stop_prefix):
    for _ in range(10):
        if response.status_code not in REDIRECT_CODES:
            return response, None
        location = urljoin(response.url, response.headers["Location"])
        if location.startswith(stop_prefix):
            return response, location
        response = _request(session, "GET", location)
    raise AssertionError("redirect loop")


def _submit_form(session, page, overrides):
    form = _primary_form(page.text)
    match = FORM_ACTION_RE.search(form)
    action = urljoin(page.url, html.unescape(match.group(1))) if match else page.url
    fields = _form_fields(form)
    fields.update(overrides)
    return _request(session, "POST", action, data=fields)


def _answer_page(session, page, username, password):
    fields = _form_fields(_primary_form(page.text))
    if "password" in fields:
        return _submit_form(session, page, {"username": username, "password": password})
    if "firstName" in fields or "lastName" in fields:
        profile = {}
        if not fields.get("firstName"):
            profile["firstName"] = "Lab"
        if not fields.get("lastName"):
            profile["lastName"] = "User"
        if "email" in fields and not fields.get("email"):
            profile["email"] = f"{username}@lab.test"
        if "username" in fields and not fields.get("username"):
            profile["username"] = username
        return _submit_form(session, page, profile)
    raise AssertionError(f"unrecognized form on {page.url}: fields={sorted(fields)}")


def client_credentials(issuer, client_id, client_secret) -> str:
    r = requests.post(
        f"{issuer}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
        timeout=30,
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def authorization_code(
    issuer: str,
    client_id: str,
    redirect_uri: str,
    username: str,
    password: str,
    idp_hint: str | None = None,
    scope: str = "openid",
    dpop_key=None,
) -> str:
    """Drive a full auth-code + PKCE login; return the access token. When
    dpop_key is given, attach a DPoP proof so the issuer binds cnf.jkt."""
    session = requests.Session()
    verifier, challenge = _pkce()
    state = secrets.token_urlsafe(16)
    expected_iss = issuer

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if idp_hint:
        params["kc_idp_hint"] = idp_hint

    response = _request(session, "GET", f"{issuer}/protocol/openid-connect/auth", params=params)
    page, callback = _follow(session, response, stop_prefix=redirect_uri)

    for _ in range(5):
        if callback:
            break
        assert page.status_code == 200, f"{page.status_code} at {page.url}: {page.text[:400]}"
        response = _answer_page(session, page, username, password)
        page, callback = _follow(session, response, stop_prefix=redirect_uri)
    assert callback, f"login for {username} never redirected to {redirect_uri}"

    query = parse_qs(urlparse(callback).query)
    code = query["code"][0]
    assert query.get("iss", [None])[0] == expected_iss, (
        f"RFC 9207: authorization response iss {query.get('iss')} != {expected_iss}"
    )
    assert query["state"][0] == state, "state mismatch on callback"

    token_url = f"{issuer}/protocol/openid-connect/token"
    headers = {}
    if dpop_key is not None:
        from . import dpop as _dpop

        headers["DPoP"] = _dpop.proof(dpop_key, "POST", token_url)
    token_response = requests.post(
        token_url,
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
        headers=headers,
        timeout=30,
    )
    assert token_response.status_code == 200, token_response.text
    return token_response.json()["access_token"]
