"""Requests-based OIDC flow drivers for the Phase 1 acceptance suite.

Walks real authorization-code + PKCE logins (including brokered legs) by
scripting the HTML login forms — no browser. Validates RFC 9207 `iss` on the
authorization response per claims contract §8.

Cookie note: Keycloak marks its cookies Secure even over HTTP. Browsers send
Secure cookies to http://localhost (a trustworthy origin per the Secure
Contexts spec); python-requests never does, and it re-jars cookies with a
default policy on every request, so a custom CookiePolicy can't help. Instead
we follow every redirect manually and clear the Secure flag between hops —
harmless for real-HTTPS hops (Auth0), where cookies are sent either way.
"""
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
    """The login/profile form — pages may carry secondary forms (social logins)."""
    forms = FORM_BLOCK_RE.findall(text)
    assert forms, f"no form found: {text[:400]}"
    for form in forms:
        if 'data-form-primary="true"' in form or NAME_ATTR_RE.search(form) and any(
            f'name="{marker}"' in form for marker in ("password", "username", "firstName")
        ):
            return form
    return forms[0]


def _form_fields(form_block: str) -> dict[str, str]:
    """Named input/button fields of one form with current values (like a browser)."""
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
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def _request(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    response = session.request(method, url, allow_redirects=False, **kwargs)
    for cookie in session.cookies:
        cookie.secure = False  # see module docstring
    return response


def _follow(session: requests.Session, response: requests.Response,
            stop_prefix: str) -> tuple[requests.Response, str | None]:
    """Follow redirects one hop at a time; stop early if one targets stop_prefix."""
    for _ in range(10):
        if response.status_code not in REDIRECT_CODES:
            return response, None
        location = urljoin(response.url, response.headers["Location"])
        if location.startswith(stop_prefix):
            return response, location
        response = _request(session, "GET", location)
    raise AssertionError("redirect loop")


def _submit_form(session: requests.Session, page: requests.Response,
                 overrides: dict[str, str]) -> requests.Response:
    """Submit the page's primary form with its existing fields plus `overrides`."""
    form = _primary_form(page.text)
    match = FORM_ACTION_RE.search(form)
    # a form without action posts back to the current URL (Auth0 does this)
    action = urljoin(page.url, html.unescape(match.group(1))) if match else page.url
    fields = _form_fields(form)
    fields.update(overrides)
    return _request(session, "POST", action, data=fields)


def _answer_page(session: requests.Session, page: requests.Response,
                 username: str, password: str) -> requests.Response:
    """Answer whichever form the IdP presented: credentials or profile review."""
    fields = _form_fields(_primary_form(page.text))
    if "password" in fields:
        return _submit_form(session, page, {"username": username, "password": password})
    if "firstName" in fields or "lastName" in fields:
        # Keycloak first-broker-login Review Profile: fill whatever is missing
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


def authorization_code_login(
    kc_base: str,
    realm: str,
    client_id: str,
    redirect_uri: str,
    username: str,
    password: str,
    idp_hint: str | None = None,
    scope: str = "openid",
) -> dict:
    """Drive a full auth-code+PKCE login; returns the token endpoint response."""
    session = requests.Session()
    verifier, challenge = _pkce()
    state = secrets.token_urlsafe(16)
    expected_iss = f"{kc_base}/realms/{realm}"

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

    response = _request(
        session,
        "GET",
        f"{kc_base}/realms/{realm}/protocol/openid-connect/auth",
        params=params,
    )
    page, callback = _follow(session, response, stop_prefix=redirect_uri)

    # login form, then possibly more (review-profile, identifier-first IdPs)
    for _ in range(5):
        if callback:
            break
        assert page.status_code == 200, f"{page.status_code} at {page.url}: {page.text[:400]}"
        response = _answer_page(session, page, username, password)
        page, callback = _follow(session, response, stop_prefix=redirect_uri)
    assert callback, f"login for {username} never redirected to {redirect_uri}"

    query = parse_qs(urlparse(callback).query)
    code = query["code"][0]
    # RFC 9207: strict iss comparison on the authorization response (contract §8)
    assert query.get("iss", [None])[0] == expected_iss, (
        f"authorization response iss {query.get('iss')} != {expected_iss}"
    )
    assert query["state"][0] == state, "state mismatch on callback"

    token_response = requests.post(
        f"{kc_base}/realms/{realm}/protocol/openid-connect/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    assert token_response.status_code == 200, token_response.text
    return token_response.json()


def client_credentials_token(kc_base: str, realm: str, client_id: str, client_secret: str) -> dict:
    response = requests.post(
        f"{kc_base}/realms/{realm}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def homegrown_exchange_token(
    kc_base: str,
    realm: str,
    issuer_base: str,
    issuer_client_id: str,
    issuer_client_secret: str,
    exchange_client_id: str,
    exchange_client_secret: str,
) -> dict:
    subject = requests.post(
        f"{issuer_base}/token",
        data={
            "grant_type": "client_credentials",
            "client_id": issuer_client_id,
            "client_secret": issuer_client_secret,
        },
    )
    assert subject.status_code == 200, subject.text
    response = requests.post(
        f"{kc_base}/realms/{realm}/protocol/openid-connect/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": exchange_client_id,
            "client_secret": exchange_client_secret,
            "subject_token": subject.json()["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "subject_issuer": "homegrown",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()
