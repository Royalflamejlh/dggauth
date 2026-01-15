from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Dict, Optional, Tuple

import requests
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

app = FastAPI()

# -----------------------------
# Config (env)
# -----------------------------
DGG_CLIENT_ID = os.environ["DGG_CLIENT_ID"]
DGG_CLIENT_SECRET = os.environ["DGG_CLIENT_SECRET"]

# Must match what you registered in destiny.gg developer settings
# Example: https://auth.dgglocal.com/callback
REDIRECT_URI = os.environ["REDIRECT_URI"]

# Where to send the user after successful login (e.g. https://dgglocal.com)
POST_LOGIN_REDIRECT = os.environ.get("POST_LOGIN_REDIRECT", "/")

# Cookie + signing
SESSION_SIGNING_KEY = os.environ["SESSION_SIGNING_KEY"].encode("utf-8")
COOKIE_NAME = os.environ.get("COOKIE_NAME", "dgg_session")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
COOKIE_DOMAIN = os.environ.get("COOKIE_DOMAIN")  # e.g. ".dgglocal.com" (optional)
COOKIE_SAMESITE = os.environ.get("COOKIE_SAMESITE", "Lax")  # Lax/Strict/None
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "86400"))  # 1 day

# Admin list: comma-separated Destiny user IDs
ADMIN_USER_IDS = {
    s.strip() for s in os.environ.get("ADMIN_USER_IDS", "").split(",") if s.strip()
}

# Destiny endpoints
AUTHORIZE_URL = "https://www.destiny.gg/oauth/authorize"
TOKEN_URL = "https://www.destiny.gg/oauth/token"
USERINFO_URL = "https://www.destiny.gg/api/userinfo"  # GET ?token=...

# state store: state -> (code_verifier, expires_at)
STATE_STORE: Dict[str, Tuple[str, float]] = {}


# -----------------------------
# Helpers
# -----------------------------
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def cleanup_state_store() -> None:
    now = time.time()
    dead = [k for k, (_, exp) in STATE_STORE.items() if exp < now]
    for k in dead:
        STATE_STORE.pop(k, None)


def make_state() -> str:
    # CSRF state
    return secrets.token_hex(32)


def make_code_verifier() -> str:
    # URL-safe random string, comfortably > 43 chars
    return secrets.token_urlsafe(48)


def make_code_challenge(code_verifier: str) -> str:
    """
    Destiny uses a custom challenge scheme based on:
      secret_hex = sha256(client_secret).hexdigest()
      code_challenge = base64( sha256( code_verifier + secret_hex ) )
    """
    secret_hex = hashlib.sha256(DGG_CLIENT_SECRET.encode("utf-8")).hexdigest()
    digest = hashlib.sha256((code_verifier + secret_hex).encode("utf-8")).digest()
    return _b64(digest)


def sign_session(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(SESSION_SIGNING_KEY, raw, hashlib.sha256).digest()
    return _b64(raw) + "." + _b64(sig)


def verify_session(value: str) -> Optional[dict]:
    try:
        raw_b64, sig_b64 = value.split(".", 1)
        raw = base64.b64decode(raw_b64.encode("ascii"))
        sig = base64.b64decode(sig_b64.encode("ascii"))
        expected = hmac.new(SESSION_SIGNING_KEY, raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(raw.decode("utf-8"))
        if float(payload.get("exp", 0)) < time.time():
            return None
        return payload
    except Exception:
        return None


def token_exchange(code: str, code_verifier: str) -> dict:
    """
    Exchange code for access_token. Destiny docs show GET, but some servers require POST.
    We try GET then POST.

    NOTE: If Destiny ever requires client_secret here, uncomment the client_secret line.
    """
    params = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": DGG_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
        # "client_secret": DGG_CLIENT_SECRET,
    }

    r = requests.get(TOKEN_URL, params=params, timeout=10)
    if r.status_code >= 400:
        r = requests.post(TOKEN_URL, data=params, timeout=10)

    r.raise_for_status()
    return r.json()


def fetch_userinfo(access_token: str) -> dict:
    r = requests.get(USERINFO_URL, params={"token": access_token}, timeout=10)
    r.raise_for_status()
    return r.json()


def extract_identity(userinfo: dict) -> Tuple[str, str]:
    """
    Destiny's userinfo schema can vary. We try a few common keys.
    """
    destiny_id = (
        userinfo.get("id")
        or userinfo.get("user_id")
        or userinfo.get("userid")
        or userinfo.get("userId")
    )
    username = (
        userinfo.get("username")
        or userinfo.get("name")
        or userinfo.get("nick")
        or userinfo.get("display_name")
        or userinfo.get("displayName")
    )
    return (str(destiny_id) if destiny_id is not None else "", str(username) if username else "")


def set_cookie(resp: RedirectResponse, cookie_val: str) -> None:
    resp.set_cookie(
        COOKIE_NAME,
        cookie_val,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        domain=COOKIE_DOMAIN,
        path="/",
        max_age=SESSION_TTL_SECONDS,
    )


# -----------------------------
# Routes
# -----------------------------
@app.get("/healthz")
def healthz():
    return PlainTextResponse("ok", status_code=200)


@app.get("/login")
def login():
    cleanup_state_store()

    state = make_state()
    code_verifier = make_code_verifier()
    code_challenge = make_code_challenge(code_verifier)

    # store verifier for callback
    STATE_STORE[state] = (code_verifier, time.time() + 600)  # 10 minutes

    # Build authorize URL
    qs = {
        "response_type": "code",
        "client_id": DGG_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": code_challenge,
    }

    url = requests.Request("GET", AUTHORIZE_URL, params=qs).prepare().url
    return RedirectResponse(url, status_code=302)


@app.get("/callback")
def callback(code: str, state: str):
    cleanup_state_store()

    entry = STATE_STORE.pop(state, None)
    if not entry:
        return PlainTextResponse("Invalid/expired state", status_code=400)

    code_verifier, exp = entry
    if exp < time.time():
        return PlainTextResponse("Invalid/expired state", status_code=400)

    token_data = token_exchange(code=code, code_verifier=code_verifier)
    access_token = token_data.get("access_token")
    if not access_token:
        return PlainTextResponse(f"Token response missing access_token: {token_data}", status_code=502)

    userinfo = fetch_userinfo(access_token)
    destiny_id, username = extract_identity(userinfo)
    if not destiny_id:
        return PlainTextResponse(f"userinfo missing id: {userinfo}", status_code=502)

    is_admin = destiny_id in ADMIN_USER_IDS

    session = {
        "destiny_id": destiny_id,
        "username": username,
        "admin": bool(is_admin),
        "exp": time.time() + SESSION_TTL_SECONDS,
    }
    cookie_val = sign_session(session)

    resp = RedirectResponse(POST_LOGIN_REDIRECT, status_code=302)
    set_cookie(resp, cookie_val)
    return resp


@app.get("/auth")
def auth(request: Request):
    """
    For SWAG/Nginx auth_request:
      - 200 + headers if authenticated
      - 401 if not
    """
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return PlainTextResponse("unauthorized", status_code=401)

    session = verify_session(cookie)
    if not session:
        return PlainTextResponse("unauthorized", status_code=401)

    resp = PlainTextResponse("ok", status_code=200)
    resp.headers["X-Destiny-Id"] = session.get("destiny_id", "")
    resp.headers["X-Destiny-User"] = session.get("username", "")
    resp.headers["X-Destiny-Admin"] = "true" if session.get("admin") else "false"
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(COOKIE_NAME, domain=COOKIE_DOMAIN, path="/")
    return resp
