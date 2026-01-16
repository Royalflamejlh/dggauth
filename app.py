import os
import time
import secrets
import base64
import hashlib
import hmac
import json
from typing import Dict, Tuple, Optional

import requests
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, PlainTextResponse, JSONResponse

app = FastAPI()

# -----------------------------
# Config (env)
# -----------------------------
DGG_CLIENT_ID = os.environ["DGG_CLIENT_ID"]
DGG_CLIENT_SECRET = os.environ["DGG_CLIENT_SECRET"]
REDIRECT_URI = os.environ["REDIRECT_URI"]
POST_LOGIN_REDIRECT = os.environ.get("POST_LOGIN_REDIRECT", "https://app.dgglocal.com/")

SESSION_SIGNING_KEY = os.environ["SESSION_SIGNING_KEY"].encode("utf-8")
COOKIE_NAME = os.environ.get("COOKIE_NAME", "dgg_session")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
COOKIE_DOMAIN = os.environ.get("COOKIE_DOMAIN")  # e.g ".dgglocal.com"
COOKIE_SAMESITE = os.environ.get("COOKIE_SAMESITE", "Lax")
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "86400"))

ADMIN_USER_IDS = {
    s.strip() for s in os.environ.get("ADMIN_USER_IDS", "").split(",") if s.strip()
}

AUTHORIZE_URL = "https://www.destiny.gg/oauth/authorize"
TOKEN_URL = "https://www.destiny.gg/oauth/token"
USERINFO_URL = "https://www.destiny.gg/api/userinfo"

# state -> expires_at
STATE_STORE: Dict[str, float] = {}

# -----------------------------
# Helpers
# -----------------------------
def cleanup():
    now = time.time()
    for k, exp in list(STATE_STORE.items()):
        if exp < now:
            del STATE_STORE[k]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def make_state() -> str:
    return secrets.token_hex(32)


def make_code_challenge(state: str) -> str:
    """
    Working Destiny-specific challenge:
      secret_hex = sha256(client_secret).hexdigest()
      digest_hex = sha256(state + secret_hex).hexdigest()
      code_challenge = base64( digest_hex-as-bytes )
    """
    secret_hex = hashlib.sha256(DGG_CLIENT_SECRET.encode()).hexdigest()
    digest_hex = hashlib.sha256((state + secret_hex).encode()).hexdigest()
    challenge = base64.b64encode(digest_hex.encode()).decode()

    print("DEBUG challenge inputs:")
    print("  state:", state)
    print("  secret_hex:", secret_hex)
    print("  digest_hex:", digest_hex)
    print("  code_challenge:", challenge)
    return challenge


def token_exchange(code: str, state: str) -> dict:
    params = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": DGG_CLIENT_ID,
        "client_secret": DGG_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": state,  # verifier==state
    }
    r = requests.get(TOKEN_URL, params=params, timeout=10)
    r.raise_for_status()
    return r.json()


def fetch_userinfo(access_token: str) -> dict:
    r = requests.get(USERINFO_URL, params={"token": access_token}, timeout=10)
    r.raise_for_status()
    return r.json()


def sign_session(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(SESSION_SIGNING_KEY, raw, hashlib.sha256).digest()
    return b64(raw) + "." + b64(sig)


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
    cleanup()

    state = make_state()
    code_challenge = make_code_challenge(state)
    STATE_STORE[state] = time.time() + 600

    params = {
        "response_type": "code",
        "client_id": DGG_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": code_challenge,
    }

    url = requests.Request("GET", AUTHORIZE_URL, params=params).prepare().url
    print("\n=== LOGIN START ===")
    print("Authorize URL:", url)
    print("Stored state:", state)
    print("===================\n")
    return RedirectResponse(url, status_code=302)


@app.get("/callback")
def callback(code: str, state: str):
    cleanup()

    print("\n=== CALLBACK RECEIVED ===")
    print("code:", code)
    print("state:", state)

    exp = STATE_STORE.pop(state, None)
    if not exp:
        return PlainTextResponse("Invalid or expired state", status_code=400)

    token = token_exchange(code=code, state=state)
    access_token = token.get("access_token")
    if not access_token:
        return PlainTextResponse(f"Token response missing access_token: {token}", status_code=502)

    userinfo = fetch_userinfo(access_token)

    destiny_id = str(userinfo.get("userId", ""))
    username = str(userinfo.get("username") or "")
    nick = str(userinfo.get("nick") or "")

    is_admin = (destiny_id in ADMIN_USER_IDS) if destiny_id else False

    session = {
        "destiny_id": destiny_id,
        "username": username,
        "nick": nick,
        "admin": bool(is_admin),
        "userinfo": userinfo,  # keep full blob for /whoami/debug
        "exp": time.time() + SESSION_TTL_SECONDS,
    }

    cookie_val = sign_session(session)
    resp = RedirectResponse(POST_LOGIN_REDIRECT, status_code=302)
    set_cookie(resp, cookie_val)

    print("=== USERINFO (full) ===")
    print(json.dumps(userinfo, indent=2))
    print("=======================")

    return resp


@app.get("/auth")
def auth(request: Request):
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return PlainTextResponse("unauthorized", status_code=401)

    session = verify_session(cookie)
    if not session:
        return PlainTextResponse("unauthorized", status_code=401)

    ui = session.get("userinfo") or {}

    resp = PlainTextResponse("ok", status_code=200)
    resp.headers["X-Dgg-UserId"] = str(ui.get("userId", session.get("destiny_id", "")))
    resp.headers["X-Dgg-Username"] = session.get("username", "") or str(ui.get("username", ""))
    resp.headers["X-Dgg-Nick"] = session.get("nick", "") or str(ui.get("nick", ""))
    resp.headers["X-Dgg-Admin"] = "true" if session.get("admin") else "false"

    resp.headers["X-Dgg-Team"] = str(ui.get("team", ""))
    resp.headers["X-Dgg-Roles"] = ",".join(ui.get("roles", []) or [])
    resp.headers["X-Dgg-Features"] = ",".join(ui.get("features", []) or [])

    sub = ui.get("subscription") or {}
    resp.headers["X-Dgg-SubTier"] = str(sub.get("tier", ""))
    resp.headers["X-Dgg-SubEnd"] = str(sub.get("end", ""))

    resp.headers["X-Dgg-Status"] = str(ui.get("status", ""))
    resp.headers["X-Dgg-AllowChatting"] = "true" if ui.get("allowChatting") else "false"
    return resp




@app.get("/whoami")
def whoami(request: Request):
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return JSONResponse({"authenticated": False}, status_code=401)

    session = verify_session(cookie)
    if not session:
        return JSONResponse({"authenticated": False}, status_code=401)

    return JSONResponse(session.get("userinfo", {}))