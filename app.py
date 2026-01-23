import os
import time
import secrets
import base64
import hashlib
import hmac
import json
import threading
from typing import Dict, Optional

import requests
import httpx
import mysql.connector
from mysql.connector import pooling
from fastapi import FastAPI, Request, Response, Header, HTTPException, APIRouter
from fastapi.responses import RedirectResponse, PlainTextResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI()

# -----------------------------
# Helpers (config)
# -----------------------------
def read_secret_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        print(f"Secret file not found: {path}")
    except Exception as exc:
        print(f"Failed to read secret file {path}: {exc}")
    return None


# -----------------------------
# Config (env)
# -----------------------------
DGG_CLIENT_ID = os.environ["DGG_CLIENT_ID"]
DGG_CLIENT_SECRET = os.environ["DGG_CLIENT_SECRET"]
REDIRECT_URI = os.environ["REDIRECT_URI"]
POST_LOGIN_REDIRECT = os.environ.get("POST_LOGIN_REDIRECT", "https://app.dgglocal.com/")
POST_LOGOUT_REDIRECT = os.environ.get("POST_LOGOUT_REDIRECT", POST_LOGIN_REDIRECT)
LINK_CODE_TTL_SECONDS = int(os.environ.get("LINK_CODE_TTL_SECONDS", "600"))
LINK_SERVER_KEY = os.environ.get("LINK_SERVER_KEY")
MINECRAFT_PROFILE_CACHE_TTL = int(os.environ.get("MINECRAFT_PROFILE_CACHE_TTL", "300"))
LINK_DB_HOST = os.environ.get("LINK_DB_HOST") or os.environ.get("DB_HOST")
LINK_DB_PORT = int(os.environ.get("LINK_DB_PORT", os.environ.get("DB_PORT", "3306")))
LINK_DB_USER = os.environ.get("LINK_DB_USER") or os.environ.get("DB_USER")
LINK_DB_PASSWORD_FILE = os.environ.get("LINK_DB_PASSWORD_FILE") or os.environ.get("DB_PASSWORD_FILE")
LINK_DB_PASSWORD = read_secret_file(LINK_DB_PASSWORD_FILE) or os.environ.get("LINK_DB_PASSWORD") or os.environ.get("DB_PASSWORD")
LINK_DB_NAME = os.environ.get("LINK_DB_NAME") or os.environ.get("DB_NAME")

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
# link_code -> record
LINK_CODES: Dict[str, dict] = {}
# destiny_id -> link_code
LINK_CODES_BY_USER: Dict[str, str] = {}
MINECRAFT_PROFILE_CACHE: Dict[str, dict] = {}

DB_CONFIG = None
if LINK_DB_HOST and LINK_DB_USER and LINK_DB_PASSWORD and LINK_DB_NAME:
    DB_CONFIG = {
        "host": LINK_DB_HOST,
        "port": LINK_DB_PORT,
        "user": LINK_DB_USER,
        "password": LINK_DB_PASSWORD,
        "database": LINK_DB_NAME,
        "autocommit": True,
    }

DB_POOL: Optional[pooling.MySQLConnectionPool] = None
DB_POOL_LOCK = threading.Lock()
DB_POOL_READY = False

link_router = APIRouter(prefix="/link")

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


def clear_cookie(resp: Response) -> None:
    resp.delete_cookie(
        COOKIE_NAME,
        domain=COOKIE_DOMAIN,
        path="/",
        secure=COOKIE_SECURE,
        httponly=True,
        samesite=COOKIE_SAMESITE,
    )


def get_session_from_request(request: Request) -> Optional[dict]:
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None
    return verify_session(cookie)


def cleanup_link_codes():
    now = time.time()
    for code, record in list(LINK_CODES.items()):
        if record.get("expires_at", 0) < now:
            LINK_CODES.pop(code, None)
            user_id = record.get("destiny_id")
            if user_id and LINK_CODES_BY_USER.get(user_id) == code:
                LINK_CODES_BY_USER.pop(user_id, None)


def cleanup_minecraft_profile_cache():
    now = time.time()
    for key, record in list(MINECRAFT_PROFILE_CACHE.items()):
        if record.get("expires_at", 0) < now:
            MINECRAFT_PROFILE_CACHE.pop(key, None)


def make_link_code(length: int = 8) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        code = "".join(secrets.choice(alphabet) for _ in range(length))
        if code not in LINK_CODES:
            return code


def get_destiny_id(session: dict) -> str:
    if not session:
        return ""
    if session.get("destiny_id"):
        return str(session["destiny_id"])
    ui = session.get("userinfo") or {}
    if ui.get("userId") is None:
        return ""
    return str(ui.get("userId"))


def init_db_pool():
    global DB_POOL_READY, DB_POOL
    if DB_POOL_READY:
        return
    if not DB_CONFIG:
        raise RuntimeError("Link DB env vars are not fully configured")
    with DB_POOL_LOCK:
        if DB_POOL_READY:
            return
        DB_POOL = pooling.MySQLConnectionPool(pool_name="link_pool", pool_size=5, **DB_CONFIG)
        conn = DB_POOL.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS dgg_users (
                    destiny_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
                    nick VARCHAR(255),
                    userinfo_json LONGTEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS account_links (
                    mc_uuid VARCHAR(64) NOT NULL PRIMARY KEY,
                    destiny_id BIGINT UNSIGNED NOT NULL,
                    linked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uq_destiny_id (destiny_id),
                    CONSTRAINT fk_account_links_destiny_id
                        FOREIGN KEY (destiny_id) REFERENCES dgg_users(destiny_id)
                        ON DELETE CASCADE ON UPDATE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )
            conn.commit()
        finally:
            conn.close()
        DB_POOL_READY = True


def get_db_connection():
    init_db_pool()
    if not DB_POOL:
        raise RuntimeError("DB pool is not initialized")
    return DB_POOL.get_connection()


def coerce_destiny_id(destiny_id: str) -> int:
    try:
        return int(destiny_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid_destiny_id") from exc


def upsert_dgg_user(destiny_id: str, nick: str, userinfo: dict):
    conn = get_db_connection()
    did = coerce_destiny_id(destiny_id)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO dgg_users (destiny_id, nick, userinfo_json)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
                nick = VALUES(nick),
                userinfo_json = VALUES(userinfo_json),
                updated_at = CURRENT_TIMESTAMP
            """,
            (did, nick, json.dumps(userinfo, separators=(",", ":"), sort_keys=True)),
        )
        conn.commit()
    finally:
        conn.close()


def save_account_link(destiny_id: str, minecraft_uuid: str):
    conn = get_db_connection()
    did = coerce_destiny_id(destiny_id)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO account_links (mc_uuid, destiny_id)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE
                mc_uuid = VALUES(mc_uuid),
                destiny_id = VALUES(destiny_id),
                linked_at = CURRENT_TIMESTAMP
            """,
            (minecraft_uuid, did),
        )
        conn.commit()
    finally:
        conn.close()


def fetch_account_link(destiny_id: str) -> Optional[dict]:
    conn = get_db_connection()
    did = coerce_destiny_id(destiny_id)
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT al.destiny_id,
                   al.mc_uuid AS minecraft_uuid,
                   UNIX_TIMESTAMP(al.linked_at) AS linked_at,
                   du.nick,
                   du.userinfo_json,
                   UNIX_TIMESTAMP(du.updated_at) AS user_updated_at
            FROM account_links al
            LEFT JOIN dgg_users du ON du.destiny_id = al.destiny_id
            WHERE al.destiny_id = %s
            """,
            (did,),
        )
        row = cursor.fetchone()
        return row
    finally:
        conn.close()


def fetch_account_link_by_uuid(mc_uuid: str) -> Optional[dict]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT al.destiny_id,
                   al.mc_uuid AS minecraft_uuid,
                   UNIX_TIMESTAMP(al.linked_at) AS linked_at,
                   du.nick,
                   du.userinfo_json,
                   UNIX_TIMESTAMP(du.updated_at) AS user_updated_at
            FROM account_links al
            LEFT JOIN dgg_users du ON du.destiny_id = al.destiny_id
            WHERE al.mc_uuid = %s
            """,
            (mc_uuid,),
        )
        row = cursor.fetchone()
        return row
    finally:
        conn.close()


def ensure_link_db():
    if not DB_CONFIG:
        raise HTTPException(status_code=500, detail="Link DB is not configured")


class RedeemRequest(BaseModel):
    code: str
    minecraftUuid: str


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
        "userinfo": userinfo,
        "exp": time.time() + SESSION_TTL_SECONDS,
    }

    try:
        ensure_link_db()
        upsert_dgg_user(destiny_id, nick, userinfo)
    except Exception as exc:
        print("Failed to upsert dgg_user on login:", exc)

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



@app.get("/logout")
def logout(redirect: bool = True):
    if redirect:
        resp = RedirectResponse(POST_LOGOUT_REDIRECT, status_code=302)
    else:
        resp = PlainTextResponse("logged out", status_code=200)
    clear_cookie(resp)
    return resp


@link_router.post("/code")
def create_link_code(request: Request):
    cleanup_link_codes()
    session = get_session_from_request(request)
    if not session:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    destiny_id = get_destiny_id(session)
    if not destiny_id:
        return JSONResponse({"error": "missing_user_id"}, status_code=400)

    try:
        ensure_link_db()
        upsert_dgg_user(destiny_id, session.get("nick", ""), session.get("userinfo", {}))
    except HTTPException as exc:
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
    except Exception as exc:
        print("Failed to upsert dgg_user on link code creation:", exc)
        return JSONResponse({"error": "db_error"}, status_code=500)

    existing = LINK_CODES_BY_USER.pop(destiny_id, None)
    if existing:
        LINK_CODES.pop(existing, None)

    code = make_link_code()
    expires_at = time.time() + LINK_CODE_TTL_SECONDS
    LINK_CODES[code] = {
        "destiny_id": destiny_id,
        "username": session.get("username", ""),
        "nick": session.get("nick", ""),
        "userinfo": session.get("userinfo", {}),
        "expires_at": expires_at,
    }
    LINK_CODES_BY_USER[destiny_id] = code
    return JSONResponse({"code": code, "expiresAt": int(expires_at * 1000)}, status_code=200)


@link_router.post("/redeem")
def redeem_link_code(payload: RedeemRequest, server_key: Optional[str] = Header(default=None, alias="X-Server-Key")):
    cleanup_link_codes()
    if not LINK_SERVER_KEY:
        raise HTTPException(status_code=500, detail="LINK_SERVER_KEY is not configured")
    if not server_key or server_key != LINK_SERVER_KEY:
        raise HTTPException(status_code=403, detail="forbidden")
    if not payload.minecraftUuid:
        raise HTTPException(status_code=400, detail="minecraftUuid is required")

    code = (payload.code or "").strip().upper()
    record = LINK_CODES.pop(code, None)
    if not record:
        raise HTTPException(status_code=404, detail="invalid_or_expired_code")

    destiny_id = record.get("destiny_id")
    if destiny_id and LINK_CODES_BY_USER.get(destiny_id) == code:
        LINK_CODES_BY_USER.pop(destiny_id, None)

    minecraft_uuid = payload.minecraftUuid.strip().lower()
    try:
        ensure_link_db()
        upsert_dgg_user(destiny_id, record.get("nick", ""), record.get("userinfo", {}) or {})
        save_account_link(destiny_id, minecraft_uuid)
    except HTTPException:
        raise
    except Exception as exc:
        print("Failed to save link binding:", exc)
        raise HTTPException(status_code=500, detail="db_error")

    dgg_id = record.get("destiny_id", "")
    try:
        dgg_id = int(dgg_id)
    except Exception:
        dgg_id = str(dgg_id)

    return JSONResponse({"dggId": dgg_id, "dggNick": record.get("nick", "")}, status_code=200)


@link_router.get("/status")
def link_status(request: Request):
    cleanup_link_codes()
    session = get_session_from_request(request)
    if not session:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    destiny_id = get_destiny_id(session)
    if not destiny_id:
        return JSONResponse({"error": "missing_user_id"}, status_code=400)

    try:
        ensure_link_db()
        binding = fetch_account_link(destiny_id)
    except HTTPException as exc:
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
    except Exception as exc:
        print("Failed to fetch link binding:", exc)
        return JSONResponse({"error": "db_error"}, status_code=500)

    pending_code = LINK_CODES_BY_USER.get(destiny_id)
    pending_record = LINK_CODES.get(pending_code) if pending_code else None

    response = {"linked": bool(binding)}
    if binding:
        linked_at_ms = int(float(binding.get("linked_at", 0)) * 1000)
        response.update(
            {
                "minecraftUuid": binding.get("minecraft_uuid"),
                "linkedAt": linked_at_ms,
            }
        )
        if binding.get("nick") is not None:
            response["dggNick"] = binding.get("nick")
    if pending_record:
        response.update(
            {
                "pendingCode": pending_code,
                "pendingExpiresAt": int(pending_record.get("expires_at", 0) * 1000),
            }
        )

    return JSONResponse(response, status_code=200)


@link_router.get("/lookup")
def link_lookup(uuid: Optional[str] = None, destinyId: Optional[str] = None):
    cleanup_link_codes()
    try:
        ensure_link_db()
    except HTTPException as exc:
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    if (uuid and destinyId) or (not uuid and not destinyId):
        return JSONResponse({"error": "provide_exactly_one_of_uuid_or_destinyId"}, status_code=400)

    record: Optional[dict] = None
    if uuid:
        record = fetch_account_link_by_uuid(uuid.strip().lower())
    else:
        try:
            record = fetch_account_link(destinyId)
        except HTTPException as exc:
            return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    if not record:
        return JSONResponse({"error": "not_found"}, status_code=404)

    linked_at_ms = int(float(record.get("linked_at", 0)) * 1000)
    userinfo_json = record.get("userinfo_json")
    try:
        userinfo = json.loads(userinfo_json) if userinfo_json else {}
    except Exception:
        userinfo = {}

    subscription_tier = ""
    try:
        subscription_tier = userinfo.get("subscription", {}).get("tier", "")
    except Exception:
        subscription_tier = ""

    resp = {
        "destinyId": str(record.get("destiny_id", "")),
        "minecraftUuid": record.get("minecraft_uuid", ""),
        "linkedAt": linked_at_ms,
        "dggNick": record.get("nick", ""),
        "subscriptionTier": subscription_tier,
        "updatedAt": int(float(record.get("user_updated_at", 0)) * 1000),
        "userinfo": userinfo,
    }
    return JSONResponse(resp, status_code=200)


@link_router.get("/minecraft-profile/{uuid}")
async def minecraft_profile(uuid: str):
    cleanup_minecraft_profile_cache()
    key = (uuid or "").strip().lower()
    if not key:
        raise HTTPException(status_code=400, detail="invalid_uuid")

    cached = MINECRAFT_PROFILE_CACHE.get(key)
    if cached and cached.get("expires_at", 0) > time.time():
        return JSONResponse(cached["data"], status_code=200)

    url = f"https://api.minecraftservices.com/minecraft/profile/lookup/{key}"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="lookup_failed") from exc

    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail="not_found")
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail="upstream_error")
    try:
        data = resp.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="invalid_response") from exc

    MINECRAFT_PROFILE_CACHE[key] = {
        "data": data,
        "expires_at": time.time() + MINECRAFT_PROFILE_CACHE_TTL,
    }
    return JSONResponse(data, status_code=200)


@app.get("/whoami")
def whoami(request: Request):
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return JSONResponse({"authenticated": False}, status_code=401)

    session = verify_session(cookie)
    if not session:
        return JSONResponse({"authenticated": False}, status_code=401)

    return JSONResponse({
        "authenticated": True,
        "admin": bool(session.get("admin")),
        "destiny_id": session.get("destiny_id", ""),
        "username": session.get("username", ""),
        "nick": session.get("nick", ""),
        "userinfo": session.get("userinfo", {}),
    })


app.include_router(link_router)
