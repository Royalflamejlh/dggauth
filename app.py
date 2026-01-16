import os
import time
import secrets
import base64
import hashlib
from typing import Dict, Tuple

import requests
from fastapi import FastAPI
from fastapi.responses import RedirectResponse, PlainTextResponse

app = FastAPI()

# docker things
DGG_CLIENT_ID = os.environ["DGG_CLIENT_ID"]
DGG_CLIENT_SECRET = os.environ["DGG_CLIENT_SECRET"]
REDIRECT_URI = os.environ["REDIRECT_URI"]

AUTHORIZE_URL = "https://www.destiny.gg/oauth/authorize"
TOKEN_URL = "https://www.destiny.gg/oauth/token"

STATE_STORE: Dict[str, float] = {}

def cleanup():
    now = time.time()
    for k, exp in list(STATE_STORE.items()):
        if exp < now:
            del STATE_STORE[k]


def make_state() -> str:
    return secrets.token_hex(32)


def make_code_challenge(state: str) -> str:
    secret_hex = hashlib.sha256(DGG_CLIENT_SECRET.encode()).hexdigest()
    digest = hashlib.sha256((state + secret_hex).encode()).digest()
    challenge = base64.b64encode(digest).decode()
    print("DEBUG challenge inputs:")
    print("  state:", state)
    print("  secret_hex:", secret_hex)
    print("  code_challenge:", challenge)
    return challenge


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

    return RedirectResponse(url)


@app.get("/callback")
def callback(code: str, state: str):
    cleanup()

    print("\n=== CALLBACK RECEIVED ===")
    print("code:", code)
    print("state:", state)

    exp = STATE_STORE.pop(state, None)
    if not exp:
        print("ERROR: state not found or expired")
        return PlainTextResponse("Invalid or expired state", status_code=400)

    code_verifier = state
    print("Using code_verifier = state:", code_verifier)

    params = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": DGG_CLIENT_ID,
        "client_secret": DGG_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }

    print("\n=== TOKEN REQUEST ===")
    for k, v in params.items():
        if k == "client_secret":
            print(f"{k}: <hidden>")
        else:
            print(f"{k}: {v}")
    print("=====================")

    r = requests.get(TOKEN_URL, params=params, timeout=10)

    print("\n=== TOKEN RESPONSE ===")
    print("HTTP status:", r.status_code)
    print("Raw text:", r.text)
    try:
        data = r.json()
        print("Parsed JSON:", data)
    except Exception:
        print("Not JSON!")
        return PlainTextResponse(f"Non-JSON response: {r.text}", status_code=502)
    print("======================\n")

    if "access_token" not in data:
        return PlainTextResponse(
            f"Token exchange failed ({r.status_code}): {data}",
            status_code=502,
        )

    return PlainTextResponse(f"SUCCESS, access_token = {data['access_token']}")