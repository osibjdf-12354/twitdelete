#!/usr/bin/env python3
"""Get X OAuth 2.0 user token (PKCE) and save to auth.json."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import secrets
import sys
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import requests

AUTHORIZE_URL = "https://x.com/i/oauth2/authorize"
TOKEN_URL = "https://api.x.com/2/oauth2/token"


@dataclass
class CallbackResult:
    code: str | None
    state: str | None
    error: str | None
    error_description: str | None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fetch X OAuth2 user token and save auth.json.")
    p.add_argument("--client-id", required=True, help="X App Client ID")
    p.add_argument("--client-secret", default="", help="Optional for confidential client")
    p.add_argument(
        "--redirect-uri",
        default="http://127.0.0.1:8765/callback",
        help="Must exactly match your app callback URL",
    )
    p.add_argument(
        "--scopes",
        default="tweet.read tweet.write users.read offline.access",
        help="Space or comma separated scopes",
    )
    p.add_argument("--auth-file", default="auth.json", help="Output auth file path")
    p.add_argument("--timeout", type=float, default=300.0, help="Wait timeout seconds for callback")
    p.add_argument("--no-browser", action="store_true", help="Do not auto-open browser")
    p.add_argument("--manual", action="store_true", help="Manual mode: paste callback URL")
    return p.parse_args()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_pkce_pair() -> tuple[str, str]:
    verifier = b64url(secrets.token_bytes(64))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def normalize_scopes(raw: str) -> str:
    items = [x.strip() for x in raw.replace(",", " ").split() if x.strip()]
    # Keep input order, remove duplicates.
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return " ".join(out)


def build_authorize_url(
    client_id: str, redirect_uri: str, scope: str, state: str, code_challenge: str
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return AUTHORIZE_URL + "?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)


def parse_callback_query(query: str) -> CallbackResult:
    data = urllib.parse.parse_qs(query)
    return CallbackResult(
        code=(data.get("code") or [None])[0],
        state=(data.get("state") or [None])[0],
        error=(data.get("error") or [None])[0],
        error_description=(data.get("error_description") or [None])[0],
    )


def wait_for_callback_local(redirect_uri: str, timeout: float) -> CallbackResult:
    parsed = urllib.parse.urlparse(redirect_uri)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"

    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("Local callback mode supports only localhost/127.0.0.1 redirect URI")

    done = threading.Event()
    holder: dict[str, CallbackResult] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            req = urllib.parse.urlparse(self.path)
            if req.path != path:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")
                return

            holder["result"] = parse_callback_query(req.query)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                (
                    "<html><body><h3>Authorization received.</h3>"
                    "<p>You can close this tab and return to terminal.</p></body></html>"
                ).encode("utf-8")
            )
            done.set()

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: ANN401
            return

    server = http.server.ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        ok = done.wait(timeout=timeout)
        if not ok:
            raise TimeoutError(f"Timed out waiting callback ({timeout}s)")
        result = holder.get("result")
        if not result:
            raise ValueError("Callback result missing")
        return result
    finally:
        server.shutdown()
        server.server_close()


def wait_for_callback_manual() -> CallbackResult:
    print("[INPUT] Paste the full callback URL from browser address bar:")
    url = input("> ").strip()
    parsed = urllib.parse.urlparse(url)
    return parse_callback_query(parsed.query)


def exchange_code_for_token(
    *,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict[str, Any]:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "client_id": client_id,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if client_secret:
        basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {basic}"

    resp = requests.post(TOKEN_URL, headers=headers, data=form, timeout=30)
    if resp.status_code != 200:
        raise ValueError(f"Token exchange failed HTTP {resp.status_code}: {resp.text[:300]}")

    try:
        payload = resp.json()
    except ValueError as exc:
        raise ValueError(f"Token exchange invalid JSON: {resp.text[:300]}") from exc

    if not isinstance(payload, dict):
        raise ValueError("Token exchange response is not an object")
    if "access_token" not in payload:
        raise ValueError(f"access_token missing in response: {payload}")
    return payload


def save_auth(auth_file: str, token_payload: dict[str, Any]) -> None:
    current: dict[str, Any] = {}
    if os.path.exists(auth_file):
        try:
            with open(auth_file, encoding="utf-8") as fp:
                loaded = json.load(fp)
            if isinstance(loaded, dict):
                current = loaded
        except Exception:
            current = {}

    now_ts = int(time.time())
    out = dict(current)
    out["access_token"] = token_payload.get("access_token")
    if token_payload.get("refresh_token"):
        out["refresh_token"] = token_payload.get("refresh_token")
    if token_payload.get("token_type"):
        out["token_type"] = token_payload.get("token_type")
    if token_payload.get("scope"):
        out["scope"] = token_payload.get("scope")
    if isinstance(token_payload.get("expires_in"), int):
        out["expires_in"] = token_payload["expires_in"]
        out["access_token_expires_at"] = now_ts + int(token_payload["expires_in"])
    out["obtained_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    with open(auth_file, "w", encoding="utf-8") as fp:
        json.dump(out, fp, ensure_ascii=False, indent=2)
        fp.write("\n")


def main() -> int:
    args = parse_args()
    scope = normalize_scopes(args.scopes)
    if not scope:
        print("[ERROR] scopes is empty", file=sys.stderr)
        return 2

    state = secrets.token_urlsafe(24)
    code_verifier, code_challenge = make_pkce_pair()
    auth_url = build_authorize_url(
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
    )

    print("[INFO] Open this URL and authorize the app:")
    print(auth_url)
    if not args.no_browser:
        webbrowser.open(auth_url)

    try:
        if args.manual:
            callback = wait_for_callback_manual()
        else:
            callback = wait_for_callback_local(args.redirect_uri, args.timeout)
    except Exception as exc:
        print(f"[ERROR] Failed waiting callback: {exc}", file=sys.stderr)
        return 2

    if callback.error:
        print(f"[ERROR] Authorization error: {callback.error} ({callback.error_description or ''})", file=sys.stderr)
        return 2
    if not callback.code:
        print("[ERROR] Authorization code missing in callback", file=sys.stderr)
        return 2
    if callback.state != state:
        print("[ERROR] State mismatch. Abort for safety.", file=sys.stderr)
        return 2

    try:
        token_payload = exchange_code_for_token(
            client_id=args.client_id,
            client_secret=args.client_secret,
            code=callback.code,
            redirect_uri=args.redirect_uri,
            code_verifier=code_verifier,
        )
    except Exception as exc:
        print(f"[ERROR] Token exchange failed: {exc}", file=sys.stderr)
        return 2

    try:
        save_auth(args.auth_file, token_payload)
    except Exception as exc:
        print(f"[ERROR] Failed saving auth file: {exc}", file=sys.stderr)
        return 2

    print(f"[INFO] Saved access token to {args.auth_file}")
    if token_payload.get("refresh_token"):
        print("[INFO] refresh_token saved as well (offline.access scope).")
    else:
        print("[WARN] refresh_token missing. Add offline.access scope if you need long-term auto refresh.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
