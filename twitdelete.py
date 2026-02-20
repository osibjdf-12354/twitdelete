#!/usr/bin/env python3
"""Delete tweets directly from logged-in X account timeline."""

from __future__ import annotations

import argparse
import email.utils
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

import requests

DEFAULT_BEARER_TOKEN = (
    "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D"
    "1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
)
DEFAULT_DELETE_QUERY_ID = "VaenaVgh5q5ih7kvyVjgtg"
MAIN_JS_URL_RE = re.compile(r"https://abs\.twimg\.com/responsive-web/client-web/main\.[^\"']+\.js")


@dataclass
class AuthConfig:
    cookie: str
    csrf_token: str
    bearer_token: str
    user_agent: str
    x_client_transaction_id: str | None = None
    x_twitter_client_language: str | None = None


@dataclass
class GraphQLOperation:
    name: str
    query_id: str
    feature_switches: list[str]
    field_toggles: list[str]


@dataclass
class TweetMeta:
    tweet_id: str
    author: str | None
    author_id: str | None
    text: str | None
    created_ts: int | None
    has_media: bool = False
    conversation_id: str | None = None


@dataclass
class DeleteResult:
    success: bool
    message: str
    status_code: int | None = None
    retry_after_seconds: float | None = None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Delete your own visible tweets from logged-in X account timeline."
    )
    p.add_argument("--timeline-pages", type=int, default=8)
    p.add_argument("--timeline-page-size", type=int, default=40)
    p.add_argument("--include-replies", action="store_true")
    p.add_argument(
        "--media-tab",
        action="store_true",
        help="Use profile media timeline source (UserMedia).",
    )
    p.add_argument(
        "--media-delete-conversation",
        action="store_true",
        help="When --media-tab is used, also delete your own tweets in the same conversation thread.",
    )
    p.add_argument("--max", type=int, default=0)
    p.add_argument(
        "--delete-all",
        action="store_true",
        help="Repeat fetch/delete passes until no more visible tweets are found.",
    )
    p.add_argument(
        "--pass-delay",
        type=float,
        default=2.0,
        help="Seconds to wait between --delete-all passes (default: 2.0).",
    )
    p.add_argument(
        "--pass-limit",
        type=int,
        default=0,
        help="Maximum passes in --delete-all mode (0 = unlimited).",
    )
    p.add_argument(
        "--batch-limit",
        type=int,
        default=30,
        help=(
            "Maximum tweets to process per pass (default: 30). "
            "Use 0 to disable and process full loaded batch."
        ),
    )

    p.add_argument("--auth-file", default="auth.json")
    p.add_argument("--cookie")
    p.add_argument("--csrf-token")
    p.add_argument("--bearer-token")
    p.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    p.add_argument(
        "--x-client-transaction-id",
        default="",
        help="Optional x-client-transaction-id header value (helps UserTweetsAndReplies).",
    )
    p.add_argument(
        "--client-language",
        default="",
        help="Optional x-twitter-client-language header value (e.g. ko, en).",
    )
    p.add_argument("--auto-auth", action="store_true")
    p.add_argument(
        "--browser",
        default="auto",
        choices=["auto", "edge", "chrome", "brave", "chromium", "firefox", "opera", "vivaldi"],
    )
    p.add_argument(
        "--cdp-url",
        default="",
        help="Optional Chrome DevTools endpoint, e.g. http://127.0.0.1:9222 (fallback for Brave).",
    )
    p.add_argument(
        "--cdp-user-data-dir",
        default="",
        help=(
            "User-data-dir for auto-launched Edge CDP profile "
            "(default: %%LOCALAPPDATA%%\\twitdelete-edge-cdp-profile)."
        ),
    )
    p.add_argument(
        "--cdp-open-wait",
        type=float,
        default=15.0,
        help="Seconds to wait for CDP endpoint after auto-launching Edge (default: 15).",
    )
    p.add_argument(
        "--no-auto-open-cdp",
        action="store_true",
        help="Disable auto-launching Edge when CDP endpoint is unreachable.",
    )

    p.add_argument("--before", help="UTC date/time, e.g. 2024-01-01")
    p.add_argument("--after", help="UTC date/time, e.g. 2023-01-01")
    p.add_argument("--contains")
    p.add_argument("--author")

    p.add_argument("--delay", type=float, default=0.8)
    p.add_argument(
        "--rate-limit-mode",
        default="wait",
        choices=["wait", "stop"],
        help="How to handle HTTP 429 on delete requests (default: wait).",
    )
    p.add_argument(
        "--rate-limit-retries",
        type=int,
        default=20,
        help="Max retry attempts for a tweet when 429 occurs (default: 20).",
    )
    p.add_argument(
        "--rate-limit-wait",
        type=float,
        default=60.0,
        help="Fallback wait seconds when 429 has no reset header (default: 60).",
    )
    p.add_argument(
        "--rate-limit-max-wait",
        type=float,
        default=900.0,
        help="Cap wait seconds per 429 retry (default: 900).",
    )
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


def parse_utc_datetime(raw: str) -> int:
    t = raw.strip()
    if "T" in t:
        dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return int(dt.timestamp())
    return int(datetime.strptime(t, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp())


def parse_twitter_created_at(raw: Any) -> int | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return int(datetime.strptime(raw, "%a %b %d %H:%M:%S %z %Y").timestamp())
    except ValueError:
        return None


def tweet_legacy_has_media(legacy: dict[str, Any]) -> bool:
    entities = legacy.get("entities") if isinstance(legacy.get("entities"), dict) else {}
    ext_entities = legacy.get("extended_entities") if isinstance(legacy.get("extended_entities"), dict) else {}
    media_entities = entities.get("media") if isinstance(entities.get("media"), list) else []
    media_ext = ext_entities.get("media") if isinstance(ext_entities.get("media"), list) else []
    return bool(media_entities or media_ext)


def coerce_tweet_id(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if re.fullmatch(r"\d{10,25}", text) else None


def load_cookie_map_from_browser(loader: Callable[..., Any]) -> dict[str, str]:
    return load_cookie_map_from_browser_file(loader, cookie_file=None)


def load_cookie_map_from_browser_file(
    loader: Callable[..., Any], cookie_file: str | None
) -> dict[str, str]:
    out: dict[str, str] = {}
    for domain in ("x.com", "twitter.com"):
        if cookie_file:
            jar = loader(domain_name=domain, cookie_file=cookie_file)
        else:
            jar = loader(domain_name=domain)
        for c in jar:
            if c.is_expired() or not c.name or not c.value:
                continue
            out[c.name] = c.value
    return out


def get_chromium_profile_cookie_files(browser_name: str) -> list[tuple[str, str]]:
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")
    base_map = {
        "edge": os.path.join(local, "Microsoft", "Edge", "User Data"),
        "chrome": os.path.join(local, "Google", "Chrome", "User Data"),
        "brave": os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"),
        "chromium": os.path.join(local, "Chromium", "User Data"),
        "opera": os.path.join(roaming, "Opera Software", "Opera Stable"),
        "vivaldi": os.path.join(local, "Vivaldi", "User Data"),
    }
    base = base_map.get(browser_name, "")
    if not base or not os.path.isdir(base):
        return []

    profile_dirs: list[tuple[str, str]] = []
    if browser_name == "opera":
        profile_dirs.append(("Opera Stable", base))
    else:
        for entry in sorted(os.listdir(base)):
            full = os.path.join(base, entry)
            if not os.path.isdir(full):
                continue
            if entry == "Default" or entry.startswith("Profile ") or entry.startswith("Guest Profile"):
                profile_dirs.append((entry, full))

    files: list[tuple[str, str]] = []
    for profile_name, profile_dir in profile_dirs:
        for rel in (os.path.join("Network", "Cookies"), "Cookies"):
            cookie_path = os.path.join(profile_dir, rel)
            if os.path.isfile(cookie_path):
                files.append((profile_name, cookie_path))
                break
    return files


def load_auth_from_browser(browser_name: str) -> tuple[str, str, str]:
    try:
        import browser_cookie3
    except Exception as exc:
        raise ValueError("browser-cookie3 is required") from exc

    loaders = {
        "edge": getattr(browser_cookie3, "edge", None),
        "chrome": getattr(browser_cookie3, "chrome", None),
        "brave": getattr(browser_cookie3, "brave", None),
        "chromium": getattr(browser_cookie3, "chromium", None),
        "firefox": getattr(browser_cookie3, "firefox", None),
        "opera": getattr(browser_cookie3, "opera", None),
        "vivaldi": getattr(browser_cookie3, "vivaldi", None),
    }
    order = ["edge", "chrome", "brave", "chromium", "firefox", "opera", "vivaldi"] if browser_name == "auto" else [browser_name]

    errs: list[str] = []
    for name in order:
        loader = loaders.get(name)
        if loader is None:
            errs.append(f"{name}: unsupported")
            continue

        # 1) default loader path
        try:
            m = load_cookie_map_from_browser(loader)
        except Exception as exc:
            errs.append(f"{name}: {exc}")
            m = {}
        if m.get("auth_token") and m.get("ct0"):
            cookie_header = "; ".join(f"{k}={v}" for k, v in m.items())
            return cookie_header, m["ct0"], name

        # 2) chromium profile scan fallback (Default/Profile 1/...)
        scanned = 0
        for profile_name, cookie_file in get_chromium_profile_cookie_files(name):
            scanned += 1
            try:
                pm = load_cookie_map_from_browser_file(loader, cookie_file=cookie_file)
            except Exception as exc:
                errs.append(f"{name}({profile_name}): {exc}")
                continue
            if pm.get("auth_token") and pm.get("ct0"):
                cookie_header = "; ".join(f"{k}={v}" for k, v in pm.items())
                return cookie_header, pm["ct0"], f"{name}({profile_name})"

        if scanned == 0:
            errs.append(f"{name}: auth_token/ct0 not found")
        else:
            errs.append(f"{name}: auth_token/ct0 not found in {scanned} profile(s)")

    raise ValueError("Failed to read browser cookies: " + " | ".join(errs))


def normalize_cdp_url(raw: str) -> str:
    url = raw.strip()
    if not url:
        raise ValueError("Empty CDP URL")
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url
    return url.rstrip("/")


def cdp_host_port(cdp_url: str) -> tuple[str, int]:
    base = normalize_cdp_url(cdp_url)
    parsed = urllib.parse.urlparse(base)
    host = parsed.hostname or "127.0.0.1"
    if parsed.port:
        return host, parsed.port
    return host, (443 if parsed.scheme == "https" else 80)


def is_cdp_reachable(cdp_url: str, timeout: float) -> bool:
    base = normalize_cdp_url(cdp_url)
    try:
        res = requests.get(f"{base}/json", timeout=max(1.0, timeout))
        if res.status_code != 200:
            return False
        return isinstance(res.json(), list)
    except Exception:
        return False


def wait_for_cdp(cdp_url: str, wait_seconds: float) -> bool:
    end = time.time() + max(1.0, wait_seconds)
    while time.time() < end:
        if is_cdp_reachable(cdp_url, timeout=1.5):
            return True
        time.sleep(0.35)
    return False


def find_edge_executable() -> str | None:
    candidates = [
        shutil.which("msedge"),
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def default_edge_cdp_user_data_dir() -> str:
    local = os.environ.get("LOCALAPPDATA", "").strip()
    if local:
        return os.path.join(local, "twitdelete-edge-cdp-profile")
    return os.path.join(os.getcwd(), "twitdelete-edge-cdp-profile")


def auto_open_edge_cdp(
    cdp_url: str,
    *,
    user_data_dir: str,
    wait_seconds: float,
    target_url: str = "https://x.com/home",
) -> tuple[str, str]:
    host, port = cdp_host_port(cdp_url)
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError(f"Auto-open supports local CDP host only: {host}")

    edge_exe = find_edge_executable()
    if not edge_exe:
        raise ValueError("Could not find Edge executable (msedge.exe)")

    profile_dir = user_data_dir.strip() if user_data_dir.strip() else default_edge_cdp_user_data_dir()
    os.makedirs(profile_dir, exist_ok=True)

    cmd = [
        edge_exe,
        f"--remote-debugging-port={port}",
        "--remote-allow-origins=*",
        f"--user-data-dir={profile_dir}",
        target_url,
    ]
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:
        raise ValueError(f"Failed to launch Edge CDP window: {exc}") from exc

    if not wait_for_cdp(cdp_url, wait_seconds=wait_seconds):
        raise ValueError(f"CDP endpoint did not open in time ({wait_seconds:.0f}s): {normalize_cdp_url(cdp_url)}")
    return edge_exe, profile_dir


def should_auto_open_cdp(exc: Exception, browser: str) -> bool:
    # Only auto-open for Edge path (or auto mode which prefers Edge).
    if browser not in {"auto", "edge"}:
        return False
    msg = str(exc)
    hints = [
        "Cannot connect to CDP endpoint",
        "Failed to establish a new connection",
        "Max retries exceeded",
        "connection refused",
        "WinError 10061",
    ]
    return any(h.lower() in msg.lower() for h in hints)


def pick_cdp_target(targets: list[dict[str, Any]]) -> dict[str, Any]:
    with_ws = [t for t in targets if isinstance(t, dict) and isinstance(t.get("webSocketDebuggerUrl"), str)]
    if not with_ws:
        raise ValueError("No debuggable CDP targets found")

    preferred = [
        t for t in with_ws if "x.com" in str(t.get("url", "")).lower() or "twitter.com" in str(t.get("url", "")).lower()
    ]
    return preferred[0] if preferred else with_ws[0]


def load_transaction_id_from_cdp(
    cdp_url: str,
    timeout: float,
    *,
    target_url: str = "https://x.com/home",
    operation_name: str | None = None,
) -> tuple[str, str]:
    try:
        import websocket
    except Exception as exc:
        raise ValueError("websocket-client is required for --cdp-url") from exc

    base = normalize_cdp_url(cdp_url)
    try:
        targets_resp = requests.get(f"{base}/json", timeout=timeout)
        targets_resp.raise_for_status()
        targets = targets_resp.json()
    except Exception as exc:
        raise ValueError(f"Cannot connect to CDP endpoint {base}: {exc}") from exc

    if not isinstance(targets, list):
        raise ValueError("Invalid CDP /json response")

    encoded_target = urllib.parse.quote(target_url, safe=":/?&=%")
    try:
        created = requests.put(f"{base}/json/new?{encoded_target}", timeout=timeout)
        created.raise_for_status()
        target = created.json()
    except Exception:
        # Fallback to existing target when /json/new is blocked.
        target = pick_cdp_target(targets)

    ws_url = target.get("webSocketDebuggerUrl")
    if not isinstance(ws_url, str) or not ws_url:
        raise ValueError("Selected CDP target has no webSocketDebuggerUrl")

    ws = websocket.create_connection(ws_url, timeout=timeout, suppress_origin=True)
    msg_id = 0

    def send(method: str, params: dict[str, Any] | None = None) -> None:
        nonlocal msg_id
        msg_id += 1
        ws.send(json.dumps({"id": msg_id, "method": method, "params": params or {}}))

    try:
        send("Network.enable")
        send("Page.enable")
        send("Page.navigate", {"url": target_url})
        end = time.time() + max(5.0, min(timeout, 20.0))
        while time.time() < end:
            raw = ws.recv()
            if not isinstance(raw, str):
                continue
            try:
                obj = json.loads(raw)
            except ValueError:
                continue
            if obj.get("method") != "Network.requestWillBeSent":
                continue
            req = (obj.get("params") or {}).get("request") or {}
            url = req.get("url", "")
            if "/i/api/graphql/" not in url:
                continue
            if operation_name and f"/{operation_name}?" not in url:
                continue
            headers = req.get("headers") or {}
            xctid = headers.get("x-client-transaction-id")
            xlang = headers.get("x-twitter-client-language")
            if isinstance(xctid, str) and xctid.strip():
                return xctid.strip(), (xlang.strip() if isinstance(xlang, str) and xlang.strip() else "en")
    finally:
        ws.close()

    op_msg = f" for operation {operation_name}" if operation_name else ""
    raise ValueError(f"Could not capture x-client-transaction-id{op_msg} from CDP network events")


def load_auth_from_cdp(cdp_url: str, timeout: float) -> tuple[str, str, str]:
    try:
        import websocket
    except Exception as exc:
        raise ValueError("websocket-client is required for --cdp-url") from exc

    base = normalize_cdp_url(cdp_url)
    try:
        targets_resp = requests.get(f"{base}/json", timeout=timeout)
        targets_resp.raise_for_status()
        targets = targets_resp.json()
    except Exception as exc:
        raise ValueError(f"Cannot connect to CDP endpoint {base}: {exc}") from exc

    if not isinstance(targets, list):
        raise ValueError("Invalid CDP /json response")

    target = pick_cdp_target(targets)
    ws_url = target.get("webSocketDebuggerUrl")
    if not isinstance(ws_url, str) or not ws_url:
        raise ValueError("Selected CDP target has no webSocketDebuggerUrl")

    # Chromium/Brave may reject unknown Origin for CDP websocket.
    # Suppress Origin header to avoid 403 without forcing remote-allow-origins.
    ws = websocket.create_connection(ws_url, timeout=timeout, suppress_origin=True)
    try:
        ws.send(json.dumps({"id": 1, "method": "Network.getAllCookies"}))
        response_obj: dict[str, Any] | None = None
        for _ in range(50):
            raw = ws.recv()
            if not isinstance(raw, str):
                continue
            try:
                obj = json.loads(raw)
            except ValueError:
                continue
            if obj.get("id") == 1:
                response_obj = obj
                break
        if response_obj is None:
            raise ValueError("Timeout waiting for Network.getAllCookies response")
    finally:
        ws.close()

    result = response_obj.get("result") if isinstance(response_obj, dict) else None
    cookies = result.get("cookies") if isinstance(result, dict) else None
    if not isinstance(cookies, list):
        raise ValueError("CDP response does not contain cookies")

    cookie_map: dict[str, str] = {}
    for c in cookies:
        if not isinstance(c, dict):
            continue
        domain = str(c.get("domain", "")).lower().lstrip(".")
        if not (domain.endswith("x.com") or domain.endswith("twitter.com")):
            continue
        name = c.get("name")
        value = c.get("value")
        if isinstance(name, str) and isinstance(value, str) and name and value:
            cookie_map[name] = value

    auth_token = cookie_map.get("auth_token")
    ct0 = cookie_map.get("ct0")
    if not auth_token or not ct0:
        raise ValueError("auth_token/ct0 not found in CDP cookies; open x.com in that browser first")

    cookie_header = "; ".join(f"{k}={v}" for k, v in cookie_map.items())
    return cookie_header, ct0, base


def load_auth(args: argparse.Namespace) -> AuthConfig:
    file_values: dict[str, str] = {}
    if os.path.exists(args.auth_file):
        with open(args.auth_file, encoding="utf-8") as fp:
            data = json.load(fp)
        if isinstance(data, dict):
            file_values = {k: str(v) for k, v in data.items() if v is not None}

    cookie = args.cookie or os.getenv("TWITDELETE_COOKIE") or file_values.get("cookie", "")
    csrf = args.csrf_token or os.getenv("TWITDELETE_CSRF_TOKEN") or file_values.get("csrf_token", "")
    bearer = args.bearer_token or os.getenv("TWITDELETE_BEARER_TOKEN") or file_values.get("bearer_token") or DEFAULT_BEARER_TOKEN
    ua = args.user_agent or file_values.get("user_agent") or "Mozilla/5.0"
    xctid = (
        args.x_client_transaction_id
        or os.getenv("TWITDELETE_X_CLIENT_TRANSACTION_ID")
        or file_values.get("x_client_transaction_id", "")
    )
    xlang = (
        args.client_language
        or os.getenv("TWITDELETE_CLIENT_LANGUAGE")
        or file_values.get("client_language")
        or "en"
    )

    if args.auto_auth and (not cookie or not csrf):
        auth_errors: list[str] = []

        # If CDP is provided, prefer it first because Brave cookie decryption
        # can fail on recent Chromium builds.
        if args.cdp_url:
            try:
                auto_cookie, auto_csrf, source = load_auth_from_cdp(args.cdp_url, args.timeout)
                if not cookie:
                    cookie = auto_cookie
                if not csrf:
                    csrf = auto_csrf
                print(f"[INFO] Auto auth loaded via CDP: {source}")
            except Exception as exc:
                latest_cdp_exc: Exception = exc
                if not args.no_auto_open_cdp and should_auto_open_cdp(exc, args.browser):
                    try:
                        edge_exe, profile_dir = auto_open_edge_cdp(
                            args.cdp_url,
                            user_data_dir=args.cdp_user_data_dir,
                            wait_seconds=args.cdp_open_wait,
                            target_url="https://x.com/home",
                        )
                        print(
                            f"[INFO] CDP endpoint unavailable. Auto-opened Edge CDP window: {edge_exe} "
                            f"(profile: {profile_dir})"
                        )
                        auto_cookie, auto_csrf, source = load_auth_from_cdp(args.cdp_url, args.timeout)
                        if not cookie:
                            cookie = auto_cookie
                        if not csrf:
                            csrf = auto_csrf
                        print(f"[INFO] Auto auth loaded via CDP: {source}")
                        latest_cdp_exc = None  # type: ignore[assignment]
                    except Exception as auto_exc:
                        latest_cdp_exc = ValueError(f"{exc} | auto-open failed: {auto_exc}")
                if latest_cdp_exc is not None:
                    auth_errors.append(f"CDP: {latest_cdp_exc}")

        if not cookie or not csrf:
            try:
                auto_cookie, auto_csrf, bname = load_auth_from_browser(args.browser)
                if not cookie:
                    cookie = auto_cookie
                if not csrf:
                    csrf = auto_csrf
                print(f"[INFO] Auto auth loaded from browser: {bname}")
            except Exception as exc:
                auth_errors.append(f"browser-cookie3: {exc}")

        if (not cookie or not csrf) and auth_errors:
            raise ValueError(" | ".join(auth_errors))

    # Some GraphQL endpoints (notably UserTweetsAndReplies) may return 404
    # unless this header is present.
    if not xctid and args.cdp_url:
        try:
            auto_xctid, auto_lang = load_transaction_id_from_cdp(args.cdp_url, args.timeout)
            xctid = auto_xctid
            if not args.client_language and not file_values.get("client_language"):
                xlang = auto_lang
            print("[INFO] Captured x-client-transaction-id via CDP")
        except Exception as exc:
            print(f"[WARN] Could not capture x-client-transaction-id: {exc}")

    if not cookie:
        raise ValueError("Missing cookie")
    if not csrf:
        raise ValueError("Missing csrf_token")

    return AuthConfig(
        cookie=cookie.strip(),
        csrf_token=csrf.strip(),
        bearer_token=bearer.strip(),
        user_agent=ua.strip(),
        x_client_transaction_id=xctid.strip() if xctid else None,
        x_twitter_client_language=xlang.strip() if xlang else None,
    )


def build_x_headers(auth: AuthConfig) -> dict[str, str]:
    headers = {
        "accept": "*/*",
        "authorization": f"Bearer {auth.bearer_token}",
        "cookie": auth.cookie,
        "origin": "https://x.com",
        "referer": "https://x.com/home",
        "user-agent": auth.user_agent,
        "x-csrf-token": auth.csrf_token,
        "x-twitter-active-user": "yes",
        "x-twitter-auth-type": "OAuth2Session",
    }
    if auth.x_client_transaction_id:
        headers["x-client-transaction-id"] = auth.x_client_transaction_id
    if auth.x_twitter_client_language:
        headers["x-twitter-client-language"] = auth.x_twitter_client_language
    return headers

def parse_js_string_list(raw: str) -> list[str]:
    return re.findall(r'"([^"\\]+)"', raw)


def fetch_main_js_text(session: requests.Session, timeout: float) -> str:
    html = session.get("https://x.com/home", timeout=timeout)
    html.raise_for_status()
    m = MAIN_JS_URL_RE.search(html.text)
    if not m:
        raise ValueError("Could not find X main JS")
    js = session.get(m.group(0), timeout=timeout)
    js.raise_for_status()
    return js.text


def extract_operation(js_text: str, name: str) -> GraphQLOperation | None:
    full = re.compile(
        rf'queryId:"(?P<qid>[^"]+)",operationName:"{re.escape(name)}",'
        r'operationType:"[^"]+",metadata:\{featureSwitches:\[(?P<fs>[^\]]*)\],fieldToggles:\[(?P<ft>[^\]]*)\]\}'
    )
    m = full.search(js_text)
    if m:
        return GraphQLOperation(
            name=name,
            query_id=m.group("qid"),
            feature_switches=parse_js_string_list(m.group("fs")),
            field_toggles=parse_js_string_list(m.group("ft")),
        )

    fallback = re.compile(rf'queryId:"(?P<qid>[^"]+)",operationName:"{re.escape(name)}"')
    m2 = fallback.search(js_text)
    if m2:
        return GraphQLOperation(name=name, query_id=m2.group("qid"), feature_switches=[], field_toggles=[])
    return None


def discover_graphql_operations(
    session: requests.Session,
    timeout: float,
    required: list[str],
    optional: list[str] | None = None,
) -> dict[str, GraphQLOperation]:
    optional = optional or []
    js = fetch_main_js_text(session, timeout)
    names = []
    for n in required + optional:
        if n not in names:
            names.append(n)

    out: dict[str, GraphQLOperation] = {}
    for n in names:
        op = extract_operation(js, n)
        if op:
            out[n] = op

    missing = [n for n in required if n not in out]
    if missing:
        raise ValueError("Missing GraphQL operations: " + ", ".join(missing))
    return out


def graphql_get(
    session: requests.Session,
    auth: AuthConfig,
    op: GraphQLOperation,
    variables: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    url = f"https://x.com/i/api/graphql/{op.query_id}/{op.name}"
    params = {
        "variables": json.dumps(variables, separators=(",", ":")),
        "features": json.dumps({k: True for k in op.feature_switches}, separators=(",", ":")),
        "fieldToggles": json.dumps({k: True for k in op.field_toggles}, separators=(",", ":")),
    }
    res = session.get(url, headers=build_x_headers(auth), params=params, timeout=timeout)
    preview = res.text[:260].replace("\n", " ")
    if res.status_code != 200:
        raise ValueError(f"GraphQL {op.name} HTTP {res.status_code}: {preview}")
    try:
        payload = res.json()
    except ValueError as exc:
        raise ValueError(f"GraphQL {op.name} invalid JSON: {preview}") from exc
    if payload.get("errors"):
        raise ValueError(f"GraphQL {op.name} errors: {payload['errors']}")
    return payload


def extract_http_status_from_error(exc: Exception) -> int | None:
    m = re.search(r"\bHTTP (\d{3})\b", str(exc))
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def extract_user(node: Any) -> tuple[str, str] | None:
    if isinstance(node, dict):
        rid = coerce_tweet_id(node.get("rest_id"))
        legacy = node.get("legacy") if isinstance(node.get("legacy"), dict) else {}
        core = node.get("core") if isinstance(node.get("core"), dict) else {}
        sn = legacy.get("screen_name") if isinstance(legacy.get("screen_name"), str) else None
        if sn is None and isinstance(core.get("screen_name"), str):
            sn = core.get("screen_name")
        if rid and sn:
            return rid, sn
        for k in ("result", "user_results", "viewer", "data"):
            if k in node:
                got = extract_user(node.get(k))
                if got:
                    return got
        for v in node.values():
            got = extract_user(v)
            if got:
                return got
    if isinstance(node, list):
        for item in node:
            got = extract_user(item)
            if got:
                return got
    return None


def unwrap_result(node: Any) -> dict[str, Any] | None:
    cur = node
    while isinstance(cur, dict):
        if isinstance(cur.get("result"), dict):
            cur = cur["result"]
            continue
        if cur.get("__typename") == "TweetWithVisibilityResults" and isinstance(cur.get("tweet"), dict):
            cur = cur["tweet"]
            continue
        return cur
    return None


def parse_tweet(node: Any) -> TweetMeta | None:
    t = unwrap_result(node)
    if not isinstance(t, dict):
        return None
    if t.get("__typename") in {"TweetTombstone", "TweetUnavailable"}:
        return None

    tid = coerce_tweet_id(t.get("rest_id"))
    if not tid:
        return None

    legacy = t.get("legacy") if isinstance(t.get("legacy"), dict) else {}
    text = legacy.get("full_text") if isinstance(legacy.get("full_text"), str) else None
    if text is None and isinstance(legacy.get("text"), str):
        text = legacy.get("text")
    created = parse_twitter_created_at(legacy.get("created_at"))
    has_media = tweet_legacy_has_media(legacy)
    conversation_id = coerce_tweet_id(legacy.get("conversation_id_str"))

    author = None
    author_id = coerce_tweet_id(legacy.get("user_id_str"))
    core = t.get("core") if isinstance(t.get("core"), dict) else {}
    user_results = core.get("user_results") if isinstance(core.get("user_results"), dict) else {}
    ur = unwrap_result(user_results)
    if isinstance(ur, dict):
        author_id = coerce_tweet_id(ur.get("rest_id")) or author_id
        ulegacy = ur.get("legacy") if isinstance(ur.get("legacy"), dict) else {}
        ucore = ur.get("core") if isinstance(ur.get("core"), dict) else {}
        if isinstance(ulegacy.get("screen_name"), str):
            author = ulegacy.get("screen_name")
        elif isinstance(ucore.get("screen_name"), str):
            author = ucore.get("screen_name")

    return TweetMeta(
        tweet_id=tid,
        author=author,
        author_id=author_id,
        text=text,
        created_ts=created,
        has_media=has_media,
        conversation_id=conversation_id,
    )


def extract_tweets(payload: dict[str, Any], viewer_id: str, viewer_name: str) -> list[TweetMeta]:
    out: dict[str, TweetMeta] = {}

    def consider(node: Any) -> None:
        m = parse_tweet(node)
        if not m:
            return
        owner = (m.author_id == viewer_id) or (m.author and m.author.lower() == viewer_name.lower())
        if owner and m.tweet_id not in out:
            out[m.tweet_id] = m

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            consider(node)
            tr = node.get("tweet_results")
            if isinstance(tr, dict):
                consider(tr)
                if isinstance(tr.get("result"), dict):
                    consider(tr["result"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for it in node:
                walk(it)

    walk(payload)
    return list(out.values())


def build_tweet_detail_variables(tweet_id: str) -> dict[str, Any]:
    return {
        "focalTweetId": tweet_id,
        "referrer": "profile",
        "with_rux_injections": False,
        "includePromotedContent": True,
        "withCommunity": True,
        "withQuickPromoteEligibilityTweetFields": True,
        "withBirdwatchNotes": True,
        "withVoice": True,
    }


def load_media_conversation_tweets(
    session: requests.Session,
    auth: AuthConfig,
    op_tweet_detail: GraphQLOperation,
    *,
    media_tweet: TweetMeta,
    viewer_id: str,
    viewer_name: str,
    timeout: float,
) -> list[TweetMeta]:
    payload = graphql_get(
        session,
        auth,
        op_tweet_detail,
        variables=build_tweet_detail_variables(media_tweet.tweet_id),
        timeout=timeout,
    )
    out: list[TweetMeta] = []
    for t in extract_tweets(payload, viewer_id, viewer_name):
        if t.tweet_id == media_tweet.tweet_id:
            continue
        # Keep only tweets in the same conversation to mirror "below conversation history".
        if media_tweet.conversation_id and t.conversation_id and t.conversation_id != media_tweet.conversation_id:
            continue
        out.append(t)
    return out


def extract_bottom_cursor(payload: dict[str, Any]) -> str | None:
    vals: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("cursorType") == "Bottom" and isinstance(node.get("value"), str) and node.get("value"):
                vals.append(node["value"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for it in node:
                walk(it)

    walk(payload)
    return vals[0] if vals else None

def should_delete(
    m: TweetMeta,
    before_ts: int | None,
    after_ts: int | None,
    contains: str | None,
    author: str | None,
) -> tuple[bool, str]:
    if author:
        if not m.author:
            return False, "missing author"
        if m.author.lower() != author.lower():
            return False, f"author mismatch ({m.author})"

    if contains:
        if not m.text:
            return False, "missing text"
        if contains.lower() not in m.text.lower():
            return False, "contains mismatch"

    if before_ts is not None:
        if m.created_ts is None:
            return False, "missing created timestamp"
        if m.created_ts >= before_ts:
            return False, "before mismatch"

    if after_ts is not None:
        if m.created_ts is None:
            return False, "missing created timestamp"
        if m.created_ts < after_ts:
            return False, "after mismatch"

    return True, "match"


def format_ts(ts: int | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_retry_after_seconds(headers: requests.structures.CaseInsensitiveDict) -> float | None:
    retry_after = headers.get("Retry-After")
    if retry_after:
        value = retry_after.strip()
        if value.isdigit():
            seconds = float(value)
            if seconds > 0:
                return seconds
        else:
            try:
                dt = email.utils.parsedate_to_datetime(value)
                if dt is not None:
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    seconds = (dt - datetime.now(timezone.utc)).total_seconds()
                    if seconds > 0:
                        return seconds
            except Exception:
                pass

    reset = headers.get("x-rate-limit-reset")
    if reset:
        try:
            reset_ts = float(reset.strip())
            seconds = reset_ts - time.time() + 1.0
            if seconds > 0:
                return seconds
        except Exception:
            pass

    return None


def delete_tweet(
    session: requests.Session,
    auth: AuthConfig,
    tweet_id: str,
    delete_query_id: str,
    timeout: float,
) -> DeleteResult:
    url = f"https://x.com/i/api/graphql/{delete_query_id}/DeleteTweet"
    headers = build_x_headers(auth)
    headers["content-type"] = "application/json"
    payload = {
        "variables": {"tweet_id": tweet_id, "dark_request": False},
        "queryId": delete_query_id,
    }

    try:
        res = session.post(url, headers=headers, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        return DeleteResult(False, f"REQUEST_ERROR: {exc}")

    preview = res.text[:260].replace("\n", " ")
    if res.status_code != 200:
        return DeleteResult(
            False,
            f"HTTP {res.status_code}: {preview}",
            status_code=res.status_code,
            retry_after_seconds=parse_retry_after_seconds(res.headers),
        )

    try:
        body = res.json()
    except ValueError:
        return DeleteResult(False, f"INVALID_JSON: {preview}")

    if body.get("errors"):
        return DeleteResult(False, f"API_ERRORS: {body['errors']}")

    data = body.get("data")
    if not isinstance(data, dict) or data.get("delete_tweet") is None:
        return DeleteResult(False, f"UNKNOWN_RESPONSE: {body}")

    return DeleteResult(True, "Deleted", status_code=200)


def delete_tweet_with_rate_limit_retry(
    session: requests.Session,
    auth: AuthConfig,
    tweet_id: str,
    delete_query_id: str,
    timeout: float,
    *,
    rate_limit_mode: str,
    rate_limit_retries: int,
    rate_limit_wait: float,
    rate_limit_max_wait: float,
) -> DeleteResult:
    attempt = 0
    max_retries = max(0, rate_limit_retries)

    while True:
        result = delete_tweet(
            session=session,
            auth=auth,
            tweet_id=tweet_id,
            delete_query_id=delete_query_id,
            timeout=timeout,
        )
        if result.success:
            return result

        if result.status_code != 429:
            return result

        if rate_limit_mode == "stop":
            return DeleteResult(
                False,
                f"HTTP 429 rate limited (mode=stop): {result.message}",
                status_code=429,
                retry_after_seconds=result.retry_after_seconds,
            )

        if attempt >= max_retries:
            return DeleteResult(
                False,
                f"HTTP 429 retries exceeded ({max_retries})",
                status_code=429,
                retry_after_seconds=result.retry_after_seconds,
            )

        wait_seconds = result.retry_after_seconds if result.retry_after_seconds else rate_limit_wait
        wait_seconds = max(1.0, min(wait_seconds, rate_limit_max_wait))
        attempt += 1
        print(f"[WARN] Rate limited (429). Waiting {wait_seconds:.0f}s before retry {attempt}/{max_retries}.")
        time.sleep(wait_seconds)


def main() -> int:
    args = parse_args()

    before_ts = parse_utc_datetime(args.before) if args.before else None
    after_ts = parse_utc_datetime(args.after) if args.after else None
    if before_ts is not None and after_ts is not None and before_ts <= after_ts:
        print("[ERROR] --before must be later than --after", file=sys.stderr)
        return 2

    try:
        auth = load_auth(args)
    except Exception as exc:
        print(f"[ERROR] Failed to load auth: {exc}", file=sys.stderr)
        return 2

    session = requests.Session()

    optional_ops = ["DeleteTweet", "UserTweetsAndReplies", "UserMedia", "TweetDetail"]

    try:
        ops = discover_graphql_operations(
            session,
            timeout=args.timeout,
            required=["Viewer", "UserTweets"],
            optional=optional_ops,
        )
    except Exception as exc:
        print(f"[ERROR] Failed to discover X operations: {exc}", file=sys.stderr)
        return 2

    if args.media_tab:
        if "UserMedia" in ops:
            timeline_name = "UserMedia"
        else:
            timeline_name = "UserTweets"
            print("[WARN] UserMedia operation not found. Falling back to UserTweets with media filter.")
    elif args.include_replies:
        if "UserTweetsAndReplies" in ops:
            timeline_name = "UserTweetsAndReplies"
        else:
            timeline_name = "UserTweets"
            print("[WARN] UserTweetsAndReplies operation not found. Falling back to UserTweets.")
    else:
        timeline_name = "UserTweets"

    try:
        viewer_payload = graphql_get(session, auth, ops["Viewer"], variables={}, timeout=args.timeout)
    except Exception as exc:
        print(f"[ERROR] Failed to load viewer info: {exc}", file=sys.stderr)
        return 2

    viewer = extract_user(viewer_payload)
    if not viewer:
        print("[ERROR] Could not parse logged-in user", file=sys.stderr)
        return 2
    viewer_id, viewer_name = viewer
    print(f"[INFO] Logged-in user: @{viewer_name} ({viewer_id})")

    if timeline_name == "UserTweetsAndReplies" and args.cdp_url:
        try:
            op_xctid, op_lang = load_transaction_id_from_cdp(
                args.cdp_url,
                args.timeout,
                target_url=f"https://x.com/{viewer_name}/with_replies",
                operation_name="UserTweetsAndReplies",
            )
            auth.x_client_transaction_id = op_xctid
            if not args.client_language:
                auth.x_twitter_client_language = op_lang
            print("[INFO] Captured UserTweetsAndReplies transaction id via CDP")
        except Exception as exc:
            print(f"[WARN] Could not capture UserTweetsAndReplies transaction id: {exc}")

    if args.media_tab and timeline_name == "UserMedia" and args.cdp_url:
        try:
            op_xctid, op_lang = load_transaction_id_from_cdp(
                args.cdp_url,
                args.timeout,
                target_url=f"https://x.com/{viewer_name}/media",
                operation_name="UserMedia",
            )
            auth.x_client_transaction_id = op_xctid
            if not args.client_language:
                auth.x_twitter_client_language = op_lang
            print("[INFO] Captured UserMedia transaction id via CDP")
        except Exception as exc:
            print(f"[WARN] Could not capture UserMedia transaction id: {exc}")

    if args.author:
        print(f"[INFO] Filter author: {args.author}")
    if args.contains:
        print(f"[INFO] Filter contains: {args.contains}")
    if before_ts is not None:
        print(f"[INFO] Filter before: {format_ts(before_ts)}")
    if after_ts is not None:
        print(f"[INFO] Filter after : {format_ts(after_ts)}")
    if args.media_tab:
        print("[INFO] Source: Media tab")
    if args.media_delete_conversation and not args.media_tab:
        print("[WARN] --media-delete-conversation requires --media-tab. Ignoring.")
    elif args.media_delete_conversation:
        print("[INFO] Media mode: include same-conversation tweets under media items")
    print(f"[INFO] Mode: {'DRY-RUN' if args.dry_run else 'DELETE'}")
    if args.delete_all:
        print(
            f"[INFO] Delete-all mode ON (pass_limit={'unlimited' if args.pass_limit <= 0 else args.pass_limit})"
        )
        print(f"[INFO] Batch limit per pass: {'unlimited' if args.batch_limit <= 0 else args.batch_limit}")

    delete_query_id = ops.get("DeleteTweet", GraphQLOperation("DeleteTweet", DEFAULT_DELETE_QUERY_ID, [], [])).query_id

    considered = 0
    matched = 0
    deleted = 0
    skipped = 0
    failed = 0

    page_size = max(1, min(args.timeline_page_size, 100))
    pages = max(1, args.timeline_pages)
    if args.batch_limit > 0 and page_size > args.batch_limit:
        print(
            f"[INFO] batch-limit ({args.batch_limit}) is lower than timeline-page-size ({page_size}); "
            f"per-pass seed fetch is capped by batch-limit."
        )

    media_filter_mode = args.media_tab

    def load_batch(limit: int) -> list[TweetMeta] | None:
        nonlocal timeline_name, media_filter_mode

        collected: list[TweetMeta] = []
        seen: set[str] = set()
        cursor: str | None = None

        for page in range(1, pages + 1):
            variables: dict[str, Any] = {
                "userId": viewer_id,
                "count": page_size,
                "includePromotedContent": False,
                "withVoice": True,
                "withV2Timeline": True,
            }
            if cursor:
                variables["cursor"] = cursor

            try:
                payload = graphql_get(session, auth, ops[timeline_name], variables=variables, timeout=args.timeout)
            except Exception as exc:
                latest_exc: Exception = exc
                status = extract_http_status_from_error(latest_exc)
                recovered = False

                is_replies_404 = (
                    args.include_replies
                    and timeline_name == "UserTweetsAndReplies"
                    and status == 404
                )
                is_media_404 = (
                    args.media_tab
                    and timeline_name == "UserMedia"
                    and status == 404
                )

                # Stale x-client-transaction-id can trigger 404 for UserTweetsAndReplies.
                # Refresh it from CDP and retry once before falling back.
                if is_replies_404 and args.cdp_url:
                    try:
                        op_xctid, op_lang = load_transaction_id_from_cdp(
                            args.cdp_url,
                            args.timeout,
                            target_url=f"https://x.com/{viewer_name}/with_replies",
                            operation_name="UserTweetsAndReplies",
                        )
                        auth.x_client_transaction_id = op_xctid
                        if not args.client_language:
                            auth.x_twitter_client_language = op_lang
                        print("[INFO] Refreshed UserTweetsAndReplies transaction id via CDP after 404")
                        payload = graphql_get(session, auth, ops[timeline_name], variables=variables, timeout=args.timeout)
                        recovered = True
                    except Exception as retry_exc:
                        latest_exc = retry_exc
                        status = extract_http_status_from_error(latest_exc)
                        print(f"[WARN] UserTweetsAndReplies retry after transaction-id refresh failed: {retry_exc}")

                if is_media_404 and args.cdp_url:
                    try:
                        op_xctid, op_lang = load_transaction_id_from_cdp(
                            args.cdp_url,
                            args.timeout,
                            target_url=f"https://x.com/{viewer_name}/media",
                            operation_name="UserMedia",
                        )
                        auth.x_client_transaction_id = op_xctid
                        if not args.client_language:
                            auth.x_twitter_client_language = op_lang
                        print("[INFO] Refreshed UserMedia transaction id via CDP after 404")
                        payload = graphql_get(session, auth, ops[timeline_name], variables=variables, timeout=args.timeout)
                        recovered = True
                    except Exception as retry_exc:
                        latest_exc = retry_exc
                        status = extract_http_status_from_error(latest_exc)
                        print(f"[WARN] UserMedia retry after transaction-id refresh failed: {retry_exc}")

                if (
                    not recovered
                    and args.include_replies
                    and timeline_name == "UserTweetsAndReplies"
                    and status == 404
                    and "UserTweets" in ops
                ):
                    timeline_name = "UserTweets"
                    print("[WARN] UserTweetsAndReplies unavailable (404). Falling back to UserTweets.")
                    try:
                        payload = graphql_get(
                            session, auth, ops[timeline_name], variables=variables, timeout=args.timeout
                        )
                        recovered = True
                    except Exception as exc2:
                        print(f"[ERROR] Failed to load timeline page {page}: {exc2}", file=sys.stderr)
                        return None

                if (
                    not recovered
                    and args.media_tab
                    and timeline_name == "UserMedia"
                    and status == 404
                    and "UserTweets" in ops
                ):
                    timeline_name = "UserTweets"
                    media_filter_mode = True
                    print("[WARN] UserMedia unavailable (404). Falling back to UserTweets with media filter.")
                    try:
                        payload = graphql_get(
                            session, auth, ops[timeline_name], variables=variables, timeout=args.timeout
                        )
                        recovered = True
                    except Exception as exc2:
                        print(f"[ERROR] Failed to load timeline page {page}: {exc2}", file=sys.stderr)
                        return None

                if not recovered:
                    print(f"[ERROR] Failed to load timeline page {page}: {latest_exc}", file=sys.stderr)
                    return None

            page_tweets = extract_tweets(payload, viewer_id, viewer_name)
            if media_filter_mode:
                page_tweets = [t for t in page_tweets if t.has_media]
            added = 0
            for m in page_tweets:
                if m.tweet_id in seen:
                    continue
                seen.add(m.tweet_id)
                collected.append(m)
                added += 1
                if limit > 0 and len(collected) >= limit:
                    break

            print(f"[INFO] Timeline page {page}: +{added} tweets (batch total {len(collected)})")
            if limit > 0 and len(collected) >= limit:
                break

            nxt = extract_bottom_cursor(payload)
            if not nxt or nxt == cursor:
                break
            cursor = nxt

        return collected

    pass_no = 0
    prev_batch_ids: list[str] = []

    while True:
        if args.pass_limit > 0 and pass_no >= args.pass_limit:
            print(f"[INFO] Reached pass limit: {args.pass_limit}")
            break

        pass_no += 1
        if args.max > 0:
            remaining = args.max - considered
            if remaining <= 0:
                print(f"[INFO] Reached max processed count: {args.max}")
                break
        else:
            remaining = 0

        if args.batch_limit > 0:
            if remaining > 0:
                batch_limit = min(remaining, args.batch_limit)
            else:
                batch_limit = args.batch_limit
        else:
            batch_limit = remaining

        seed_batch_limit = batch_limit
        if args.media_tab and args.media_delete_conversation and batch_limit > 0:
            # Keep room for conversation-expansion tweets while respecting total batch cap.
            seed_batch_limit = max(1, batch_limit // 2)
            print(
                f"[INFO] Media conversation mode: seed batch limit {seed_batch_limit} "
                f"(total cap {batch_limit})"
            )

        print(f"[INFO] Starting pass {pass_no}")
        collected = load_batch(seed_batch_limit)
        if collected is None:
            return 2
        if not collected:
            if pass_no == 1:
                print("[ERROR] No visible tweets found from timeline", file=sys.stderr)
                return 2
            print("[INFO] No more visible tweets found. Stopping.")
            break

        if args.media_tab and args.media_delete_conversation:
            if "TweetDetail" not in ops:
                print("[WARN] TweetDetail operation not found. Skipping media conversation expansion.")
            else:
                extra_cap: int | None = None
                if batch_limit > 0:
                    extra_cap = max(0, batch_limit - len(collected))
                if args.max > 0:
                    max_cap = max(0, args.max - considered - len(collected))
                    extra_cap = min(extra_cap, max_cap) if extra_cap is not None else max_cap

                if extra_cap is not None and extra_cap <= 0:
                    print("[INFO] Media conversation expansion skipped: no remaining capacity in this pass.")

                batch_seen = {m.tweet_id for m in collected}
                seed_media = [m for m in collected if m.has_media]
                extras: list[TweetMeta] = []
                for idx, media_tweet in enumerate(seed_media, start=1):
                    if extra_cap is not None and len(extras) >= extra_cap:
                        break
                    try:
                        related = load_media_conversation_tweets(
                            session,
                            auth,
                            ops["TweetDetail"],
                            media_tweet=media_tweet,
                            viewer_id=viewer_id,
                            viewer_name=viewer_name,
                            timeout=args.timeout,
                        )
                    except Exception as exc:
                        print(f"[WARN] Media conversation load failed ({idx}/{len(seed_media)}): {exc}")
                        continue

                    added_related = 0
                    for t in related:
                        if extra_cap is not None and len(extras) >= extra_cap:
                            break
                        if t.tweet_id in batch_seen:
                            continue
                        batch_seen.add(t.tweet_id)
                        extras.append(t)
                        added_related += 1
                    if added_related > 0:
                        print(
                            f"[INFO] Media conversation {idx}/{len(seed_media)}: +{added_related} own tweets"
                        )

                if extras:
                    collected.extend(extras)
                    print(f"[INFO] Media conversation expansion: +{len(extras)} tweets (batch total {len(collected)})")

        total = len(collected)
        batch_deleted = 0
        batch_ids = [m.tweet_id for m in collected]
        stop_due_rate_limit = False

        for i, m in enumerate(collected, start=1):
            considered += 1
            ok, reason = should_delete(
                m,
                before_ts=before_ts,
                after_ts=after_ts,
                contains=args.contains,
                author=args.author,
            )
            if not ok:
                skipped += 1
                print(f"[SKIP P{pass_no} {i}/{total}] {m.tweet_id} | {reason}")
                continue

            matched += 1
            author_text = m.author or "-"
            created_text = format_ts(m.created_ts)

            if args.dry_run:
                print(
                    f"[CANDIDATE P{pass_no} {i}/{total}] {m.tweet_id} | @{author_text} | {created_text}"
                )
                continue

            result = delete_tweet_with_rate_limit_retry(
                session=session,
                auth=auth,
                tweet_id=m.tweet_id,
                delete_query_id=delete_query_id,
                timeout=args.timeout,
                rate_limit_mode=args.rate_limit_mode,
                rate_limit_retries=args.rate_limit_retries,
                rate_limit_wait=args.rate_limit_wait,
                rate_limit_max_wait=args.rate_limit_max_wait,
            )
            if result.success:
                deleted += 1
                batch_deleted += 1
                print(f"[DELETED P{pass_no} {i}/{total}] {m.tweet_id} | @{author_text} | {created_text}")
            else:
                failed += 1
                print(f"[FAILED P{pass_no} {i}/{total}] {m.tweet_id} | {result.message}")

                # Stop current run early when delete API is still rate-limited
                # after retries. Continuing would just spam more 429 errors.
                if result.status_code == 429 and args.rate_limit_mode == "wait":
                    print("[WARN] Persistent 429 after retries. Stopping current run.")
                    stop_due_rate_limit = True
                    break

            if args.delay > 0:
                time.sleep(args.delay)

        if stop_due_rate_limit:
            break

        if args.dry_run:
            if args.delete_all:
                print("[INFO] Dry-run mode: stopping after first pass.")
            break

        if not args.delete_all:
            break

        if batch_deleted <= 0:
            if batch_ids == prev_batch_ids:
                print("[WARN] No progress in repeated batch. Stopping delete-all loop.")
            else:
                print("[WARN] No deletions in this pass. Stopping delete-all loop.")
            break

        prev_batch_ids = batch_ids
        if args.pass_delay > 0:
            time.sleep(args.pass_delay)

    print("\n========== SUMMARY ==========")
    print(f"considered : {considered}")
    print(f"matched    : {matched}")
    print(f"deleted    : {deleted}")
    print(f"skipped    : {skipped}")
    print(f"failed     : {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
