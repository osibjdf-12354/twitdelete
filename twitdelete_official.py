#!/usr/bin/env python3
"""Bulk delete your own posts via official X API v2.

Requirements:
- OAuth user access token with scopes: tweet.read, tweet.write, users.read

References:
- GET /2/users/me
- GET /2/users/{id}/tweets
- DELETE /2/tweets/{id}
"""

from __future__ import annotations

import argparse
import email.utils
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import requests

API_BASE = "https://api.x.com/2"


@dataclass
class AuthConfig:
    access_token: str


@dataclass
class TweetMeta:
    tweet_id: str
    text: str | None
    created_ts: int | None
    author_id: str | None
    author_username: str | None
    is_reply: bool
    is_retweet: bool


@dataclass
class HttpResult:
    ok: bool
    status_code: int | None
    message: str
    payload: dict[str, Any] | None = None
    retry_after_seconds: float | None = None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Delete your own posts via official X API v2.")
    p.add_argument("--access-token", help="OAuth user access token (Bearer).")
    p.add_argument("--auth-file", default="auth.json", help="Path to auth file (default: auth.json).")
    p.add_argument(
        "--timeline-pages",
        type=int,
        default=8,
        help="Pages per pass for /2/users/{id}/tweets (default: 8).",
    )
    p.add_argument(
        "--timeline-page-size",
        type=int,
        default=100,
        help="Max results per page (5..100, default: 100).",
    )
    p.add_argument(
        "--include-replies",
        action="store_true",
        help="Include replies. By default replies are excluded.",
    )
    p.add_argument(
        "--exclude-retweets",
        action="store_true",
        help="Exclude retweets from listing.",
    )
    p.add_argument("--max", type=int, default=0, help="Max posts to process (0 = all).")
    p.add_argument(
        "--delete-all",
        action="store_true",
        help="Repeat fetch/delete passes until no more visible posts are found.",
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
    p.add_argument("--before", help="Delete only older than this UTC datetime, e.g. 2024-01-01")
    p.add_argument("--after", help="Delete only newer/equal than this UTC datetime, e.g. 2023-01-01")
    p.add_argument("--contains", help="Delete only when text contains this substring.")
    p.add_argument("--author", help="Delete only when author username matches this value.")
    p.add_argument("--delay", type=float, default=0.8, help="Seconds between delete calls.")
    p.add_argument(
        "--rate-limit-mode",
        default="wait",
        choices=["wait", "stop"],
        help="How to handle HTTP 429 (default: wait).",
    )
    p.add_argument(
        "--rate-limit-retries",
        type=int,
        default=20,
        help="Max retry attempts per request on 429 (default: 20).",
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
        help="Cap wait seconds for each 429 retry (default: 900).",
    )
    p.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout seconds.")
    p.add_argument("--dry-run", action="store_true", help="Print candidates only, do not delete.")
    return p.parse_args()


def parse_utc_datetime(raw: str) -> int:
    text = raw.strip()
    if "T" in text:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return int(dt.timestamp())
    return int(datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp())


def parse_api_datetime(raw: Any) -> int | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return int(dt.timestamp())


def to_api_datetime(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


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


def preview_response(resp: requests.Response) -> str:
    return resp.text[:260].replace("\n", " ")


def build_headers(auth: AuthConfig) -> dict[str, str]:
    return {
        "accept": "application/json",
        "authorization": f"Bearer {auth.access_token}",
        "content-type": "application/json",
    }


def request_with_rate_limit_retry(
    session: requests.Session,
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    timeout: float,
    label: str,
    mode: str,
    retries: int,
    wait_seconds: float,
    max_wait: float,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> HttpResult:
    attempt = 0
    max_retries = max(0, retries)

    while True:
        try:
            resp = session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=timeout,
            )
        except requests.RequestException as exc:
            return HttpResult(False, None, f"REQUEST_ERROR: {exc}")

        retry_after = parse_retry_after_seconds(resp.headers)
        if resp.status_code == 429:
            if mode == "stop":
                return HttpResult(
                    False,
                    429,
                    f"{label} HTTP 429 rate limited (mode=stop)",
                    retry_after_seconds=retry_after,
                )
            if attempt >= max_retries:
                return HttpResult(
                    False,
                    429,
                    f"{label} HTTP 429 retries exceeded ({max_retries})",
                    retry_after_seconds=retry_after,
                )

            wait_for = retry_after if retry_after else wait_seconds
            wait_for = max(1.0, min(wait_for, max_wait))
            attempt += 1
            print(f"[WARN] {label} rate limited (429). Waiting {wait_for:.0f}s before retry {attempt}/{max_retries}.")
            time.sleep(wait_for)
            continue

        payload: dict[str, Any] | None = None
        try:
            payload_obj = resp.json()
            if isinstance(payload_obj, dict):
                payload = payload_obj
        except ValueError:
            payload = None

        if 200 <= resp.status_code < 300:
            return HttpResult(True, resp.status_code, "OK", payload=payload)

        return HttpResult(
            False,
            resp.status_code,
            f"{label} HTTP {resp.status_code}: {preview_response(resp)}",
            payload=payload,
        )


def load_auth(args: argparse.Namespace) -> AuthConfig:
    file_values: dict[str, str] = {}
    if os.path.exists(args.auth_file):
        with open(args.auth_file, encoding="utf-8") as fp:
            obj = json.load(fp)
        if isinstance(obj, dict):
            file_values = {k: str(v) for k, v in obj.items() if v is not None}

    token = (
        args.access_token
        or os.getenv("X_ACCESS_TOKEN")
        or os.getenv("TWITDELETE_ACCESS_TOKEN")
        or file_values.get("access_token", "")
    )
    if not token:
        raise ValueError("Missing access token. Set --access-token, X_ACCESS_TOKEN, or auth.json access_token.")
    return AuthConfig(access_token=token.strip())


def fetch_me(
    session: requests.Session,
    auth: AuthConfig,
    args: argparse.Namespace,
) -> tuple[str, str]:
    result = request_with_rate_limit_retry(
        session,
        method="GET",
        url=f"{API_BASE}/users/me",
        headers=build_headers(auth),
        timeout=args.timeout,
        label="GET /2/users/me",
        mode=args.rate_limit_mode,
        retries=args.rate_limit_retries,
        wait_seconds=args.rate_limit_wait,
        max_wait=args.rate_limit_max_wait,
        params={"user.fields": "id,username"},
    )
    if not result.ok:
        raise ValueError(result.message)
    data = result.payload.get("data") if isinstance(result.payload, dict) else None
    if not isinstance(data, dict):
        raise ValueError("Invalid /2/users/me response")
    user_id = str(data.get("id", "")).strip()
    username = str(data.get("username", "")).strip()
    if not user_id or not username:
        raise ValueError("Cannot parse id/username from /2/users/me")
    return user_id, username


def fetch_tweets_page(
    session: requests.Session,
    auth: AuthConfig,
    args: argparse.Namespace,
    *,
    user_id: str,
    max_results: int,
    pagination_token: str | None,
    before_ts: int | None,
    after_ts: int | None,
) -> tuple[list[TweetMeta], str | None]:
    exclude: list[str] = []
    if not args.include_replies:
        exclude.append("replies")
    if args.exclude_retweets:
        exclude.append("retweets")

    params: dict[str, Any] = {
        "max_results": max_results,
        "tweet.fields": "created_at,author_id,referenced_tweets",
        "expansions": "author_id",
        "user.fields": "username",
    }
    if exclude:
        params["exclude"] = ",".join(exclude)
    if pagination_token:
        params["pagination_token"] = pagination_token
    if after_ts is not None:
        params["start_time"] = to_api_datetime(after_ts)
    if before_ts is not None:
        params["end_time"] = to_api_datetime(before_ts)

    result = request_with_rate_limit_retry(
        session,
        method="GET",
        url=f"{API_BASE}/users/{user_id}/tweets",
        headers=build_headers(auth),
        timeout=args.timeout,
        label="GET /2/users/{id}/tweets",
        mode=args.rate_limit_mode,
        retries=args.rate_limit_retries,
        wait_seconds=args.rate_limit_wait,
        max_wait=args.rate_limit_max_wait,
        params=params,
    )
    if not result.ok:
        raise ValueError(result.message)

    payload = result.payload if isinstance(result.payload, dict) else {}
    includes = payload.get("includes") if isinstance(payload.get("includes"), dict) else {}
    users = includes.get("users") if isinstance(includes.get("users"), list) else []
    user_map: dict[str, str] = {}
    for u in users:
        if not isinstance(u, dict):
            continue
        uid = str(u.get("id", "")).strip()
        uname = str(u.get("username", "")).strip()
        if uid and uname:
            user_map[uid] = uname

    items = payload.get("data") if isinstance(payload.get("data"), list) else []
    tweets: list[TweetMeta] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        tweet_id = str(item.get("id", "")).strip()
        if not tweet_id:
            continue
        author_id = str(item.get("author_id", "")).strip() or None
        refs = item.get("referenced_tweets") if isinstance(item.get("referenced_tweets"), list) else []
        ref_types = {str(r.get("type", "")).strip() for r in refs if isinstance(r, dict)}
        tweets.append(
            TweetMeta(
                tweet_id=tweet_id,
                text=item.get("text") if isinstance(item.get("text"), str) else None,
                created_ts=parse_api_datetime(item.get("created_at")),
                author_id=author_id,
                author_username=user_map.get(author_id) if author_id else None,
                is_reply="replied_to" in ref_types,
                is_retweet="retweeted" in ref_types,
            )
        )

    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    next_token = str(meta.get("next_token", "")).strip() or None
    return tweets, next_token


def should_delete(
    tweet: TweetMeta,
    *,
    viewer_id: str,
    viewer_name: str,
    before_ts: int | None,
    after_ts: int | None,
    contains: str | None,
    author: str | None,
) -> tuple[bool, str]:
    # Safety: never attempt deleting posts that do not look like ours.
    if tweet.author_id and tweet.author_id != viewer_id:
        return False, f"not own post (author_id={tweet.author_id})"
    if tweet.author_username and tweet.author_username.lower() != viewer_name.lower():
        return False, f"not own post (@{tweet.author_username})"

    if author:
        if not tweet.author_username:
            return False, "missing author username"
        if tweet.author_username.lower() != author.lower():
            return False, f"author mismatch (@{tweet.author_username})"

    if contains:
        if not tweet.text:
            return False, "missing text"
        if contains.lower() not in tweet.text.lower():
            return False, "contains mismatch"

    if before_ts is not None:
        if tweet.created_ts is None:
            return False, "missing created_at"
        if tweet.created_ts >= before_ts:
            return False, "before mismatch"

    if after_ts is not None:
        if tweet.created_ts is None:
            return False, "missing created_at"
        if tweet.created_ts < after_ts:
            return False, "after mismatch"

    return True, "match"


def delete_post(
    session: requests.Session,
    auth: AuthConfig,
    args: argparse.Namespace,
    tweet_id: str,
) -> HttpResult:
    result = request_with_rate_limit_retry(
        session,
        method="DELETE",
        url=f"{API_BASE}/tweets/{tweet_id}",
        headers=build_headers(auth),
        timeout=args.timeout,
        label=f"DELETE /2/tweets/{tweet_id}",
        mode=args.rate_limit_mode,
        retries=args.rate_limit_retries,
        wait_seconds=args.rate_limit_wait,
        max_wait=args.rate_limit_max_wait,
    )
    if not result.ok:
        return result

    payload = result.payload if isinstance(result.payload, dict) else {}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    deleted = data.get("deleted")
    if deleted is True:
        return result
    return HttpResult(False, result.status_code, f"Unexpected delete response: {payload}", payload=payload)


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
    try:
        viewer_id, viewer_name = fetch_me(session, auth, args)
    except Exception as exc:
        print(f"[ERROR] Failed to identify user via /2/users/me: {exc}", file=sys.stderr)
        return 2

    print(f"[INFO] Authenticated user: @{viewer_name} ({viewer_id})")
    print(f"[INFO] Mode: {'DRY-RUN' if args.dry_run else 'DELETE'}")
    if args.delete_all:
        print(f"[INFO] Delete-all mode ON (pass_limit={'unlimited' if args.pass_limit <= 0 else args.pass_limit})")
    if args.author:
        print(f"[INFO] Filter author: {args.author}")
    if args.contains:
        print(f"[INFO] Filter contains: {args.contains}")
    if before_ts is not None:
        print(f"[INFO] Filter before: {format_ts(before_ts)}")
    if after_ts is not None:
        print(f"[INFO] Filter after : {format_ts(after_ts)}")

    considered = 0
    matched = 0
    deleted = 0
    skipped = 0
    failed = 0

    pass_no = 0
    prev_batch_ids: list[str] = []
    page_size = max(5, min(args.timeline_page_size, 100))
    pages_per_pass = max(1, args.timeline_pages)

    while True:
        if args.pass_limit > 0 and pass_no >= args.pass_limit:
            print(f"[INFO] Reached pass limit: {args.pass_limit}")
            break
        if args.max > 0 and considered >= args.max:
            print(f"[INFO] Reached max processed count: {args.max}")
            break

        pass_no += 1
        print(f"[INFO] Starting pass {pass_no}")

        remaining = (args.max - considered) if args.max > 0 else 0
        collected: list[TweetMeta] = []
        seen: set[str] = set()
        pagination_token: str | None = None

        for page in range(1, pages_per_pass + 1):
            if remaining > 0 and len(collected) >= remaining:
                break
            request_size = page_size
            if remaining > 0:
                request_size = max(5, min(page_size, remaining - len(collected)))

            try:
                page_items, next_token = fetch_tweets_page(
                    session,
                    auth,
                    args,
                    user_id=viewer_id,
                    max_results=request_size,
                    pagination_token=pagination_token,
                    before_ts=before_ts,
                    after_ts=after_ts,
                )
            except Exception as exc:
                print(f"[ERROR] Failed to load tweets page {page}: {exc}", file=sys.stderr)
                return 2

            added = 0
            for t in page_items:
                if t.tweet_id in seen:
                    continue
                seen.add(t.tweet_id)
                collected.append(t)
                added += 1
                if remaining > 0 and len(collected) >= remaining:
                    break

            print(f"[INFO] Timeline page {page}: +{added} posts (batch total {len(collected)})")
            if not next_token:
                break
            pagination_token = next_token

        if not collected:
            if pass_no == 1:
                print("[INFO] No visible posts found. Nothing to delete.")
                break
            print("[INFO] No more visible posts found. Stopping.")
            break

        batch_deleted = 0
        batch_ids = [t.tweet_id for t in collected]
        stop_due_rate_limit = False
        total = len(collected)

        for idx, t in enumerate(collected, start=1):
            considered += 1
            ok, reason = should_delete(
                t,
                viewer_id=viewer_id,
                viewer_name=viewer_name,
                before_ts=before_ts,
                after_ts=after_ts,
                contains=args.contains,
                author=args.author,
            )
            if not ok:
                skipped += 1
                print(f"[SKIP P{pass_no} {idx}/{total}] {t.tweet_id} | {reason}")
                continue

            matched += 1
            author_text = t.author_username or "-"
            created_text = format_ts(t.created_ts)

            if args.dry_run:
                print(f"[CANDIDATE P{pass_no} {idx}/{total}] {t.tweet_id} | @{author_text} | {created_text}")
                continue

            result = delete_post(session, auth, args, t.tweet_id)
            if result.ok:
                deleted += 1
                batch_deleted += 1
                print(f"[DELETED P{pass_no} {idx}/{total}] {t.tweet_id} | @{author_text} | {created_text}")
            else:
                failed += 1
                print(f"[FAILED P{pass_no} {idx}/{total}] {t.tweet_id} | {result.message}")
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

    print("")
    print("========== SUMMARY ==========")
    print(f"considered : {considered}")
    print(f"matched    : {matched}")
    print(f"deleted    : {deleted}")
    print(f"skipped    : {skipped}")
    print(f"failed     : {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
