#!/usr/bin/env python3
"""Resume missing AIDev PR diff downloads through GitHub's patch-diff host."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.client import IncompleteRead
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

if __package__:
    from .screen_github_agent_logs import _atomic_write_text
else:
    from screen_github_agent_logs import _atomic_write_text


PR_URL = re.compile(r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)\.diff$")


def default_token() -> str:
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    try:
        return subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ""


def patch_diff_url(url: str) -> str:
    match = PR_URL.fullmatch(url)
    if not match:
        raise ValueError("unsupported GitHub PR diff URL: " + url)
    owner, repo, number = match.groups()
    return f"https://patch-diff.githubusercontent.com/raw/{owner}/{repo}/pull/{number}.diff"


def api_diff_url(url: str) -> str:
    match = PR_URL.fullmatch(url)
    if not match:
        raise ValueError("unsupported GitHub PR diff URL: " + url)
    owner, repo, number = match.groups()
    return f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}"


def cache_path(cache_dir: Path, original_url: str) -> Path:
    return cache_dir / (hashlib.sha256(original_url.encode()).hexdigest() + ".json")


def download(
    original_url: str, cache_dir: Path, attempts: int, delay: float, token: str,
    max_bytes: int,
) -> tuple[str, str]:
    destination = cache_path(cache_dir, original_url)
    if destination.is_file():
        return original_url, "CACHED"
    headers = {
        "Accept": "application/vnd.github.v3.diff" if token else "text/plain",
        "User-Agent": "aidev-full-coverage-research/1.0",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    request = Request(api_diff_url(original_url) if token else patch_diff_url(original_url), headers=headers)
    for attempt in range(attempts):
        if delay:
            time.sleep(delay + random.random() * delay)
        try:
            with urlopen(request, timeout=45) as response:
                length = int(response.headers.get("Content-Length") or 0)
                if length > max_bytes:
                    return original_url, "TOO_LARGE"
                raw = response.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    return original_url, "TOO_LARGE"
                data = raw.decode("utf-8", errors="replace")
                headers = {name.lower(): value for name, value in response.headers.items()}
            _atomic_write_text(
                destination,
                json.dumps(
                    {"url": original_url, "headers": headers, "data": data},
                    ensure_ascii=False, sort_keys=True,
                ) + "\n",
            )
            return original_url, "DOWNLOADED"
        except HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt + 1 == attempts:
                return original_url, f"HTTP_{exc.code}"
            time.sleep(min(60, 2 ** attempt * 5))
        except (URLError, TimeoutError, IncompleteRead) as exc:
            if attempt + 1 == attempts:
                return original_url, "NETWORK_" + type(exc).__name__
            time.sleep(min(60, 2 ** attempt * 5))
    raise AssertionError("unreachable")


def run(args: argparse.Namespace) -> dict:
    with args.queue.open(encoding="utf-8", newline="") as handle:
        urls = sorted({row["diff_url"] for row in csv.DictReader(handle)})
    urls = [url for url in urls if not cache_path(args.cache_dir, url).is_file()]
    if args.limit:
        urls = urls[:args.limit]
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    counts = {"CACHED": 0, "DOWNLOADED": 0}
    failures = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                download, url, args.cache_dir, args.attempts, args.delay, args.token,
                args.max_bytes,
            ): url
            for url in urls
        }
        for index, future in enumerate(as_completed(futures), 1):
            try:
                url, status = future.result()
            except Exception as exc:  # keep one malformed remote response from aborting the batch
                url, status = futures[future], "UNEXPECTED_" + type(exc).__name__
            counts[status] = counts.get(status, 0) + 1
            if status not in {"CACHED", "DOWNLOADED"}:
                failures.append({"diff_url": url, "status": status})
            if index % 25 == 0 or index == len(urls):
                print(f"[{index}/{len(urls)}] downloaded={counts['DOWNLOADED']} failures={len(failures)}", flush=True)
    failure_path = args.failure_file or args.queue.with_name(args.queue.stem + "_download_failures.csv")
    with failure_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("diff_url", "status"))
        writer.writeheader()
        writer.writerows(failures)
    return {
        "requested_missing_urls": len(urls),
        "downloaded": counts["DOWNLOADED"],
        "failures": len(failures),
        "workers": args.workers,
        "transport": "authenticated_github_api" if args.token else "public_patch_diff",
        "max_bytes": args.max_bytes,
        "failure_file": str(failure_path.resolve()),
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--queue", type=Path, default=Path("outputs/aidev_full_coverage_v1/missing_diff_queue.csv"))
    value.add_argument("--cache-dir", type=Path, default=Path("data/res/aidev_observational_primary_diffs"))
    value.add_argument("--failure-file", type=Path)
    value.add_argument("--workers", type=int, default=4)
    value.add_argument("--attempts", type=int, default=4)
    value.add_argument("--delay", type=float, default=0.15)
    value.add_argument("--limit", type=int, default=0)
    value.add_argument("--max-bytes", type=int, default=50 * 1024 * 1024)
    value.add_argument("--token", default=default_token())
    return value


def main() -> int:
    args = parser().parse_args()
    if args.workers < 1 or args.attempts < 1 or args.delay < 0 or args.limit < 0 or args.max_bytes < 1:
        raise SystemExit("workers/attempts must be positive; delay/limit must be non-negative")
    print(json.dumps(run(args), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
