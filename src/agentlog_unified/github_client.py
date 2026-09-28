"""Read-only, bounded GitHub metadata collection with reusable success caches."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


def _token():
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token and shutil.which("gh"):
        try:
            result = subprocess.run(["gh", "auth", "token", "--hostname", "github.com"], capture_output=True, text=True, timeout=5, check=False)
            token = result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            token = None
    return token


class GitHubClient:
    def __init__(self, cache_dir, offline=False, timeout=30, max_retries=3):
        self.cache_dir = Path(cache_dir)
        self.offline, self.timeout, self.max_retries = offline, timeout, max_retries
        self.failures, self.last_headers, self.requests = [], {}, 0
        self.last_collected_at, self.last_source = None, None
        self._secret = None  # Retrieve credentials only when a network request is needed.
        self._loaded_secret = False
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _url(self, path):
        url = path if str(path).startswith("https://") else "https://api.github.com/" + str(path).lstrip("/")
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "api.github.com" or parsed.username or parsed.fragment:
            raise ValueError("GitHub metadata requests must use api.github.com HTTPS")
        if any(k.lower() in {"access_token", "token", "client_secret"} for k, _ in parse_qsl(parsed.query)):
            raise ValueError("Credentials are not allowed in request URLs")
        return url

    def _failure(self, url, error_type, retryable, reason, **extra):
        match = re.search(r"/repos/([^/]+/[^/]+)(?:/pulls/(\d+))?", urlparse(url).path)
        item = {"stage": "collect", "repository": match[1] if match else None, "pr": int(match[2]) if match and match[2] else None, "sha": None, "error_type": error_type, "retryable": retryable, "reason": reason, "endpoint": urlparse(url).path, **extra}
        self.failures.append(item)
        return None

    def get(self, path):
        url = self._url(path)
        cache = self.cache_dir / (hashlib.sha256(url.encode()).hexdigest() + ".json")
        self.last_headers = {}
        self.last_collected_at, self.last_source = None, None
        if cache.exists():
            try:
                cached = json.loads(cache.read_text(encoding="utf-8"))
                self.last_headers = {k.lower(): v for k, v in cached.get("headers", {}).items()}
                self.last_collected_at, self.last_source = cached.get("collected_at"), "cache"
                return cached["data"]
            except (OSError, ValueError, KeyError, TypeError):
                self._failure(url, "cache_invalid", True, "Cached JSON is unreadable; online mode will refetch")
        if self.offline:
            return self._failure(url, "offline_cache_miss", True, "Metadata unavailable in local success cache")
        if not self._loaded_secret:
            self._secret, self._loaded_secret = _token(), True
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "agentlog-unified-research/0.1"}
        if self._secret:
            headers["Authorization"] = "Bearer " + self._secret
        for attempt in range(self.max_retries + 1):
            try:
                self.requests += 1
                with urlopen(Request(url, headers=headers, method="GET"), timeout=self.timeout) as response:
                    data = json.loads(response.read())
                    self.last_headers = {k.lower(): v for k, v in response.headers.items()}
                # Persist only public response data and a small, credential-free header allowlist.
                saved_headers = {k: v for k, v in self.last_headers.items() if k in {"link", "etag", "last-modified", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"}}
                self.last_collected_at, self.last_source = datetime.now(timezone.utc).isoformat(), "network"
                payload = {"url": url, "collected_at": self.last_collected_at, "headers": saved_headers, "data": data}
                temporary = cache.with_suffix(f".{os.getpid()}.tmp")
                temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
                temporary.chmod(0o600)
                temporary.replace(cache)
                return data
            except HTTPError as exc:
                status = exc.code
                response_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
                retryable = status in {403, 429, 500, 502, 503, 504}
                delay = float(2 ** attempt)
                if response_headers.get("retry-after"):
                    try:
                        delay = max(delay, float(response_headers["retry-after"]))
                    except ValueError:
                        try:
                            delay = max(delay, parsedate_to_datetime(response_headers["retry-after"]).timestamp() - time.time())
                        except (TypeError, ValueError, OverflowError):
                            delay = max(delay, 60)
                elif response_headers.get("x-ratelimit-remaining") == "0":
                    try:
                        delay = max(delay, float(response_headers.get("x-ratelimit-reset", 0)) - time.time() + 1)
                    except ValueError:
                        delay = max(delay, 60)
                elif status in {403, 429}:
                    delay = max(delay, 60)
                if not retryable or attempt == self.max_retries or delay > 60:
                    return self._failure(url, f"HTTP_{status}", retryable, "GitHub read request failed; response body intentionally omitted", attempts=attempt + 1, retry_after_seconds=max(0, round(delay)) if retryable else None)
                time.sleep(max(0, delay))
            except (URLError, TimeoutError, ConnectionError, OSError) as exc:
                if attempt == self.max_retries:
                    return self._failure(url, type(exc).__name__, True, "Network or cache I/O failed; exception details omitted", attempts=attempt + 1)
                time.sleep(2 ** attempt)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return self._failure(url, "invalid_json_response", True, "GitHub response did not contain valid JSON")
        return None

    def paginate(self, path, max_items=1000, max_pages=10):
        url = self._url(path)
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query))
        query.setdefault("per_page", "100")
        url = urlunparse(parsed._replace(query=urlencode(query)))
        rows, seen = [], set()
        for page in range(max_pages):
            if url in seen:
                self._failure(url, "pagination_cycle", False, "Repeated next-page URL")
                break
            seen.add(url)
            result = self.get(url)
            if result is None:
                break
            if not isinstance(result, list):
                self._failure(url, "unexpected_response_shape", False, "List endpoint returned a non-list")
                break
            next_link = re.search(r'<([^>]+)>;\s*rel="next"', self.last_headers.get("link", ""))
            available = max_items - len(rows)
            rows.extend(result[:available])
            if len(result) > available or (next_link and len(rows) >= max_items):
                self._failure(url, "endpoint_or_budget_cap", True, "Item limit reached before full pagination", max_items=max_items)
                break
            if not next_link:
                break
            url = self._url(next_link[1])
        else:
            self._failure(url, "pagination_budget_exhausted", True, "Maximum page count reached", max_pages=max_pages)
        return rows


def enrich_pr(pr, client, collect_reviews=False, collect_associations=False):
    result = dict(pr)
    repository, number = result.get("repository"), result.get("pr_number")
    if result.get("is_synthetic") or not repository or not number:
        result["pr_metadata_status"] = "missing" if not number else "not_applicable"
        return result
    endpoint = f"repos/{repository}/pulls/{number}"
    missing = any(not result.get(k) for k in ("head_sha", "base_sha", "base_ref", "merged_at", "merge_commit_sha"))
    failure_start = len(client.failures)
    detail = client.get(endpoint) if missing else None
    if isinstance(detail, dict):
        for key in ("created_at", "merged_at", "closed_at", "merge_commit_sha", "state"):
            if not result.get(key):
                result[key] = detail.get(key)
        for key, value in {"head_sha": (detail.get("head") or {}).get("sha"), "base_sha": (detail.get("base") or {}).get("sha"), "base_ref": (detail.get("base") or {}).get("ref")}.items():
            if not result.get(key):
                result[key] = value
        result["github_pr_author"] = {k: (detail.get("user") or {}).get(k) for k in ("login", "type", "html_url")}
        result["github_reported_commit_count"] = detail.get("commits")
        result["metadata_collected_at"] = client.last_collected_at
        result["metadata_accessed_at"] = datetime.now(timezone.utc).isoformat()
        result["metadata_retrieval_mode"] = client.last_source
        result["metadata_source"] = "github_api"
    if not result.get("commit_shas"):
        commits = client.paginate(endpoint + "/commits", max_items=250, max_pages=3)
        result["commit_shas"] = [c["sha"] for c in commits if isinstance(c, dict) and c.get("sha")]
        result["github_commit_metadata"] = commits
    count = result.get("github_reported_commit_count")
    if (isinstance(count, int) and count != len(result.get("commit_shas", []))) or (count is None and len(result.get("commit_shas", [])) >= 250):
        client._failure(client._url(endpoint + "/commits"), "pr_commit_list_incomplete", True, "PR commits endpoint cap is 250; verify or supplement with local Git", reported_count=count, retrieved_count=len(result.get("commit_shas", [])))
        result["commit_list_status"] = "potentially_incomplete"
    else:
        result["commit_list_status"] = "count_verified" if count is not None else "count_unverified"
    if collect_reviews:
        result["reviews"] = client.paginate(endpoint + "/reviews")
        result["review_comments"] = client.paginate(endpoint + "/comments")
        result["issue_comments"] = client.paginate(f"repos/{repository}/issues/{number}/comments")
        result["events"] = client.paginate(f"repos/{repository}/issues/{number}/events")
    else:
        result["review_collection_status"] = "not_requested"
    if collect_associations:
        result["commit_pr_associations"] = {sha: client.paginate(f"repos/{repository}/commits/{sha}/pulls", max_items=100) for sha in result.get("commit_shas", [])}
    result["collection_gaps"] = list(result.get("collection_gaps") or []) + client.failures[failure_start:]
    result["pr_metadata_status"] = "partial" if result["collection_gaps"] or not all(result.get(k) for k in ("head_sha", "base_sha", "commit_shas")) else "available"
    return result
