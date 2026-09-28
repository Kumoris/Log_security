#!/usr/bin/env python3
"""Screen merged GitHub coding-agent PRs for added static log-risk candidates."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import re
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import date, timedelta
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


SOURCE_EXTENSIONS = {
    ".bash", ".c", ".cc", ".cpp", ".cs", ".cxx", ".dart", ".ex", ".exs",
    ".fs", ".fsx", ".go", ".h", ".hpp", ".java", ".js", ".jsx", ".kt",
    ".php", ".py", ".r", ".rb", ".rs", ".sh", ".svelte", ".swift", ".ts",
    ".tsx", ".vue", ".zsh", ".zig",
}
EXCLUDED_PARTS = {
    ".cache", ".git", ".next", ".nuxt", ".venv", "__pycache__", "build",
    "coverage", "dist", "example", "examples", "fixture", "fixtures", "generated",
    "e2e", "node_modules", "out", "sample", "samples", "target", "test", "testing", "tests",
    "vendor", "vendors", "venv",
}
LOG_RE = re.compile(
    r"(?:\bconsole\s*\.\s*(?:log|error|warn|debug|info|trace)\s*\("
    r"|\b(?:logger|logging|log)\s*\.\s*(?:debug|info|warn|warning|error|exception|critical|trace|fatal)\s*\("
    r"|(?<![.\w])print\s*\(|\bfmt\s*\.\s*(?:Print|Printf|Println|Fprint|Fprintf|Fprintln)\s*\("
    r"|\blog\s*\.\s*(?:Print|Printf|Println|Fatal|Fatalf|Panic|Panicf)\s*\("
    r"|\bSystem\s*\.\s*(?:out|err)\s*\.\s*print(?:ln)?\s*\("
    r"|\b(?:println|eprintln|dbg|debug|info|warn|error|trace)!\s*\("
    r"|\bNSLog\s*\()",
    re.IGNORECASE,
)
SHELL_LOG_RE = re.compile(r"^\s*(?:echo|printf)\b", re.IGNORECASE)
STRING_RE = re.compile(r"(['\"])(?:\\.|(?!\1).)*\1")
CONCEPT_PATTERNS = {
    "api_key": r"(?<![a-z0-9])api[_ -]?keys?\b",
    "config": r"\bconfig(?:uration)?\b",
    "cookie": r"\bcookies?\b",
    "credential": r"\bcredentials?\b",
    "email": r"\be-?mails?\b",
    "environment": r"\b(?:env(?:ironment)?(?:_vars?)?|process\.env)\b",
    "error": r"\b(?:errors?|exceptions?|tracebacks?|stack_trace)\b",
    "headers": r"\bheaders?\b",
    "ip": r"\bip(?:_address|addr)?\b",
    "memory": r"\b(?:agent_memory|long_term_memory|memory)\b",
    "messages": r"\b(?:system_message|developer_message|chat_messages?|llm_messages?)\b",
    "model_output": r"\b(?:model|llm|assistant)_(?:response|output)\b",
    "password": r"\bpasswords?\b",
    "path": r"\b(?:file_)?paths?\b",
    "payload": r"\bpayload\b",
    "prompt": r"\b(?:system_|developer_)?prompt\b",
    "request": r"\brequests?\b",
    "response": r"\bresponses?\b",
    "secret": r"\bsecrets?\b",
    "session": r"\b(?:sessions?|session_id)\b",
    "token": r"\b(?:access_|refresh_)?tokens?\b",
    "tool_input": r"\btool_(?:input|arguments?)\b",
    "tool_output": r"\btool_(?:result|output)\b",
    "user": r"\b(?:users?|user_id)\b",
}
AGENT_CONTROL = {"memory", "messages", "model_output", "prompt", "tool_input", "tool_output"}
AUTH_CONFIG = {"api_key", "config", "cookie", "credential", "environment", "password", "secret", "token"}
REQUEST_RESPONSE = {"headers", "payload", "request", "response"}
IDENTITY_SESSION = {"email", "ip", "path", "session", "user"}
AGENT_NATIVE_RISK_FEATURES = {"agent_control_data", "tool_io_data"}
SHARED_SENSITIVE_RISK_FEATURES = {
    "auth_config_data", "identity_session_data", "request_response_data"
}
AGENTS = {
    "claude": {
        "app_slug": "claude",
        "query": "author:app/claude is:pr is:merged",
    },
    "copilot_swe_agent": {
        "app_slug": "copilot-swe-agent",
        "query": "author:app/copilot-swe-agent is:pr is:merged",
    },
}
OUTPUT_NAMES = (
    "github_agent_pr_evidence.jsonl",
    "github_agent_log_candidates.csv",
    "github_agent_log_screening_summary.json",
    "github_agent_log_screening_report.md",
)
CANDIDATE_FIELDS = (
    "dataset", "provenance", "provenance_evidence", "provenance_granularity",
    "evidence_level", "adoption_evidence", "agent", "source_app_slug", "actor_login",
    "repo", "pr_number", "pr_key", "pr_url", "created_at", "merged_at",
    "merge_commit_sha", "head_sha", "base_sha", "head_tree_sha", "head_committed_at",
    "pr_diff_sha256", "canonical_patch_sha256", "commit_list_sha256", "metadata_sha256",
    "provenance_grade", "generation_stage", "evidence_chain_status",
    "file", "line", "path_scope",
    "is_executable_log", "static_risk_candidate", "risk_features", "log_concepts",
    "log_text_redacted", "source_url", "api_diff_incomplete", "query_window",
)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""


def sha256_json(value: object) -> str:
    return sha256_text(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def canonical_patch_sha256(diff: str) -> str:
    """Hash a diff after line-ending normalization only; code whitespace remains significant."""
    if not diff:
        return ""
    normalized = diff.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
    return sha256_text(normalized)


def patch_content_sha256(diff: str) -> str:
    """Hash patch content while ignoring only Git's optional hunk display text."""
    if not diff:
        return ""
    normalized = diff.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
    normalized = re.sub(
        r"^(@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@).*$", r"\1", normalized, flags=re.MULTILINE
    )
    return sha256_text(normalized)


def date_windows(start: date, end: date, days: int) -> list[tuple[date, date]]:
    if days < 1 or start > end:
        raise ValueError("days must be positive and start must not follow end")
    windows = []
    cursor = start
    while cursor <= end:
        window_end = min(end, cursor + timedelta(days=days - 1))
        windows.append((cursor, window_end))
        cursor = window_end + timedelta(days=1)
    return windows


def added_lines(patch: str) -> list[tuple[int, str]]:
    output = []
    new_line = 0
    for raw in (patch or "").splitlines():
        match = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
        if match:
            new_line = int(match.group(1))
        elif raw.startswith("+") and not raw.startswith("+++"):
            output.append((new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        elif raw.startswith(" "):
            new_line += 1
    return output


def is_source_file(path: str) -> bool:
    clean = path.replace("\\", "/").strip()
    parts = [part.lower() for part in clean.split("/") if part]
    if not parts or any(part in EXCLUDED_PARTS - {"test", "tests", "example", "examples", "fixture", "fixtures", "sample", "samples"} for part in parts):
        return False
    name = parts[-1]
    return name in {"dockerfile", "makefile"} or PurePosixPath(name).suffix.lower() in SOURCE_EXTENSIONS


def is_production_path(path: str) -> bool:
    clean = path.replace("\\", "/").strip()
    parts = [part.lower() for part in clean.split("/") if part]
    if not parts or any(part in EXCLUDED_PARTS for part in parts):
        return False
    name = parts[-1]
    stem_parts = name.split(".")
    return not (
        name.startswith(("test_", "test-"))
        or name.endswith("_test.py")
        or "test" in stem_parts[1:-1]
        or "spec" in stem_parts[1:-1]
        or name.endswith(".snap")
    )


def _strip_inline_comment(text: str) -> str:
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\" and quote:
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in {"'", '"'}:
            quote = char
        elif char == "#" or text[index:index + 2] == "//":
            return text[:index]
        index += 1
    return text


def _concepts(text: str) -> set[str]:
    return {name for name, pattern in CONCEPT_PATTERNS.items() if re.search(pattern, text, re.IGNORECASE)}


def classify_log(path: str, line: str) -> tuple[bool, tuple[str, ...], tuple[str, ...]]:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", "//", "/*", "*", "<!--", "--")):
        return False, (), ()
    code = _strip_inline_comment(stripped).strip()
    shell = PurePosixPath(path.lower()).suffix in {".sh", ".bash", ".zsh"}
    if not LOG_RE.search(code) and not (shell and SHELL_LOG_RE.search(code)):
        return False, (), ()

    concepts = _concepts(code)
    dynamic_text = STRING_RE.sub("", code)
    dynamic_text = re.sub(
        r"\b(?:console|logger|logging|log)\s*\.\s*"
        r"(?:debug|info|warn|warning|error|exception|critical|trace|fatal)\s*\("
        r"|\b(?:debug|info|warn|error|trace)!\s*\(",
        "(",
        dynamic_text,
        flags=re.IGNORECASE,
    )
    dynamic_concepts = _concepts(dynamic_text)
    features = set()
    if dynamic_concepts & AGENT_CONTROL:
        features.add("agent_control_data")
    if dynamic_concepts & AUTH_CONFIG:
        features.add("auth_config_data")
    if dynamic_concepts & REQUEST_RESPONSE:
        features.add("request_response_data")
    if dynamic_concepts & IDENTITY_SESSION:
        features.add("identity_session_data")
    if dynamic_concepts & {"tool_input", "tool_output"}:
        features.add("tool_io_data")
    if dynamic_concepts & (AGENT_CONTROL | AUTH_CONFIG | REQUEST_RESPONSE | IDENTITY_SESSION | {"error"}):
        features.add("whole_object_dump")
    if "error" in dynamic_concepts or re.search(
        r"\.(?:error|exception|fatal|critical)\s*\(|\berror!\s*\(", code, re.IGNORECASE
    ):
        features.add("error_diagnostic_data")
    if re.search(r"(?<![.\w])print\s*\(|\b(?:console\s*\.|fmt\s*\.|System\s*\.(?:out|err)|echo\b|printf\b)", code, re.IGNORECASE):
        features.add("unstructured_stdio")
    if re.search(r"\b(?:DEBUG|TEMP(?:ORARY)?|DIAGNOSE|DUMP)\b", code, re.IGNORECASE):
        features.add("debug_residue_marker")
    return True, tuple(sorted(features)), tuple(sorted(concepts))


def redact_excerpt(text: str) -> str:
    value = text[:800]
    replacements = (
        (r"\b(?:gh[opsu]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b", "[REDACTED_SECRET]"),
        (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "[REDACTED_SECRET]"),
        (r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", "Bearer [REDACTED_SECRET]"),
        (r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[REDACTED_EMAIL]"),
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_IP]"),
    )
    for pattern, replacement in replacements:
        value = re.sub(pattern, replacement, value, flags=re.IGNORECASE if "(?i)" not in pattern else 0)
    return value


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


class GitHubClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        cache_dir: Path,
        offline: bool = False,
        refresh: bool = False,
        timeout: int = 30,
        transport=None,
        diff_delay: float = 0.0,
        sleep=time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.cache_dir = Path(cache_dir)
        self.offline = offline
        self.refresh = refresh
        self.timeout = timeout
        self.transport = transport
        self.diff_delay = diff_delay
        self.sleep = sleep
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._origin = urlparse(self.base_url)

    def _cache_path(self, url: str) -> Path:
        return self.cache_dir / (hashlib.sha256(url.encode("utf-8")).hexdigest() + ".json")

    def _validate_url(self, url: str, allow_diff: bool = False) -> None:
        parsed = urlparse(url)
        same_origin = (parsed.scheme, parsed.netloc) == (self._origin.scheme, self._origin.netloc)
        allowed_diff = allow_diff and parsed.scheme == "https" and parsed.netloc in {
            "github.com", "patch-diff.githubusercontent.com",
        }
        if not same_origin and not allowed_diff:
            raise ValueError("refusing GitHub API request outside configured origin")

    def get_json(self, url: str) -> tuple[object, dict[str, str]]:
        self._validate_url(url)
        cache_path = self._cache_path(url)
        if cache_path.exists() and not self.refresh:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            return cached["data"], cached.get("headers", {})
        if self.offline:
            raise RuntimeError("offline cache miss: " + url)

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "agent-log-screening-research/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if self.transport is not None:
            data, response_headers = self.transport(url, headers, self.timeout)
            response_headers = {name.lower(): value for name, value in response_headers.items()}
        else:
            request = Request(url, headers=headers)
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
                    response_headers = {name.lower(): value for name, value in response.headers.items()}
            except HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[:500]
                raise RuntimeError(f"GitHub API HTTP {exc.code}: {detail}") from exc
            except (URLError, TimeoutError) as exc:
                raise RuntimeError(f"GitHub API request failed: {exc}") from exc

        _atomic_write_text(
            cache_path,
            json.dumps({"url": url, "headers": response_headers, "data": data}, ensure_ascii=False, sort_keys=True) + "\n",
        )
        return data, response_headers

    def get_text(self, url: str) -> tuple[str, dict[str, str]]:
        self._validate_url(url, allow_diff=True)
        cache_path = self._cache_path(url)
        if cache_path.exists() and not self.refresh:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            data = cached["data"]
            if not isinstance(data, str):
                raise ValueError("cached diff is not text")
            return data, cached.get("headers", {})
        if self.offline:
            raise RuntimeError("offline cache miss: " + url)

        headers = {"Accept": "text/plain", "User-Agent": "agent-log-screening-research/1.0"}
        if self.diff_delay > 0:
            self.sleep(self.diff_delay)
        if self.transport is not None:
            data, response_headers = self.transport(url, headers, self.timeout)
            response_headers = {name.lower(): value for name, value in response_headers.items()}
            if not isinstance(data, str):
                raise ValueError("diff transport did not return text")
        else:
            request = Request(url, headers=headers)
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    data = response.read().decode("utf-8", errors="replace")
                    response_headers = {name.lower(): value for name, value in response.headers.items()}
            except HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[:500]
                raise RuntimeError(f"GitHub diff HTTP {exc.code}: {detail}") from exc
            except (URLError, TimeoutError) as exc:
                raise RuntimeError(f"GitHub diff request failed: {exc}") from exc
        _atomic_write_text(
            cache_path,
            json.dumps({"url": url, "headers": response_headers, "data": data}, ensure_ascii=False, sort_keys=True) + "\n",
        )
        return data, response_headers

    def paginate(
        self,
        url: str,
        item_key: str | None,
        max_pages: int,
        stop_after: int | None = None,
    ) -> tuple[list[dict], dict[str, object]]:
        if max_pages < 1:
            raise ValueError("max_pages must be positive")
        rows: list[dict] = []
        page_count = 0
        first_metadata: dict[str, object] = {}
        next_url: str | None = url
        stopped_by_limit = False
        while next_url and page_count < max_pages:
            data, headers = self.get_json(next_url)
            page_count += 1
            if page_count == 1 and isinstance(data, dict):
                first_metadata = {
                    "total_count": int(data.get("total_count", 0)),
                    "incomplete_results": bool(data.get("incomplete_results", False)),
                }
            page_rows = data.get(item_key, []) if item_key and isinstance(data, dict) else data
            if not isinstance(page_rows, list):
                raise ValueError("paginated GitHub response is not a list")
            rows.extend(item for item in page_rows if isinstance(item, dict))
            next_url = _next_link(headers.get("link", ""))
            if stop_after is not None and len(rows) >= stop_after:
                rows = rows[:stop_after]
                stopped_by_limit = bool(next_url)
                break
        return rows, {
            **first_metadata,
            "pages": page_count,
            "page_cap_hit": bool(next_url and not stopped_by_limit),
            "stopped_by_limit": stopped_by_limit,
        }


def _next_link(value: str) -> str | None:
    for part in value.split(","):
        match = re.search(r'<([^>]+)>;\s*rel="([^"]+)"', part.strip())
        if match and match.group(2) == "next":
            return match.group(1)
    return None


def _repo_name(repository_url: str) -> str:
    parts = [part for part in urlparse(repository_url).path.split("/") if part]
    if len(parts) < 3 or parts[-3] != "repos":
        raise ValueError("unexpected repository URL: " + repository_url)
    return "/".join(parts[-2:])


def _raw_diff_files(diff: str) -> list[tuple[str, str]]:
    output = []
    for section in re.split(r"(?=^diff --git )", diff or "", flags=re.MULTILINE):
        match = re.search(r"^\+\+\+\s+(.+)$", section, re.MULTILINE)
        if not match:
            continue
        filename = match.group(1).strip()
        if filename == "/dev/null":
            continue
        if filename.startswith("b/"):
            filename = filename[2:]
        output.append((filename, section))
    return output


def _valid_agent_source(item: dict, app_slug: str) -> bool:
    user = item.get("user") or {}
    return (
        user.get("type") == "Bot"
        and user.get("html_url") == f"https://github.com/apps/{app_slug}"
    )


def _wilson(successes: int, total: int) -> tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    z = 1.959963984540054
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return center - margin, center + margin


def run_screening(
    *,
    start: date,
    end: date,
    window_days: int,
    max_prs: int,
    output_dir: Path,
    cache_dir: Path,
    agent_ids: tuple[str, ...],
    base_url: str = "https://api.github.com",
    token: str = "",
    offline: bool = False,
    refresh: bool = False,
    max_file_pages: int = 30,
    transport=None,
    metadata_mode: str = "api",
    diff_delay: float = 0.0,
) -> dict[str, object]:
    if max_prs < 1:
        raise ValueError("max_prs must be positive")
    unknown = set(agent_ids) - set(AGENTS)
    if unknown:
        raise ValueError("unknown agents: " + ", ".join(sorted(unknown)))
    if offline and refresh:
        raise ValueError("offline and refresh are mutually exclusive")
    if metadata_mode not in {"api", "search"}:
        raise ValueError("metadata_mode must be api or search")

    client = GitHubClient(
        base_url, token, cache_dir, offline=offline, refresh=refresh,
        transport=transport, diff_delay=diff_delay,
    )
    quotas = {agent: max_prs // len(agent_ids) for agent in agent_ids}
    for agent in agent_ids[: max_prs % len(agent_ids)]:
        quotas[agent] += 1

    selected: list[tuple[str, dict, str]] = []
    seen = set()
    search_stats = Counter()
    for agent in agent_ids:
        config = AGENTS[agent]
        remaining = quotas[agent]
        if remaining == 0:
            continue
        for window_start, window_end in date_windows(start, end, window_days):
            if remaining == 0:
                break
            qualifier = f"created:{window_start.isoformat()}..{window_end.isoformat()}"
            query = f"{config['query']} {qualifier}"
            url = base_url.rstrip("/") + "/search/issues?" + urlencode(
                {"q": query, "sort": "created", "order": "asc", "per_page": 100, "page": 1}
            )
            items, metadata = client.paginate(url, "items", 10, stop_after=remaining)
            search_stats["requests"] += int(metadata["pages"])
            search_stats["incomplete_windows"] += int(bool(metadata.get("incomplete_results")))
            search_stats["result_cap_windows"] += int(int(metadata.get("total_count", 0)) > 1000)
            search_stats["page_cap_windows"] += int(bool(metadata.get("page_cap_hit")))
            window_label = f"{window_start.isoformat()}..{window_end.isoformat()}"
            for item in items:
                repository_url = str(item.get("repository_url") or "")
                key = (repository_url, item.get("number"))
                if key in seen:
                    continue
                seen.add(key)
                if not _valid_agent_source(item, str(config["app_slug"])):
                    search_stats["source_rejected"] += 1
                    continue
                selected.append((agent, item, window_label))
                remaining -= 1
                if remaining == 0:
                    break

    evidence_rows = []
    log_rows = []
    for agent, item, window_label in selected:
        config = AGENTS[agent]
        pull_summary = item.get("pull_request") or {}
        pull_url = str(pull_summary.get("url") or "")
        repo = _repo_name(str(item["repository_url"]))
        line_inputs = []
        raw_diff = ""
        commits: list[dict] = []
        commit_page_cap = False
        patch_missing = 0
        file_page_cap = False
        if metadata_mode == "api":
            detail, _ = client.get_json(pull_url)
            detail_source = "rest_pr+rest_files"
            diff_completeness = "api_reported_with_explicit_missing_patch_flags"
            if not isinstance(detail, dict) or not detail.get("merged_at"):
                search_stats["unmerged_rejected"] += 1
                continue
            files_url = pull_url.rstrip("/") + "/files?" + urlencode({"per_page": 100, "page": 1})
            files, file_metadata = client.paginate(files_url, None, max_file_pages)
            file_page_cap = bool(file_metadata.get("page_cap_hit"))
            files_returned = len(files)
            file_pages = int(file_metadata["pages"])
            for file_item in files:
                filename = str(file_item.get("filename") or "")
                if not is_source_file(filename):
                    continue
                patch = file_item.get("patch")
                if not isinstance(patch, str):
                    patch_missing += 1
                    continue
                for line_number, line in added_lines(patch):
                    source_url = str(file_item.get("blob_url") or "") + f"#L{line_number}"
                    line_inputs.append((filename, line_number, line, source_url))
            api_incomplete = bool(patch_missing or file_page_cap)
            diff_url = str(
                pull_summary.get("diff_url")
                or detail.get("diff_url")
                or (str(detail.get("html_url") or item.get("html_url") or "") + ".diff")
            )
            raw_diff, _ = client.get_text(diff_url)
            commits_url = pull_url.rstrip("/") + "/commits?" + urlencode({"per_page": 100, "page": 1})
            commits, commit_metadata = client.paginate(commits_url, None, max_file_pages)
            commit_page_cap = bool(commit_metadata.get("page_cap_hit"))
            api_incomplete = bool(api_incomplete or commit_page_cap)
        else:
            merged_at = str(pull_summary.get("merged_at") or "")
            diff_url = str(pull_summary.get("diff_url") or "")
            if not merged_at or not diff_url:
                search_stats["unmerged_rejected"] += 1
                continue
            raw_diff, _ = client.get_text(diff_url)
            raw_files = _raw_diff_files(raw_diff)
            detail = {
                "number": item.get("number"),
                "html_url": item.get("html_url"),
                "merged_at": merged_at,
                "merge_commit_sha": "",
                "head": {"sha": ""},
                "base": {"sha": ""},
                "changed_files": 0,
            }
            detail_source = "search_result+raw_diff"
            diff_completeness = "unknown_github_raw_diff_limits"
            files_returned = len(raw_files)
            file_pages = 0
            api_incomplete = True
            for filename, patch in raw_files:
                if not is_source_file(filename):
                    continue
                for line_number, line in added_lines(patch):
                    line_inputs.append(
                        (filename, line_number, line, str(item.get("html_url") or "") + "/files")
                    )

        if not isinstance(detail, dict) or not detail.get("merged_at"):
            search_stats["unmerged_rejected"] += 1
            continue
        number = int(detail.get("number") or item["number"])
        pr_key = f"{repo}#{number}"
        head_sha = str((detail.get("head") or {}).get("sha") or "")
        head_commit = next((row for row in reversed(commits) if str(row.get("sha") or "") == head_sha), None)
        if head_commit is None and commits:
            head_commit = commits[-1]
        commit_detail = (head_commit or {}).get("commit") or {}
        head_tree_sha = str((commit_detail.get("tree") or {}).get("sha") or "")
        head_committed_at = str(
            (commit_detail.get("committer") or {}).get("date")
            or (commit_detail.get("author") or {}).get("date")
            or ""
        )
        evidence = {
            "head_tree_sha": head_tree_sha,
            "head_committed_at": head_committed_at,
            "pr_diff_sha256": sha256_text(raw_diff),
            "canonical_patch_sha256": canonical_patch_sha256(raw_diff),
            "commit_list_sha256": sha256_json(commits) if commits else "",
            "metadata_sha256": sha256_json(detail),
            "provenance_grade": "C",
            "generation_stage": "merged_final_unresolved_actor",
            "evidence_chain_status": (
                "complete_github_snapshot"
                if metadata_mode == "api" and head_sha and raw_diff and commits and not api_incomplete
                else "partial_api_snapshot"
                if metadata_mode == "api"
                else "partial_search_snapshot"
            ),
        }
        pr_logs = []
        for filename, line_number, line, source_url in line_inputs:
            executable, features, concepts = classify_log(filename, line)
            if not executable:
                continue
            pr_logs.append(
                {
                        "dataset": "GitHub",
                        "provenance": "AGENT_SOURCE_CANDIDATE",
                        "provenance_evidence": "github_search_author_app;actor_type=Bot;actor_app_url=" + str((item.get("user") or {}).get("html_url") or ""),
                        "provenance_granularity": "pull_request",
                        "evidence_level": "static",
                        "adoption_evidence": "merged_pull_request",
                        "agent": agent,
                        "source_app_slug": config["app_slug"],
                        "actor_login": str((item.get("user") or {}).get("login") or ""),
                        "repo": repo,
                        "pr_number": number,
                        "pr_key": pr_key,
                        "pr_url": str(detail.get("html_url") or item.get("html_url") or ""),
                        "created_at": str(item.get("created_at") or ""),
                        "merged_at": str(detail["merged_at"]),
                        "merge_commit_sha": str(detail.get("merge_commit_sha") or ""),
                        "head_sha": head_sha,
                        "base_sha": str((detail.get("base") or {}).get("sha") or ""),
                        **evidence,
                        "file": filename,
                        "line": line_number,
                        "path_scope": "production" if is_production_path(filename) else "non_production",
                        "is_executable_log": "True",
                        "static_risk_candidate": "True" if features else "False",
                        "risk_features": ";".join(features),
                        "log_concepts": ";".join(concepts),
                        "log_text_redacted": redact_excerpt(line.strip()),
                        "source_url": source_url,
                        "api_diff_incomplete": "",
                        "query_window": window_label,
                }
            )
        for row in pr_logs:
            row["api_diff_incomplete"] = "True" if api_incomplete else "False"
        log_rows.extend(pr_logs)
        event_app = item.get("performed_via_github_app") or {}
        evidence_rows.append(
            {
                "dataset": "GitHub",
                "provenance": "AGENT_SOURCE_CANDIDATE",
                "provenance_granularity": "pull_request",
                "agent": agent,
                "source_app_slug": config["app_slug"],
                "performed_via_app_slug": str(event_app.get("slug") or ""),
                "actor_login": str((item.get("user") or {}).get("login") or ""),
                "actor_type": str((item.get("user") or {}).get("type") or ""),
                "actor_app_url": str((item.get("user") or {}).get("html_url") or ""),
                "repo": repo,
                "pr_number": number,
                "pr_key": pr_key,
                "pr_url": str(detail.get("html_url") or item.get("html_url") or ""),
                "created_at": str(item.get("created_at") or ""),
                "merged_at": str(detail["merged_at"]),
                "merge_commit_sha": str(detail.get("merge_commit_sha") or ""),
                "head_sha": head_sha,
                "base_sha": str((detail.get("base") or {}).get("sha") or ""),
                **evidence,
                "pr_diff_url": diff_url,
                "commits_url": commits_url if metadata_mode == "api" else "",
                "commit_count": len(commits),
                "commit_page_cap_hit": commit_page_cap,
                "detail_source": detail_source,
                "diff_completeness": diff_completeness,
                "changed_files_reported": int(detail.get("changed_files") or 0),
                "files_returned": files_returned,
                "file_pages": file_pages,
                "patch_missing_files": patch_missing,
                "file_page_cap_hit": file_page_cap,
                "api_diff_incomplete": api_incomplete,
                "n_added_logs": len(pr_logs),
                "n_static_risk_candidates": sum(row["static_risk_candidate"] == "True" for row in pr_logs),
                "query_window": window_label,
            }
        )

    evidence_rows.sort(key=lambda row: (row["agent"], row["repo"], row["pr_number"]))
    log_rows.sort(key=lambda row: (row["agent"], row["repo"], row["pr_number"], row["file"], row["line"], row["log_text_redacted"]))
    summary = _summary(start, end, window_days, max_prs, agent_ids, evidence_rows, log_rows, search_stats, bool(token), metadata_mode)
    _write_outputs(Path(output_dir), evidence_rows, log_rows, summary)
    return summary


def _summary(
    start: date,
    end: date,
    window_days: int,
    max_prs: int,
    agent_ids: tuple[str, ...],
    evidence_rows: list[dict],
    log_rows: list[dict],
    search_stats: Counter,
    authenticated: bool,
    metadata_mode: str,
) -> dict[str, object]:
    candidates = sum(row["static_risk_candidate"] == "True" for row in log_rows)
    low, high = _wilson(candidates, len(log_rows))
    production_logs = [row for row in log_rows if row["path_scope"] == "production"]
    production_candidates = sum(row["static_risk_candidate"] == "True" for row in production_logs)
    production_low, production_high = _wilson(production_candidates, len(production_logs))
    by_agent = {}
    for agent in agent_ids:
        agent_prs = [row for row in evidence_rows if row["agent"] == agent]
        agent_logs = [row for row in log_rows if row["agent"] == agent]
        agent_candidates = sum(row["static_risk_candidate"] == "True" for row in agent_logs)
        agent_low, agent_high = _wilson(agent_candidates, len(agent_logs))
        by_agent[agent] = {
            "n_prs": len(agent_prs),
            "n_logs": len(agent_logs),
            "n_static_risk_candidates": agent_candidates,
            "candidate_rate": agent_candidates / len(agent_logs) if agent_logs else 0.0,
            "wilson95_low": agent_low,
            "wilson95_high": agent_high,
        }
    feature_counts = Counter()
    for row in log_rows:
        feature_counts.update(filter(None, row["risk_features"].split(";")))
    agent_native_candidates = sum(
        bool(set(row["risk_features"].split(";")) & AGENT_NATIVE_RISK_FEATURES) for row in log_rows
    )
    shared_sensitive_candidates = sum(
        bool(set(row["risk_features"].split(";")) & SHARED_SENSITIVE_RISK_FEATURES) for row in log_rows
    )
    return {
        "study_type": "high_confidence_enriched_candidate_pilot",
        "runtime_leak_claim": False,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "window_days": window_days,
        "max_prs": max_prs,
        "agents": list(agent_ids),
        "authenticated": authenticated,
        "metadata_mode": metadata_mode,
        "n_prs": len(evidence_rows),
        "n_repositories": len({row["repo"] for row in evidence_rows}),
        "n_logs": len(log_rows),
        "n_production_logs": len(production_logs),
        "n_static_risk_candidates": candidates,
        "n_production_static_risk_candidates": production_candidates,
        "n_agent_native_sensitive_candidates": agent_native_candidates,
        "n_shared_sensitive_candidates": shared_sensitive_candidates,
        "candidate_rate": candidates / len(log_rows) if log_rows else 0.0,
        "wilson95_low": low,
        "wilson95_high": high,
        "production_candidate_rate": production_candidates / len(production_logs) if production_logs else 0.0,
        "production_wilson95_low": production_low,
        "production_wilson95_high": production_high,
        "patch_missing_files": sum(int(row["patch_missing_files"]) for row in evidence_rows),
        "api_incomplete_prs": sum(bool(row["api_diff_incomplete"]) for row in evidence_rows),
        "complete_github_snapshot_prs": sum(
            row["evidence_chain_status"] == "complete_github_snapshot" for row in evidence_rows
        ),
        "provenance_grade_counts": dict(sorted(Counter(row["provenance_grade"] for row in evidence_rows).items())),
        "search_requests": int(search_stats["requests"]),
        "search_incomplete_windows": int(search_stats["incomplete_windows"]),
        "search_result_cap_windows": int(search_stats["result_cap_windows"]),
        "search_page_cap_windows": int(search_stats["page_cap_windows"]),
        "source_rejected": int(search_stats["source_rejected"]),
        "unmerged_rejected": int(search_stats["unmerged_rejected"]),
        "by_agent": by_agent,
        "risk_feature_counts": dict(sorted(feature_counts.items())),
    }


def _write_outputs(output_dir: Path, evidence_rows: list[dict], log_rows: list[dict], summary: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_text = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in evidence_rows)
    _atomic_write_text(output_dir / OUTPUT_NAMES[0], evidence_text)

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=CANDIDATE_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(log_rows)
    _atomic_write_text(output_dir / OUTPUT_NAMES[1], buffer.getvalue())
    _atomic_write_text(output_dir / OUTPUT_NAMES[2], json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    _atomic_write_text(output_dir / OUTPUT_NAMES[3], _report(summary))


def _report(summary: dict) -> str:
    lines = [
        "# GitHub Coding Agent 新增日志试筛报告",
        "",
        "## 结论边界",
        "",
        "本报告来自 GitHub App 原生作者证据和合并 PR diff。命中项均为静态风险候选，不代表代码已运行、敏感值已传播或日志已外发。",
        "",
        "## 样本与结果",
        "",
        f"- 时间范围：{summary['start']} 至 {summary['end']}",
        f"- 来源 Agent：{', '.join(summary['agents'])}",
        f"- 元数据/diff 模式：{summary['metadata_mode']}",
        f"- PR：{summary['n_prs']}，仓库：{summary['n_repositories']}",
        f"- 新增可执行日志：{summary['n_logs']}，其中生产路径：{summary['n_production_logs']}",
        f"- 静态风险候选：{summary['n_static_risk_candidates']}，生产路径候选：{summary['n_production_static_risk_candidates']}",
        f"- Agent 原生敏感数据候选（模型上下文/工具 I/O）：{summary['n_agent_native_sensitive_candidates']}",
        f"- 共有敏感数据候选（凭证配置/请求响应/身份会话）：{summary['n_shared_sensitive_candidates']}",
        f"- 候选率：{summary['candidate_rate']:.4f}，Wilson 95% CI [{summary['wilson95_low']:.4f}, {summary['wilson95_high']:.4f}]",
        f"- 生产路径候选率：{summary['production_candidate_rate']:.4f}，Wilson 95% CI "
        f"[{summary['production_wilson95_low']:.4f}, {summary['production_wilson95_high']:.4f}]",
        "",
        "| Agent | PR | 日志 | 静态候选 | 候选率 | Wilson 95% CI |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for agent, values in summary["by_agent"].items():
        lines.append(
            f"| {agent} | {values['n_prs']} | {values['n_logs']} | {values['n_static_risk_candidates']} | "
            f"{values['candidate_rate']:.4f} | [{values['wilson95_low']:.4f}, {values['wilson95_high']:.4f}] |"
        )
    lines.extend(["", "## 风险特征分布", ""])
    if summary["risk_feature_counts"]:
        lines.extend(["| 特征 | 命中日志数 |", "| --- | ---: |"]) 
        for feature, count in summary["risk_feature_counts"].items():
            lines.append(f"| {feature} | {count} |")
    else:
        lines.append("本次样本没有静态风险特征命中。")
    lines.extend(
        [
            "",
            "## API 完整性",
            "",
            f"- 缺失 patch 的源代码文件：{summary['patch_missing_files']}",
            f"- diff 可能不完整的 PR：{summary['api_incomplete_prs']}",
            f"- GitHub 元数据、diff、commit 链齐全的 PR：{summary['complete_github_snapshot_prs']}",
            f"- 当前来源等级：{json.dumps(summary['provenance_grade_counts'], ensure_ascii=False, sort_keys=True)}",
            f"- 搜索返回 incomplete_results 的窗口：{summary['search_incomplete_windows']}",
            f"- 搜索总量超过 1,000 的窗口：{summary['search_result_cap_windows']}",
            f"- 本轮认证状态：{'已认证' if summary['authenticated'] else '匿名公共 API'}",
            "",
            "## 解释限制",
            "",
            "- 这是按 Agent App 来源富集的候选样本，不是 GitHub 总体概率样本。",
            "- PR 级 Agent 来源不等于逐行作者证明；人类可能在同一 PR 中追加或修改代码。",
            (
                "- search 模式使用 GitHub 公开 raw diff；由于无法通过文件 API 核对，所有 PR 的 diff 完整性均标为未知。"
                if summary["metadata_mode"] == "search"
                else "- REST 文件结果中缺失 patch 的 PR，需通过本地 git diff 补齐后才能用于完整率计算。"
            ),
            "- 只有验证执行可达、动态敏感值传播和外发或持久化位置后，才能标记 RUNTIME_LEAK_CONFIRMED。",
            "",
        ]
    )
    return "\n".join(lines)


def verify_outputs(output_dir: Path) -> list[str]:
    output_dir = Path(output_dir)
    errors = []
    for name in OUTPUT_NAMES:
        if not (output_dir / name).exists():
            errors.append("missing output: " + name)
    if errors:
        return errors
    try:
        evidence = [json.loads(line) for line in (output_dir / OUTPUT_NAMES[0]).read_text(encoding="utf-8").splitlines() if line]
        with (output_dir / OUTPUT_NAMES[1]).open(encoding="utf-8", newline="") as handle:
            logs = list(csv.DictReader(handle))
        summary = json.loads((output_dir / OUTPUT_NAMES[2]).read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return ["cannot parse outputs: " + str(exc)]

    pr_keys = [row.get("pr_key") for row in evidence]
    if len(pr_keys) != len(set(pr_keys)):
        errors.append("duplicate PR evidence keys")
    for row in evidence:
        if row.get("provenance") != "AGENT_SOURCE_CANDIDATE":
            errors.append("invalid provenance for " + str(row.get("pr_key")))
        if not row.get("merged_at"):
            errors.append("missing merged_at for " + str(row.get("pr_key")))
        slug = row.get("source_app_slug")
        if slug not in {config["app_slug"] for config in AGENTS.values()}:
            errors.append("unknown source app slug for " + str(row.get("pr_key")))
        if row.get("provenance_grade") not in {None, "", "C"}:
            errors.append("GitHub App evidence without session binding must remain grade C: " + str(row.get("pr_key")))
        for field in ("pr_diff_sha256", "canonical_patch_sha256", "metadata_sha256"):
            value = str(row.get(field) or "")
            if value and not re.fullmatch(r"[0-9a-f]{64}", value):
                errors.append(f"invalid {field} for " + str(row.get("pr_key")))
        if row.get("evidence_chain_status") == "complete_github_snapshot" and not all(
            row.get(field) for field in (
                "base_sha", "head_sha", "head_tree_sha", "head_committed_at",
                "pr_diff_sha256", "canonical_patch_sha256", "commit_list_sha256", "metadata_sha256",
            )
        ):
            errors.append("complete evidence snapshot is missing an anchor for " + str(row.get("pr_key")))
    evidence_keys = set(pr_keys)
    for row in logs:
        if row.get("pr_key") not in evidence_keys:
            errors.append("log without PR evidence: " + str(row.get("pr_key")))
        if (row.get("static_risk_candidate") == "True") != bool(row.get("risk_features")):
            errors.append("risk flag cannot be recomputed for " + str(row.get("source_url")))
        excerpt = row.get("log_text_redacted", "")
        if re.search(r"\bgh[opsu]_[A-Za-z0-9]{20,}\b", excerpt) or re.search(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", excerpt, re.IGNORECASE):
            errors.append("unredacted sensitive shape in " + str(row.get("source_url")))
    recomputed = {
        "n_prs": len(evidence),
        "n_repositories": len({row.get("repo") for row in evidence}),
        "n_logs": len(logs),
        "n_production_logs": sum(row.get("path_scope") == "production" for row in logs),
        "n_static_risk_candidates": sum(row.get("static_risk_candidate") == "True" for row in logs),
        "n_production_static_risk_candidates": sum(row.get("path_scope") == "production" and row.get("static_risk_candidate") == "True" for row in logs),
        "n_agent_native_sensitive_candidates": sum(
            bool(set(row.get("risk_features", "").split(";")) & AGENT_NATIVE_RISK_FEATURES)
            for row in logs
        ),
        "n_shared_sensitive_candidates": sum(
            bool(set(row.get("risk_features", "").split(";")) & SHARED_SENSITIVE_RISK_FEATURES)
            for row in logs
        ),
        "patch_missing_files": sum(int(row.get("patch_missing_files", 0)) for row in evidence),
        "api_incomplete_prs": sum(bool(row.get("api_diff_incomplete")) for row in evidence),
        "complete_github_snapshot_prs": sum(
            row.get("evidence_chain_status") == "complete_github_snapshot" for row in evidence
        ),
        "provenance_grade_counts": dict(sorted(Counter(row.get("provenance_grade", "") for row in evidence).items())),
    }
    production_n = recomputed["n_production_logs"]
    production_candidates = recomputed["n_production_static_risk_candidates"]
    production_low, production_high = _wilson(production_candidates, production_n)
    recomputed.update(
        {
            "production_candidate_rate": production_candidates / production_n if production_n else 0.0,
            "production_wilson95_low": production_low,
            "production_wilson95_high": production_high,
        }
    )
    legacy_optional = {"complete_github_snapshot_prs", "provenance_grade_counts"}
    for key, value in recomputed.items():
        if key in legacy_optional and key not in summary:
            continue
        if summary.get(key) != value:
            errors.append(f"summary mismatch for {key}: {summary.get(key)!r} != {value!r}")
    return errors


def _parse_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", type=_parse_date)
    parser.add_argument("--end", type=_parse_date)
    parser.add_argument("--window-days", type=int, default=1)
    parser.add_argument("--max-prs", type=int, default=15)
    parser.add_argument("--agent", action="append", choices=tuple(AGENTS))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/github_agent_screening"))
    parser.add_argument("--cache-dir", type=Path, default=Path("data/res/github_agent_logs"))
    parser.add_argument("--max-file-pages", type=int, default=30)
    parser.add_argument("--metadata-mode", choices=("search", "api"), default="search")
    parser.add_argument("--diff-delay", type=float, default=0.0)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--offline", action="store_true")
    mode.add_argument("--refresh", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    if args.verify_only:
        errors = verify_outputs(args.output_dir)
        print(json.dumps({"ok": not errors, "errors": errors}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(1 if errors else 0)
    if args.start is None or args.end is None:
        parser.error("--start and --end are required unless --verify-only is used")
    if args.window_days < 1 or args.max_file_pages < 1 or args.diff_delay < 0:
        parser.error("--window-days and --max-file-pages must be positive; --diff-delay must be nonnegative")
    agents = tuple(args.agent or AGENTS.keys())
    try:
        summary = run_screening(
            start=args.start,
            end=args.end,
            window_days=args.window_days,
            max_prs=args.max_prs,
            output_dir=args.output_dir,
            cache_dir=args.cache_dir,
            agent_ids=agents,
            token=os.environ.get("GITHUB_TOKEN", ""),
            offline=args.offline,
            refresh=args.refresh,
            max_file_pages=args.max_file_pages,
            metadata_mode=args.metadata_mode,
            diff_delay=args.diff_delay,
        )
        errors = verify_outputs(args.output_dir)
    except (RuntimeError, ValueError) as exc:
        parser.exit(2, "error: " + str(exc) + "\n")
    if errors:
        parser.exit(1, "verification failed: " + "; ".join(errors) + "\n")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
