import argparse
import csv
import difflib
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Iterable

import pandas as pd


DEFAULT_SWE_CHAT_DIR = Path("data/repos/SWE-chat")
DEFAULT_OUTPUT_DIR = Path("data/res/swe_chat_multilingual_logs")


LOG_PATTERNS = [
    # TypeScript / JavaScript
    r"\bconsole\s*\.\s*(log|error|warn|debug|info|trace)\s*\(",
    r"\b(logger|log)\s*\.\s*(debug|info|warn|warning|error|trace|fatal)\s*\(",
    # Python
    r"\b(logging|logger|log)\s*\.\s*(debug|info|warning|warn|error|exception|critical)\s*\(",
    r"\bprint\s*\(",
    # Go
    r"\b(log)\s*\.\s*(Print|Printf|Println|Fatal|Fatalf|Panic|Panicf)\s*\(",
    r"\b(fmt)\s*\.\s*(Print|Printf|Println|Fprint|Fprintf|Fprintln)\s*\(",
    # Rust
    r"\b(println|eprintln|dbg)\s*!\s*\(",
    r"\b(debug|info|warn|error|trace)\s*!\s*\(",
    # Java / Kotlin / Swift
    r"\bSystem\s*\.\s*(out|err)\s*\.\s*print(ln)?\s*\(",
    r"\bLog\s*\.\s*(d|i|w|e|v)\s*\(",
    r"\bNSLog\s*\(",
    r"\bprint\s*\(",
    # Ruby / PHP / Shell-ish source files
    r"\bputs\s+",
    r"\bprint\s+",
    r"\becho\s+",
    r"\bprintf\s+",
]

LOG_RE = re.compile("|".join(f"(?:{p})" for p in LOG_PATTERNS), re.IGNORECASE)

PROMPT_LOG_RE = re.compile(
    r"\b(log|logging|logger|console|debug|trace|print|stdout|stderr|error message|error output)\b",
    re.IGNORECASE,
)

HIGH_RISK_KEYWORDS = [
    "secret",
    "token",
    "api_key",
    "apikey",
    "password",
    "credential",
    "authorization",
    "bearer",
    "header",
    "headers",
    "cookie",
    "private_key",
    "access_key",
    "jwt",
]

MEDIUM_RISK_KEYWORDS = [
    "response",
    "error",
    "exception",
    "user",
    "session",
    "payload",
    "request",
    "body",
    "email",
    "phone",
    "address",
]

STRING_LITERAL_RE = re.compile(
    r"(?P<quote>['\"])(?:\\.|(?! (?P=quote)).)*(?P=quote)",
    re.VERBOSE,
)
FORMAT_PLACEHOLDER_RE = re.compile(r"(%[sdv]|{\w*}|#\{[^}]+\}|\$\{[^}]+\})")

SOURCE_EXTENSIONS = {
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".py",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".swift",
    ".cs",
    ".rb",
    ".php",
    ".dart",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hpp",
    ".sh",
    ".bash",
    ".zsh",
    ".vue",
    ".svelte",
    ".astro",
    ".ex",
    ".exs",
    ".zig",
    ".fs",
    ".fsx",
    ".r",
}

SOURCE_FILENAMES = {
    "dockerfile",
    "makefile",
}

EXCLUDED_PATH_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".next",
    ".nuxt",
    ".turbo",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "vendors",
    "dist",
    "build",
    "target",
    "out",
    "coverage",
    "__pycache__",
}

EXCLUDED_FILE_SUFFIXES = {
    ".md",
    ".mdx",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".lock",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".rar",
    ".7z",
    ".o",
    ".a",
    ".so",
    ".dylib",
    ".dll",
    ".class",
    ".jar",
    ".wasm",
}


@dataclass
class LogCandidate:
    repo: str
    commit: str
    checkpoint_pk: str
    file: str
    line: int
    add_remove: str
    attribution: str
    sensitive_keyword_hit: bool
    sensitive_keywords: str
    risk_level: str
    log_text: str
    commit_message: str
    author_date: str
    is_agent_author: bool
    agent_log_edit_same_file: bool
    agent_log_edit_sample: str
    prompt_intents: str
    prompt_pushbacks: str
    user_log_reason_excerpt: str
    manual_review_label: str
    manual_review_evidence: str


@dataclass
class RepositoryInfo:
    repo: str
    language: str


def parse_jsonish(value: object, fallback):
    if not isinstance(value, str) or not value.strip():
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def metadata_value(metadata: object, key: str) -> object:
    data = parse_jsonish(metadata, {})
    if not isinstance(data, dict):
        return None
    return data.get(key)


def normalize_repo_path(path: str, repo_id: str) -> str:
    if not path:
        return ""
    path = path.replace("\\", "/")
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    marker = "/" + repo_id.split("/", 1)[-1] + "/"
    if marker in path:
        return path.split(marker, 1)[1]
    safe_repo = repo_id.replace("/", "__")
    marker = "/" + safe_repo + "/"
    if marker in path:
        return path.split(marker, 1)[1]
    return path.lstrip("/")


def strip_string_literals(text: str) -> str:
    return STRING_LITERAL_RE.sub("", text)


def has_dynamic_output(text: str) -> bool:
    outside = strip_string_literals(text)
    if "," in outside:
        return True
    if FORMAT_PLACEHOLDER_RE.search(text):
        return True
    return bool(re.search(r"\b(request|response|headers?|cookies?|token|payload|session|user|error|err)\b\s*[.)\]}]", outside, re.I))


def risk_for_text(text: str) -> tuple[str, list[str]]:
    lower = text.lower()
    outside_lower = strip_string_literals(text).lower()
    hits = []
    for keyword in HIGH_RISK_KEYWORDS + MEDIUM_RISK_KEYWORDS:
        if keyword in lower:
            hits.append(keyword)
    high_outside = [k for k in HIGH_RISK_KEYWORDS if k in outside_lower]
    medium_outside = [k for k in MEDIUM_RISK_KEYWORDS if k in outside_lower]
    if high_outside:
        return "high", hits
    if medium_outside:
        return "medium", hits
    if any(k in hits for k in HIGH_RISK_KEYWORDS):
        return ("medium" if has_dynamic_output(text) else "low"), hits
    if hits:
        return ("medium" if has_dynamic_output(text) else "low"), hits
    return "low", []


def is_log_line(text: str) -> bool:
    return bool(LOG_RE.search(text))


def is_source_file(path: str) -> bool:
    if not path:
        return False
    clean = path.replace("\\", "/").strip()
    if clean.startswith(("a/", "b/")):
        clean = clean[2:]
    if clean in {"/dev/null", "dev/null"}:
        return False
    parts = [part.lower() for part in clean.split("/") if part]
    if any(part in EXCLUDED_PATH_PARTS for part in parts):
        return False

    name = parts[-1] if parts else ""
    if name in SOURCE_FILENAMES or name.startswith("dockerfile."):
        return True
    suffix = Path(name).suffix.lower()
    if suffix in EXCLUDED_FILE_SUFFIXES:
        return False
    return suffix in SOURCE_EXTENSIONS


def parse_patch_log_lines(patch: str) -> Iterable[tuple[str, int, str, str]]:
    current_file = ""
    old_file = ""
    old_line = 0
    new_line = 0
    for raw in (patch or "").splitlines():
        if raw.startswith("diff --git "):
            parts = raw.split()
            if len(parts) >= 4:
                old_file = parts[2]
                if old_file.startswith("a/"):
                    old_file = old_file[2:]
                current_file = parts[3]
                if current_file.startswith("b/"):
                    current_file = current_file[2:]
            continue
        if raw.startswith("--- "):
            path = raw[4:].strip()
            if path != "/dev/null":
                old_file = path[2:] if path.startswith("a/") else path
            continue
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path == "/dev/null":
                current_file = old_file
            else:
                current_file = path[2:] if path.startswith("b/") else path
            continue
        if raw.startswith("@@ "):
            m = re.search(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
            if m:
                old_line = int(m.group(1))
                new_line = int(m.group(2))
            continue
        if not current_file:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            text = raw[1:]
            if is_source_file(current_file) and is_log_line(text):
                yield current_file, new_line, "add", text
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            text = raw[1:]
            if is_source_file(current_file) and is_log_line(text):
                yield current_file, old_line, "remove", text
            old_line += 1
        else:
            if raw.startswith(" "):
                old_line += 1
                new_line += 1


def file_attribution_item_for(path: str, file_attribution: dict) -> dict:
    if not file_attribution:
        return {}
    if path in file_attribution:
        item = file_attribution[path]
        return item if isinstance(item, dict) else {}
    matches = [
        item
        for key, item in file_attribution.items()
        if isinstance(item, dict) and (key.endswith("/" + path) or path.endswith("/" + key))
    ]
    if matches:
        return matches[0]
    return {}


def file_attribution_for(path: str, file_attribution: dict) -> str:
    item = file_attribution_item_for(path, file_attribution)
    return item.get("attribution", "unknown") if item else "unknown"


def extract_log_lines_from_text(text: object) -> list[str]:
    if not isinstance(text, str) or not text:
        return []
    return [line.strip() for line in text.splitlines() if is_log_line(line)]


def nearest_log_line(target: str, candidates: list[str]) -> tuple[float, str]:
    if not candidates:
        return 0.0, ""
    scored = [
        (difflib.SequenceMatcher(a=target.strip(), b=c.strip()).ratio(), c)
        for c in candidates
    ]
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[0]


def classify_manual_review(
    text: str,
    add_remove: str,
    attribution: str,
    attr_item: dict,
    agent_samples: list[str],
) -> tuple[str, str]:
    if attribution != "mixed" or not agent_samples:
        return "not_review_target", ""

    agent_logs = extract_log_lines_from_text(attr_item.get("agent_version"))
    committed_logs = extract_log_lines_from_text(attr_item.get("committed_version"))
    clean_text = text.strip()
    agent_exact = clean_text in agent_logs
    committed_exact = clean_text in committed_logs
    sim, nearest = nearest_log_line(clean_text, agent_logs)

    if add_remove == "add" and committed_exact and not agent_exact and sim >= 0.72:
        return (
            "confirmed_by_version_diff_human_modified_ai_log",
            f"committed log differs from similar agent_version log (similarity={sim:.2f}): {nearest[:220]}",
        )
    if add_remove == "remove" and agent_exact and not committed_exact:
        return (
            "confirmed_by_version_diff_human_removed_ai_log",
            "removed log appears in agent_version but not committed_version",
        )
    if committed_exact and agent_exact:
        return (
            "mixed_file_agent_log_unchanged",
            "same log appears in both agent_version and committed_version",
        )
    if add_remove == "add" and committed_exact and not agent_exact:
        return (
            "likely_human_added_log_in_mixed_file",
            "committed log not found in agent_version and no close agent log match",
        )
    return (
        "same_file_agent_log_edit_needs_manual_review",
        "agent_changes contains same-file log edit, but version diff did not prove line-level human modification",
    )


def extract_agent_log_edits(agent_changes: list, repo_id: str) -> dict[str, list[str]]:
    by_file: dict[str, list[str]] = defaultdict(list)
    for change in agent_changes or []:
        if not isinstance(change, dict):
            continue
        file_path = normalize_repo_path(str(change.get("file_path") or ""), repo_id)
        if not file_path:
            continue
        snippets = []
        for key in ("old_string", "new_string", "content"):
            value = change.get(key)
            if isinstance(value, str):
                snippets.extend(line for line in value.splitlines() if is_log_line(line))
        for patch in change.get("structured_patch") or []:
            if not isinstance(patch, dict):
                continue
            for line in patch.get("lines") or []:
                if isinstance(line, str) and line[:1] in {"+", "-"} and is_log_line(line[1:]):
                    snippets.append(line)
        if snippets:
            by_file[file_path].extend(snippets[:10])
    return by_file


def compact_values(values: Iterable[object], limit: int = 5) -> str:
    out = []
    for value in values:
        if isinstance(value, str) and value and value not in out:
            out.append(value)
        if len(out) >= limit:
            break
    return "; ".join(out)


def compact_excerpt(values: Iterable[object], limit: int = 3, chars: int = 220) -> str:
    out = []
    for value in values:
        if isinstance(value, str) and value.strip():
            clean = re.sub(r"\s+", " ", value.strip())
            if PROMPT_LOG_RE.search(clean):
                out.append(clean[:chars])
        if len(out) >= limit:
            break
    return " || ".join(out)


def build_prompt_context(swe_chat_dir: Path) -> dict[str, dict[str, str]]:
    conv = pd.read_parquet(
        swe_chat_dir / "conversations.parquet",
        columns=["repo_id", "checkpoint_pk", "role", "turn_type", "content", "prompt_intent", "prompt_pushback"],
    )
    user_prompts = conv[(conv["role"] == "user") & (conv["turn_type"] == "user_prompt")].copy()
    context = {}
    for (repo_id, checkpoint_pk), group in user_prompts.groupby(["repo_id", "checkpoint_pk"], dropna=False):
        key = f"{repo_id}\t{checkpoint_pk}"
        context[key] = {
            "prompt_intents": compact_values(group["prompt_intent"].dropna().tolist()),
            "prompt_pushbacks": compact_values(group["prompt_pushback"].dropna().tolist()),
            "user_log_reason_excerpt": compact_excerpt(group["content"].dropna().tolist()),
        }
    return context


def load_repository_info(swe_chat_dir: Path) -> dict[str, RepositoryInfo]:
    repos = pd.read_parquet(
        swe_chat_dir / "repositories.parquet",
        columns=["repo_id", "repo_github_metadata"],
    )
    info = {}
    for row in repos.itertuples(index=False):
        language = metadata_value(row.repo_github_metadata, "language")
        info[row.repo_id] = RepositoryInfo(
            repo=row.repo_id,
            language=str(language or "Unknown"),
        )
    return info


def build_candidates(swe_chat_dir: Path) -> list[LogCandidate]:
    commits = pd.read_parquet(
        swe_chat_dir / "commits.parquet",
        columns=[
            "commit_sha",
            "checkpoint_pk",
            "repo_id",
            "author_date",
            "commit_message",
            "is_agent_author",
            "patch",
            "agent_changes",
            "file_attribution",
            "status",
        ],
    )
    commits = commits[commits["status"] == "ok"].copy()
    prompt_context = build_prompt_context(swe_chat_dir)
    candidates: list[LogCandidate] = []

    for row in commits.itertuples(index=False):
        patch = row.patch if isinstance(row.patch, str) else ""
        if not patch or not is_log_line(patch):
            continue
        file_attr = parse_jsonish(row.file_attribution, {})
        agent_logs_by_file = extract_agent_log_edits(parse_jsonish(row.agent_changes, []), row.repo_id)
        prompt = prompt_context.get(f"{row.repo_id}\t{row.checkpoint_pk}", {})
        for file_path, line, add_remove, text in parse_patch_log_lines(patch):
            attr_item = file_attribution_item_for(file_path, file_attr)
            attribution = attr_item.get("attribution", "unknown") if attr_item else "unknown"
            risk_level, keywords = risk_for_text(text)
            agent_samples = agent_logs_by_file.get(file_path, [])
            review_label, review_evidence = classify_manual_review(
                text, add_remove, attribution, attr_item, agent_samples
            )
            candidates.append(
                LogCandidate(
                    repo=row.repo_id,
                    commit=row.commit_sha,
                    checkpoint_pk=row.checkpoint_pk,
                    file=file_path,
                    line=line,
                    add_remove=add_remove,
                    attribution=attribution,
                    sensitive_keyword_hit=bool(keywords),
                    sensitive_keywords=";".join(keywords),
                    risk_level=risk_level,
                    log_text=text.strip(),
                    commit_message=str(row.commit_message or "").splitlines()[0][:240],
                    author_date=str(row.author_date),
                    is_agent_author=bool(row.is_agent_author),
                    agent_log_edit_same_file=bool(agent_samples),
                    agent_log_edit_sample=" || ".join(s.strip()[:180] for s in agent_samples[:3]),
                    prompt_intents=prompt.get("prompt_intents", ""),
                    prompt_pushbacks=prompt.get("prompt_pushbacks", ""),
                    user_log_reason_excerpt=prompt.get("user_log_reason_excerpt", ""),
                    manual_review_label=review_label,
                    manual_review_evidence=review_evidence,
                )
            )
    return candidates


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_outputs(candidates: list[LogCandidate], repo_info: dict[str, RepositoryInfo], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = [asdict(c) for c in candidates]
    candidate_columns = [field.name for field in fields(LogCandidate)]
    df = pd.DataFrame(rows, columns=candidate_columns)
    if not df.empty:
        df = df.drop_duplicates(
            subset=["repo", "commit", "file", "line", "add_remove", "log_text"],
            keep="first",
        ).reset_index(drop=True)
    csv_path = output_dir / "swe_chat_multilingual_log_candidates.csv"
    parquet_path = output_dir / "swe_chat_multilingual_log_candidates.parquet"
    df.to_csv(csv_path, index=False)
    df.to_parquet(parquet_path, index=False)

    pushback = df[
        (df["user_log_reason_excerpt"].fillna("") != "")
        | (df["prompt_pushbacks"].fillna("").str.contains("correction|failure|rejection|takeover", case=False, regex=True))
    ].copy()
    pushback.to_csv(output_dir / "swe_chat_log_pushback_reasons.csv", index=False)

    reason_prompts = pushback[
        [
            "repo",
            "checkpoint_pk",
            "prompt_intents",
            "prompt_pushbacks",
            "user_log_reason_excerpt",
        ]
    ].drop_duplicates()
    reason_prompts.to_csv(output_dir / "swe_chat_log_reason_prompts.csv", index=False)

    review = df[(df["attribution"] == "mixed") & (df["agent_log_edit_same_file"])].copy()
    if not review.empty:
        review["review_note"] = (
            "file_attribution=mixed and agent_changes contains a log edit in the same file; "
            "manual_review_label is based on agent_version versus committed_version when available."
        )
    review.to_csv(output_dir / "swe_chat_mixed_attribution_manual_review.csv", index=False)

    repos_with_candidates = set(df["repo"].dropna().unique()) if not df.empty else set()
    no_candidate_rows = [
        asdict(info)
        for repo, info in sorted(repo_info.items())
        if repo not in repos_with_candidates
    ]
    write_csv(output_dir / "swe_chat_no_candidate_repos.csv", no_candidate_rows)

    summary = {
        "total_repositories_considered": len(repo_info),
        "candidate_rows": len(df),
        "repos": int(df["repo"].nunique()) if not df.empty else 0,
        "repos_with_candidates": len(repos_with_candidates),
        "repos_without_candidates": len(no_candidate_rows),
        "commits": int(df["commit"].nunique()) if not df.empty else 0,
        "by_add_remove": df["add_remove"].value_counts().to_dict() if not df.empty else {},
        "by_attribution": df["attribution"].value_counts().to_dict() if not df.empty else {},
        "by_risk_level": df["risk_level"].value_counts().to_dict() if not df.empty else {},
        "by_repo_language": (
            pd.Series([repo_info[repo].language for repo in repos_with_candidates if repo in repo_info])
            .value_counts()
            .to_dict()
            if repos_with_candidates
            else {}
        ),
        "sensitive_keyword_rows": int(df["sensitive_keyword_hit"].sum()) if not df.empty else 0,
        "pushback_reason_rows": int(len(pushback)),
        "reason_prompt_rows": int(len(reason_prompts)),
        "mixed_manual_review_rows": int(len(review)),
        "manual_review_labels": review["manual_review_label"].value_counts().to_dict() if not review.empty else {},
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_markdown_summary(output_dir / "summary.md", df, review, summary)


def top_counts(df: pd.DataFrame, col: str, n: int = 10) -> str:
    if df.empty:
        return "_No rows._"
    lines = ["| Value | Rows |", "| --- | ---: |"]
    for value, count in df[col].value_counts(dropna=False).head(n).items():
        lines.append(f"| `{value}` | {count} |")
    return "\n".join(lines)


def write_markdown_summary(path: Path, df: pd.DataFrame, review: pd.DataFrame, summary: dict) -> None:
    risk_table = top_counts(df, "risk_level")
    attr_table = top_counts(df, "attribution")
    repo_table = top_counts(df, "repo")
    review_examples = "_No mixed-attribution review rows found._"
    if not review.empty:
        label_order = {
            "confirmed_by_version_diff_human_modified_ai_log": 0,
            "confirmed_by_version_diff_human_removed_ai_log": 1,
            "same_file_agent_log_edit_needs_manual_review": 2,
            "likely_human_added_log_in_mixed_file": 3,
            "mixed_file_agent_log_unchanged": 4,
        }
        review = review.assign(
            _label_order=review["manual_review_label"].map(label_order).fillna(99)
        ).sort_values(["_label_order", "risk_level", "repo", "file", "line"])
        lines = ["| Repo | Commit | File | Line | Risk | Evidence |", "| --- | --- | --- | ---: | --- | --- |"]
        for r in review.head(15).itertuples(index=False):
            evidence = str(r.manual_review_evidence or r.agent_log_edit_sample).replace("|", "/")[:160]
            lines.append(f"| `{r.repo}` | `{str(r.commit)[:12]}` | `{r.file}` | {r.line} | {r.risk_level} | {evidence} |")
        review_examples = "\n".join(lines)
    label_table = "_No mixed-attribution review rows found._"
    if summary.get("manual_review_labels"):
        lines = ["| Label | Rows |", "| --- | ---: |"]
        for label, count in summary["manual_review_labels"].items():
            lines.append(f"| `{label}` | {count} |")
        label_table = "\n".join(lines)

    path.write_text(
        f"""# SWE-chat Multilingual Log Candidate Summary

## Outputs

- `swe_chat_multilingual_log_candidates.csv`: full candidate detail table.
- `swe_chat_multilingual_log_candidates.parquet`: parquet copy of the same table.
- `swe_chat_log_pushback_reasons.csv`: candidates joined to user prompt intent/pushback and log-related prompt excerpts.
- `swe_chat_log_reason_prompts.csv`: de-duplicated repo/checkpoint-level natural-language reason excerpts.
- `swe_chat_mixed_attribution_manual_review.csv`: mixed-attribution rows where agent_changes also edited logs in the same file.
- `swe_chat_no_candidate_repos.csv`: repositories with no source-code log candidates.
- `summary.json`: machine-readable counts.

## Counts

| Metric | Value |
| --- | ---: |
| Total repositories considered | {summary["total_repositories_considered"]} |
| Candidate rows | {summary["candidate_rows"]} |
| Repositories with candidates | {summary["repos_with_candidates"]} |
| Repositories without candidates | {summary["repos_without_candidates"]} |
| Commits | {summary["commits"]} |
| Sensitive keyword rows | {summary["sensitive_keyword_rows"]} |
| Pushback/reason rows | {summary["pushback_reason_rows"]} |
| Reason prompt rows | {summary["reason_prompt_rows"]} |
| Mixed manual-review rows | {summary["mixed_manual_review_rows"]} |

## Risk Levels

{risk_table}

## Attribution

{attr_table}

## Top Repositories

{repo_table}

## Mixed-Attribution Review Examples

### Label Counts

{label_table}

### Priority Examples

{review_examples}
""",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate SWE-chat multilingual log candidate tables.")
    parser.add_argument("--swe-chat-dir", type=Path, default=DEFAULT_SWE_CHAT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    repo_info = load_repository_info(args.swe_chat_dir)
    candidates = build_candidates(args.swe_chat_dir)
    write_outputs(candidates, repo_info, args.output_dir)
    summary = json.loads((args.output_dir / "summary.json").read_text(encoding="utf-8"))
    print(
        f"Wrote {summary['candidate_rows']} log candidates from "
        f"{summary['repos_with_candidates']}/{summary['total_repositories_considered']} "
        f"repositories to {args.output_dir}"
    )


if __name__ == "__main__":
    main()
