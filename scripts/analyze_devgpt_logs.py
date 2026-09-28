import argparse
import base64
import binascii
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Iterable

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.analyze_swe_chat_multilingual_logs import (
    EXCLUDED_FILE_SUFFIXES,
    EXCLUDED_PATH_PARTS,
    FORMAT_PLACEHOLDER_RE,
    HIGH_RISK_KEYWORDS,
    LOG_RE,
    MEDIUM_RISK_KEYWORDS,
    PROMPT_LOG_RE,
    SOURCE_EXTENSIONS,
    SOURCE_FILENAMES,
    STRING_LITERAL_RE,
    compact_excerpt,
    compact_values,
    extract_log_lines_from_text,
    is_log_line,
    risk_for_text,
    strip_string_literals,
)


DEFAULT_DEVGPT_DIR = Path("data/repos/DevGPT")
DEFAULT_OUTPUT_DIR = Path("data/res/devgpt_logs")

DEVGPT_SOURCE_EXTENSIONS = SOURCE_EXTENSIONS | {
    ".cjs",
    ".css",
    ".html",
    ".htm",
    ".ipynb",
    ".less",
    ".lua",
    ".mjs",
    ".pl",
    ".ps1",
    ".sass",
    ".scala",
    ".scss",
    ".sql",
}

PUSHBACK_RE = re.compile(
    r"\b(error|exception|bug|fix|fail|failure|wrong|issue|problem|debug|trace|log|logging|logger|console)\b",
    re.IGNORECASE,
)

COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "--")


@dataclass
class DevGPTLogCandidate:
    repo: str
    repo_language: str
    snapshot: str
    source_type: str
    source_url: str
    chatgpt_url: str
    commit: str
    file: str
    line: int
    add_remove: str
    candidate_source: str
    attribution: str
    sensitive_keyword_hit: bool
    sensitive_keywords: str
    risk_level: str
    log_text: str
    commit_message: str
    author_date: str
    chatgpt_model: str
    conversation_index: int
    code_block_index: int
    code_block_type: str
    prompt_intents: str
    prompt_pushbacks: str
    user_log_reason_excerpt: str
    answer_log_excerpt: str
    manual_review_label: str
    manual_review_evidence: str


@dataclass
class RepositoryInfo:
    repo: str
    language: str


def snapshot_name(path: Path) -> str:
    return path.parent.name.replace("snapshot_", "")


def sharing_kind(path: Path) -> str:
    name = path.name
    if "_commit_sharings.json" in name:
        return "commit"
    if "_file_sharings.json" in name:
        return "code file"
    if "_pr_sharings.json" in name:
        return "pull request"
    if "_issue_sharings.json" in name:
        return "issue"
    if "_discussion_sharings.json" in name:
        return "discussion"
    if "_hn_sharings.json" in name:
        return "hacker news"
    return "unknown"


def load_sources(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        sources = data.get("Sources", [])
    else:
        sources = data
    return [item for item in sources if isinstance(item, dict)]


def clean_language(value: object) -> str:
    text = str(value or "").strip()
    if not text or text.lower() == "none":
        return "Unknown"
    return text


def choose_language(languages: Iterable[str]) -> str:
    cleaned = [clean_language(language) for language in languages]
    known = [language for language in cleaned if language != "Unknown"]
    if known:
        return Counter(known).most_common(1)[0][0]
    return "Unknown"


def normalize_commit_list(value: object) -> str:
    if isinstance(value, list):
        return ";".join(str(item) for item in value if item)
    text = str(value or "").strip()
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text.replace("'", '"'))
            if isinstance(parsed, list):
                return ";".join(str(item) for item in parsed if item)
        except json.JSONDecodeError:
            pass
    return text


def first_line(value: object, limit: int = 240) -> str:
    lines = str(value or "").splitlines()
    return lines[0][:limit] if lines else ""


def decode_content(value: object) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        raw = base64.b64decode(value, validate=False)
    except (binascii.Error, ValueError):
        return value
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def is_devgpt_source_file(path: str) -> bool:
    if not path:
        return False
    clean = path.replace("\\", "/").strip()
    if clean.startswith(("a/", "b/")):
        clean = clean[2:]
    parts = [part.lower() for part in clean.split("/") if part]
    if not parts or any(part in EXCLUDED_PATH_PARTS for part in parts):
        return False

    name = parts[-1]
    if name in SOURCE_FILENAMES or name.startswith("dockerfile."):
        return True
    suffix = Path(name).suffix.lower()
    if suffix in EXCLUDED_FILE_SUFFIXES:
        return False
    return suffix in DEVGPT_SOURCE_EXTENSIONS


def is_executable_log_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(COMMENT_PREFIXES):
        return False
    code = re.split(r"(?://|#)", stripped, maxsplit=1)[0]
    return is_log_line(code)


def source_file_log_lines(path: str, content: str) -> Iterable[tuple[int, str]]:
    if not is_devgpt_source_file(path):
        return
    for line_number, line in enumerate(content.splitlines(), start=1):
        if is_executable_log_line(line):
            yield line_number, line.strip()


def code_block_log_lines(content: object) -> Iterable[tuple[int, str]]:
    if not isinstance(content, str) or not content:
        return
    for line_number, line in enumerate(content.splitlines(), start=1):
        if is_executable_log_line(line):
            yield line_number, line.strip()


def sharing_url(sharing: object) -> str:
    if not isinstance(sharing, dict):
        return ""
    return str(sharing.get("URL") or "")


def conversations(sharing: object) -> list[dict]:
    if not isinstance(sharing, dict):
        return []
    convs = sharing.get("Conversations") or []
    return [item for item in convs if isinstance(item, dict)]


def chatgpt_model(sharing: object) -> str:
    if not isinstance(sharing, dict):
        return ""
    return str(sharing.get("Model") or "")


def prompt_context(convs: list[dict]) -> dict[str, str]:
    prompts = [conv.get("Prompt") for conv in convs]
    answers = [conv.get("Answer") for conv in convs]
    return {
        "prompt_intents": "log_related" if any(isinstance(p, str) and PROMPT_LOG_RE.search(p) for p in prompts) else "",
        "prompt_pushbacks": compact_values(
            "pushback_or_debug_context" for p in prompts if isinstance(p, str) and PUSHBACK_RE.search(p)
        ),
        "user_log_reason_excerpt": compact_excerpt(prompts),
        "answer_log_excerpt": compact_excerpt(answers),
    }


def base_candidate(
    source: dict,
    snapshot: str,
    source_type: str,
    sharing: dict,
    prompt: dict[str, str],
    file_path: str,
    line: int,
    add_remove: str,
    candidate_source: str,
    attribution: str,
    log_text: str,
    conversation_index: int,
    code_block_index: int,
    code_block_type: str,
    manual_review_label: str,
    manual_review_evidence: str,
) -> DevGPTLogCandidate:
    risk_level, keywords = risk_for_text(log_text)
    return DevGPTLogCandidate(
        repo=str(source.get("RepoName") or ""),
        repo_language=clean_language(source.get("RepoLanguage")),
        snapshot=snapshot,
        source_type=source_type,
        source_url=str(source.get("URL") or ""),
        chatgpt_url=sharing_url(sharing),
        commit=normalize_commit_list(source.get("CommitSha") or source.get("Sha")),
        file=file_path,
        line=line,
        add_remove=add_remove,
        candidate_source=candidate_source,
        attribution=attribution,
        sensitive_keyword_hit=bool(keywords),
        sensitive_keywords=";".join(keywords),
        risk_level=risk_level,
        log_text=log_text.strip(),
        commit_message=first_line(source.get("CommitMessage") or source.get("Message")),
        author_date=str(source.get("AuthorAt") or source.get("CommitAt") or source.get("CreatedAt") or ""),
        chatgpt_model=chatgpt_model(sharing),
        conversation_index=conversation_index,
        code_block_index=code_block_index,
        code_block_type=code_block_type,
        prompt_intents=prompt.get("prompt_intents", ""),
        prompt_pushbacks=prompt.get("prompt_pushbacks", ""),
        user_log_reason_excerpt=prompt.get("user_log_reason_excerpt", ""),
        answer_log_excerpt=prompt.get("answer_log_excerpt", ""),
        manual_review_label=manual_review_label,
        manual_review_evidence=manual_review_evidence,
    )


def iter_candidates(devgpt_dir: Path) -> tuple[list[DevGPTLogCandidate], dict[str, RepositoryInfo], dict]:
    candidates: list[DevGPTLogCandidate] = []
    repo_languages: dict[str, list[str]] = defaultdict(list)
    raw_counts = Counter()
    snapshot_counts = Counter()

    for json_path in sorted(devgpt_dir.glob("snapshot_*/*_sharings.json")):
        snapshot = snapshot_name(json_path)
        kind = sharing_kind(json_path)
        sources = load_sources(json_path)
        raw_counts[kind] += len(sources)
        snapshot_counts[snapshot] += len(sources)
        for source in sources:
            repo = str(source.get("RepoName") or "")
            if repo:
                repo_languages[repo].append(clean_language(source.get("RepoLanguage")))
            sharings = source.get("ChatgptSharing") or []
            sharings = [item for item in sharings if isinstance(item, dict)] or [{}]

            if kind == "code file":
                file_path = str(source.get("FilePath") or source.get("FileName") or "")
                content = decode_content(source.get("Content"))
                for sharing in sharings:
                    convs = conversations(sharing)
                    prompt = prompt_context(convs)
                    for line, text in source_file_log_lines(file_path, content):
                        candidates.append(
                            base_candidate(
                                source=source,
                                snapshot=snapshot,
                                source_type=kind,
                                sharing=sharing,
                                prompt=prompt,
                                file_path=file_path,
                                line=line,
                                add_remove="present",
                                candidate_source="file_content",
                                attribution="committed_file",
                                log_text=text,
                                conversation_index=-1,
                                code_block_index=-1,
                                code_block_type="",
                                manual_review_label="committed_file_log_candidate",
                                manual_review_evidence="Log-like line appears in a source file captured by DevGPT.",
                            )
                        )

            for sharing in sharings:
                convs = conversations(sharing)
                prompt = prompt_context(convs)
                for conv_index, conv in enumerate(convs):
                    code_blocks = conv.get("ListOfCode") or []
                    if not isinstance(code_blocks, list):
                        continue
                    for block_index, block in enumerate(code_blocks):
                        if not isinstance(block, dict):
                            continue
                        code_type = str(block.get("Type") or "")
                        for line, text in code_block_log_lines(block.get("Content")):
                            candidates.append(
                                base_candidate(
                                    source=source,
                                    snapshot=snapshot,
                                    source_type=kind,
                                    sharing=sharing,
                                    prompt=prompt,
                                    file_path=f"<chatgpt_answer_code:{code_type or 'unknown'}>",
                                    line=line,
                                    add_remove="generated",
                                    candidate_source="chatgpt_answer_code",
                                    attribution="chatgpt_answer",
                                    log_text=text,
                                    conversation_index=conv_index,
                                    code_block_index=block_index,
                                    code_block_type=code_type,
                                    manual_review_label="chatgpt_answer_code_log_needs_commit_trace",
                                    manual_review_evidence=(
                                        "Log-like line appears in shared ChatGPT answer code; DevGPT local data "
                                        "does not include a patch to prove whether this exact line was committed."
                                    ),
                                )
                            )

    repo_info = {
        repo: RepositoryInfo(repo=repo, language=choose_language(languages))
        for repo, languages in sorted(repo_languages.items())
    }
    metadata = {
        "raw_source_counts": dict(raw_counts),
        "snapshot_source_counts": dict(snapshot_counts),
    }
    return candidates, repo_info, metadata


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def top_counts(df: pd.DataFrame, col: str, n: int = 10) -> str:
    if df.empty:
        return "_No rows._"
    lines = ["| Value | Rows |", "| --- | ---: |"]
    for value, count in df[col].value_counts(dropna=False).head(n).items():
        lines.append(f"| `{value}` | {count} |")
    return "\n".join(lines)


def write_markdown_summary(path: Path, df: pd.DataFrame, review: pd.DataFrame, summary: dict) -> None:
    candidate_source_table = top_counts(df, "candidate_source")
    risk_table = top_counts(df, "risk_level")
    repo_table = top_counts(df, "repo")
    language_table = top_counts(df, "repo_language")
    source_type_table = top_counts(df, "source_type")

    review_examples = "_No manual-review rows found._"
    if not review.empty:
        lines = ["| Repo | Source | File | Line | Risk | Evidence |", "| --- | --- | --- | ---: | --- | --- |"]
        for r in review.sort_values(["risk_level", "repo", "file", "line"]).head(15).itertuples(index=False):
            evidence = str(r.manual_review_evidence or "").replace("|", "/")[:160]
            lines.append(f"| `{r.repo}` | `{r.candidate_source}` | `{r.file}` | {r.line} | {r.risk_level} | {evidence} |")
        review_examples = "\n".join(lines)

    path.write_text(
        f"""# DevGPT Log Candidate Summary

## Outputs

- `devgpt_log_candidates.csv`: full candidate detail table.
- `devgpt_log_candidates.parquet`: parquet copy of the same table.
- `devgpt_log_pushback_reasons.csv`: candidates connected to log/debug/problem-related prompt context.
- `devgpt_log_reason_prompts.csv`: de-duplicated repo/chat-level prompt excerpts.
- `devgpt_answer_code_manual_review.csv`: ChatGPT answer code log candidates needing commit trace review.
- `devgpt_no_candidate_repos.csv`: repositories represented in DevGPT but without log candidates.
- `summary.json`: machine-readable counts.

## Counts

| Metric | Value |
| --- | ---: |
| Total repositories considered | {summary["total_repositories_considered"]} |
| Candidate rows | {summary["candidate_rows"]} |
| Repositories with candidates | {summary["repos_with_candidates"]} |
| Repositories without candidates | {summary["repos_without_candidates"]} |
| Unique commits | {summary["commits"]} |
| Unique ChatGPT shares | {summary["chatgpt_shares"]} |
| Sensitive keyword rows | {summary["sensitive_keyword_rows"]} |
| Pushback/reason rows | {summary["pushback_reason_rows"]} |
| Reason prompt rows | {summary["reason_prompt_rows"]} |
| Manual-review rows | {summary["manual_review_rows"]} |

## Candidate Sources

{candidate_source_table}

## Risk Levels

{risk_table}

## Source Types

{source_type_table}

## Repository Languages

{language_table}

## Top Repositories

{repo_table}

## Manual-Review Examples

{review_examples}

## Notes

DevGPT local snapshots do not include unified commit patches, so file-content rows are marked as `present` and ChatGPT answer code rows are marked as `generated` rather than `add` or `remove`.
""",
        encoding="utf-8",
    )


def write_outputs(candidates: list[DevGPTLogCandidate], repo_info: dict[str, RepositoryInfo], metadata: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = [asdict(candidate) for candidate in candidates]
    candidate_columns = [field.name for field in fields(DevGPTLogCandidate)]
    df = pd.DataFrame(rows, columns=candidate_columns)
    if not df.empty:
        df = df.drop_duplicates(
            subset=[
                "repo",
                "source_url",
                "chatgpt_url",
                "commit",
                "file",
                "line",
                "candidate_source",
                "conversation_index",
                "code_block_index",
                "log_text",
            ],
            keep="first",
        ).reset_index(drop=True)

    df.to_csv(output_dir / "devgpt_log_candidates.csv", index=False)
    df.to_parquet(output_dir / "devgpt_log_candidates.parquet", index=False)

    pushback = df[
        (df["user_log_reason_excerpt"].fillna("") != "")
        | (df["answer_log_excerpt"].fillna("") != "")
        | (df["prompt_pushbacks"].fillna("") != "")
    ].copy()
    pushback.to_csv(output_dir / "devgpt_log_pushback_reasons.csv", index=False)

    reason_prompts = pushback[
        [
            "repo",
            "source_type",
            "source_url",
            "chatgpt_url",
            "prompt_intents",
            "prompt_pushbacks",
            "user_log_reason_excerpt",
            "answer_log_excerpt",
        ]
    ].drop_duplicates()
    reason_prompts.to_csv(output_dir / "devgpt_log_reason_prompts.csv", index=False)

    review = df[df["manual_review_label"] == "chatgpt_answer_code_log_needs_commit_trace"].copy()
    review.to_csv(output_dir / "devgpt_answer_code_manual_review.csv", index=False)

    repos_with_candidates = (
        {repo for repo in df["repo"].dropna().unique() if repo in repo_info}
        if not df.empty
        else set()
    )
    no_candidate_rows = [
        asdict(info)
        for repo, info in sorted(repo_info.items())
        if repo not in repos_with_candidates
    ]
    write_csv(output_dir / "devgpt_no_candidate_repos.csv", no_candidate_rows)

    summary = {
        "total_repositories_considered": len(repo_info),
        "candidate_rows": len(df),
        "repos": len(repos_with_candidates),
        "repos_with_candidates": len(repos_with_candidates),
        "repos_without_candidates": len(no_candidate_rows),
        "commits": int(df["commit"].replace("", pd.NA).dropna().nunique()) if not df.empty else 0,
        "chatgpt_shares": int(df["chatgpt_url"].replace("", pd.NA).dropna().nunique()) if not df.empty else 0,
        "by_candidate_source": df["candidate_source"].value_counts().to_dict() if not df.empty else {},
        "by_add_remove": df["add_remove"].value_counts().to_dict() if not df.empty else {},
        "by_attribution": df["attribution"].value_counts().to_dict() if not df.empty else {},
        "by_risk_level": df["risk_level"].value_counts().to_dict() if not df.empty else {},
        "by_source_type": df["source_type"].value_counts().to_dict() if not df.empty else {},
        "by_repo_language": df["repo_language"].value_counts().to_dict() if not df.empty else {},
        "sensitive_keyword_rows": int(df["sensitive_keyword_hit"].sum()) if not df.empty else 0,
        "pushback_reason_rows": int(len(pushback)),
        "reason_prompt_rows": int(len(reason_prompts)),
        "manual_review_rows": int(len(review)),
        **metadata,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_markdown_summary(output_dir / "summary.md", df, review, summary)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate DevGPT log candidate tables.")
    parser.add_argument("--devgpt-dir", type=Path, default=DEFAULT_DEVGPT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    candidates, repo_info, metadata = iter_candidates(args.devgpt_dir)
    write_outputs(candidates, repo_info, metadata, args.output_dir)
    summary = json.loads((args.output_dir / "summary.json").read_text(encoding="utf-8"))
    print(
        f"Wrote {summary['candidate_rows']} DevGPT log candidates from "
        f"{summary['repos_with_candidates']}/{summary['total_repositories_considered']} "
        f"repositories to {args.output_dir}"
    )


if __name__ == "__main__":
    main()
