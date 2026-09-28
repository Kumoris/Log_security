#!/usr/bin/env python3
"""Reconstruct full SWE-chat log statements and their attribution evidence.

This is the Parquet-reading extraction boundary.  The downstream analysis reads
only the emitted CSV and uses the Python standard library.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    from .analyze_aidev_log_privacy_semantics import _paren_balance
    from .analyze_coding_agent_log_leakage import is_production_path
except ImportError:
    from analyze_aidev_log_privacy_semantics import _paren_balance
    from analyze_coding_agent_log_leakage import is_production_path


FIELDS = (
    "repo", "commit", "checkpoint_pk", "file", "line", "add_remove",
    "attribution_original", "attribution_consensus", "attribution_values",
    "path_scope", "sink_family", "sink_executable", "sink_reason",
    "statement_source", "statement_lines", "statement_complete",
    "line_matches_original", "source_checkpoint_rows", "source_item_matches",
    "attribution_consistent", "version_consistent", "evidence_grade",
    "log_text_redacted", "full_statement_redacted", "context_redacted",
    "commit_message", "author_date", "manual_review_label",
)

SINK_PATTERNS = (
    ("structured_logger", re.compile(r"\b(?:logging|logger|log)\s*\.\s*(?:trace|debug|info|warn|warning|error|fatal|critical|exception)\s*\(", re.IGNORECASE)),
    ("console_stdio", re.compile(r"\bconsole\s*\.\s*(?:log|error|warn|debug|info|trace)\s*\(", re.IGNORECASE)),
    ("structured_logger", re.compile(r"\b(?:debug|info|warn|error|trace)\s*!\s*\(")),
    ("print_stdio", re.compile(r"\b(?:print|println|eprintln|dbg|NSLog)\s*!?\s*\(", re.IGNORECASE)),
    ("print_stdio", re.compile(r"\bSystem\s*\.\s*(?:out|err)\s*\.\s*print(?:ln)?\s*\(", re.IGNORECASE)),
    ("print_stdio", re.compile(r"\b(?:fmt|log)\s*\.\s*(?:Print|Printf|Println|Fatal|Fatalf|Panic|Panicf|Fprint|Fprintf|Fprintln)\s*\(", re.IGNORECASE)),
    ("shell_stdio", re.compile(r"(?:^|[;&|]\s*)\b(?:echo|printf)\b", re.IGNORECASE)),
    ("print_stdio", re.compile(r"^\s*(?:puts|print)\s+", re.IGNORECASE)),
)

AGENT_TOOLING_PARTS = {".agent-memory", ".claude", ".codex", ".cursor", ".opencode"}
NONPRODUCTION_PARTS = {"doc", "docs", "documentation", "template", "templates", "demo", "demos"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact(text: str, limit: int = 4_000) -> str:
    value = (text or "")[:limit]
    for pattern, replacement in (
        (r"\b(?:gh[opsu]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b", "[REDACTED_SECRET]"),
        (r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[REDACTED_EMAIL]"),
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_IP]"),
    ):
        value = re.sub(pattern, replacement, value, flags=re.IGNORECASE)
    return value


def item_for(path: str, attribution: dict) -> dict:
    item = attribution.get(path)
    if isinstance(item, dict):
        return item
    matches = [
        value for key, value in attribution.items()
        if isinstance(value, dict) and (key.endswith("/" + path) or path.endswith("/" + key))
    ]
    return matches[0] if len(matches) == 1 else {}


def classify_path(path: str) -> str:
    parts = {part.lower() for part in path.replace("\\", "/").split("/") if part}
    name = path.rsplit("/", 1)[-1].lower()
    if parts & AGENT_TOOLING_PARTS:
        return "agent_tooling"
    if ".github" in parts or parts & NONPRODUCTION_PARTS or name.endswith((".min.js", ".min.css")):
        return "nonproduction"
    if name.startswith(("test-", "test_", "demo_", "demo-")) or re.search(r"(?:^|[._-])(?:test|spec)(?:[._-]|$)", name):
        return "nonproduction"
    return "production" if is_production_path(path) else "nonproduction"


def _inside_string(text: str, position: int) -> bool:
    quote = ""
    escaped = False
    for char in text[:position]:
        if escaped:
            escaped = False
        elif char == "\\" and quote:
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in {"'", '"', "`"}:
            quote = char
    return bool(quote)


def classify_sink(line: str, path: str) -> tuple[str, bool, str]:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", "//", "/*", "*", "--")):
        return "noncode_match", False, "comment_or_blank"
    matches = []
    for family, pattern in SINK_PATTERNS:
        match = pattern.search(line)
        if match:
            matches.append((match.start(), family))
    if not matches:
        return "unknown", False, "no_supported_sink"
    position, family = min(matches)
    if _inside_string(line, position):
        return family, False, "sink_token_inside_string"
    suffix = Path(path).suffix.lower()
    if suffix in {".sh", ".bash", ".zsh"}:
        if re.search(r"\w+\s*=\s*\$\(", line[:position + 1]):
            return family, False, "captured_command_substitution"
        if family == "shell_stdio" and re.search(r"\b(?:echo|printf)\b[^|]*\|", line, re.IGNORECASE):
            return family, False, "piped_data_not_log"
    return family, True, "executable_sink"


def reconstruct_statement(source: str, line: int, fallback: str, max_lines: int = 20) -> dict:
    lines = source.splitlines() if isinstance(source, str) else []
    index = line - 1
    if not lines or index < 0 or index >= len(lines):
        return {
            "statement": fallback,
            "context": "",
            "statement_lines": 1,
            "statement_complete": _paren_balance(fallback) <= 0,
            "statement_source": "single_line_fallback",
            "line_matches_original": False,
        }
    parts = [lines[index]]
    initial_balance = _paren_balance(parts[0])
    cursor = index + 1
    while initial_balance > 0 and _paren_balance("\n".join(parts)) > 0 and cursor < len(lines) and len(parts) < max_lines:
        parts.append(lines[cursor])
        cursor += 1
    balance = _paren_balance("\n".join(parts))
    return {
        "statement": "\n".join(parts),
        "context": "\n".join(lines[max(0, index - 12):index]),
        "statement_lines": len(parts),
        "statement_complete": initial_balance <= 0 or balance <= 0,
        "statement_source": "committed_version",
        "line_matches_original": lines[index].strip() == fallback.strip(),
    }


def read_candidates(path: Path) -> list[dict]:
    csv.field_size_limit(sys.maxsize)
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    seen = set()
    for row in rows:
        key = (row["repo"], row["commit"], row["file"], row["line"], row["add_remove"], row["log_text"])
        if key in seen:
            raise ValueError("candidate input contains duplicate row: " + repr(key))
        seen.add(key)
    return rows


def extract(candidate_path: Path, commits_path: Path, output_path: Path) -> dict:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:  # extraction dependency; analysis itself is stdlib-only
        raise RuntimeError("pyarrow is required only to read the source Parquet") from exc

    candidates = read_candidates(candidate_path)
    targets: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, row in enumerate(candidates):
        targets[(row["repo"], row["commit"])].append(index)

    observations: dict[int, list[dict]] = defaultdict(list)
    source_checkpoint_counts = defaultdict(int)
    parquet_file = parquet.ParquetFile(commits_path)
    columns = ["repo_id", "commit_sha", "checkpoint_pk", "status", "file_attribution"]
    for batch in parquet_file.iter_batches(batch_size=64, columns=columns):
        for source_row in batch.to_pylist():
            key = (str(source_row["repo_id"]), str(source_row["commit_sha"]))
            if key not in targets or source_row.get("status") != "ok":
                continue
            source_checkpoint_counts[key] += 1
            try:
                attribution = json.loads(source_row.get("file_attribution") or "{}")
            except json.JSONDecodeError:
                attribution = {}
            for index in targets[key]:
                candidate = candidates[index]
                item = item_for(candidate["file"], attribution)
                if not item:
                    continue
                source = item.get("committed_version")
                reconstructed = reconstruct_statement(
                    source if isinstance(source, str) else "",
                    int(candidate["line"]),
                    candidate["log_text"],
                )
                observations[index].append({
                    "attribution": str(item.get("attribution") or "unknown"),
                    "version_hash": hashlib.sha256((source or "").encode("utf-8")).hexdigest() if isinstance(source, str) else "",
                    **reconstructed,
                })

    output = []
    evidence_counts = defaultdict(int)
    for index, candidate in enumerate(candidates):
        values = observations[index]
        attributions = sorted({value["attribution"] for value in values if value["attribution"]})
        version_hashes = {value["version_hash"] for value in values if value["version_hash"]}
        attribution_consistent = len(attributions) == 1
        version_consistent = len(version_hashes) <= 1
        consensus = attributions[0] if attribution_consistent else ("ambiguous" if attributions else candidate["attribution"])
        reconstructed = next(
            (value for value in values if value["statement_source"] == "committed_version"),
            reconstruct_statement("", int(candidate["line"]), candidate["log_text"]),
        )
        grade_a = bool(
            reconstructed["statement_source"] == "committed_version"
            and reconstructed["line_matches_original"]
            and reconstructed["statement_complete"]
            and attribution_consistent
            and version_consistent
            and consensus == candidate["attribution"]
        )
        grade = "A" if grade_a else ("B" if values else "C")
        evidence_counts[grade] += 1
        key = (candidate["repo"], candidate["commit"])
        output.append({
            "repo": candidate["repo"],
            "commit": candidate["commit"],
            "checkpoint_pk": candidate["checkpoint_pk"],
            "file": candidate["file"],
            "line": candidate["line"],
            "add_remove": candidate["add_remove"],
            "attribution_original": candidate["attribution"],
            "attribution_consensus": consensus,
            "attribution_values": ";".join(attributions),
            "path_scope": classify_path(candidate["file"]),
            "sink_family": classify_sink(candidate["log_text"], candidate["file"])[0],
            "sink_executable": classify_sink(candidate["log_text"], candidate["file"])[1],
            "sink_reason": classify_sink(candidate["log_text"], candidate["file"])[2],
            "statement_source": reconstructed["statement_source"],
            "statement_lines": reconstructed["statement_lines"],
            "statement_complete": reconstructed["statement_complete"],
            "line_matches_original": reconstructed["line_matches_original"],
            "source_checkpoint_rows": source_checkpoint_counts[key],
            "source_item_matches": len(values),
            "attribution_consistent": attribution_consistent,
            "version_consistent": version_consistent,
            "evidence_grade": grade,
            "log_text_redacted": redact(candidate["log_text"]),
            "full_statement_redacted": redact(reconstructed["statement"]),
            "context_redacted": redact(reconstructed["context"]),
            "commit_message": candidate["commit_message"],
            "author_date": candidate["author_date"],
            "manual_review_label": candidate["manual_review_label"],
        })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(output)
    summary = {
        "status": "PASS",
        "candidate_rows": len(candidates),
        "output_rows": len(output),
        "target_commits": len(targets),
        "matched_target_commits": sum(bool(source_checkpoint_counts[key]) for key in targets),
        "evidence_grade_counts": dict(sorted(evidence_counts.items())),
        "multiline_reconstructed": sum(int(row["statement_lines"]) > 1 for row in output),
        "incomplete_statements": sum(str(row["statement_complete"]) != "True" for row in output),
        "attribution_disagreements": sum(str(row["attribution_consistent"]) != "True" for row in output),
        "candidate_sha256": sha256(candidate_path),
        "commits_sha256": sha256(commits_path),
        "output_sha256": sha256(output_path),
    }
    (output_path.parent / "extraction_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument(
        "--candidates", type=Path,
        default=Path("data/res/swe_chat_multilingual_logs/swe_chat_multilingual_log_candidates.csv"),
    )
    value.add_argument("--commits", type=Path, default=Path("data/repos/commits.parquet"))
    value.add_argument(
        "--output", type=Path,
        default=Path("outputs/swe_chat_value_aware_privacy/full_log_evidence.csv"),
    )
    return value


def main() -> int:
    args = parser().parse_args()
    print(json.dumps(extract(args.candidates, args.commits, args.output), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
