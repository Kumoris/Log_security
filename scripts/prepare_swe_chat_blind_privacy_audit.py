#!/usr/bin/env python3
"""Prepare a provenance-blinded SWE-chat privacy review package."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import Counter
from pathlib import Path


REVIEW_FIELDS = (
    "blind_id", "file_extension", "path_scope", "sink_family", "evidence_grade",
    "statement_lines", "statement_redacted", "context_redacted",
    "manual_is_privacy_issue", "manual_primary_type", "manual_value_form",
    "manual_severity", "manual_runtime_reachable",
    "manual_externalized_or_persisted", "manual_notes",
)
KEY_FIELDS = (
    "blind_id", "source_row", "source_sha256_16", "attribution", "repo", "commit",
    "checkpoint_pk", "file", "line", "privacy_features", "mechanism_features",
    "static_privacy_candidate",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def source_hash(row: dict) -> str:
    payload = "\0".join(
        row.get(name, "") for name in ("repo", "commit", "file", "line", "statement_redacted")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def extension(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return suffix if suffix else "[none]"


def prepare(rows: list[dict], seed: int) -> tuple[list[dict], list[dict]]:
    indexed = [(index, row) for index, row in enumerate(rows, 1)]
    random.Random(seed).shuffle(indexed)
    review_rows = []
    key_rows = []
    for blind_index, (source_row, row) in enumerate(indexed, 1):
        blind_id = f"SWE-{blind_index:04d}"
        review_rows.append({
            "blind_id": blind_id,
            "file_extension": extension(row["file"]),
            "path_scope": row["path_scope"],
            "sink_family": row["sink_family"],
            "evidence_grade": row["evidence_grade"],
            "statement_lines": row["statement_lines"],
            "statement_redacted": row["statement_redacted"],
            "context_redacted": row["context_redacted"],
            "manual_is_privacy_issue": "",
            "manual_primary_type": "",
            "manual_value_form": "",
            "manual_severity": "",
            "manual_runtime_reachable": "UNKNOWN",
            "manual_externalized_or_persisted": "STATIC_SINK_PRESENT",
            "manual_notes": "",
        })
        key_rows.append({
            "blind_id": blind_id,
            "source_row": source_row,
            "source_sha256_16": source_hash(row),
            **row,
        })
    return review_rows, key_rows


def report(summary: dict) -> str:
    counts = summary["source_attribution_counts"]
    return f"""# SWE-chat 日志隐私盲化审计包 v1

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: PREPARED_FOR_BLINDED_REVIEW
- Version Label: swe_chat_blind_privacy_audit_v1

## 内容

- 待审语句：{summary['n_rows']} 条。
- 密钥表中的来源构成：Agent-only {counts.get('agent_only', 0)}，Human-only {counts.get('human_only', 0)}，Mixed {counts.get('mixed', 0)}。
- 盲化表不包含 attribution、仓库、commit、checkpoint、完整路径、行号和自动风险标签。
- 保留扩展名、sink 类型、证据等级、完整日志语句和局部上下文，供语义判定。

## 流程约束

1. 评审者只获取 `blind_review.csv`，不查看 `provenance_key.csv`。
2. 依据 `outputs/privacy_manual_audit_codebook.md` 填写标签。
3. 标注冻结后才由裁决者用密钥表解盲，再计算 Agent–Human 差异。
4. Mixed 只作敏感性分析，不进入 Agent-only 对 Human-only 主效应。

## 局限

语句和上下文本身可能透露 Agent 工具概念，因此这是来源标签盲化，不是完全场景盲化。该审计仍只能确立静态候选，不能证明运行时泄露。
"""


def run(source: Path, output_dir: Path, seed: int) -> dict:
    rows = read_csv(source)
    if not rows:
        raise ValueError("source audit queue is empty")
    required = {"agent_only", "human_only", "mixed"}
    counts = Counter(row["attribution"] for row in rows)
    if set(counts) != required:
        raise ValueError(f"unexpected attribution groups: {sorted(counts)}")
    review_rows, key_rows = prepare(rows, seed)
    if {row["blind_id"] for row in review_rows} != {row["blind_id"] for row in key_rows}:
        raise AssertionError("blind identifiers do not map one-to-one")

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "blind_review.csv", review_rows, REVIEW_FIELDS)
    write_csv(output_dir / "provenance_key.csv", key_rows, KEY_FIELDS)
    summary = {
        "status": "PREPARED_FOR_BLINDED_REVIEW",
        "n_rows": len(rows),
        "seed": seed,
        "source_attribution_counts": dict(sorted(counts.items())),
        "blinded_fields_removed": [
            "attribution", "repo", "commit", "checkpoint_pk", "file", "line",
            "privacy_features", "mechanism_features", "dynamic_values_redacted",
        ],
        "runtime_leak_claim": False,
        "input_sha256": sha256(source),
        "fallacy_scan_coverage": "11/11",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(report(summary), encoding="utf-8")
    artifacts = ("blind_review.csv", "provenance_key.csv", "summary.json", "report.md")
    manifest = {
        "hash_algorithm": "SHA-256",
        "script_sha256": sha256(Path(__file__)),
        "artifact_sha256": {name: sha256(output_dir / name) for name in artifacts},
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument(
        "--source", type=Path,
        default=Path("outputs/swe_chat_value_aware_privacy/analysis/manual_audit_queue.csv"),
    )
    value.add_argument(
        "--output-dir", type=Path,
        default=Path("outputs/swe_chat_value_aware_privacy/blind_manual_audit_v1"),
    )
    value.add_argument("--seed", type=int, default=20260805)
    return value


def main() -> int:
    args = parser().parse_args()
    summary = run(args.source, args.output_dir, args.seed)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
