#!/usr/bin/env python3
"""Build a fresh within-repository Agent/Human matched blind audit queue."""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

if __package__:
    from .analyze_swe_chat_log_privacy_semantics import read_csv, sha256, truth, write_csv
    from .prepare_swe_chat_blind_privacy_audit import extension, source_hash
else:
    from analyze_swe_chat_log_privacy_semantics import read_csv, sha256, truth, write_csv
    from prepare_swe_chat_blind_privacy_audit import extension, source_hash


REVIEW_FIELDS = (
    "blind_id", "file_extension", "sink_family", "evidence_grade", "statement_lines",
    "statement_redacted", "context_redacted", "manual_is_privacy_issue",
    "manual_primary_type", "manual_value_form", "manual_severity", "manual_notes",
)
KEY_FIELDS = (
    "blind_id", "pair_id", "pair_side", "source_sha256_16", "attribution", "repo",
    "commit", "checkpoint_pk", "file", "line", "privacy_features", "mechanism_features",
)


def build_pairs(rows: list[dict], excluded_hashes: set[str], seed: int, repo_cap: int) -> list[tuple[dict, dict]]:
    strata: dict[tuple[str, str, str], dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        if (
            row["path_scope"] != "production"
            or row["evidence_grade"] != "A"
            or row["attribution"] not in {"agent_only", "human_only"}
            or not truth(row["static_privacy_candidate"])
            or source_hash(row) in excluded_hashes
        ):
            continue
        strata[(row["repo"], extension(row["file"]), row["sink_family"])][row["attribution"]].append(row)

    by_repo: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    rng = random.Random(seed)
    for (repo, _ext, _sink), sides in sorted(strata.items()):
        agent = sorted(sides["agent_only"], key=source_hash)
        human = sorted(sides["human_only"], key=source_hash)
        rng.shuffle(agent)
        rng.shuffle(human)
        by_repo[repo].extend(zip(agent, human))

    output = []
    for repo in sorted(by_repo):
        values = by_repo[repo]
        rng.shuffle(values)
        output.extend(values[:repo_cap])
    rng.shuffle(output)
    return output


def prepare_review(pairs: list[tuple[dict, dict]], seed: int) -> tuple[list[dict], list[dict]]:
    values = []
    for pair_index, (agent, human) in enumerate(pairs, 1):
        pair_id = f"PAIR-{pair_index:04d}"
        values.extend(((pair_id, "A", agent), (pair_id, "B", human)))
    random.Random(seed + 1).shuffle(values)
    review, key = [], []
    for blind_index, (pair_id, side, row) in enumerate(values, 1):
        blind_id = f"MATCH-{blind_index:04d}"
        review.append({
            "blind_id": blind_id, "file_extension": extension(row["file"]),
            "sink_family": row["sink_family"], "evidence_grade": row["evidence_grade"],
            "statement_lines": row["statement_lines"],
            "statement_redacted": row["statement_redacted"],
            "context_redacted": row["context_redacted"],
            "manual_is_privacy_issue": "", "manual_primary_type": "",
            "manual_value_form": "", "manual_severity": "", "manual_notes": "",
        })
        key.append({
            "blind_id": blind_id, "pair_id": pair_id, "pair_side": side,
            "source_sha256_16": source_hash(row), **row,
        })
    return review, key


def run(source_dir: Path, output_dir: Path, seed: int, repo_cap: int) -> dict:
    source_path = source_dir / "classified_log_statements.csv"
    prior_path = source_dir / "manual_audit_queue.csv"
    rows = read_csv(source_path)
    prior = read_csv(prior_path)
    excluded = {source_hash(row) for row in prior}
    pairs = build_pairs(rows, excluded, seed, repo_cap)
    review, key = prepare_review(pairs, seed)
    if len(review) != 2 * len(pairs):
        raise AssertionError("each matched pair must create exactly two blind rows")
    for agent, human in pairs:
        if (
            agent["repo"] != human["repo"]
            or extension(agent["file"]) != extension(human["file"])
            or agent["sink_family"] != human["sink_family"]
        ):
            raise AssertionError("matched-pair invariant failed")

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "blind_review.csv", review, REVIEW_FIELDS)
    write_csv(output_dir / "provenance_key.csv", key, KEY_FIELDS)
    repo_counts = Counter(agent["repo"] for agent, _ in pairs)
    summary = {
        "status": "PREPARED_FOR_BLINDED_MATCHED_REVIEW",
        "n_pairs": len(pairs), "n_rows": len(review), "n_repositories": len(repo_counts),
        "repo_cap": repo_cap, "seed": seed,
        "largest_repo_pairs": max(repo_counts.values(), default=0),
        "largest_repo_pair_share": max(repo_counts.values(), default=0) / len(pairs) if pairs else 0.0,
        "matching_exact": ["repo", "file_extension", "sink_family", "path_scope=production", "evidence_grade=A"],
        "excluded_prior_review_rows": len(excluded),
        "unavailable_matching_variables": ["task_type", "timestamp", "change_size"],
        "runtime_leak_claim": False, "fallacy_scan_coverage": "11/11",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(f"""# SWE-chat 仓库内匹配盲化语义审计队列

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: PREPARED_FOR_BLINDED_MATCHED_REVIEW
- Version Label: swe_chat_matched_blind_audit_v1

## 队列概况

- {len(pairs)} 对 Agent/Human 日志，共 {len(review)} 条，来自 {len(repo_counts)} 个仓库。
- 精确匹配：同仓库、同扩展名、同 sink family、生产路径、A 级证据。
- 每仓库最多 {repo_cap} 对；最大仓库占 {summary['largest_repo_pair_share'] * 100:.1f}%。
- 排除上一轮已审的 {len(excluded)} 条语句，用作新的确证样本。
- 评审表隐藏 provenance、repo、commit、路径、配对编号和自动特征；标注冻结后才可使用密钥表解盲。

## 推断边界

数据中缺少统一可用的任务类型、时间和修改规模字段，因此这是仓库/语言/sink 匹配敏感性队列，不是完全任务匹配实验。主假设预先限定为 `AGENT_CTX: Agent > Human` 与 `CFG: Agent < Human`。
""", encoding="utf-8")
    artifacts = ("blind_review.csv", "provenance_key.csv", "summary.json", "report.md")
    manifest = {
        "hash_algorithm": "SHA-256",
        "input_sha256": {source_path.name: sha256(source_path), prior_path.name: sha256(prior_path)},
        "script_sha256": sha256(Path(__file__)),
        "artifact_sha256": {name: sha256(output_dir / name) for name in artifacts},
        "seed": seed, "repo_cap": repo_cap,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--source-dir", type=Path, default=Path("outputs/swe_chat_value_aware_privacy/analysis"))
    value.add_argument("--output-dir", type=Path, default=Path("outputs/swe_chat_value_aware_privacy/matched_blind_audit_v1"))
    value.add_argument("--seed", type=int, default=20260805)
    value.add_argument("--repo-cap", type=int, default=10)
    return value


def main() -> int:
    args = parser().parse_args()
    summary = run(args.source_dir, args.output_dir, args.seed, args.repo_cap)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
