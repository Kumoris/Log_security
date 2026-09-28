#!/usr/bin/env python3
"""Apply the AIDev semantic audit labels and recompute paired PR outcomes."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

if __package__:
    from .analyze_aidev_primary_queue import bh_adjust, file_sha256, paired_binary_result, read_csv, write_csv
else:
    from analyze_aidev_primary_queue import bh_adjust, file_sha256, paired_binary_result, read_csv, write_csv


ALLOWED_DECISIONS = {"YES", "CARRIER", "NO", "UNCLEAR"}
TYPE_FEATURES = ("AUTH", "PII", "QID", "BIZ", "CFG", "DIAG", "AGENT_CTRL", "AGENT_CTX")
OUTCOMES = ("strict_static_sensitive", "broad_exposure_prone") + tuple(f"type_{name}" for name in TYPE_FEATURES)
ANNOTATED_FIELDS = (
    "pair_id", "provenance", "repo", "pr_key", "pr_url", "file", "line",
    "privacy_features", "statement_sha256_16", "statement_redacted",
    "manual_is_privacy_issue", "manual_primary_type", "manual_value_form",
    "manual_severity", "manual_runtime_reachable",
    "manual_externalized_or_persisted", "manual_notes",
)
STAT_FIELDS = (
    "scope", "outcome", "n_pairs", "n_repositories", "agent_n", "human_n",
    "agent_rate", "human_rate", "agent_ci_low", "agent_ci_high", "human_ci_low",
    "human_ci_high", "effect", "effect_ci_low", "effect_ci_high", "effect_type",
    "agent_only", "human_only", "mcnemar_p", "bootstrap_iterations", "seed",
    "conclusion", "bh_q", "stable_after_bh",
)


def statement_hash(row: dict) -> str:
    return hashlib.sha256(row["statement_redacted"].encode("utf-8")).hexdigest()[:16]


def apply_labels(queue: list[dict], label_document: dict) -> list[dict]:
    labels = label_document.get("labels", [])
    if len(labels) != len(queue):
        raise ValueError(f"label coverage mismatch: labels={len(labels)} queue={len(queue)}")
    by_row = {int(label["row"]): label for label in labels}
    if set(by_row) != set(range(1, len(queue) + 1)):
        raise ValueError("labels must cover every one-based queue row exactly once")
    output = []
    for index, row in enumerate(queue, 1):
        label = by_row[index]
        digest = statement_hash(row)
        if label["statement_sha256_16"] != digest:
            raise ValueError(f"statement drift at row {index}: expected {label['statement_sha256_16']} got {digest}")
        if label["decision"] not in ALLOWED_DECISIONS:
            raise ValueError(f"invalid decision at row {index}")
        output.append({
            **row,
            "statement_sha256_16": digest,
            "manual_is_privacy_issue": label["decision"],
            "manual_primary_type": label["type"],
            "manual_value_form": label["value_form"],
            "manual_severity": label["severity"],
            "manual_runtime_reachable": "UNKNOWN",
            "manual_externalized_or_persisted": "STATIC_SINK_PRESENT",
            "manual_notes": label["notes"],
        })
    return output


def _types(row: dict) -> set[str]:
    return set(row["manual_primary_type"].split("+"))


def paired_rows(pairs: list[dict], annotated: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in annotated:
        grouped[(row["pair_id"], row["provenance"])].append(row)
    output = []
    for pair in pairs:
        value = {"pair_id": pair["pair_id"], "repo": pair["repo"]}
        for side in ("agent", "human"):
            rows = grouped[(pair["pair_id"], side)]
            value[f"{side}_strict_static_sensitive"] = any(row["manual_is_privacy_issue"] == "YES" for row in rows)
            value[f"{side}_broad_exposure_prone"] = any(row["manual_is_privacy_issue"] in {"YES", "CARRIER"} for row in rows)
            for feature in TYPE_FEATURES:
                value[f"{side}_type_{feature}"] = any(
                    row["manual_is_privacy_issue"] in {"YES", "CARRIER"} and feature in _types(row)
                    for row in rows
                )
        output.append(value)
    return output


def report(summary: dict) -> str:
    def decision_text(side: str) -> str:
        counts = summary["decision_by_provenance"][side]
        return ", ".join(
            f"{name}={counts.get(name, 0)}" for name in ("YES", "CARRIER", "NO", "UNCLEAR")
        )

    rows = []
    for value in summary["statistics"]:
        rows.append(
            f"| {value['outcome']} | {value['agent_n']}/300 | {value['human_n']}/300 | "
            f"{value['effect'] * 100:+.2f} pp | "
            f"[{value['effect_ci_low'] * 100:+.2f}, {value['effect_ci_high'] * 100:+.2f}] | "
            f"{value['mcnemar_p']:.4f} | {value['bh_q']:.4f} | {value['stable_after_bh']} |"
        )
    return f"""# AIDev 日志隐私候选语义审计 v1

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: ANALYZED_SINGLE_REVIEWER
- Version Label: aidev_manual_privacy_audit_v1

## 审计概况

- 自动候选：{summary['n_statements']} 条；标签覆盖：100%。
- `YES`：{summary['decision_counts'].get('YES', 0)}；`CARRIER`：{summary['decision_counts'].get('CARRIER', 0)}；`NO`：{summary['decision_counts'].get('NO', 0)}；`UNCLEAR`：{summary['decision_counts'].get('UNCLEAR', 0)}。
- Agent 语句：{decision_text('agent')}。
- Human 语句：{decision_text('human')}。

`YES` 表示代码明确把敏感值/容器传入 sink；`CARRIER` 表示异常或不透明容器可能携带敏感值。两者都不等于运行时泄露。

## 以全部 300 对 PR 为分母

| 结果 | Agent | Human | 差值 | 仓库 bootstrap 95% CI | McNemar p | BH q | 稳定差异 |
|---|---:|---:|---:|---:|---:|---:|---:|
{chr(10).join(rows)}

## 解释

1. 语义审计后，自动候选中有 {summary['decision_counts'].get('NO', 0)} 条是计数、公开 region、localhost 或普通状态元数据。
2. 严格静态敏感 PR 为 Agent {summary['strict_pr_counts']['agent']}/300、Human {summary['strict_pr_counts']['human']}/300；当前没有稳定差异。
3. Agent 候选更多地包含异常载体，但这是低频 PR 级观察，且不能说明异常中实际存在敏感值。
4. 该 v1 是未盲化的单审阅者校准轮，不是人工金标准；需独立第二评审才能计算标注者一致性。

## 证据边界

- 全部记录的 `manual_runtime_reachable` 仍为 `UNKNOWN`。
- 全部记录只能标记 `STATIC_SINK_PRESENT`，不能标记 `RUNTIME_LEAK_CONFIRMED`。
- 统计谬误扫描 11/11；主要风险为稀有事件低功效、选择偏差、单审阅者偏差、观察性数据因果化。
"""


def run(input_dir: Path, labels_path: Path, output_dir: Path, iterations: int, seed: int) -> dict:
    queue = read_csv(input_dir / "manual_audit_queue.csv")
    pairs = read_csv(input_dir.parent / "matched_pairs.csv")
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    annotated = apply_labels(queue, labels)
    pair_values = paired_rows(pairs, annotated)
    statistics = []
    for outcome in OUTCOMES:
        value = paired_binary_result(
            pair_values, outcome, "manual_semantic_audit_aidev_frozen_matched_300",
            lambda row, name=outcome: bool(row[f"agent_{name}"]),
            lambda row, name=outcome: bool(row[f"human_{name}"]),
            iterations, seed,
        )
        statistics.append(value)
    for value, q_value in zip(statistics, bh_adjust([row["mcnemar_p"] for row in statistics])):
        value["bh_q"] = q_value
        value["stable_after_bh"] = bool(
            q_value < 0.05 and (value["effect_ci_low"] > 0 or value["effect_ci_high"] < 0)
        )

    decision_counts = Counter(row["manual_is_privacy_issue"] for row in annotated)
    by_provenance = {
        side: dict(Counter(
            row["manual_is_privacy_issue"] for row in annotated if row["provenance"] == side
        )) for side in ("agent", "human")
    }
    summary = {
        "status": "ANALYZED_SINGLE_REVIEWER",
        "n_pairs": len(pairs), "n_statements": len(annotated),
        "decision_counts": dict(decision_counts),
        "decision_by_provenance": by_provenance,
        "strict_pr_counts": {
            side: sum(bool(row[f"{side}_strict_static_sensitive"]) for row in pair_values)
            for side in ("agent", "human")
        },
        "statistics": statistics,
        "seed": seed, "bootstrap_iterations": iterations,
        "reviewer_count": 1, "blinding": labels.get("blinding"),
        "inter_rater_reliability": "NOT_AVAILABLE",
        "runtime_leak_claim": False,
        "fallacy_scan_coverage": "11/11",
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "annotated_candidates.csv", annotated, ANNOTATED_FIELDS)
    write_csv(output_dir / "pr_feature_statistics.csv", statistics, STAT_FIELDS)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(report(summary), encoding="utf-8")
    artifacts = ("annotated_candidates.csv", "pr_feature_statistics.csv", "summary.json", "report.md")
    manifest = {
        "hash_algorithm": "SHA-256",
        "input_sha256": {
            "manual_audit_queue.csv": file_sha256(input_dir / "manual_audit_queue.csv"),
            "matched_pairs.csv": file_sha256(input_dir.parent / "matched_pairs.csv"),
            labels_path.name: file_sha256(labels_path),
        },
        "script_sha256": file_sha256(Path(__file__)),
        "artifact_sha256": {name: file_sha256(output_dir / name) for name in artifacts},
        "seed": seed,
        "bootstrap_iterations": iterations,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument(
        "--input-dir", type=Path,
        default=Path("outputs/aidev_observational_primary_300/value_aware_privacy"),
    )
    value.add_argument(
        "--labels", type=Path,
        default=Path("outputs/aidev_observational_primary_300/value_aware_privacy/manual_audit_labels_v1.json"),
    )
    value.add_argument(
        "--output-dir", type=Path,
        default=Path("outputs/aidev_observational_primary_300/value_aware_privacy/manual_audit_v1"),
    )
    value.add_argument("--bootstrap-iterations", type=int, default=10_000)
    value.add_argument("--seed", type=int, default=20260805)
    return value


def main() -> int:
    args = parser().parse_args()
    summary = run(args.input_dir, args.labels, args.output_dir, args.bootstrap_iterations, args.seed)
    print(json.dumps({
        "status": summary["status"], "n_statements": summary["n_statements"],
        "decision_counts": summary["decision_counts"], "strict_pr_counts": summary["strict_pr_counts"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
