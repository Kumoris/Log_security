#!/usr/bin/env python3
"""Formal paired analysis for every accessible, quality-accepted AIDev pair."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

if __package__:
    from .analyze_aidev_primary_queue import bh_adjust, paired_binary_result, truth
else:
    from analyze_aidev_primary_queue import bh_adjust, paired_binary_result, truth


FIELDS = (
    "scope", "outcome", "n_pairs", "n_repositories", "agent_n", "human_n",
    "agent_rate", "human_rate", "agent_ci_low", "agent_ci_high", "human_ci_low",
    "human_ci_high", "effect", "effect_ci_low", "effect_ci_high", "effect_type",
    "agent_only", "human_only", "mcnemar_p", "bh_q", "bootstrap_iterations", "seed",
    "conclusion",
)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def report(summary: dict, results: list[dict]) -> str:
    by_outcome = {row["outcome"]: row for row in results}
    logs = by_outcome["added_production_log_presence"]
    privacy = by_outcome["broad_static_privacy_candidate_presence"]

    def line(row: dict) -> str:
        return (
            f"Agent {row['agent_n']}/{row['n_pairs']}（{row['agent_rate']:.1%}），"
            f"Human {row['human_n']}/{row['n_pairs']}（{row['human_rate']:.1%}）；"
            f"差值 {row['effect']:+.2%}，仓库 bootstrap 95% CI "
            f"[{row['effect_ci_low']:+.2%}, {row['effect_ci_high']:+.2%}]，"
            f"McNemar p={row['mcnemar_p']:.4f}，BH q={row['bh_q']:.4f}。"
        )

    return f"""# AIDev 全量可访问配对主分析

## 质量审计

- 元数据候选 {summary['all_pairs']:,} 对；双方 diff 可读 {summary['both_diffs_cached']:,} 对；最终纳入 {summary['accepted_pairs']:,} 对、{summary['repositories']:,} 个仓库。
- 纳入条件：同仓库、同任务类型、同语言、时间差不超过 180 天、双方存在生产代码修改、最终修改规模比不超过 10。
- 排除：{json.dumps(summary['exclusion_reasons'], ensure_ascii=False)}。
- Agent/Human PR 均未重复；输入队列、统计表和报告均保存 SHA-256。

## 结果

1. **新增至少一条生产日志**：{line(logs)}
2. **至少一条宽口径隐私安全静态候选**：{line(privacy)}

按预设规则，只有仓库 bootstrap 区间排除 0 且 BH q<0.05 才称为稳定差异。当前日志触达结果为 `{logs['conclusion']}`，隐私候选结果为 `{privacy['conclusion']}`。

## 解释边界

- 这是观察性匹配结果，不是因果结论。
- “隐私候选”由凭证/配置、请求响应、身份会话、对象整体输出和错误诊断模式静态命中，不代表真实运行泄露。
- 1,007 对明显高于此前 480 对，但仍低于稀有类型分析规划的 1,422 对；适合分析总体日志触达和宽口径候选，不足以稳定估计每一种低频泄露类型。
- 80 对因 160 个 GitHub diff 返回 HTTP 404 而无法恢复；缺失规模较小，但未假设其随机缺失。
- 匹配未设置仓库上限，因此主区间按仓库聚类；仍应另做仓库限额敏感性分析。
"""


def run(args: argparse.Namespace) -> dict:
    rows = read_csv(args.input)
    accepted = [row for row in rows if row["status"] == "ACCEPTED"]
    errors = []
    if len({row["pair_id"] for row in accepted}) != len(accepted):
        errors.append("duplicate pair id")
    if len({row["agent_pr_id"] for row in accepted}) != len(accepted):
        errors.append("Agent PR reuse")
    if len({row["human_pr_id"] for row in accepted}) != len(accepted):
        errors.append("Human PR reuse")
    if {row["agent_pr_url"] for row in accepted} & {row["human_pr_url"] for row in accepted}:
        errors.append("Agent/Human URL overlap")
    if any(float(row["date_distance_days"]) > 180 for row in accepted):
        errors.append("date caliper exceeded")
    if any(float(row["size_ratio"]) > 10 for row in accepted):
        errors.append("size caliper exceeded")
    if any(
        not truth(row[name]) for row in accepted
        for name in ("exact_repo", "exact_task_type", "exact_language")
    ):
        errors.append("inexact categorical match")
    if errors:
        raise ValueError("; ".join(errors))

    specs = (
        ("added_production_log_presence", "agent_has_log", "human_has_log"),
        (
            "broad_static_privacy_candidate_presence",
            "agent_has_privacy_candidate", "human_has_privacy_candidate",
        ),
    )
    results = [
        paired_binary_result(
            accepted, outcome, "production_pr", lambda row, key=agent: truth(row[key]),
            lambda row, key=human: truth(row[key]), args.iterations, args.seed,
        )
        for outcome, agent, human in specs
    ]
    for row, q_value in zip(results, bh_adjust([row["mcnemar_p"] for row in results])):
        row["bh_q"] = q_value
        stable = (row["effect_ci_low"] > 0 or row["effect_ci_high"] < 0) and q_value < 0.05
        row["conclusion"] = "stable_difference_detected" if stable else "no_stable_difference_detected"

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "statistics.csv", results, FIELDS)
    reasons = Counter(row["reason"] or "accepted" for row in rows)
    repo_counts = Counter(row["repo"] for row in accepted)
    summary = {
        "status": "PASS",
        "all_pairs": len(rows),
        "both_diffs_cached": sum(row["status"] != "CACHE_MISSING" for row in rows),
        "accepted_pairs": len(accepted),
        "repositories": len(repo_counts),
        "largest_repository_pairs": max(repo_counts.values(), default=0),
        "largest_repository_share": max(repo_counts.values(), default=0) / len(accepted) if accepted else 0,
        "exclusion_reasons": dict(sorted(reasons.items())),
        "bootstrap_iterations": args.iterations,
        "seed": args.seed,
        "runtime_leak_claim": False,
        "causal_claim": False,
        "validation_errors": errors,
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output_dir / "report.md").write_text(report(summary, results), encoding="utf-8")
    artifacts = ("statistics.csv", "summary.json", "report.md")
    manifest = {
        "input_sha256": sha256(args.input),
        "script_sha256": sha256(Path(__file__)),
        "artifact_sha256": {name: sha256(args.output_dir / name) for name in artifacts},
        "parameters": {"iterations": args.iterations, "seed": args.seed},
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {"summary": summary, "statistics": results}


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument(
        "--input", type=Path,
        default=Path("outputs/aidev_full_coverage_v1/matched_pair_cache_audit.csv"),
    )
    value.add_argument("--output-dir", type=Path, default=Path("outputs/aidev_full_formal_v1"))
    value.add_argument("--iterations", type=int, default=10_000)
    value.add_argument("--seed", type=int, default=20_260_805)
    return value


def main() -> int:
    args = parser().parse_args()
    if args.iterations < 1:
        raise SystemExit("--iterations must be positive")
    print(json.dumps(run(args), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
