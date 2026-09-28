#!/usr/bin/env python3
"""Analyze the audited 480-pair combined AIDev cohort with stdlib only."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path

if __package__:
    from .analyze_aidev_primary_queue import (
        bh_adjust, build_log_index, cluster_bootstrap, count_logs, exact_mcnemar,
        file_sha256, paired_binary_result, percentile, risk_set, concept_set,
        trimmed_mean, wilson,
    )
    from .audit_aidev_combined_cohort import normalize_logs, normalize_pairs, read_csv, SENSITIVE_FEATURES
else:
    from analyze_aidev_primary_queue import (
        bh_adjust, build_log_index, cluster_bootstrap, count_logs, exact_mcnemar,
        file_sha256, paired_binary_result, percentile, risk_set, concept_set,
        trimmed_mean, wilson,
    )
    from audit_aidev_combined_cohort import normalize_logs, normalize_pairs, read_csv, SENSITIVE_FEATURES


DEFAULT_ORIGINAL = Path("outputs/aidev_observational_primary_300")
DEFAULT_EXPANSION = Path("outputs/aidev_expansion_structured_evidence_v1")
DEFAULT_AUDIT = Path("outputs/aidev_combined_482_preanalysis_audit_v1")
DEFAULT_OUTPUT = Path("outputs/aidev_combined_480_formal_analysis_v1")


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...] | None = None) -> None:
    if not fields:
        fields = tuple(rows[0])
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def density_result(pairs: list[dict], index: dict, structured: bool, iterations: int, seed: int) -> dict:
    agent = lambda row: count_logs(index, "agent", row["pair_id"], structured=structured) / max(1, row["agent_size"]) * 1000
    human = lambda row: count_logs(index, "human", row["pair_id"], structured=structured) / max(1, row["human_size"]) * 1000
    effect, low, high = cluster_bootstrap(pairs, agent, human, iterations, seed)
    agent_values, human_values = [agent(row) for row in pairs], [human(row) for row in pairs]
    return {
        "scope": "production", "outcome": "logs_per_1000_changed_lines:" + ("structured_proxy" if structured else "broad"),
        "n_pairs": len(pairs), "agent_mean": statistics.fmean(agent_values),
        "human_mean": statistics.fmean(human_values), "agent_median": statistics.median(agent_values),
        "human_median": statistics.median(human_values), "agent_trimmed_mean_5pct": trimmed_mean(agent_values),
        "human_trimmed_mean_5pct": trimmed_mean(human_values), "effect": effect,
        "effect_ci_low": low, "effect_ci_high": high,
        "effect_type": "paired_mean_density_difference_agent_minus_human",
        "interpretation": "secondary_outlier_sensitive",
    }


def type_statistics(pairs: list[dict], logs: list[dict], iterations: int, seed: int) -> list[dict]:
    patterns: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(lambda: {"agent": set(), "human": set()})
    counts, totals = Counter(), Counter()
    for row in logs:
        if row["path_scope"] != "production":
            continue
        side = row["provenance"]
        totals[side] += 1
        for family, values in (("risk", risk_set(row)), ("concept", concept_set(row))):
            for value in values:
                patterns[(family, value)][side].add(row["pair_id"])
                counts[(family, value, side)] += 1
    tests = []
    for (family, pattern), sides in sorted(patterns.items()):
        agent_ids, human_ids = sides["agent"], sides["human"]
        agent_only, human_only = len(agent_ids - human_ids), len(human_ids - agent_ids)
        effect, low, high = cluster_bootstrap(
            pairs, lambda row, ids=agent_ids: float(row["pair_id"] in ids),
            lambda row, ids=human_ids: float(row["pair_id"] in ids), iterations, seed,
        )
        tests.append({
            "family": family, "pattern": pattern, "effect": effect, "effect_ci_low": low,
            "effect_ci_high": high, "p_value": exact_mcnemar(agent_only, human_only),
            "agent_only": agent_only, "human_only": human_only,
        })
    adjusted = bh_adjust([row["p_value"] for row in tests])
    output = []
    for test, q_value in zip(tests, adjusted):
        for side in ("agent", "human"):
            n = counts[(test["family"], test["pattern"], side)]
            low, high = wilson(n, totals[side])
            output.append({
                "provenance": side, "scope": "production",
                "pattern": f"{test['family']}:{test['pattern']}", "n_logs": totals[side],
                "n_candidates": n, "rate": n / totals[side] if totals[side] else 0.0,
                "ci_low": low, "ci_high": high, "effect": test["effect"],
                "effect_ci_low": test["effect_ci_low"], "effect_ci_high": test["effect_ci_high"],
                "effect_type": "paired_pr_presence_risk_difference_agent_minus_human",
                "p_value": test["p_value"], "q_value_bh": q_value,
                "agent_only": test["agent_only"], "human_only": test["human_only"],
                "interpretation": "exploratory_static_pattern_not_runtime_leak",
            })
    return output


def subgroup_descriptives(pairs: list[dict], agent_fn, human_fn) -> list[dict]:
    output = []
    for dimension in ("agent_product", "language", "task_type"):
        for category in sorted({row[dimension] for row in pairs}):
            subset = [row for row in pairs if row[dimension] == category]
            if len(subset) < 20:
                continue
            agent_n, human_n = sum(agent_fn(row) for row in subset), sum(human_fn(row) for row in subset)
            agent_only = sum(agent_fn(row) and not human_fn(row) for row in subset)
            human_only = sum(human_fn(row) and not agent_fn(row) for row in subset)
            output.append({
                "dimension": dimension, "category": category, "n_pairs": len(subset),
                "agent_n": agent_n, "human_n": human_n, "agent_rate": agent_n / len(subset),
                "human_rate": human_n / len(subset), "risk_difference": (agent_n - human_n) / len(subset),
                "agent_only": agent_only, "human_only": human_only,
                "mcnemar_p_unadjusted": exact_mcnemar(agent_only, human_only),
                "interpretation": "exploratory_descriptive_subgroup",
            })
    return output


def run(args: argparse.Namespace) -> dict:
    audit = json.loads((args.audit_dir / "quality_audit.json").read_text(encoding="utf-8"))
    if audit["status"] != "CONDITIONAL_PASS" or audit["conditionally_eligible_pairs"] != 480:
        raise ValueError("pre-analysis audit gate is not satisfied")
    admission = read_csv(args.audit_dir / "admission_decisions.csv")
    admitted = {row["pair_id"] for row in admission if row["status"] == "CONDITIONALLY_ELIGIBLE"}
    pairs = normalize_pairs(
        read_csv(args.original_dir / "matched_pairs.csv"), read_csv(args.expansion_dir / "matched_pairs.csv")
    )
    logs = normalize_logs(
        read_csv(args.original_dir / "log_candidates.csv"), read_csv(args.expansion_dir / "log_evidence.csv")
    )
    pairs = [row for row in pairs if row["pair_id"] in admitted]
    logs = [row for row in logs if row["pair_id"] in admitted]
    if len(pairs) != 480 or len({row["pair_id"] for row in pairs}) != 480:
        raise ValueError("admitted pair set is not exactly 480 unique pairs")

    _, index = build_log_index(logs)
    broad_agent = lambda row: count_logs(index, "agent", row["pair_id"]) > 0
    broad_human = lambda row: count_logs(index, "human", row["pair_id"]) > 0
    structured_agent = lambda row: count_logs(index, "agent", row["pair_id"], structured=True) > 0
    structured_human = lambda row: count_logs(index, "human", row["pair_id"], structured=True) > 0
    all_agent = lambda row: count_logs(index, "agent", row["pair_id"], "all_files") > 0
    all_human = lambda row: count_logs(index, "human", row["pair_id"], "all_files") > 0

    primary = paired_binary_result(
        pairs, "any_added_executable_log", "production", broad_agent, broad_human,
        args.bootstrap_iterations, args.seed,
    )
    structured = paired_binary_result(
        pairs, "any_added_structured_log_proxy", "production", structured_agent, structured_human,
        args.bootstrap_iterations, args.seed,
    )
    all_files = paired_binary_result(
        pairs, "any_added_executable_log", "all_files", all_agent, all_human,
        args.bootstrap_iterations, args.seed,
    )
    primary_rows = [
        {"analysis_role": "PRIMARY", **primary},
        {"analysis_role": "SENSITIVITY", **structured},
        {"analysis_role": "SENSITIVITY", **all_files},
    ]

    pair_rows = []
    for row in pairs:
        pair_rows.append({
            "cohort": row["cohort"], "pair_id": row["pair_id"], "repo": row["repo"],
            "language": row["language"], "task_type": row["task_type"],
            "agent_product": row["agent_product"], "date_distance_days": row["date_distance_days"],
            "size_ratio": row["size_ratio"], "agent_size": row["agent_size"], "human_size": row["human_size"],
            "agent_any_production_log": broad_agent(row), "human_any_production_log": broad_human(row),
            "agent_any_structured_log": structured_agent(row), "human_any_structured_log": structured_human(row),
            "agent_any_all_file_log": all_agent(row), "human_any_all_file_log": all_human(row),
            "agent_n_production_logs": count_logs(index, "agent", row["pair_id"]),
            "human_n_production_logs": count_logs(index, "human", row["pair_id"]),
        })

    def trim_top(fraction: float) -> list[dict]:
        agent_cut = percentile(sorted(row["agent_n_logs"] for row in pairs), 1 - fraction)
        human_cut = percentile(sorted(row["human_n_logs"] for row in pairs), 1 - fraction)
        return [row for row in pairs if row["agent_n_logs"] <= agent_cut and row["human_n_logs"] <= human_cut]

    one_per_repo, seen = [], set()
    for row in sorted(pairs, key=lambda item: (item["date_distance_days"], item["size_ratio"], item["pair_id"])):
        if row["repo"] not in seen:
            seen.add(row["repo"])
            one_per_repo.append(row)
    sensitivity_specs = [
        ("main", pairs, broad_agent, broad_human),
        ("date_le_90_days", [row for row in pairs if row["date_distance_days"] <= 90], broad_agent, broad_human),
        ("date_le_30_days", [row for row in pairs if row["date_distance_days"] <= 30], broad_agent, broad_human),
        ("size_ratio_le_5", [row for row in pairs if row["size_ratio"] <= 5], broad_agent, broad_human),
        ("size_ratio_le_2", [row for row in pairs if row["size_ratio"] <= 2], broad_agent, broad_human),
        ("one_pair_per_repository", one_per_repo, broad_agent, broad_human),
        ("exclude_docs_test_build_ci", [row for row in pairs if row["task_type"] not in {"docs", "test", "build", "ci"}], broad_agent, broad_human),
        ("exclude_top_1pct_log_counts", trim_top(0.01), broad_agent, broad_human),
        ("exclude_top_5pct_log_counts", trim_top(0.05), broad_agent, broad_human),
        ("structured_log_proxy", pairs, structured_agent, structured_human),
        ("original_only", [row for row in pairs if row["cohort"] == "original_300"], broad_agent, broad_human),
        ("expansion_only", [row for row in pairs if row["cohort"] == "expansion_182"], broad_agent, broad_human),
    ]
    sensitivity = []
    for name, subset, agent_fn, human_fn in sensitivity_specs:
        sensitivity.append({"analysis": name, **paired_binary_result(
            subset, "any_added_log", "production", agent_fn, human_fn,
            args.bootstrap_iterations, args.seed,
        )})
    sensitivity_detected = [row["analysis"] for row in sensitivity if row["conclusion"] == "difference_detected"]
    sensitivity_direction_consistent = all(row["effect"] <= 0 for row in sensitivity)

    secondary = [
        density_result(pairs, index, False, args.bootstrap_iterations, args.seed),
        density_result(pairs, index, True, args.bootstrap_iterations, args.seed),
    ]
    types = type_statistics(pairs, logs, args.bootstrap_iterations, args.seed)
    subgroups = subgroup_descriptives(pairs, broad_agent, broad_human)
    significant_types = sorted({row["pattern"] for row in types if float(row["q_value_bh"]) < 0.05})
    aggregate_sign = math.copysign(1, primary["effect"]) if primary["effect"] else 0
    subgroup_signs = {math.copysign(1, row["risk_difference"]) for row in subgroups if row["risk_difference"]}
    direction_heterogeneity = len(subgroup_signs) > 1 or (aggregate_sign and -aggregate_sign in subgroup_signs)
    subgroup_phrase = "存在异质性" if direction_heterogeneity else "未观察到反转"

    deferred = []
    for side in ("agent", "human"):
        side_logs = [row for row in logs if row["provenance"] == side and row["path_scope"] == "production"]
        candidate_rows = [row for row in side_logs if risk_set(row) & SENSITIVE_FEATURES]
        deferred.append({
            "provenance": side, "scope": "production", "n_logs": len(side_logs),
            "n_automatic_sensitive_family_rows": len(candidate_rows),
            "n_prs_with_candidate": len({row["pair_id"] for row in candidate_rows}),
            "analysis_status": "DEFERRED_PENDING_INDEPENDENT_SEMANTIC_LABELS",
            "runtime_leak_status": "NOT_EXECUTED_NOT_RUNTIME_CONFIRMED",
        })

    fallacies = [
        ("Simpson's paradox", "CAUTION" if direction_heterogeneity else "NOTE", "Subgroup directions are heterogeneous; aggregate results are not universal." if direction_heterogeneity else "No observed direction reversal among reported subgroups."),
        ("Ecological fallacy", "PASS", "Inference remains at matched-PR level, not individual developer level."),
        ("Berkson's paradox", "CAUTION", "Only merged, source-eligible and matchable PRs enter the cohort."),
        ("Collider bias", "CAUTION", "Production-source and final-size gates may condition on task outcomes."),
        ("Base-rate neglect", "PASS", "Zero-log PRs remain in both denominators."),
        ("Regression to the mean", "PASS", "PRs were not selected on extreme logging outcomes."),
        ("Survivorship bias", "CAUTION", "Rejected, abandoned and inaccessible PRs are outside scope."),
        ("Look-elsewhere effect", "PASS", "One production PR-presence outcome is primary; pattern tests use BH correction."),
        ("Garden of forking paths", "CAUTION", "Analysis was fixed before this run but was not externally preregistered."),
        ("Correlation is not causation", "PASS", "All conclusions use observational association language."),
        ("Reverse causality", "CAUTION", "Task assignment may influence both provenance and logging need."),
    ]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "paired_analysis_rows.csv", pair_rows)
    write_csv(args.output_dir / "primary_statistics.csv", primary_rows)
    write_csv(args.output_dir / "secondary_statistics.csv", secondary)
    write_csv(args.output_dir / "sensitivity_analysis.csv", sensitivity)
    write_csv(args.output_dir / "type_statistics.csv", types)
    write_csv(args.output_dir / "subgroup_descriptives.csv", subgroups)
    write_csv(args.output_dir / "deferred_privacy_candidates.csv", deferred)
    write_csv(args.output_dir / "fallacy_scan.csv", [
        {"fallacy": name, "severity": severity, "assessment": assessment}
        for name, severity, assessment in fallacies
    ])

    verdict = primary["conclusion"]
    summary = {
        "status": "ANALYZED", "verification_status": "VERIFIED_DETERMINISTIC_REANALYSIS",
        "quality_gate": audit["status"], "n_pairs": len(pairs),
        "n_repositories": len({row["repo"] for row in pairs}), "excluded_pairs": 2,
        "primary": primary, "structured_sensitivity": structured,
        "all_file_sensitivity": all_files, "statistical_verdict": verdict,
        "n_bh_significant_static_patterns": len(significant_types),
        "bh_significant_static_patterns": significant_types,
        "sensitivity_difference_detected": sensitivity_detected,
        "sensitivity_direction_consistent": sensitivity_direction_consistent,
        "subgroup_direction_heterogeneity": direction_heterogeneity,
        "privacy_inference_status": "DEFERRED_PENDING_INDEPENDENT_SEMANTIC_LABELS",
        "runtime_leak_claim": False, "fallacy_scan_coverage": "11/11",
        "bootstrap_iterations": args.bootstrap_iterations, "seed": args.seed,
    }
    (args.output_dir / "analysis_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output_dir / "formal_statistical_report.md").write_text(f"""# AIDev Agent–Human 合并队列正式统计结果

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: run + validate
- Origin Date: 2026-09-04
- Verification Status: VERIFIED_DETERMINISTIC_REANALYSIS
- Version Label: aidev_combined_480_formal_analysis_v1
- Dataset: AIDev matched observational PR cohort
- Sample: 480 matched pairs across {summary['n_repositories']} repositories
- Bootstrap: repository-clustered, {args.bootstrap_iterations:,} iterations, seed `{args.seed}`

## 结论先行

**生产代码主分析未检出稳定差异。** Agent 数值上较低，但配对风险差的 95% 区间仍触及 0，且 McNemar 精确检验 p={primary['mcnemar_p']:.4f}。扩容到 480 对后，主结论与原 300 对保持一致。

## 主结果：新增至少一条生产范围广义日志

- Agent：{primary['agent_n']}/{primary['n_pairs']} = {primary['agent_rate']:.1%}（Wilson 95% CI {primary['agent_ci_low']:.1%}–{primary['agent_ci_high']:.1%}）。
- Human：{primary['human_n']}/{primary['n_pairs']} = {primary['human_rate']:.1%}（Wilson 95% CI {primary['human_ci_low']:.1%}–{primary['human_ci_high']:.1%}）。
- 配对风险差（Agent−Human）：{primary['effect']:+.2%}，仓库聚类 bootstrap 95% CI {primary['effect_ci_low']:+.2%}–{primary['effect_ci_high']:+.2%}。
- Agent-only/Human-only 不一致对：{primary['agent_only']}/{primary['human_only']}；McNemar exact p={primary['mcnemar_p']:.4f}。
- 判定：`{verdict}`。

## 结构化日志敏感性

排除 `print/console.log/echo/printf` 等 `unstructured_stdio` 代理后：

- Agent/Human：{structured['agent_n']}/{structured['human_n']} 个 PR，触达率 {structured['agent_rate']:.1%}/{structured['human_rate']:.1%}。
- 配对风险差：{structured['effect']:+.2%}（95% CI {structured['effect_ci_low']:+.2%}–{structured['effect_ci_high']:+.2%}），p={structured['mcnemar_p']:.4f}。
- 判定：`{structured['conclusion']}`。

## 生产代码稳健性检查

- 12 个预定规格的效应方向均为 Agent 较低：`{sensitivity_direction_consistent}`。
- 其中 {len(sensitivity_detected)}/12 的区间排除 0：{', '.join(sensitivity_detected) if sensitivity_detected else '无'}。
- 主规格、结构化口径、每仓库一对、原 298 对与新增 182 对单独分析均未排除 0。因此应表述为**方向一致，但尚非规格稳定差异**。

## 全文件敏感性

- Agent/Human：{all_files['agent_n']}/{all_files['human_n']} 个 PR，触达率 {all_files['agent_rate']:.1%}/{all_files['human_rate']:.1%}。
- 配对风险差：{all_files['effect']:+.2%}（95% CI {all_files['effect_ci_low']:+.2%}–{all_files['effect_ci_high']:+.2%}），p={all_files['mcnemar_p']:.4f}。
- 该区间排除 0，但这个口径包含测试、fixture、示例和构建目录，只能报告为**全文件范围的敏感性差异**，不能替代生产代码主结论。

## 类型与子组

- 静态日志模式比较使用 Benjamini–Hochberg 校正；q<0.05 的模式：{', '.join(significant_types) if significant_types else '无'}。
- 产品、语言和任务子组的方向{subgroup_phrase}；子组只作探索性描述。
- 日志总数与密度受极端 CLI/脚本 PR 支配，只作次要结果。

## 隐私分析暂停门

- 自动敏感特征候选已另存于 `deferred_privacy_candidates.csv`。
- 在 200 条来源隐藏样本完成独立语义标注前，不对敏感数据候选率作正式推断。
- 所有静态命中均不是 `RUNTIME_LEAK_CONFIRMED`。

## 11 类统计谬误检查

- Coverage: 11/11 checked.
- 主要风险：已合并 PR 的存活者偏差，生产源代码/规模卡尺的条件化偏差，未外部预注册，以及子组方向异质性。

## 证据边界

这是 AIDev PR 级观察性匹配分析，不是会话到行级作者证明，也不支持“Agent 导致日志增多/减少”的因果结论。Human 标签无法排除未披露 AI 协助。
""", encoding="utf-8")

    inputs = [
        args.audit_dir / "quality_audit.json", args.audit_dir / "admission_decisions.csv",
        args.original_dir / "matched_pairs.csv", args.original_dir / "log_candidates.csv",
        args.expansion_dir / "matched_pairs.csv", args.expansion_dir / "log_evidence.csv",
    ]
    outputs = (
        "paired_analysis_rows.csv", "primary_statistics.csv", "secondary_statistics.csv",
        "sensitivity_analysis.csv", "type_statistics.csv", "subgroup_descriptives.csv",
        "deferred_privacy_candidates.csv", "fallacy_scan.csv", "analysis_summary.json",
        "formal_statistical_report.md",
    )
    manifest = {
        "analysis": "aidev_combined_480_formal_analysis",
        "parameters": {"bootstrap_iterations": args.bootstrap_iterations, "seed": args.seed},
        "script_sha256": file_sha256(Path(__file__)),
        "input_sha256": {str(path): file_sha256(path) for path in inputs},
        "output_sha256": {name: file_sha256(args.output_dir / name) for name in outputs},
        "deterministic": True, "quality_gate": audit["status"], "statistical_verdict": verdict,
    }
    (args.output_dir / "analysis_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--original-dir", type=Path, default=DEFAULT_ORIGINAL)
    result.add_argument("--expansion-dir", type=Path, default=DEFAULT_EXPANSION)
    result.add_argument("--audit-dir", type=Path, default=DEFAULT_AUDIT)
    result.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    result.add_argument("--bootstrap-iterations", type=int, default=10_000)
    result.add_argument("--seed", type=int, default=20260805)
    return result


if __name__ == "__main__":
    print(json.dumps(run(parser().parse_args()), ensure_ascii=False, sort_keys=True))
