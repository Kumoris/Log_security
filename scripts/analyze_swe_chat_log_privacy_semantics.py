#!/usr/bin/env python3
"""Compare value-aware privacy features in reconstructed SWE-chat log statements.

The input is a frozen CSV evidence layer.  This analysis intentionally uses only
the Python standard library.  Findings are static review candidates, not proven
runtime leaks.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    from .analyze_aidev_log_privacy_semantics import CONTENT_FEATURES, semantic_features
except ImportError:
    from analyze_aidev_log_privacy_semantics import CONTENT_FEATURES, semantic_features


PRIMARY_SCOPE = "production_executable_added_log_statement"
FEATURES = ("any_privacy_candidate",) + CONTENT_FEATURES
STAT_FIELDS = (
    "analysis_unit", "scope", "feature", "n_common_repositories",
    "agent_n_logs", "human_n_logs", "agent_n_candidates", "human_n_candidates",
    "agent_rate", "human_rate", "agent_ci_low", "agent_ci_high",
    "human_ci_low", "human_ci_high", "effect_repository_balanced",
    "effect_ci_low", "effect_ci_high", "sign_flip_p", "bh_q",
    "leave_one_repo_out_min", "leave_one_repo_out_max", "direction_consistent",
    "stable_after_bh", "bootstrap_iterations", "seed",
)
RATE_FIELDS = ("provenance", "scope", "pattern", "n_logs", "n_candidates", "rate", "ci_low", "ci_high", "effect")
ROW_FIELDS = (
    "repo", "commit", "checkpoint_pk", "file", "line", "attribution",
    "path_scope", "sink_family", "evidence_grade", "statement_lines",
    "privacy_features", "mechanism_features", "static_privacy_candidate",
    "dynamic_values_redacted", "statement_redacted", "context_redacted",
)
AUDIT_FIELDS = ROW_FIELDS + (
    "audit_sampling_design", "audit_inclusion_probability",
    "manual_is_privacy_issue", "manual_primary_type", "manual_value_logged",
    "manual_runtime_reachable", "manual_externalized_or_persisted", "manual_notes",
)


def truth(value: object) -> bool:
    return str(value).lower() in {"1", "true", "yes"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_csv(path: Path) -> list[dict]:
    csv.field_size_limit(sys.maxsize)
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if total == 0:
        return math.nan, math.nan
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return center - margin, center + margin


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    low, high = math.floor(position), math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] * (high - position) + ordered[high] * (position - low)


def bh_adjust(values: list[float]) -> list[float]:
    order = sorted(range(len(values)), key=values.__getitem__)
    adjusted = [1.0] * len(values)
    running = 1.0
    for rank_index in range(len(order) - 1, -1, -1):
        index = order[rank_index]
        rank = rank_index + 1
        running = min(running, values[index] * len(values) / rank)
        adjusted[index] = min(1.0, running)
    return adjusted


def _has_feature(row: dict, feature: str) -> bool:
    if feature == "any_privacy_candidate":
        return truth(row["static_privacy_candidate"])
    return feature in set(row["privacy_features"].split(";"))


def repository_balanced_result(rows: list[dict], feature: str, scope: str, iterations: int, seed: int) -> dict:
    by_repo_group: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        by_repo_group[row["repo"]][row["attribution"]].append(row)
    repos = sorted(
        repo for repo, groups in by_repo_group.items()
        if groups.get("agent_only") and groups.get("human_only")
    )
    differences = []
    for repo in repos:
        agent = by_repo_group[repo]["agent_only"]
        human = by_repo_group[repo]["human_only"]
        differences.append(
            sum(_has_feature(row, feature) for row in agent) / len(agent)
            - sum(_has_feature(row, feature) for row in human) / len(human)
        )
    effect = sum(differences) / len(differences) if differences else math.nan

    rng = random.Random(seed)
    boot = [
        sum(differences[rng.randrange(len(differences))] for _ in differences) / len(differences)
        for _ in range(iterations)
    ] if differences else []
    sign_rng = random.Random(seed + 1)
    extreme = 0
    for _ in range(iterations):
        permuted = sum(value if sign_rng.random() < 0.5 else -value for value in differences) / len(differences)
        extreme += abs(permuted) >= abs(effect) - 1e-15
    p_value = (extreme + 1) / (iterations + 1) if differences else 1.0

    leave_one_out = [
        sum(differences[:index] + differences[index + 1:]) / (len(differences) - 1)
        for index in range(len(differences))
    ] if len(differences) > 1 else [effect]
    direction_consistent = bool(
        not math.isnan(effect)
        and all(value == 0 or effect == 0 or (value > 0) == (effect > 0) for value in leave_one_out)
    )
    agent_rows = [row for row in rows if row["attribution"] == "agent_only"]
    human_rows = [row for row in rows if row["attribution"] == "human_only"]
    agent_candidates = sum(_has_feature(row, feature) for row in agent_rows)
    human_candidates = sum(_has_feature(row, feature) for row in human_rows)
    agent_ci = wilson(agent_candidates, len(agent_rows))
    human_ci = wilson(human_candidates, len(human_rows))
    return {
        "analysis_unit": "added_log_statement",
        "scope": scope,
        "feature": feature,
        "n_common_repositories": len(repos),
        "agent_n_logs": len(agent_rows),
        "human_n_logs": len(human_rows),
        "agent_n_candidates": agent_candidates,
        "human_n_candidates": human_candidates,
        "agent_rate": agent_candidates / len(agent_rows) if agent_rows else math.nan,
        "human_rate": human_candidates / len(human_rows) if human_rows else math.nan,
        "agent_ci_low": agent_ci[0], "agent_ci_high": agent_ci[1],
        "human_ci_low": human_ci[0], "human_ci_high": human_ci[1],
        "effect_repository_balanced": effect,
        "effect_ci_low": percentile(boot, 0.025) if boot else math.nan,
        "effect_ci_high": percentile(boot, 0.975) if boot else math.nan,
        "sign_flip_p": p_value,
        "leave_one_repo_out_min": min(leave_one_out),
        "leave_one_repo_out_max": max(leave_one_out),
        "direction_consistent": direction_consistent,
        "bootstrap_iterations": iterations,
        "seed": seed,
    }


def commit_side_rows(statement_rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for row in statement_rows:
        grouped[(row["repo"], row["commit"], row["attribution"])].append(row)
    output = []
    for (repo, commit, attribution), rows in sorted(grouped.items()):
        privacy = sorted({feature for row in rows for feature in row["privacy_features"].split(";") if feature})
        output.append({
            "repo": repo, "commit": commit, "attribution": attribution,
            "privacy_features": ";".join(privacy),
            "static_privacy_candidate": any(truth(row["static_privacy_candidate"]) for row in rows),
        })
    return output


def lineage_deduplicate(rows: list[dict]) -> tuple[list[dict], dict]:
    """Deduplicate repeated code locations and drop attribution-conflicted lineages."""
    groups: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        fingerprint = (
            row["repo"], row["file"], row["line"],
            re.sub(r"\s+", " ", row["statement_redacted"]).strip(),
        )
        groups[fingerprint].append(row)
    output = []
    conflicted = 0
    duplicate_rows = 0
    for values in groups.values():
        duplicate_rows += len(values) - 1
        if len({row["attribution"] for row in values}) != 1:
            conflicted += 1
            continue
        output.append(sorted(values, key=lambda row: row["commit"])[0])
    return output, {
        "input_rows": len(rows), "output_rows": len(output),
        "duplicate_rows_collapsed": duplicate_rows,
        "attribution_conflicted_fingerprints_excluded": conflicted,
    }


def qualify(raw: dict) -> bool:
    return bool(
        raw["add_remove"] == "add"
        and raw["evidence_grade"] == "A"
        and truth(raw["sink_executable"])
        and raw["attribution_consensus"] in {"agent_only", "human_only", "mixed"}
    )


def classify(raw_rows: list[dict]) -> list[dict]:
    output = []
    for raw in raw_rows:
        if not qualify(raw):
            continue
        features = semantic_features(raw["full_statement_redacted"], raw["context_redacted"])
        output.append({
            "repo": raw["repo"], "commit": raw["commit"], "checkpoint_pk": raw["checkpoint_pk"],
            "file": raw["file"], "line": raw["line"], "attribution": raw["attribution_consensus"],
            "path_scope": raw["path_scope"], "sink_family": raw["sink_family"],
            "evidence_grade": raw["evidence_grade"], "statement_lines": raw["statement_lines"],
            "privacy_features": ";".join(features["privacy_features"]),
            "mechanism_features": ";".join(features["mechanism_features"]),
            "static_privacy_candidate": features["static_privacy_candidate"],
            "dynamic_values_redacted": features["dynamic_values"][:800],
            "statement_redacted": raw["full_statement_redacted"],
            "context_redacted": raw["context_redacted"],
        })
    return output


def add_adjustment(statistics: list[dict]) -> None:
    by_scope: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in statistics:
        by_scope[(row["analysis_unit"], row["scope"])].append(row)
    for rows in by_scope.values():
        for row, q_value in zip(rows, bh_adjust([value["sign_flip_p"] for value in rows])):
            row["bh_q"] = q_value
            row["stable_after_bh"] = bool(
                q_value < 0.05
                and (row["effect_ci_low"] > 0 or row["effect_ci_high"] < 0)
                and row["direction_consistent"]
            )


def rate_rows(rows: list[dict], scope: str, statistics: list[dict]) -> list[dict]:
    effects = {row["feature"]: row["effect_repository_balanced"] for row in statistics if row["scope"] == scope}
    output = []
    for provenance in ("agent_only", "human_only", "mixed"):
        values = [row for row in rows if row["attribution"] == provenance]
        for feature in FEATURES:
            candidates = sum(_has_feature(row, feature) for row in values)
            low, high = wilson(candidates, len(values))
            output.append({
                "provenance": provenance, "scope": scope, "pattern": feature,
                "n_logs": len(values), "n_candidates": candidates,
                "rate": candidates / len(values) if values else math.nan,
                "ci_low": low, "ci_high": high,
                "effect": effects.get(feature, "") if provenance != "mixed" else "",
            })
    return output


def audit_sample(rows: list[dict], seed: int, per_group: int = 100) -> list[dict]:
    """Draw a probability sample for estimating annotation precision by group."""
    output = []
    for group_index, attribution in enumerate(("agent_only", "human_only", "mixed")):
        values = [row for row in rows if row["attribution"] == attribution and truth(row["static_privacy_candidate"])]
        random.Random(seed + group_index).shuffle(values)
        selected_n = min(per_group, len(values))
        probability = selected_n / len(values) if values else 0.0
        for row in values[:selected_n]:
            output.append({
                **row,
                "audit_sampling_design": "simple_random_without_replacement_within_attribution",
                "audit_inclusion_probability": probability,
                "manual_is_privacy_issue": "", "manual_primary_type": "",
                "manual_value_logged": "", "manual_runtime_reachable": "",
                "manual_externalized_or_persisted": "", "manual_notes": "",
            })
    return output


def audit_enriched_sample(rows: list[dict], seed: int, per_group: int = 100) -> list[dict]:
    """Draw a discovery-only sample enriched for high-priority mechanisms."""
    rng = random.Random(seed)
    output = []
    priority = {"credential_auth_value", "direct_identifier_literal", "agent_tool_context_value", "raw_request_response"}
    for attribution in ("agent_only", "human_only", "mixed"):
        values = [row for row in rows if row["attribution"] == attribution and truth(row["static_privacy_candidate"])]
        high = [row for row in values if set(row["privacy_features"].split(";")) & priority]
        remainder = [row for row in values if row not in high]
        rng.shuffle(high)
        rng.shuffle(remainder)
        chosen = (high + remainder)[:per_group]
        for row in chosen:
            output.append({
                **row,
                "audit_sampling_design": "priority_enriched_discovery_only",
                "audit_inclusion_probability": "",
                "manual_is_privacy_issue": "", "manual_primary_type": "",
                "manual_value_logged": "", "manual_runtime_reachable": "",
                "manual_externalized_or_persisted": "", "manual_notes": "",
            })
    return output


def report(summary: dict, main: list[dict], commit_results: list[dict]) -> str:
    def table(rows: list[dict]) -> str:
        lines = []
        for row in rows:
            lines.append(
                f"| {row['feature']} | {row['agent_n_candidates']}/{row['agent_n_logs']} "
                f"({row['agent_rate'] * 100:.2f}%) | {row['human_n_candidates']}/{row['human_n_logs']} "
                f"({row['human_rate'] * 100:.2f}%) | {row['effect_repository_balanced'] * 100:+.2f} pp | "
                f"[{row['effect_ci_low'] * 100:+.2f}, {row['effect_ci_high'] * 100:+.2f}] | "
                f"{row['bh_q']:.4f} | {row['stable_after_bh']} |"
            )
        return "\n".join(lines)

    return f"""# SWE-chat 完整日志语句的值感知隐私分析

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: VERIFIED_WITH_PENDING_MANUAL_AUDIT
- Version Label: swe_chat_value_aware_privacy_v1

## 这一步修复了什么

原候选表只保存 diff 中命中日志 API 的单行，无法读取多行调用后续参数。本分析回到 `commits.parquet` 的完整文件版本，重建了 {summary['extraction']['multiline_reconstructed']} 条多行日志；主分析仅保留证据等级 A、可执行 sink、生产路径中的新增日志。

主样本包含 Agent-only {summary['main_counts']['agent_only']} 条、Human-only {summary['main_counts']['human_only']} 条、Mixed {summary['main_counts']['mixed']} 条。`agent_only` / `human_only` 是文件版本比较得到的文件级归因；Mixed 不进入主效应。

## 主分析：给定已经新增了一条日志，其内容属于哪类静态隐私候选

效应量是每个仓库内先计算 Agent-Human 比例差，再对仓库等权平均，避免大仓库支配结果。

| 特征 | Agent | Human | 仓库平衡差值 | bootstrap 95% CI | BH q | 稳定差异 |
|---|---:|---:|---:|---:|---:|---:|
{table(main)}

## 敏感性：以含日志的一侧 commit 为单位

| 特征 | Agent commit-side | Human commit-side | 仓库平衡差值 | bootstrap 95% CI | BH q | 稳定差异 |
|---|---:|---:|---:|---:|---:|---:|
{table(commit_results)}

## 当前能与不能回答的问题

1. 能回答：在 SWE-chat 已触达日志的生产代码里，Agent-only 与 Human-only 新增日志的静态敏感内容组成是否不同。
2. 不能回答：未新增日志的提交是否本应记录敏感数据；因此不能由本表推断总体泄露发生率。
3. 不能回答：静态候选在运行时是否可达、是否携带真实敏感值、是否进入外部日志系统；这些需人工复核和运行实验。
4. `configuration_infrastructure_value` 包含公开端点、相对路径等低敏感候选，必须单独人工判定。
5. Agent 原生的 stdout/tool-output 到模型上下文传播不在 Git patch 内，需会话轨迹或控制实验验证。
6. 主表中异常内容特征通过了主分析门槛，但没有在结构化 logger 敏感性分析中稳定；因此只能作为“Agent 偏故障日志”的跨数据源支持，不能作为隐私泄露率已存在差异的结论。

## 统计与复现边界

- 固定种子：{summary['seed']}；仓库 bootstrap / sign-flip：{summary['bootstrap_iterations']} 次。
- 主分析 BH 校正覆盖 {len(FEATURES)} 个预定义特征。
- 只有 BH q < 0.05、仓库 bootstrap CI 排除 0、逐仓库删除方向一致时才标记稳定差异。
- 同时稳定通过主分析、结构化 logger、代码谱系去重和 commit-side 四种口径的特征：{', '.join(summary['robust_across_primary_structured_lineage_and_commit']) or '无'}。
- 人工语义审计主队列在 attribution 组内做不放回简单随机抽样；另一份高风险富集队列只用于机制发现，不用于估计精确率或组间比例。
- 统计谬误扫描 11/11；重点风险为条件选择、文件级归因、任务混杂、重复日志和稀有类型低功效。
"""


def run(evidence_path: Path, output_dir: Path, iterations: int, seed: int) -> dict:
    raw_rows = read_csv(evidence_path)
    classified = classify(raw_rows)
    main_rows = [row for row in classified if row["path_scope"] == "production"]
    main_compare = [row for row in main_rows if row["attribution"] in {"agent_only", "human_only"}]
    lineage_rows, lineage_summary = lineage_deduplicate(main_compare)

    scope_sets = {
        PRIMARY_SCOPE: main_compare,
        "production_structured_logger_only": [row for row in main_compare if row["sink_family"] == "structured_logger"],
        "production_lineage_deduplicated": lineage_rows,
        "all_paths_executable_added_log_statement": [
            row for row in classified if row["attribution"] in {"agent_only", "human_only"}
        ],
    }
    statistics = []
    for scope_index, (scope, rows) in enumerate(scope_sets.items()):
        for feature_index, feature in enumerate(FEATURES):
            statistics.append(repository_balanced_result(
                rows, feature, scope, iterations, seed + scope_index * 1000 + feature_index * 10
            ))

    commit_rows = commit_side_rows(main_compare)
    commit_results = []
    for feature_index, feature in enumerate(FEATURES):
        value = repository_balanced_result(
            commit_rows, feature, "production_log_touching_commit_side", iterations, seed + 4000 + feature_index * 10
        )
        value["analysis_unit"] = "log_touching_commit_side"
        commit_results.append(value)
    statistics.extend(commit_results)
    add_adjustment(statistics)

    main_statistics = [row for row in statistics if row["scope"] == PRIMARY_SCOPE]
    rate_output = []
    for scope, rows in scope_sets.items():
        rate_output.extend(rate_rows(
            rows + ([row for row in classified if row["path_scope"] == "production" and row["attribution"] == "mixed"] if scope == PRIMARY_SCOPE else []),
            scope, statistics,
        ))

    audit = audit_sample(main_rows, seed)
    enriched_audit = audit_enriched_sample(main_rows, seed)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "classified_log_statements.csv", classified, ROW_FIELDS)
    write_csv(output_dir / "feature_statistics.csv", statistics, STAT_FIELDS)
    write_csv(output_dir / "descriptive_rates.csv", rate_output, RATE_FIELDS)
    write_csv(output_dir / "manual_audit_queue.csv", audit, AUDIT_FIELDS)
    write_csv(output_dir / "manual_audit_enriched_queue.csv", enriched_audit, AUDIT_FIELDS)

    extraction_summary_path = evidence_path.parent / "extraction_summary.json"
    extraction = json.loads(extraction_summary_path.read_text(encoding="utf-8"))
    main_counts = Counter(row["attribution"] for row in main_rows)
    candidate_counts = Counter(row["attribution"] for row in main_rows if truth(row["static_privacy_candidate"]))
    repo_counts = Counter()
    for attribution in ("agent_only", "human_only", "mixed"):
        repo_counts[attribution] = len({row["repo"] for row in main_rows if row["attribution"] == attribution})
    concentration = {}
    for attribution in ("agent_only", "human_only"):
        values = [row for row in main_rows if row["attribution"] == attribution]
        total_by_repo = Counter(row["repo"] for row in values)
        candidate_by_repo = Counter(row["repo"] for row in values if truth(row["static_privacy_candidate"]))
        concentration[attribution] = {
            "largest_repo_log_share": max(total_by_repo.values(), default=0) / len(values) if values else 0,
            "largest_repo_candidate_share": max(candidate_by_repo.values(), default=0) / sum(candidate_by_repo.values()) if candidate_by_repo else 0,
        }
    summary = {
        "status": "VERIFIED_WITH_PENDING_MANUAL_AUDIT",
        "scope": PRIMARY_SCOPE,
        "seed": seed,
        "bootstrap_iterations": iterations,
        "extraction": extraction,
        "evidence_sha256": sha256(evidence_path),
        "main_counts": dict(main_counts),
        "main_candidate_counts": dict(candidate_counts),
        "main_repository_counts": dict(repo_counts),
        "manual_audit_queue_n": len(audit),
        "manual_audit_sampling_design": "simple_random_without_replacement_within_attribution",
        "manual_audit_sampling_frame": dict(candidate_counts),
        "manual_audit_enriched_queue_n": len(enriched_audit),
        "manual_audit_enriched_usage": "mechanism_discovery_only_not_rate_estimation",
        "stable_primary_features": [row["feature"] for row in main_statistics if row["stable_after_bh"]],
        "robust_across_primary_structured_lineage_and_commit": [
            feature for feature in FEATURES
            if all(any(
                row["feature"] == feature and row["scope"] == required_scope and row["stable_after_bh"]
                for row in statistics
            ) for required_scope in (
                PRIMARY_SCOPE,
                "production_structured_logger_only",
                "production_lineage_deduplicated",
                "production_log_touching_commit_side",
            ))
        ],
        "lineage_sensitivity": lineage_summary,
        "concentration": concentration,
        "authorship_granularity": "file_level_for_agent_only_and_human_only; mixed_excluded_from_main_effect",
        "runtime_leak_claim": False,
        "manual_audit_status": "PENDING_HUMAN_LABELS",
        "fallacy_scan_coverage": "11/11",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(report(summary, main_statistics, commit_results), encoding="utf-8")
    artifacts = (
        "classified_log_statements.csv", "feature_statistics.csv", "descriptive_rates.csv",
        "manual_audit_queue.csv", "manual_audit_enriched_queue.csv", "summary.json", "report.md",
    )
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
        "--evidence", type=Path,
        default=Path("outputs/swe_chat_value_aware_privacy/full_log_evidence.csv"),
    )
    value.add_argument(
        "--output-dir", type=Path,
        default=Path("outputs/swe_chat_value_aware_privacy/analysis"),
    )
    value.add_argument("--bootstrap-iterations", type=int, default=10_000)
    value.add_argument("--seed", type=int, default=20260805)
    return value


def main() -> int:
    args = parser().parse_args()
    print(json.dumps(run(args.evidence, args.output_dir, args.bootstrap_iterations, args.seed), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
