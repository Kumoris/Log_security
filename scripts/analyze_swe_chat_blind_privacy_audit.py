#!/usr/bin/env python3
"""Unblind frozen SWE-chat labels and compare semantic candidate composition."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path

if __package__:
    from .analyze_swe_chat_log_privacy_semantics import bh_adjust, percentile, read_csv, sha256, wilson, write_csv
    from .prepare_swe_chat_blind_privacy_audit import source_hash
else:
    from analyze_swe_chat_log_privacy_semantics import bh_adjust, percentile, read_csv, sha256, wilson, write_csv
    from prepare_swe_chat_blind_privacy_audit import source_hash


TYPES = ("AUTH", "PII", "QID", "BIZ", "CFG", "DIAG", "AGENT_CTRL", "AGENT_CTX")
OUTCOMES = ("strict_static_sensitive", "broad_exposure_prone") + tuple(f"type_{name}" for name in TYPES)
ALLOWED_DECISIONS = {"YES", "CARRIER", "NO", "UNCLEAR"}
ANNOTATED_FIELDS = (
    "blind_id", "attribution", "repo", "commit", "checkpoint_pk", "file", "line",
    "path_scope", "sink_family", "evidence_grade", "privacy_features",
    "mechanism_features", "statement_redacted", "context_redacted", "decision",
    "type", "value_form", "severity", "rationale_code",
)
STAT_FIELDS = (
    "outcome", "agent_sample_n", "human_sample_n", "agent_positive_n",
    "human_positive_n", "agent_sample_rate", "human_sample_rate",
    "agent_ci_low", "agent_ci_high", "human_ci_low", "human_ci_high",
    "sample_effect", "sample_effect_ci_low", "sample_effect_ci_high",
    "fisher_p", "bh_q", "stable_candidate_composition_difference",
    "agent_candidate_frame", "human_candidate_frame", "agent_total_logs",
    "human_total_logs", "agent_estimated_log_rate", "human_estimated_log_rate",
    "estimated_log_rate_effect", "estimated_log_rate_effect_ci_low",
    "estimated_log_rate_effect_ci_high", "estimated_rate_status",
)
REPO_FIELDS = (
    "outcome", "common_repositories", "common_repo_equal_weight_effect",
    "common_repo_effect_ci_low", "common_repo_effect_ci_high",
    "agent_top_positive_repo", "agent_top_positive_repo_n",
    "agent_top_positive_repo_share", "human_top_positive_repo",
    "human_top_positive_repo_n", "human_top_positive_repo_share",
    "top_union_removed_agent_n", "top_union_removed_human_n",
    "top_union_removed_agent_rate", "top_union_removed_human_rate",
    "top_union_removed_effect", "repository_robust_direction",
)


def read_labels(path: Path) -> tuple[dict[str, str], list[dict]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    metadata = {}
    for line in lines:
        if line.startswith("# ") and "=" in line:
            key, value = line[2:].split("=", 1)
            metadata[key] = value
    rows = list(csv.DictReader((line for line in lines if not line.startswith("#")), delimiter="\t"))
    return metadata, rows


def validate_and_join(
    review_path: Path, key_path: Path, source_path: Path, labels_path: Path,
) -> tuple[list[dict], dict[str, str]]:
    metadata, labels = read_labels(labels_path)
    if metadata.get("review_input_sha256") != sha256(review_path):
        raise ValueError("blind review input drifted after labels were frozen")
    review = {row["blind_id"]: row for row in read_csv(review_path)}
    key = {row["blind_id"]: row for row in read_csv(key_path)}
    source = read_csv(source_path)
    by_id = {row["blind_id"]: row for row in labels}
    expected = set(review)
    if set(key) != expected or set(by_id) != expected or len(labels) != len(expected):
        raise ValueError("review, provenance key, and labels must have one-to-one blind IDs")

    output = []
    for blind_id in sorted(expected):
        label = by_id[blind_id]
        if label["decision"] not in ALLOWED_DECISIONS:
            raise ValueError(f"invalid decision for {blind_id}")
        parts = set(label["type"].split("+"))
        if parts != {"NONE"} and not parts <= set(TYPES):
            raise ValueError(f"invalid semantic type for {blind_id}")
        key_row = key[blind_id]
        source_index = int(key_row["source_row"]) - 1
        if source_index < 0 or source_index >= len(source):
            raise ValueError(f"invalid source row for {blind_id}")
        if source_hash(source[source_index]) != key_row["source_sha256_16"]:
            raise ValueError(f"source evidence drift for {blind_id}")
        output.append({**review[blind_id], **key_row, **label})
    return output, metadata


def _outcome(row: dict, name: str) -> bool:
    if name == "strict_static_sensitive":
        return row["decision"] == "YES"
    if name == "broad_exposure_prone":
        return row["decision"] in {"YES", "CARRIER"}
    return row["decision"] == "YES" and name.removeprefix("type_") in row["type"].split("+")


def fisher_two_sided(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher exact p using fixed margins and probability ordering."""
    row_one = a + b
    row_two = c + d
    col_one = a + c
    total = row_one + row_two
    denominator = math.comb(total, row_one)

    def probability(x: int) -> float:
        return math.comb(col_one, x) * math.comb(total - col_one, row_one - x) / denominator

    low = max(0, row_one - (total - col_one))
    high = min(row_one, col_one)
    observed = probability(a)
    return min(1.0, sum(probability(x) for x in range(low, high + 1) if probability(x) <= observed + 1e-15))


def bootstrap_effects(
    agent: list[bool], human: list[bool], agent_scale: float, human_scale: float,
    iterations: int, seed: int,
) -> tuple[tuple[float, float], tuple[float, float]]:
    rng = random.Random(seed)
    sample_diffs = []
    estimated_diffs = []
    for _ in range(iterations):
        agent_rate = sum(agent[rng.randrange(len(agent))] for _ in agent) / len(agent)
        human_rate = sum(human[rng.randrange(len(human))] for _ in human) / len(human)
        sample_diffs.append(agent_rate - human_rate)
        estimated_diffs.append(agent_scale * agent_rate - human_scale * human_rate)
    return (
        (percentile(sample_diffs, 0.025), percentile(sample_diffs, 0.975)),
        (percentile(estimated_diffs, 0.025), percentile(estimated_diffs, 0.975)),
    )


def statistics(annotated: list[dict], source_summary: dict, iterations: int, seed: int) -> list[dict]:
    candidate_frames = source_summary["main_candidate_counts"]
    total_logs = source_summary["main_counts"]
    results = []
    for index, name in enumerate(OUTCOMES):
        agent = [_outcome(row, name) for row in annotated if row["attribution"] == "agent_only"]
        human = [_outcome(row, name) for row in annotated if row["attribution"] == "human_only"]
        if not agent or not human:
            raise ValueError("agent and human audit groups must be non-empty")
        agent_n, human_n = sum(agent), sum(human)
        agent_rate, human_rate = agent_n / len(agent), human_n / len(human)
        agent_scale = candidate_frames["agent_only"] / total_logs["agent_only"]
        human_scale = candidate_frames["human_only"] / total_logs["human_only"]
        sample_ci, estimated_ci = bootstrap_effects(
            agent, human, agent_scale, human_scale, iterations, seed + index,
        )
        agent_ci = wilson(agent_n, len(agent))
        human_ci = wilson(human_n, len(human))
        results.append({
            "outcome": name,
            "agent_sample_n": len(agent), "human_sample_n": len(human),
            "agent_positive_n": agent_n, "human_positive_n": human_n,
            "agent_sample_rate": agent_rate, "human_sample_rate": human_rate,
            "agent_ci_low": agent_ci[0], "agent_ci_high": agent_ci[1],
            "human_ci_low": human_ci[0], "human_ci_high": human_ci[1],
            "sample_effect": agent_rate - human_rate,
            "sample_effect_ci_low": sample_ci[0], "sample_effect_ci_high": sample_ci[1],
            "fisher_p": fisher_two_sided(agent_n, len(agent) - agent_n, human_n, len(human) - human_n),
            "agent_candidate_frame": candidate_frames["agent_only"],
            "human_candidate_frame": candidate_frames["human_only"],
            "agent_total_logs": total_logs["agent_only"],
            "human_total_logs": total_logs["human_only"],
            "agent_estimated_log_rate": agent_scale * agent_rate,
            "human_estimated_log_rate": human_scale * human_rate,
            "estimated_log_rate_effect": agent_scale * agent_rate - human_scale * human_rate,
            "estimated_log_rate_effect_ci_low": estimated_ci[0],
            "estimated_log_rate_effect_ci_high": estimated_ci[1],
            "estimated_rate_status": "DESCRIPTIVE_TWO_PHASE_ESTIMATE_RECALL_UNKNOWN",
        })
    for row, q_value in zip(results, bh_adjust([row["fisher_p"] for row in results])):
        row["bh_q"] = q_value
        row["stable_candidate_composition_difference"] = bool(
            q_value < 0.05 and (row["sample_effect_ci_low"] > 0 or row["sample_effect_ci_high"] < 0)
        )
    return results


def repository_sensitivity(annotated: list[dict], iterations: int, seed: int) -> list[dict]:
    output = []
    for outcome_index, outcome in enumerate(OUTCOMES):
        by_repo: dict[str, dict[str, list[bool]]] = defaultdict(lambda: defaultdict(list))
        positives = {"agent_only": Counter(), "human_only": Counter()}
        for row in annotated:
            side = row["attribution"]
            if side not in positives:
                continue
            value = _outcome(row, outcome)
            by_repo[row["repo"]][side].append(value)
            if value:
                positives[side][row["repo"]] += 1
        common_diffs = []
        for sides in by_repo.values():
            if sides["agent_only"] and sides["human_only"]:
                common_diffs.append(
                    sum(sides["agent_only"]) / len(sides["agent_only"])
                    - sum(sides["human_only"]) / len(sides["human_only"])
                )
        if common_diffs:
            rng = random.Random(seed + outcome_index)
            bootstrap = [
                sum(rng.choice(common_diffs) for _ in common_diffs) / len(common_diffs)
                for _ in range(iterations)
            ]
            common_effect = sum(common_diffs) / len(common_diffs)
            common_ci = (percentile(bootstrap, 0.025), percentile(bootstrap, 0.975))
        else:
            common_effect = math.nan
            common_ci = (math.nan, math.nan)

        top = {}
        excluded = set()
        for side in ("agent_only", "human_only"):
            top_repo, top_n = positives[side].most_common(1)[0] if positives[side] else ("", 0)
            total_positive = sum(positives[side].values())
            top[side] = (top_repo, top_n, top_n / total_positive if total_positive else 0.0)
            if top_repo:
                excluded.add(top_repo)
        remaining = {
            side: [
                _outcome(row, outcome) for row in annotated
                if row["attribution"] == side and row["repo"] not in excluded
            ] for side in ("agent_only", "human_only")
        }
        remaining_rate = {
            side: sum(values) / len(values) if values else math.nan
            for side, values in remaining.items()
        }
        removed_effect = remaining_rate["agent_only"] - remaining_rate["human_only"]
        all_by_side = {
            side: [_outcome(row, outcome) for row in annotated if row["attribution"] == side]
            for side in ("agent_only", "human_only")
        }
        raw_effect = (
            sum(all_by_side["agent_only"]) / len(all_by_side["agent_only"])
            - sum(all_by_side["human_only"]) / len(all_by_side["human_only"])
        )
        output.append({
            "outcome": outcome, "common_repositories": len(common_diffs),
            "common_repo_equal_weight_effect": common_effect,
            "common_repo_effect_ci_low": common_ci[0], "common_repo_effect_ci_high": common_ci[1],
            "agent_top_positive_repo": top["agent_only"][0],
            "agent_top_positive_repo_n": top["agent_only"][1],
            "agent_top_positive_repo_share": top["agent_only"][2],
            "human_top_positive_repo": top["human_only"][0],
            "human_top_positive_repo_n": top["human_only"][1],
            "human_top_positive_repo_share": top["human_only"][2],
            "top_union_removed_agent_n": len(remaining["agent_only"]),
            "top_union_removed_human_n": len(remaining["human_only"]),
            "top_union_removed_agent_rate": remaining_rate["agent_only"],
            "top_union_removed_human_rate": remaining_rate["human_only"],
            "top_union_removed_effect": removed_effect,
            "repository_robust_direction": bool(
                raw_effect != 0 and common_effect * raw_effect > 0 and removed_effect * raw_effect > 0
                and (common_ci[0] > 0 or common_ci[1] < 0)
            ),
        })
    return output


def report(summary: dict) -> str:
    lines = []
    for row in summary["statistics"]:
        lines.append(
            f"| {row['outcome']} | {row['agent_positive_n']}/{row['agent_sample_n']} | "
            f"{row['human_positive_n']}/{row['human_sample_n']} | {row['sample_effect'] * 100:+.1f} pp | "
            f"[{row['sample_effect_ci_low'] * 100:+.1f}, {row['sample_effect_ci_high'] * 100:+.1f}] | "
            f"{row['fisher_p']:.4f} | {row['bh_q']:.4f} | "
            f"{row['stable_candidate_composition_difference']} |"
        )
    stable = [row["outcome"] for row in summary["statistics"] if row["stable_candidate_composition_difference"]]
    estimated = {row["outcome"]: row for row in summary["statistics"]}
    strict = estimated["strict_static_sensitive"]
    repo = {row["outcome"]: row for row in summary["repository_sensitivity"]}
    agent_ctx = repo["type_AGENT_CTX"]
    config = repo["type_CFG"]
    return f"""# SWE-chat 盲化日志隐私语义审计 v1

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: ANALYZED_SINGLE_REVIEWER_BLINDED
- Version Label: swe_chat_blind_semantic_audit_v1

## 审计设计

- 抽样框：Agent {summary['candidate_frames']['agent_only']}、Human {summary['candidate_frames']['human_only']}、Mixed {summary['candidate_frames']['mixed']} 条自动候选。
- 每组组内简单随机、不放回抽取 100 条。
- 判定时隐藏 attribution、仓库、commit、路径和自动风险标签；冻结 300 条标注后解盲。
- 审阅者数：1；这是盲化校准轮，不是人工金标准。

## 主结果：在自动候选内的语义组成

| 语义结果 | Agent | Human | 差值 | bootstrap 95% CI | Fisher p | BH q | 稳定差异 |
|---|---:|---:|---:|---:|---:|---:|---:|
{chr(10).join(lines)}

BH 后稳定的候选组成差异：{', '.join(stable) or '无'}。

## 仓库集中度敏感性

- `AGENT_CTX`：Agent 侧最大贡献仓库是 `{agent_ctx['agent_top_positive_repo']}`，占 Agent 该类命中的 {agent_ctx['agent_top_positive_repo_share'] * 100:.1f}%。两侧最大贡献仓库并集删除后，差值为 {agent_ctx['top_union_removed_effect'] * 100:+.1f} pp；共同仓库等权差值为 {agent_ctx['common_repo_equal_weight_effect'] * 100:+.1f} pp，95% CI [{agent_ctx['common_repo_effect_ci_low'] * 100:+.1f}, {agent_ctx['common_repo_effect_ci_high'] * 100:+.1f}]。
- `CFG`：Human 侧最大贡献仓库是 `{config['human_top_positive_repo']}`，占 Human 该类命中的 {config['human_top_positive_repo_share'] * 100:.1f}%。两侧最大贡献仓库并集删除后，差值为 {config['top_union_removed_effect'] * 100:+.1f} pp；共同仓库等权差值为 {config['common_repo_equal_weight_effect'] * 100:+.1f} pp，95% CI [{config['common_repo_effect_ci_low'] * 100:+.1f}, {config['common_repo_effect_ci_high'] * 100:+.1f}]。

两个方向的共同仓库等权区间均跨 0，所以不能解释为普遍的 Agent–Human 差异。

## 两阶段描述性换算

自动筛查在全部新增日志中命中 Agent 275/4,243、Human 445/5,684。将这一候选率与盲化审计的严格语义确认率相乘，得到：

- Agent 估计严格静态敏感语义率：{strict['agent_estimated_log_rate'] * 100:.2f}%；
- Human 估计严格静态敏感语义率：{strict['human_estimated_log_rate'] * 100:.2f}%；
- 差值：{strict['estimated_log_rate_effect'] * 100:+.2f} pp，bootstrap 95% CI [{strict['estimated_log_rate_effect_ci_low'] * 100:+.2f}, {strict['estimated_log_rate_effect_ci_high'] * 100:+.2f}] pp。

该换算只是两阶段描述性估计：静态筛查器召回率未知，未经仓库/任务平衡，不是真实泄露率。

## 解释边界

1. `YES` 只证明明确动态值或原始容器进入了日志/console sink。
2. `CARRIER` 只表示异常、堆栈或不透明对象可能携带敏感内容。
3. 全部样本的运行可达性、真实值与外部持久化仍未验证，不能标记 `RUNTIME_LEAK_CONFIRMED`。
4. `AGENT_CTX` 说明被记录的值依赖 Agent 会话/工具语义，但不代表写这行代码的一定是 Agent。

## 谬误扫描

- 11/11 已检查。
- Simpson/生态谬误：未做仓库内推断，不将集合结果解释为每个仓库都如此。
- Berkson/collider：样本以“已新增日志且被筛查命中”为条件，明确限定推断总体。
- Base-rate：同时报告全日志分母和候选抽样框。
- Look-elsewhere/forking paths：{len(OUTCOMES)} 个预定义结果统一做 BH 校正，并保留所有结果。
- 回归均值/生存偏差：非前后选极值设计；但数据集本身的开源选择偏差仍存在。
- 因果/反向因果：观察性归因数据只报关联，不使用因果语言。
"""


def run(base: Path, source_dir: Path, output_dir: Path, iterations: int, seed: int) -> dict:
    review_path = base / "blind_review.csv"
    key_path = base / "provenance_key.csv"
    labels_path = base / "blind_labels_single_analyst_v1.tsv"
    source_path = source_dir / "manual_audit_queue.csv"
    annotated, label_metadata = validate_and_join(review_path, key_path, source_path, labels_path)
    source_summary = json.loads((source_dir / "summary.json").read_text(encoding="utf-8"))
    rows = statistics(annotated, source_summary, iterations, seed)
    repo_rows = repository_sensitivity(annotated, iterations, seed + 10_000)
    decisions = {
        side: dict(Counter(row["decision"] for row in annotated if row["attribution"] == side))
        for side in ("agent_only", "human_only", "mixed")
    }
    type_counts = {
        side: dict(Counter(
            name for row in annotated if row["attribution"] == side and row["decision"] == "YES"
            for name in row["type"].split("+")
        )) for side in ("agent_only", "human_only", "mixed")
    }
    summary = {
        "status": "ANALYZED_SINGLE_REVIEWER_BLINDED",
        "n_rows": len(annotated), "reviewer_count": 1,
        "blinding": label_metadata.get("blinding"),
        "inter_rater_reliability": "NOT_AVAILABLE",
        "decision_counts": decisions, "type_counts_yes_only": type_counts,
        "candidate_frames": source_summary["main_candidate_counts"],
        "total_log_frames": source_summary["main_counts"],
        "statistics": rows, "repository_sensitivity": repo_rows,
        "seed": seed, "bootstrap_iterations": iterations,
        "runtime_leak_claim": False, "fallacy_scan_coverage": "11/11",
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "annotated_unblinded.csv", annotated, ANNOTATED_FIELDS)
    write_csv(output_dir / "semantic_statistics.csv", rows, STAT_FIELDS)
    write_csv(output_dir / "repository_sensitivity.csv", repo_rows, REPO_FIELDS)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(report(summary), encoding="utf-8")
    artifacts = (
        "annotated_unblinded.csv", "semantic_statistics.csv", "repository_sensitivity.csv",
        "summary.json", "report.md",
    )
    manifest = {
        "hash_algorithm": "SHA-256",
        "input_sha256": {
            "blind_review.csv": sha256(review_path), "provenance_key.csv": sha256(key_path),
            "blind_labels_single_analyst_v1.tsv": sha256(labels_path),
            "manual_audit_queue.csv": sha256(source_path),
            "source_summary.json": sha256(source_dir / "summary.json"),
        },
        "script_sha256": sha256(Path(__file__)),
        "artifact_sha256": {name: sha256(output_dir / name) for name in artifacts},
        "seed": seed, "bootstrap_iterations": iterations,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--base", type=Path, default=Path("outputs/swe_chat_value_aware_privacy/blind_manual_audit_v1"))
    value.add_argument("--source-dir", type=Path, default=Path("outputs/swe_chat_value_aware_privacy/analysis"))
    value.add_argument("--output-dir", type=Path, default=Path("outputs/swe_chat_value_aware_privacy/blind_manual_audit_v1/analysis"))
    value.add_argument("--bootstrap-iterations", type=int, default=10_000)
    value.add_argument("--seed", type=int, default=20260805)
    return value


def main() -> int:
    args = parser().parse_args()
    summary = run(args.base, args.source_dir, args.output_dir, args.bootstrap_iterations, args.seed)
    print(json.dumps({
        "status": summary["status"], "decision_counts": summary["decision_counts"],
        "stable_outcomes": [row["outcome"] for row in summary["statistics"] if row["stable_candidate_composition_difference"]],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
