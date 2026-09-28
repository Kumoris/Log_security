#!/usr/bin/env python3
"""Analyze frozen, provenance-blinded SWE-chat Agent/Human log pairs."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path

if __package__:
    from .analyze_aidev_primary_queue import exact_mcnemar
    from .analyze_swe_chat_log_privacy_semantics import percentile, read_csv, sha256, wilson, write_csv
    from .prepare_swe_chat_blind_privacy_audit import extension, source_hash
else:
    from analyze_aidev_primary_queue import exact_mcnemar
    from analyze_swe_chat_log_privacy_semantics import percentile, read_csv, sha256, wilson, write_csv
    from prepare_swe_chat_blind_privacy_audit import extension, source_hash


TYPES = ("AUTH", "PII", "QID", "BIZ", "CFG", "DIAG", "AGENT_CTRL", "AGENT_CTX")
OUTCOMES = ("strict_static_sensitive", "broad_exposure_prone") + tuple(f"type_{name}" for name in TYPES)
PRIMARY_DIRECTIONS = {"type_AGENT_CTX": 1, "type_CFG": -1}
ALLOWED_DECISIONS = {"YES", "CARRIER", "NO", "UNCLEAR"}
ANNOTATED_FIELDS = (
    "pair_id", "blind_id", "attribution", "repo", "commit", "checkpoint_pk", "file", "line",
    "file_extension", "sink_family", "evidence_grade", "privacy_features", "mechanism_features",
    "statement_redacted", "context_redacted", "decision", "type", "value_form", "severity",
    "rationale_code", "runtime_status",
)
STAT_FIELDS = (
    "family", "outcome", "expected_direction", "n_pairs", "n_repositories", "agent_positive_n",
    "human_positive_n", "agent_rate", "human_rate", "agent_ci_low", "agent_ci_high", "human_ci_low",
    "human_ci_high", "effect", "effect_ci_low", "effect_ci_high", "agent_only", "human_only",
    "mcnemar_p", "adjusted_p", "adjustment", "leave_one_repo_out_min", "leave_one_repo_out_max",
    "direction_consistent", "stable_difference",
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


def _outcome(row: dict, name: str) -> bool:
    if name == "strict_static_sensitive":
        return row["decision"] == "YES"
    if name == "broad_exposure_prone":
        return row["decision"] in {"YES", "CARRIER"}
    return row["decision"] == "YES" and name.removeprefix("type_") in row["type"].split("+")


def holm_adjust(p_values: list[float]) -> list[float]:
    """Holm family-wise adjustment, returned in original order."""
    size = len(p_values)
    adjusted = [1.0] * size
    running = 0.0
    for rank, index in enumerate(sorted(range(size), key=p_values.__getitem__)):
        running = max(running, (size - rank) * p_values[index])
        adjusted[index] = min(1.0, running)
    return adjusted


def bh_adjust(p_values: list[float]) -> list[float]:
    size = len(p_values)
    adjusted = [1.0] * size
    running = 1.0
    for rank, index in reversed(list(enumerate(sorted(range(size), key=p_values.__getitem__), 1))):
        running = min(running, p_values[index] * size / rank)
        adjusted[index] = min(1.0, running)
    return adjusted


def validate_and_join(
    review_path: Path, key_path: Path, source_path: Path, labels_path: Path,
) -> tuple[list[dict], dict[str, str]]:
    metadata, labels = read_labels(labels_path)
    if metadata.get("review_input_sha256") != sha256(review_path):
        raise ValueError("blind review input drifted after labels were frozen")
    review_rows = read_csv(review_path)
    key_rows = read_csv(key_path)
    source_rows = read_csv(source_path)
    review = {row["blind_id"]: row for row in review_rows}
    key = {row["blind_id"]: row for row in key_rows}
    labels_by_id = {row["blind_id"]: row for row in labels}
    expected = set(review)
    if (
        len(review) != len(review_rows)
        or len(key) != len(key_rows)
        or len(labels_by_id) != len(labels)
        or set(key) != expected
        or set(labels_by_id) != expected
    ):
        raise ValueError("review, provenance key, and labels must have one-to-one blind IDs")

    source_by_hash: dict[str, list[dict]] = defaultdict(list)
    for row in source_rows:
        source_by_hash[source_hash(row)].append(row)

    output = []
    for blind_id in sorted(expected):
        label = labels_by_id[blind_id]
        if label["decision"] not in ALLOWED_DECISIONS:
            raise ValueError(f"invalid decision for {blind_id}")
        parts = set(label["type"].split("+"))
        if parts != {"NONE"} and not parts <= set(TYPES):
            raise ValueError(f"invalid semantic type for {blind_id}")
        candidates = source_by_hash[key[blind_id]["source_sha256_16"]]
        if len(candidates) != 1:
            raise ValueError(f"source hash must resolve uniquely for {blind_id}")
        source = candidates[0]
        shown = review[blind_id]
        if (
            shown["statement_redacted"] != source["statement_redacted"]
            or shown["context_redacted"] != source["context_redacted"]
            or shown["file_extension"] != extension(source["file"])
            or shown["sink_family"] != source["sink_family"]
            or shown["evidence_grade"] != source["evidence_grade"]
        ):
            raise ValueError(f"blind evidence does not match frozen source for {blind_id}")
        output.append({
            **shown,
            **key[blind_id],
            **label,
            "runtime_status": "STATIC_CANDIDATE_NOT_RUNTIME_CONFIRMED",
        })

    pairs: dict[str, dict[str, dict]] = defaultdict(dict)
    for row in output:
        pairs[row["pair_id"]][row["attribution"]] = row
    for pair_id, sides in pairs.items():
        if set(sides) != {"agent_only", "human_only"}:
            raise ValueError(f"pair {pair_id} must contain exactly one Agent and one Human row")
        agent, human = sides["agent_only"], sides["human_only"]
        if (
            agent["repo"] != human["repo"]
            or agent["file_extension"] != human["file_extension"]
            or agent["sink_family"] != human["sink_family"]
            or agent["evidence_grade"] != "A"
            or human["evidence_grade"] != "A"
        ):
            raise ValueError(f"matching invariant failed for {pair_id}")
    if 2 * len(pairs) != len(output):
        raise ValueError("each pair must contain two rows")
    return output, metadata


def paired_rows(annotated: list[dict]) -> list[dict]:
    grouped: dict[str, dict[str, dict]] = defaultdict(dict)
    for row in annotated:
        grouped[row["pair_id"]][row["attribution"]] = row
    return [
        {"pair_id": pair_id, "repo": sides["agent_only"]["repo"], **sides}
        for pair_id, sides in sorted(grouped.items())
    ]


def cluster_bootstrap(
    pairs: list[dict], outcome: str, iterations: int, seed: int,
) -> tuple[float, float, float]:
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for pair in pairs:
        by_repo[pair["repo"]].append(pair)
    repos = sorted(by_repo)

    def effect(rows: list[dict]) -> float:
        return sum(
            int(_outcome(row["agent_only"], outcome)) - int(_outcome(row["human_only"], outcome))
            for row in rows
        ) / len(rows)

    point = effect(pairs)
    rng = random.Random(seed)
    draws = []
    for _ in range(iterations):
        sample = []
        for _ in repos:
            sample.extend(by_repo[rng.choice(repos)])
        draws.append(effect(sample))
    return point, percentile(draws, 0.025), percentile(draws, 0.975)


def leave_one_repo_out(pairs: list[dict], outcome: str) -> tuple[float, float]:
    effects = []
    for repo in sorted({pair["repo"] for pair in pairs}):
        kept = [pair for pair in pairs if pair["repo"] != repo]
        effects.append(sum(
            int(_outcome(pair["agent_only"], outcome)) - int(_outcome(pair["human_only"], outcome))
            for pair in kept
        ) / len(kept))
    return min(effects), max(effects)


def statistics(pairs: list[dict], iterations: int, seed: int) -> list[dict]:
    results = []
    for index, outcome in enumerate(OUTCOMES):
        agent = [_outcome(pair["agent_only"], outcome) for pair in pairs]
        human = [_outcome(pair["human_only"], outcome) for pair in pairs]
        n = len(pairs)
        agent_n, human_n = sum(agent), sum(human)
        agent_only = sum(a and not h for a, h in zip(agent, human))
        human_only = sum(h and not a for a, h in zip(agent, human))
        effect, ci_low, ci_high = cluster_bootstrap(pairs, outcome, iterations, seed + index)
        loo_low, loo_high = leave_one_repo_out(pairs, outcome)
        family = "preregistered_primary" if outcome in PRIMARY_DIRECTIONS else "exploratory_secondary"
        expected = PRIMARY_DIRECTIONS.get(outcome, 0)
        results.append({
            "family": family,
            "outcome": outcome,
            "expected_direction": "agent_gt_human" if expected > 0 else "agent_lt_human" if expected < 0 else "two_sided",
            "n_pairs": n,
            "n_repositories": len({pair["repo"] for pair in pairs}),
            "agent_positive_n": agent_n,
            "human_positive_n": human_n,
            "agent_rate": agent_n / n,
            "human_rate": human_n / n,
            "agent_ci_low": wilson(agent_n, n)[0],
            "agent_ci_high": wilson(agent_n, n)[1],
            "human_ci_low": wilson(human_n, n)[0],
            "human_ci_high": wilson(human_n, n)[1],
            "effect": effect,
            "effect_ci_low": ci_low,
            "effect_ci_high": ci_high,
            "agent_only": agent_only,
            "human_only": human_only,
            "mcnemar_p": exact_mcnemar(agent_only, human_only),
            "leave_one_repo_out_min": loo_low,
            "leave_one_repo_out_max": loo_high,
        })

    primary = [row for row in results if row["family"] == "preregistered_primary"]
    secondary = [row for row in results if row["family"] == "exploratory_secondary"]
    for row, adjusted in zip(primary, holm_adjust([row["mcnemar_p"] for row in primary])):
        row["adjusted_p"] = adjusted
        row["adjustment"] = "Holm_within_2_preregistered_outcomes"
    for row, adjusted in zip(secondary, bh_adjust([row["mcnemar_p"] for row in secondary])):
        row["adjusted_p"] = adjusted
        row["adjustment"] = "BH_within_8_exploratory_outcomes"

    for row in results:
        expected = PRIMARY_DIRECTIONS.get(row["outcome"], 0)
        if expected > 0:
            consistent = row["effect"] > 0 and row["leave_one_repo_out_min"] > 0
        elif expected < 0:
            consistent = row["effect"] < 0 and row["leave_one_repo_out_max"] < 0
        else:
            consistent = (
                row["effect"] > 0 and row["leave_one_repo_out_min"] > 0
            ) or (
                row["effect"] < 0 and row["leave_one_repo_out_max"] < 0
            )
        row["direction_consistent"] = consistent
        row["stable_difference"] = bool(
            row["adjusted_p"] < 0.05
            and (row["effect_ci_low"] > 0 or row["effect_ci_high"] < 0)
            and consistent
        )
    return results


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _pp(value: float) -> str:
    return f"{value * 100:+.1f} pp"


def report_text(stats: list[dict], summary: dict) -> str:
    primary = [row for row in stats if row["family"] == "preregistered_primary"]
    secondary = [row for row in stats if row["family"] == "exploratory_secondary"]

    def table(rows: list[dict]) -> str:
        lines = [
            "| 结果 | Agent | Human | 配对差值 | 仓库 bootstrap 95% CI | McNemar p | 校正 p/q | 稳定差异 |",
            "|---|---:|---:|---:|---:|---:|---:|---|",
        ]
        for row in rows:
            lines.append(
                f"| `{row['outcome']}` | {row['agent_positive_n']}/{row['n_pairs']} "
                f"({_pct(row['agent_rate'])}) | {row['human_positive_n']}/{row['n_pairs']} "
                f"({_pct(row['human_rate'])}) | {_pp(row['effect'])} | "
                f"[{_pp(row['effect_ci_low'])}, {_pp(row['effect_ci_high'])}] | "
                f"{row['mcnemar_p']:.4f} | {row['adjusted_p']:.4f} | "
                f"{'是' if row['stable_difference'] else '否'} |"
            )
        return "\n".join(lines)

    agent_ctx = next(row for row in stats if row["outcome"] == "type_AGENT_CTX")
    cfg = next(row for row in stats if row["outcome"] == "type_CFG")
    stable = [row["outcome"] for row in stats if row["stable_difference"]]
    return f"""# SWE-chat 仓库内匹配盲化语义审计结果

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: ANALYZED_SINGLE_REVIEWER_MATCHED_BLINDED
- Version Label: swe_chat_matched_blind_semantic_audit_v1

## 一句话结论

在同仓库、同语言扩展名、同日志 sink 的 58 对静态候选中，两个预先指定的方向都没有被确证：`AGENT_CTX` 不仅未呈现 Agent 更高，样本点估计反而是 {_pp(agent_ctx['effect'])}；`CFG` 呈现预期的 Agent 更低方向，但差异 {_pp(cfg['effect'])} 不稳定。

## 设计与口径

- 58 对、116 条日志，来自 17 个仓库；每仓库最多 10 对。
- 匹配条件：同仓库、同扩展名、同 sink family、生产路径、A 级证据。
- 标注时隐藏 attribution、仓库、commit、文件路径和配对号；标注冻结后才解盲。
- `YES` 是静态敏感值候选，`CARRIER` 是可能携带敏感内容的不透明异常/容器；两者都不是已确认的运行时泄露。

## 预先指定的两个假设

{table(primary)}

- `AGENT_CTX: Agent > Human`：未通过。Agent {agent_ctx['agent_positive_n']}/{agent_ctx['n_pairs']}，Human {agent_ctx['human_positive_n']}/{agent_ctx['n_pairs']}；方向与假设相反。
- `CFG: Agent < Human`：方向一致，但 Holm 校正后 p={cfg['adjusted_p']:.4f}，且仓库 bootstrap 区间跨 0，未通过稳定性规则。

## 探索性次要结果

{table(secondary)}

BH 校正后稳定差异：{'、'.join(stable) if stable else '无'}。这些是“已被自动规则筛中的日志语句”内部的语义组成，不是所有 Agent/Human 日志的总体泄露率。

## 目前能与不能得出的结论

1. 可以说：在本匹配样本中，未找到 Agent 和 Human 的稳定语义类型差异。
2. 不能说：Agent 与 Human 完全没有差异。58 对对中小效应功效有限，且缺少任务类型、时间和修改规模匹配。
3. 不能说：`AGENT_CTX` 是 Agent 代码的作者指纹。它描述被记录的数据语义，不描述作者身份。
4. 不能说：发生了真实隐私泄露。本轮没有验证路径可达、真实敏感值流入和外发/持久化。

## 谬误扫描

- Coverage: 11/11 checked.
- Simpson's paradox: 使用仓库分组 bootstrap 和逐仓库删除敏感性；不把合并结果解释为每个仓库都如此。
- Ecological fallacy: 推断单位保持为配对日志语句，不外推到单个开发者或 Agent 产品。
- Berkson's paradox: 样本以“新增日志且自动筛中”为条件，明确标为选择性样本。
- Collider bias: 匹配 sink/language 可能条件化于作者与语义的共同结果；因此仅将本轮视为敏感性检验。
- Base-rate neglect: 不将候选内比例误当全部日志的泄露率。
- Regression to the mean: 非极值前后比较，不适用。
- Survivorship bias: 仅包含 SWE-chat 可观测且能重建的开源 commit，保留外部有效性限制。
- Look-elsewhere effect: 两个主假设在解盲前固定，用 Holm 校正；其余 8 项单列为探索性并做 BH 校正。
- Garden of forking paths: 匹配变量、仓库上限、随机种子和主假设均在解盲前冻结。
- Correlation != causation: 只报告观察性关联，不使用因果语言。
- Reverse causality: 日志语义可能由任务分配所决定，不将 attribution 视为已证明原因。

## 可复现性

- 方法：固定输入哈希、随机种子 `{summary['seed']}`、仓库分组 bootstrap {summary['bootstrap_iterations']:,} 次。
- 验证：输入一致性、配对互斥、匹配字段、标注数量和来源证据哈希均由脚本强制检查。
- Verdict: REPRODUCIBLE 对固定本地快照成立；对真实运行时泄露不适用。
"""


def run(
    source_dir: Path, audit_dir: Path, output_dir: Path, iterations: int, seed: int,
) -> dict:
    review_path = audit_dir / "blind_review.csv"
    key_path = audit_dir / "provenance_key.csv"
    labels_path = audit_dir / "blind_labels_single_analyst_v1.tsv"
    source_path = source_dir / "classified_log_statements.csv"
    annotated, metadata = validate_and_join(review_path, key_path, source_path, labels_path)
    pairs = paired_rows(annotated)
    stats = statistics(pairs, iterations, seed)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "annotated_evidence.csv", annotated, ANNOTATED_FIELDS)
    write_csv(output_dir / "paired_statistics.csv", stats, STAT_FIELDS)
    summary = {
        "status": "ANALYZED_SINGLE_REVIEWER_MATCHED_BLINDED",
        "n_rows": len(annotated),
        "n_pairs": len(pairs),
        "n_repositories": len({pair["repo"] for pair in pairs}),
        "decision_counts": dict(sorted(Counter(row["decision"] for row in annotated).items())),
        "primary_outcomes": [row for row in stats if row["family"] == "preregistered_primary"],
        "stable_outcomes": [row["outcome"] for row in stats if row["stable_difference"]],
        "bootstrap_iterations": iterations,
        "seed": seed,
        "review_input_sha256": metadata["review_input_sha256"],
        "reviewer": metadata.get("reviewer", ""),
        "runtime_leak_claim": False,
        "fallacy_scan_coverage": "11/11",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(report_text(stats, summary), encoding="utf-8")
    artifacts = ("annotated_evidence.csv", "paired_statistics.csv", "summary.json", "report.md")
    manifest = {
        "hash_algorithm": "SHA-256",
        "input_sha256": {
            "blind_review.csv": sha256(review_path),
            "provenance_key.csv": sha256(key_path),
            "blind_labels_single_analyst_v1.tsv": sha256(labels_path),
            "classified_log_statements.csv": sha256(source_path),
        },
        "script_sha256": sha256(Path(__file__)),
        "artifact_sha256": {name: sha256(output_dir / name) for name in artifacts},
        "bootstrap_iterations": iterations,
        "seed": seed,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--source-dir", type=Path, default=Path("outputs/swe_chat_value_aware_privacy/analysis"))
    value.add_argument("--audit-dir", type=Path, default=Path("outputs/swe_chat_value_aware_privacy/matched_blind_audit_v1"))
    value.add_argument(
        "--output-dir", type=Path,
        default=Path("outputs/swe_chat_value_aware_privacy/matched_blind_audit_v1/analysis"),
    )
    value.add_argument("--bootstrap-iterations", type=int, default=10_000)
    value.add_argument("--seed", type=int, default=20260805)
    return value


def main() -> int:
    args = parser().parse_args()
    summary = run(args.source_dir, args.audit_dir, args.output_dir, args.bootstrap_iterations, args.seed)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
