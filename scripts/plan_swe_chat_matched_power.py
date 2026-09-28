#!/usr/bin/env python3
"""Plan a larger paired SWE-chat audit with a transparent normal approximation.

The calculation treats each Agent/Human pair as one observation with outcome
X = Agent - Human in {-1, 0, 1}. Repository clustering is not estimable from
17 repositories, so the script reports independent-pair requirements and a
clearly labelled planning inflation rather than pretending to have a precise
design effect.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from statistics import NormalDist


DEFAULT_INPUT = Path(
    "outputs/swe_chat_value_aware_privacy/matched_blind_audit_v1/analysis/paired_statistics.csv"
)
DEFAULT_KEY = Path(
    "outputs/swe_chat_value_aware_privacy/matched_blind_audit_v1/provenance_key.csv"
)
DEFAULT_OUTPUT = Path(
    "outputs/swe_chat_value_aware_privacy/matched_blind_audit_v1/power_plan"
)
PRIMARY_ALPHA = 0.025
CLUSTER_INFLATION = 1.5
TARGET_POWERS = (0.80, 0.90)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normal_approx_power(n_pairs: int, delta: float, discordance: float, alpha: float) -> float:
    """Two-sided large-sample power for a paired binary difference.

    delta is |P(Agent only) - P(Human only)| and discordance is their sum.
    The test statistic is approximated as D / sqrt(n * discordance).
    """
    if n_pairs <= 0:
        raise ValueError("n_pairs must be positive")
    if not 0 < alpha < 1:
        raise ValueError("alpha must be between 0 and 1")
    if not 0 < discordance <= 1:
        raise ValueError("discordance must be in (0, 1]")
    delta = abs(delta)
    if delta > discordance:
        raise ValueError("absolute delta cannot exceed discordance")
    normal = NormalDist()
    critical = normal.inv_cdf(1 - alpha / 2)
    mean = delta * math.sqrt(n_pairs / discordance)
    sd = math.sqrt(max(0.0, (discordance - delta * delta) / discordance))
    if sd == 0:
        return 1.0 if mean > critical else 0.0
    upper = 1 - normal.cdf((critical - mean) / sd)
    lower = normal.cdf((-critical - mean) / sd)
    return min(1.0, max(0.0, upper + lower))


def required_pairs(
    delta: float,
    discordance: float,
    target_power: float,
    alpha: float,
    max_pairs: int = 100_000,
) -> int | None:
    if not 0 < target_power < 1:
        raise ValueError("target_power must be between 0 and 1")
    normal_approx_power(1, delta, discordance, alpha)
    if normal_approx_power(max_pairs, delta, discordance, alpha) < target_power:
        return None
    low, high = 1, max_pairs
    while low < high:
        middle = (low + high) // 2
        if normal_approx_power(middle, delta, discordance, alpha) >= target_power:
            high = middle
        else:
            low = middle + 1
    return low


def minimum_detectable_effect(
    n_pairs: int,
    discordance: float,
    target_power: float,
    alpha: float,
) -> float | None:
    """Smallest absolute paired difference detectable at the target power."""
    if normal_approx_power(n_pairs, discordance, discordance, alpha) < target_power:
        return None
    low, high = 0.0, discordance
    for _ in range(80):
        middle = (low + high) / 2
        if normal_approx_power(n_pairs, middle, discordance, alpha) >= target_power:
            high = middle
        else:
            low = middle
    return high


def _integer_or_blank(value: int | None) -> int | str:
    return "" if value is None else value


def _inflated(value: int | None, factor: float) -> int | str:
    return "" if value is None else math.ceil(value * factor)


def observed_rows(stats: list[dict[str, str]], cluster_inflation: float) -> list[dict]:
    settings = {
        "type_AGENT_CTX": ("preregistered_primary", PRIMARY_ALPHA),
        "type_CFG": ("preregistered_primary", PRIMARY_ALPHA),
        "strict_static_sensitive": ("descriptive_overall", 0.05),
    }
    by_outcome = {row["outcome"]: row for row in stats}
    missing = set(settings) - set(by_outcome)
    if missing:
        raise ValueError(f"missing outcomes: {', '.join(sorted(missing))}")
    output = []
    for outcome, (role, alpha) in settings.items():
        source = by_outcome[outcome]
        n_pairs = int(source["n_pairs"])
        agent_only = int(source["agent_only"])
        human_only = int(source["human_only"])
        delta = abs(agent_only - human_only) / n_pairs
        discordance = (agent_only + human_only) / n_pairs
        n80 = required_pairs(delta, discordance, 0.80, alpha)
        n90 = required_pairs(delta, discordance, 0.90, alpha)
        mde80 = minimum_detectable_effect(n_pairs, discordance, 0.80, alpha)
        mde90 = minimum_detectable_effect(n_pairs, discordance, 0.90, alpha)
        output.append({
            "outcome": outcome,
            "role": role,
            "n_pairs": n_pairs,
            "agent_only": agent_only,
            "human_only": human_only,
            "observed_abs_effect": delta,
            "discordance_rate": discordance,
            "alpha_two_sided": alpha,
            "current_approx_power": normal_approx_power(n_pairs, delta, discordance, alpha),
            "mde_80": "" if mde80 is None else mde80,
            "mde_90": "" if mde90 is None else mde90,
            "independent_pairs_80": _integer_or_blank(n80),
            "inflated_pairs_80": _inflated(n80, cluster_inflation),
            "independent_pairs_90": _integer_or_blank(n90),
            "inflated_pairs_90": _inflated(n90, cluster_inflation),
        })
    return output


def scenario_rows(cluster_inflation: float) -> list[dict]:
    output = []
    for discordance in (0.15, 0.25, 0.35):
        for delta in (0.05, 0.075, 0.10):
            n80 = required_pairs(delta, discordance, 0.80, PRIMARY_ALPHA)
            n90 = required_pairs(delta, discordance, 0.90, PRIMARY_ALPHA)
            output.append({
                "discordance_rate": discordance,
                "target_abs_effect": delta,
                "alpha_two_sided": PRIMARY_ALPHA,
                "independent_pairs_80": _integer_or_blank(n80),
                "inflated_pairs_80": _inflated(n80, cluster_inflation),
                "independent_pairs_90": _integer_or_blank(n90),
                "inflated_pairs_90": _inflated(n90, cluster_inflation),
            })
    return output


def repository_diagnostics(key_rows: list[dict[str, str]]) -> dict:
    pair_repo: dict[str, str] = {}
    for row in key_rows:
        pair_id, repo = row["pair_id"], row["repo"]
        if pair_id in pair_repo and pair_repo[pair_id] != repo:
            raise ValueError(f"pair {pair_id} spans repositories")
        pair_repo[pair_id] = repo
    counts = Counter(pair_repo.values())
    n_pairs = len(pair_repo)
    squared = sum(value * value for value in counts.values())
    return {
        "n_pairs": n_pairs,
        "n_repositories": len(counts),
        "mean_pairs_per_repository": n_pairs / len(counts),
        "max_pairs_in_repository": max(counts.values()),
        "kish_effective_repository_count_concentration_diagnostic": n_pairs * n_pairs / squared,
        "repository_pair_counts": dict(sorted(counts.items())),
    }


def _pct(value: float | str) -> str:
    return "n/a" if value == "" else f"{float(value) * 100:.1f}%"


def report_text(observed: list[dict], scenarios: list[dict], summary: dict) -> str:
    observed_lines = [
        "| Outcome | 当前效应 | 不一致率 | 当前近似功效 | 80% MDE | 独立对数 80% | 1.5x 对数 80% | 1.5x 对数 90% |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in observed:
        observed_lines.append(
            f"| `{row['outcome']}` | {_pct(row['observed_abs_effect'])} | "
            f"{_pct(row['discordance_rate'])} | {_pct(row['current_approx_power'])} | "
            f"{_pct(row['mde_80'])} | {row['independent_pairs_80']} | "
            f"{row['inflated_pairs_80']} | {row['inflated_pairs_90']} |"
        )
    scenario_lines = [
        "| 不一致率 | 目标差异 | 独立对数 80% | 1.5x 对数 80% | 独立对数 90% | 1.5x 对数 90% |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for row in scenarios:
        scenario_lines.append(
            f"| {_pct(row['discordance_rate'])} | {_pct(row['target_abs_effect'])} | "
            f"{row['independent_pairs_80']} | {row['inflated_pairs_80']} | "
            f"{row['independent_pairs_90']} | {row['inflated_pairs_90']} |"
        )
    diag = summary["repository_diagnostics"]
    return f"""# SWE-chat 配对语义审计：功效与扩样规划

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: APPROXIMATE_POWER_PLAN_FROM_FROZEN_MATCHED_AUDIT
- Version Label: swe_chat_matched_power_plan_v1

## 结论先行

当前 58 对样本**不足以把“未显著”解释为“Agent 与 Human 没有区别”**。在两个预注册语义结果上，它达到 80% 功效时只能检出约 18%--21% 的绝对配对差异，而目前观察到的是 10.3% 和 6.9%。

若下一轮希望在多重检验门槛 `alpha=0.025` 下检出本轮 `CFG` 量级的 6.9% 差异，独立配对近似需要 549 对；加入透明的 1.5 倍仓库聚类规划余量后是 **824 对（80% 功效）**。若把有研究意义的最小差异预先定为 5%、不一致率按 25% 规划，则需要 **1,422 对（80%）或 1,856 对（90%）**。

## 基于本轮观察值的敏感性规划

{chr(10).join(observed_lines)}

这里的“基于观察值”是事后敏感性分析，不能把样本效应当成真实效应。它只解释为什么 58 对没有能力稳定验证中小差异。

## 前瞻性情景表

{chr(10).join(scenario_lines)}

推荐以 5% 绝对差异、不一致率 25%、80% 功效为最低主方案，即 1,422 对；资源允许时使用 90% 方案 1,856 对。最终方案应在看新标签前冻结。

## 仓库集中度与抽样约束

- 当前有 {diag['n_pairs']} 对、{diag['n_repositories']} 个仓库，平均每仓库 {diag['mean_pairs_per_repository']:.2f} 对，单仓库最多 {diag['max_pairs_in_repository']} 对。
- Kish 仓库集中度诊断为 {diag['kish_effective_repository_count_concentration_diagnostic']:.2f}；它只是集中度指标，**不是**未知 ICC 下的有效样本量。
- 下一轮建议至少覆盖 100 个仓库、每仓库最多 5 对，并继续匹配任务类型、语言、时间和修改规模。
- 1.5 倍只是保守的规划余量，不是从 17 个仓库可靠估得的设计效应；正式分析仍应使用仓库分组 bootstrap/置换或合适的分层模型。

## 计算定义

每对定义 `X = Agent - Human`，取值为 -1、0、1。令 `delta = |P(Agent-only)-P(Human-only)|`，`q = P(Agent-only)+P(Human-only)`。正态近似检验量使用 `D / sqrt(n*q)`；在备择假设下，均值为 `delta*sqrt(n/q)`，方差为 `(q-delta^2)/q`。两个预注册结果采用双侧 `alpha=0.025`，相当于保守的 Bonferroni 规划；它不是对精确 McNemar/Holm 功效的精确闭式解。

## 结论边界

1. 该规划不推翻论文的 logging 行为结论，也不验证隐私泄露差异；论文主要测量日志修改行为，不测量隐私结果。
2. 当前结果说明数据规模和匹配维度仍不足，而不是“结论永远无法验证”。
3. 真实隐私差异必须同时扩大来源可靠的 Agent/Human 队列、完成双人盲标，并保持静态候选与运行时泄露分离。

## 谬误扫描

- Coverage: 11/11 checked.
- Simpson's paradox: 将仓库作为聚类层，并要求扩大仓库覆盖。
- Ecological fallacy: 功效单位是配对日志语句，不外推到个体开发者。
- Berkson's paradox: 样本条件化于新增且被筛中的日志，故不当作全部日志发生率。
- Collider bias: 同 sink/语言匹配可能条件化于共同结果，保留该限制。
- Base-rate neglect: 不一致率与绝对效应分别建模，不用候选内比例替代总体率。
- Regression to the mean: 不把本轮观察效应当下一轮真实效应。
- Survivorship bias: 当前仅含可重建的开源 SWE-chat 样本。
- Look-elsewhere effect: 两个主结果按 `alpha=0.025` 规划，探索性结果不混入主功效。
- Garden of forking paths: 情景网格、膨胀系数和目标功效由脚本固定。
- Correlation != causation: 扩样仍是观察性匹配设计。
- Reverse causality: 任务分配可能同时影响作者来源与日志语义。

## 可复现性

- 输入为冻结的 `paired_statistics.csv` 与 `provenance_key.csv`，哈希记录在 manifest。
- 计算只使用 Python 标准库，无随机过程；重复运行应产生相同产物哈希。
- Verdict: REPRODUCIBLE_APPROXIMATION；精确功效仍需仿真并给定仓库 ICC/分布。
"""


def run(stats_path: Path, key_path: Path, output_dir: Path, cluster_inflation: float) -> dict:
    if cluster_inflation < 1:
        raise ValueError("cluster_inflation must be at least 1")
    stats = read_csv(stats_path)
    keys = read_csv(key_path)
    observed = observed_rows(stats, cluster_inflation)
    scenarios = scenario_rows(cluster_inflation)
    diagnostics = repository_diagnostics(keys)
    output_dir.mkdir(parents=True, exist_ok=True)

    observed_fields = (
        "outcome", "role", "n_pairs", "agent_only", "human_only", "observed_abs_effect",
        "discordance_rate", "alpha_two_sided", "current_approx_power", "mde_80", "mde_90",
        "independent_pairs_80", "inflated_pairs_80", "independent_pairs_90", "inflated_pairs_90",
    )
    scenario_fields = (
        "discordance_rate", "target_abs_effect", "alpha_two_sided", "independent_pairs_80",
        "inflated_pairs_80", "independent_pairs_90", "inflated_pairs_90",
    )
    write_csv(output_dir / "observed_sensitivity.csv", observed, observed_fields)
    write_csv(output_dir / "prospective_scenarios.csv", scenarios, scenario_fields)
    summary = {
        "status": "APPROXIMATE_POWER_PLAN_FROM_FROZEN_MATCHED_AUDIT",
        "method": "two_sided_normal_approximation_for_paired_binary_difference",
        "primary_alpha": PRIMARY_ALPHA,
        "cluster_planning_inflation": cluster_inflation,
        "target_powers": list(TARGET_POWERS),
        "observed_sensitivity": observed,
        "repository_diagnostics": diagnostics,
        "runtime_leak_claim": False,
        "causal_claim": False,
        "fallacy_scan_coverage": "11/11",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(
        report_text(observed, scenarios, summary), encoding="utf-8"
    )
    artifacts = ("observed_sensitivity.csv", "prospective_scenarios.csv", "summary.json", "report.md")
    manifest = {
        "hash_algorithm": "SHA-256",
        "input_sha256": {
            stats_path.name: sha256(stats_path),
            key_path.name: sha256(key_path),
        },
        "script_sha256": sha256(Path(__file__)),
        "artifact_sha256": {name: sha256(output_dir / name) for name in artifacts},
        "deterministic": True,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--stats", type=Path, default=DEFAULT_INPUT)
    value.add_argument("--provenance-key", type=Path, default=DEFAULT_KEY)
    value.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    value.add_argument("--cluster-inflation", type=float, default=CLUSTER_INFLATION)
    return value


def main() -> int:
    args = parser().parse_args()
    summary = run(args.stats, args.provenance_key, args.output_dir, args.cluster_inflation)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
