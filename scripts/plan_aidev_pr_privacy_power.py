#!/usr/bin/env python3
"""Plan power for the AIDev PR-level strict privacy-candidate outcome."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

if __package__:
    from .plan_swe_chat_matched_power import minimum_detectable_effect, normal_approx_power, required_pairs
else:
    from plan_swe_chat_matched_power import minimum_detectable_effect, normal_approx_power, required_pairs


DEFAULT_AUDIT = Path(
    "outputs/aidev_observational_primary_300/value_aware_privacy/manual_audit_v1/summary.json"
)
DEFAULT_CAPACITY = Path("outputs/privacy_cohort_expansion_capacity_v1/summary.json")
DEFAULT_OUTPUT = Path(
    "outputs/aidev_observational_primary_300/value_aware_privacy/manual_audit_v1/power_plan"
)
ALPHA = 0.05
CLUSTER_INFLATION = 1.5


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def strict_outcome(summary: dict) -> dict:
    matches = [row for row in summary["statistics"] if row["outcome"] == "strict_static_sensitive"]
    if len(matches) != 1:
        raise ValueError("expected exactly one strict_static_sensitive result")
    return matches[0]


def build_plan(audit: dict, capacity: dict, cluster_inflation: float) -> tuple[dict, list[dict]]:
    strict = strict_outcome(audit)
    n = int(strict["n_pairs"])
    discordance = (int(strict["agent_only"]) + int(strict["human_only"])) / n
    effect = abs(float(strict["effect"]))
    n80 = required_pairs(effect, discordance, 0.80, ALPHA)
    n90 = required_pairs(effect, discordance, 0.90, ALPHA)
    available = int(capacity["aidev_default_scenario"]["metadata_feasible_total_pairs"])
    scenarios = []
    for q in (0.02, 0.03, 0.05):
        for delta in (0.005, 0.01, 0.02):
            if delta > q:
                continue
            independent80 = required_pairs(delta, q, 0.80, ALPHA)
            independent90 = required_pairs(delta, q, 0.90, ALPHA)
            scenarios.append({
                "discordance_rate": q,
                "target_abs_pr_risk_difference": delta,
                "alpha_two_sided": ALPHA,
                "independent_pairs_80": independent80,
                "inflated_pairs_80": math.ceil(independent80 * cluster_inflation),
                "independent_pairs_90": independent90,
                "inflated_pairs_90": math.ceil(independent90 * cluster_inflation),
                "within_local_metadata_capacity_80": math.ceil(independent80 * cluster_inflation) <= available,
            })
    observed = {
        "n_pairs": n,
        "agent_positive": int(strict["agent_n"]),
        "human_positive": int(strict["human_n"]),
        "agent_only": int(strict["agent_only"]),
        "human_only": int(strict["human_only"]),
        "observed_abs_pr_risk_difference": effect,
        "discordance_rate": discordance,
        "current_approx_power": normal_approx_power(n, effect, discordance, ALPHA),
        "current_mde_80": minimum_detectable_effect(n, discordance, 0.80, ALPHA),
        "independent_pairs_for_observed_effect_80": n80,
        "inflated_pairs_for_observed_effect_80": math.ceil(n80 * cluster_inflation),
        "independent_pairs_for_observed_effect_90": n90,
        "inflated_pairs_for_observed_effect_90": math.ceil(n90 * cluster_inflation),
        "local_metadata_capacity_pairs": available,
        "local_capacity_can_detect_observed_effect": math.ceil(n80 * cluster_inflation) <= available,
    }
    return observed, scenarios


def pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def report_text(observed: dict, scenarios: list[dict]) -> str:
    lines = [
        "| 不一致率 | 目标 PR 风险差 | 80% 独立对数 | 80% + 1.5x | 90% + 1.5x | 本地容量可达（80%） |",
        "|---:|---:|---:|---:|---:|---|",
    ]
    for row in scenarios:
        lines.append(
            f"| {pct(row['discordance_rate'])} | {pct(row['target_abs_pr_risk_difference'])} | "
            f"{row['independent_pairs_80']} | {row['inflated_pairs_80']} | "
            f"{row['inflated_pairs_90']} | {'是' if row['within_local_metadata_capacity_80'] else '否'} |"
        )
    return f"""# AIDev PR 级隐私候选功效规划

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: APPROXIMATE_PR_LEVEL_POWER_PLAN
- Version Label: aidev_pr_privacy_power_plan_v1

## 结论先行

当前 300 对中，严格静态候选为 Agent {observed['agent_positive']}/300、Human {observed['human_positive']}/300，配对风险差 {pct(observed['observed_abs_pr_risk_difference'])}。对该观察效应的当前近似功效只有 {pct(observed['current_approx_power'])}，80% 功效时的最小可检出差异约为 {pct(observed['current_mde_80'])}。

若不对观察效应做收缩，检出 {pct(observed['observed_abs_pr_risk_difference'])} 差异需独立近似 {observed['independent_pairs_for_observed_effect_80']:,} 对；加 1.5 倍仓库聚类规划余量后约 **{observed['inflated_pairs_for_observed_effect_80']:,} 对**。当前本地 AIDev 元数据在严格仓库上限下最多只有 {observed['local_metadata_capacity_pairs']} 对，所以无法检出当前 0.67 pp 量级的差异。

## 前瞻性情景

{chr(10).join(lines)}

在不一致率 3% 的中性情景下，检出 2 pp 差异约需 881 对（含 1.5 倍余量），在本地元数据上限 950 对内；检出 1 pp 则约需 3,530 对，明显超出本地数据能力。

## 解释边界

- 这是 PR 级“任一严格静态候选”功效，不是日志语义类型功效。
- 当前 19 条 YES 来自未盲化单评审校准，不是人工金标准。
- 1.5 倍是保守规划余量，不是从 223 个仓库精确估计的 ICC 设计效应。
- 静态候选不等于运行时泄露，观察性差异不等于因果效应。

## 谬误扫描

- Coverage: 11/11 checked.
- Simpson's paradox: 正式分析仍需仓库分层。
- Ecological fallacy: 推断单位保持为 PR 对。
- Berkson's paradox: 主队列保留零日志 PR，未按 outcome 选样。
- Collider bias: 任务和规模匹配可能条件化于共同结果。
- Base-rate neglect: 直接使用稀有事件不一致率规划。
- Regression to the mean: 不将当前 0.67 pp 观察值当作真实效应。
- Survivorship bias: 只覆盖已合并、可观测的开源 PR。
- Look-elsewhere effect: 严格候选作为单一主结果计划。
- Garden of forking paths: 情景网格与聚类余量由脚本固定。
- Correlation != causation: 不做因果表述。
- Reverse causality: 任务分配可同时影响 attribution 与日志风险。

## 可复现性

输入与输出 SHA-256 记录在 `manifest.json`；脚本仅使用 Python 标准库。
"""


def run(audit_path: Path, capacity_path: Path, output_dir: Path, cluster_inflation: float) -> dict:
    if cluster_inflation < 1:
        raise ValueError("cluster_inflation must be at least 1")
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    capacity = json.loads(capacity_path.read_text(encoding="utf-8"))
    observed, scenarios = build_plan(audit, capacity, cluster_inflation)
    output_dir.mkdir(parents=True, exist_ok=True)
    fields = (
        "discordance_rate", "target_abs_pr_risk_difference", "alpha_two_sided",
        "independent_pairs_80", "inflated_pairs_80", "independent_pairs_90",
        "inflated_pairs_90", "within_local_metadata_capacity_80",
    )
    write_csv(output_dir / "prospective_scenarios.csv", scenarios, fields)
    summary = {
        "status": "APPROXIMATE_PR_LEVEL_POWER_PLAN",
        "observed": observed,
        "scenarios": scenarios,
        "cluster_planning_inflation": cluster_inflation,
        "runtime_leak_claim": False,
        "causal_claim": False,
        "fallacy_scan_coverage": "11/11",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(report_text(observed, scenarios), encoding="utf-8")
    artifacts = ("prospective_scenarios.csv", "summary.json", "report.md")
    manifest = {
        "hash_algorithm": "SHA-256",
        "input_sha256": {audit_path.name: sha256(audit_path), capacity_path.name: sha256(capacity_path)},
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
    value.add_argument("--audit-summary", type=Path, default=DEFAULT_AUDIT)
    value.add_argument("--capacity-summary", type=Path, default=DEFAULT_CAPACITY)
    value.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    value.add_argument("--cluster-inflation", type=float, default=CLUSTER_INFLATION)
    return value


def main() -> int:
    args = parser().parse_args()
    print(json.dumps(run(args.audit_summary, args.capacity_summary, args.output_dir, args.cluster_inflation), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
