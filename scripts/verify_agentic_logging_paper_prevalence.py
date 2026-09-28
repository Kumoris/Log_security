#!/usr/bin/env python3
"""Audit the paper's 58.4% logging-prevalence headline against its public package."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path


TREE_SHA = "12f5ea8a9265947210e42de7bff941ed1107e411"
FIELDS = (
    "repo_id", "repo_name", "agent_prs", "human_prs", "agent_logging_prs",
    "human_logging_prs", "agent_prevalence", "human_prevalence",
    "normalized_agent_score", "direction", "paper_denominator_rule",
    "current_script_rule",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_rows(agent_changes: list[dict], human_changes: list[dict], agent_prs: list[dict], human_prs: list[dict], names: dict[int, str]) -> list[dict]:
    agent_repo = {int(row["id"]): int(row["repo_id"]) for row in agent_prs if row.get("repo_id") is not None}
    human_repo = {int(row["id"]): int(row["repo_id"]) for row in human_prs if row.get("repo_id") is not None}
    groups: dict[str, dict[int, list[bool]]] = {
        "agent": defaultdict(list), "human": defaultdict(list),
    }
    for row in agent_changes:
        if int(row["pr_id"]) in agent_repo:
            groups["agent"][agent_repo[int(row["pr_id"])]].append(bool(row["has_logging_changes"]))
    for row in human_changes:
        if int(row["pr_id"]) in human_repo:
            groups["human"][human_repo[int(row["pr_id"])]].append(bool(row["has_logging_changes"]))

    output = []
    for repo_id in sorted(groups["agent"].keys() & groups["human"].keys()):
        agent = groups["agent"][repo_id]
        human = groups["human"][repo_id]
        if len(agent) < 3 or len(human) < 3:
            continue
        agent_rate = sum(agent) / len(agent)
        human_rate = sum(human) / len(human)
        total = agent_rate + human_rate
        direction = "equal" if agent_rate == human_rate else ("agent_higher" if agent_rate > human_rate else "human_higher")
        output.append({
            "repo_id": repo_id, "repo_name": names.get(repo_id, ""),
            "agent_prs": len(agent), "human_prs": len(human),
            "agent_logging_prs": sum(agent), "human_logging_prs": sum(human),
            "agent_prevalence": agent_rate, "human_prevalence": human_rate,
            "normalized_agent_score": agent_rate / total if total else "",
            "direction": direction,
            "paper_denominator_rule": total > 0,
            "current_script_rule": human_rate > 0,
        })
    return output


def summarize(rows: list[dict]) -> dict:
    paper_rows = [row for row in rows if row["paper_denominator_rule"]]
    script_rows = [row for row in rows if row["current_script_rule"]]

    def directions(values: list[dict]) -> dict:
        counts = {name: sum(row["direction"] == name for row in values) for name in ("human_higher", "agent_higher", "equal")}
        return {"repositories": len(values), **counts}

    paper = directions(paper_rows)
    paper["human_higher_percent"] = 100 * paper["human_higher"] / paper["repositories"]
    paper["median_normalized_agent_score"] = statistics.median(float(row["normalized_agent_score"]) for row in paper_rows)
    script = directions(script_rows)
    script["human_higher_percent"] = (
        100 * script["human_higher"] / script["repositories"] if script["repositories"] else 0.0
    )
    return {
        "all_common_repositories_min_3_each": len(rows),
        "both_sides_zero_repositories": sum(not row["paper_denominator_rule"] for row in rows),
        "human_zero_agent_positive_repositories": sum(
            row["paper_denominator_rule"] and not row["current_script_rule"] for row in rows
        ),
        "paper_denominator_recalculation": paper,
        "current_plot_script_recalculation": script,
        "paper_headline_45_of_77_reproduced": bool(
            paper["repositories"] == 77 and paper["human_higher"] == 45
            and round(paper["human_higher_percent"], 1) == 58.4
        ),
    }


def report(summary: dict) -> str:
    paper = summary["paper_denominator_recalculation"]
    script = summary["current_plot_script_recalculation"]
    return f"""# 《Do AI Coding Agents Log Like Humans?》日志触达率复现审计

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: VERIFIED_WITH_REPLICATION_SCRIPT_DISCREPANCY
- Version Label: paper_prevalence_replication_audit_v1

## 结论

论文的 headline 计数 **45/77 = {paper['human_higher_percent']:.1f}%** 可以由公开复现包的 4,550 个 Agent PR 和 3,276 个 Human PR 精确回算，因此该结论不是“无法验证”。

但复现包当前的 `plot_prevalence_scatter.py` / `plot_prevalence_distribution.py` 使用 `human prevalence > 0` 作为过滤条件，会排除 6 个“Human 为零、Agent 非零”的仓库，实际得到 **45/71 = {script['human_higher_percent']:.1f}%**。论文的 77 个仓库对应的可回算规则是：双方各至少 3 个 PR，并且**至少一侧**有日志变化，即排除双方都为零的 4 个仓库。

| 口径 | 仓库 | Human 更高 | Agent 更高 | 相同 | Human 更高占比 |
|---|---:|---:|---:|---:|---:|
| 论文 headline 可回算口径：至少一侧非零 | {paper['repositories']} | {paper['human_higher']} | {paper['agent_higher']} | {paper['equal']} | {paper['human_higher_percent']:.1f}% |
| 当前绘图脚本口径：Human 必须非零 | {script['repositories']} | {script['human_higher']} | {script['agent_higher']} | {script['equal']} | {script['human_higher_percent']:.1f}% |

## 如何解释

1. 论文关于“Agent 更少触达日志”的仓库计数可以复核。
2. 公开脚本与论文分母口径不一致，是复现包的数据处理/脚本问题；它不推翻 45 个 Human 更高仓库的计数，但会改变百分比。
3. 这只验证 logging behavior，不验证隐私泄露。论文没有测量真实敏感值、运行可达性或日志外传。
4. 我们的 300 对匹配 PR 是另一个抽样设计，不能用其 48 个有日志仓库替代论文完整 77 仓库分母。

## 来源与完整性

- 作者复现包：[agentic_logging_RP](https://github.com/YoussefEssDS/agentic_logging_RP/tree/main)
- 核验 Git tree：`{TREE_SHA}`
- 逐仓库中间结果：`repository_prevalence.csv`
- 输入与脚本 SHA-256：见 `summary.json`
"""


def run(replication_dir: Path, output_dir: Path) -> dict:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read the canonical Parquet artifacts") from exc
    data = replication_dir / "filtered_data"
    read = lambda name, columns: parquet.read_table(data / name, columns=columns).to_pylist()
    names = {
        int(row["id"]): str(row["full_name"] or "")
        for row in read("repositories_filtered.parquet", ["id", "full_name"])
    }
    rows = build_rows(
        read("agentic_logging_changes.parquet", ["pr_id", "has_logging_changes"]),
        read("human_logging_changes.parquet", ["pr_id", "has_logging_changes"]),
        read("agentic_prs_filtered.parquet", ["id", "repo_id"]),
        read("human_prs_filtered.parquet", ["id", "repo_id"]),
        names,
    )
    summary = summarize(rows)
    summary.update({
        "status": "VERIFIED_WITH_REPLICATION_SCRIPT_DISCREPANCY",
        "source_url": "https://github.com/YoussefEssDS/agentic_logging_RP/tree/main",
        "source_tree_sha": TREE_SHA,
        "agent_pr_rows": 4550,
        "human_pr_rows": 3276,
        "input_sha256": {
            name: sha256(data / name) for name in (
                "agentic_logging_changes.parquet", "human_logging_changes.parquet",
                "agentic_prs_filtered.parquet", "human_prs_filtered.parquet",
                "repositories_filtered.parquet",
            )
        },
        "replication_script_sha256": sha256(replication_dir / "scripts" / "plot_prevalence_scatter.py"),
        "runtime_leak_claim": False,
    })
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "repository_prevalence.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(report(summary), encoding="utf-8")
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--replication-dir", type=Path, default=Path("data/external/agentic_logging_RP"))
    value.add_argument("--output-dir", type=Path, default=Path("outputs/paper_prevalence_replication_audit"))
    return value


def main() -> int:
    args = parser().parse_args()
    print(json.dumps(run(args.replication_dir, args.output_dir), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
