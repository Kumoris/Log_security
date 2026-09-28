#!/usr/bin/env python3
"""Audit whether local AIDev and SWE-chat pools can support the next cohort."""

from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path


DEFAULT_AGENT_POOL = Path("outputs/aidev_observational_primary_300/eligible_agent_pool.csv")
DEFAULT_HUMAN_POOL = Path("outputs/aidev_observational_primary_300/eligible_human_pool.csv")
DEFAULT_EXISTING_PAIRS = Path("outputs/aidev_observational_primary_300/matched_pairs.csv")
DEFAULT_SWE_ROWS = Path("outputs/swe_chat_value_aware_privacy/analysis/classified_log_statements.csv")
DEFAULT_SWE_PRIOR = Path("outputs/swe_chat_value_aware_privacy/analysis/manual_audit_queue.csv")
DEFAULT_SWE_MATCHED = Path("outputs/swe_chat_value_aware_privacy/matched_blind_audit_v1/provenance_key.csv")
DEFAULT_OUTPUT = Path("outputs/privacy_cohort_expansion_capacity_v1")


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
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def truth(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def source_hash(row: dict[str, str]) -> str:
    payload = "\0".join(
        row.get(name, "") for name in ("repo", "commit", "file", "line", "statement_redacted")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def extension(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return suffix if suffix else "[none]"


def exact_temporal_matching(
    humans: list[dict[str, str]], agents: list[dict[str, str]], max_days: float,
) -> list[tuple[dict[str, str], dict[str, str], float]]:
    """Maximum-cardinality matching within exact repo/task/language strata."""
    agents_by_stratum: dict[tuple[str, str, str], list[tuple[datetime, dict[str, str]]]] = defaultdict(list)
    for agent in agents:
        key = (agent["repo"], agent["task_type"], agent["language"])
        agents_by_stratum[key].append((timestamp(agent["created_at"]), agent))
    for values in agents_by_stratum.values():
        values.sort(key=lambda item: (item[0], item[1]["pr_id"]))

    human_rows: dict[str, dict[str, str]] = {}
    agent_rows: dict[str, dict[str, str]] = {}
    adjacency: dict[str, list[tuple[float, str]]] = {}
    window = timedelta(days=max_days)
    for human in humans:
        key = (human["repo"], human["task_type"], human["language"])
        values = agents_by_stratum.get(key, [])
        dates = [item[0] for item in values]
        center = timestamp(human["created_at"])
        left = bisect.bisect_left(dates, center - window)
        right = bisect.bisect_right(dates, center + window)
        window_values = values[left:right]
        choices = sorted(
            ((abs((date - center).total_seconds()) / 86400, row["pr_id"]) for date, row in window_values),
            key=lambda item: (item[0], item[1]),
        )
        if choices:
            human_rows[human["pr_id"]] = human
            adjacency[human["pr_id"]] = choices
            agent_rows.update({row["pr_id"]: row for _, row in window_values})

    agent_to_human: dict[str, str] = {}

    def augment(human_id: str, seen: set[str]) -> bool:
        for _, agent_id in adjacency[human_id]:
            if agent_id in seen:
                continue
            seen.add(agent_id)
            previous = agent_to_human.get(agent_id)
            if previous is None or augment(previous, seen):
                agent_to_human[agent_id] = human_id
                return True
        return False

    order = sorted(adjacency, key=lambda human_id: (len(adjacency[human_id]), human_rows[human_id]["created_at"], human_id))
    for human_id in order:
        augment(human_id, set())

    output = []
    for agent_id, human_id in agent_to_human.items():
        human, agent = human_rows[human_id], agent_rows[agent_id]
        days = abs((timestamp(human["created_at"]) - timestamp(agent["created_at"])).total_seconds()) / 86400
        output.append((human, agent, days))
    return sorted(output, key=lambda item: (item[0]["repo"], item[2], item[0]["pr_id"], item[1]["pr_id"]))


def aidev_capacity(
    agents: list[dict[str, str]], humans: list[dict[str, str]], existing: list[dict[str, str]],
    max_days: float, total_repo_cap: int,
) -> tuple[dict, list[dict]]:
    required = ("repo", "task_type", "language", "created_at")
    remaining_agents = [
        row for row in agents if not truth(row["selected"]) and all(row.get(name) for name in required)
    ]
    remaining_humans = [
        row for row in humans if not truth(row["selected"]) and all(row.get(name) for name in required)
    ]
    matches = exact_temporal_matching(remaining_humans, remaining_agents, max_days)
    existing_counts = Counter(row["repo"] for row in existing)
    by_repo: dict[str, list[tuple[dict[str, str], dict[str, str], float]]] = defaultdict(list)
    for match in matches:
        by_repo[match[0]["repo"]].append(match)

    selected = []
    for repo in sorted(by_repo):
        room = max(0, total_repo_cap - existing_counts[repo])
        selected.extend(by_repo[repo][:room])
    rows = [{
        "candidate_id": hashlib.sha256(f"{agent['pr_id']}|{human['pr_id']}".encode()).hexdigest()[:16],
        "repo": human["repo"],
        "language": human["language"],
        "task_type": human["task_type"],
        "agent_pr_id": agent["pr_id"],
        "agent_pr_key": agent["pr_key"],
        "agent_pr_url": agent["pr_url"],
        "agent_product": agent["agent_product"],
        "agent_created_at": agent["created_at"],
        "agent_merged_at": agent["merged_at"],
        "agent_proxy_size": agent["proxy_size"],
        "human_pr_id": human["pr_id"],
        "human_pr_key": human["pr_key"],
        "human_pr_url": human["pr_url"],
        "human_actor": human["human_actor"],
        "human_created_at": human["created_at"],
        "human_merged_at": human["merged_at"],
        "date_distance_days": round(days, 6),
        "existing_pairs_in_repo": existing_counts[human["repo"]],
        "exact_repo": True,
        "exact_task_type": True,
        "exact_language": True,
        "status": "AWAITING_BOTH_FINAL_DIFFS_AND_SIZE_CALIPER",
    } for human, agent, days in selected]
    return {
        "max_date_days": max_days,
        "total_repo_cap": total_repo_cap,
        "existing_pairs": len(existing),
        "metadata_feasible_new_pairs": len(rows),
        "metadata_feasible_total_pairs": len(existing) + len(rows),
        "new_repositories": len({row["repo"] for row in rows}),
        "target_1422_met": len(existing) + len(rows) >= 1422,
        "final_diff_size_verified": False,
    }, rows


def swe_chat_remaining(
    rows: list[dict[str, str]], prior: list[dict[str, str]], matched: list[dict[str, str]],
) -> tuple[list[dict], dict]:
    excluded = {source_hash(row) for row in prior}
    excluded.update(row["source_sha256_16"] for row in matched)
    strata: dict[tuple[str, str, str], Counter] = defaultdict(Counter)
    for row in rows:
        if (
            row["path_scope"] == "production"
            and row["evidence_grade"] == "A"
            and row["attribution"] in {"agent_only", "human_only"}
            and truth(row["static_privacy_candidate"])
            and source_hash(row) not in excluded
        ):
            strata[(row["repo"], extension(row["file"]), row["sink_family"])][row["attribution"]] += 1
    output = []
    for (repo, suffix, sink), counts in sorted(strata.items()):
        available = min(counts["agent_only"], counts["human_only"])
        if available:
            output.append({
                "repo": repo,
                "file_extension": suffix,
                "sink_family": sink,
                "agent_remaining": counts["agent_only"],
                "human_remaining": counts["human_only"],
                "exact_pairs_remaining": available,
            })
    by_repo = Counter()
    for row in output:
        by_repo[row["repo"]] += row["exact_pairs_remaining"]
    return output, {
        "reviewed_or_reserved_source_hashes": len(excluded),
        "exact_pairs_remaining_uncapped": sum(by_repo.values()),
        "repositories_with_remaining_pairs": len(by_repo),
        "largest_repository_remaining_pairs": max(by_repo.values(), default=0),
        "largest_repository_share": max(by_repo.values(), default=0) / sum(by_repo.values()) if by_repo else 0,
        "remaining_pairs_with_new_repo_cap_5": sum(min(5, count) for count in by_repo.values()),
    }


def report_text(summary: dict) -> str:
    default = summary["aidev_default_scenario"]
    swe = summary["swe_chat"]
    return f"""# Agent/Human 隐私队列扩展容量审计

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: VERIFIED_METADATA_CAPACITY_NOT_FINAL_COHORT
- Version Label: privacy_cohort_expansion_capacity_v1

## 结论先行

当前本地数据不能在不改变研究分母的情况下，直接组成上一轮规划的 1,422 对盲化日志语义样本。

- AIDev 已有 {default['existing_pairs']} 对 PR。在同仓库/任务/语言、时间差不超过 {default['max_date_days']:.0f} 天、每仓库总计最多 {default['total_repo_cap']} 对时，剩余元数据最多再组成 {default['metadata_feasible_new_pairs']} 对，总计 {default['metadata_feasible_total_pairs']} 对。
- 这些 AIDev 对仍未抓取双方最终 diff，也未通过最终修改规模比校准，因此 {default['metadata_feasible_total_pairs']} 是元数据可行数，不是最终队列承诺。
- SWE-chat 排除已审样本后仅剩 {swe['exact_pairs_remaining_uncapped']} 对可按同仓库/扩展名/sink 精确匹配，来自 {swe['repositories_with_remaining_pairs']} 个仓库；最大仓库占 {swe['largest_repository_share'] * 100:.1f}%。

## 为什么不能直接相加

| 数据 | 单位 | 适合回答的问题 |
|---|---|---|
| AIDev | 匹配 PR，包含零日志 PR | Agent PR 产生任一隐私候选日志的概率是否不同 |
| SWE-chat 58 对 | 已新增且已筛中的日志语句 | 在候选日志内部，敏感语义类型是否不同 |

两者的条件概率和分母不同。将 300 对 PR 和 58 对日志直接合并，会把“是否产生风险日志”与“产生了哪种风险日志”混为一个不可解释的结果。

## 可执行的数据路线

1. **PR 级主队列**：先抓取 `aidev_prefetch_queue.csv` 中的 {default['metadata_feasible_new_pairs']} 对双方最终 diff，再用最终修改规模比和证据完整性进行二次筛选。
2. **日志语义队列**：SWE-chat 已基本耗尽跨仓库精确匹配能力，需要新的行级 Agent/Human 来源，不能靠单一仓库继续扩充。
3. **运行时机制队列**：保持与上述两个观察性分析分离，继续用 canary 对模型上下文、工具循环和会话持久化做直接运行验证。

## 证据边界

- AIDev 容量是最大一对一时间匹配后的元数据可行数；真正主队列还要抓 diff、重算生产代码规模并应用 size caliper。
- AIDev `Human` 标签不能排除未披露的 AI 辅助。
- SWE-chat 容量只针对自动筛中的静态候选，不是真实泄露率。
- 1,422 是前一轮“候选日志内语义差异”的近似功效规划，不能无条件转用为 PR 数。

## 谬误扫描

- Coverage: 11/11 checked.
- Simpson's paradox: 容量按仓库限额，不用大仓库堆满目标。
- Ecological fallacy: 分别保留 PR 与日志语句的推断单位。
- Berkson's paradox: SWE-chat 只是已筛中条件样本，不代表全部日志。
- Collider bias: 同 sink 匹配可能条件化于作者和语义的共同结果。
- Base-rate neglect: AIDev 保留零日志 PR，SWE-chat 明示为条件分析。
- Regression to the mean: 候选队列不按极端日志数选样。
- Survivorship bias: 仅有已合并、可观测开源 PR，保留外部有效性限制。
- Look-elsewhere effect: 容量审计不进行效应显著性挑选。
- Garden of forking paths: 时间 caliper 和仓库上限由情景表固定。
- Correlation != causation: 队列仍是观察性匹配设计。
- Reverse causality: 任务分配可同时影响作者来源和日志需求。

## 可复现性

所有输入和输出哈希记录在 `manifest.json`；匹配只使用 Python 标准库，无随机过程。
"""


def run(args: argparse.Namespace) -> dict:
    agents = read_csv(args.agent_pool)
    humans = read_csv(args.human_pool)
    existing = read_csv(args.existing_pairs)
    scenarios = []
    default_rows = []
    for days in (30.0, 90.0, 180.0, 365.0):
        for cap in (5, 10):
            result, rows = aidev_capacity(agents, humans, existing, days, cap)
            scenarios.append(result)
            if days == args.max_date_days and cap == args.total_repo_cap:
                default_rows = rows
                default_result = result
    if not default_rows:
        default_result, default_rows = aidev_capacity(
            agents, humans, existing, args.max_date_days, args.total_repo_cap
        )
        scenarios.append(default_result)

    if len({row["agent_pr_id"] for row in default_rows}) != len(default_rows):
        raise ValueError("default queue reuses an Agent PR")
    if len({row["human_pr_id"] for row in default_rows}) != len(default_rows):
        raise ValueError("default queue reuses a Human PR")
    existing_counts = Counter(row["repo"] for row in existing)
    new_counts = Counter(row["repo"] for row in default_rows)
    if any(existing_counts[repo] + count > args.total_repo_cap for repo, count in new_counts.items()):
        raise ValueError("default queue exceeds the total repository cap")
    if any(
        not row["repo"] or not row["task_type"] or not row["language"]
        or float(row["date_distance_days"]) > args.max_date_days
        for row in default_rows
    ):
        raise ValueError("default queue violates a categorical or date constraint")

    swe_rows, swe_summary = swe_chat_remaining(
        read_csv(args.swe_rows), read_csv(args.swe_prior), read_csv(args.swe_matched)
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    prefetch_fields = (
        "candidate_id", "repo", "language", "task_type", "agent_pr_id", "agent_pr_key",
        "agent_pr_url", "agent_product", "agent_created_at", "agent_proxy_size", "human_pr_id",
        "agent_merged_at", "human_pr_key", "human_pr_url", "human_actor", "human_created_at",
        "human_merged_at", "date_distance_days",
        "existing_pairs_in_repo", "exact_repo", "exact_task_type", "exact_language", "status",
    )
    scenario_fields = (
        "max_date_days", "total_repo_cap", "existing_pairs", "metadata_feasible_new_pairs",
        "metadata_feasible_total_pairs", "new_repositories", "target_1422_met", "final_diff_size_verified",
    )
    swe_fields = (
        "repo", "file_extension", "sink_family", "agent_remaining", "human_remaining",
        "exact_pairs_remaining",
    )
    write_csv(args.output_dir / "aidev_prefetch_queue.csv", default_rows, prefetch_fields)
    write_csv(args.output_dir / "capacity_scenarios.csv", scenarios, scenario_fields)
    write_csv(args.output_dir / "swe_chat_remaining_strata.csv", swe_rows, swe_fields)
    summary = {
        "status": "VERIFIED_METADATA_CAPACITY_NOT_FINAL_COHORT",
        "aidev_default_scenario": default_result,
        "aidev_scenarios": scenarios,
        "swe_chat": swe_summary,
        "estimand_warning": "AIDev PR pairs and SWE-chat screened log-statement pairs cannot be pooled.",
        "runtime_leak_claim": False,
        "causal_claim": False,
        "fallacy_scan_coverage": "11/11",
        "validation": {
            "status": "PASS",
            "unique_agent_prs": True,
            "unique_human_prs": True,
            "nonempty_exact_categorical_fields": True,
            "date_caliper_respected": True,
            "total_repository_cap_respected": True,
        },
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output_dir / "report.md").write_text(report_text(summary), encoding="utf-8")
    input_paths = (
        args.agent_pool, args.human_pool, args.existing_pairs, args.swe_rows, args.swe_prior, args.swe_matched,
    )
    artifact_names = (
        "aidev_prefetch_queue.csv", "capacity_scenarios.csv", "swe_chat_remaining_strata.csv",
        "summary.json", "report.md",
    )
    manifest = {
        "hash_algorithm": "SHA-256",
        "input_sha256": {path.name: sha256(path) for path in input_paths},
        "script_sha256": sha256(Path(__file__)),
        "artifact_sha256": {name: sha256(args.output_dir / name) for name in artifact_names},
        "deterministic": True,
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--agent-pool", type=Path, default=DEFAULT_AGENT_POOL)
    value.add_argument("--human-pool", type=Path, default=DEFAULT_HUMAN_POOL)
    value.add_argument("--existing-pairs", type=Path, default=DEFAULT_EXISTING_PAIRS)
    value.add_argument("--swe-rows", type=Path, default=DEFAULT_SWE_ROWS)
    value.add_argument("--swe-prior", type=Path, default=DEFAULT_SWE_PRIOR)
    value.add_argument("--swe-matched", type=Path, default=DEFAULT_SWE_MATCHED)
    value.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    value.add_argument("--max-date-days", type=float, default=180.0)
    value.add_argument("--total-repo-cap", type=int, default=5)
    return value


def main() -> int:
    args = parser().parse_args()
    print(json.dumps(run(args), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
