#!/usr/bin/env python3
"""Census every local AIDev table and materialize all currently observable code evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow.parquet as pq

if __package__:
    from .materialize_aidev_expansion_pilot import evaluate
    from .mine_github_log_lineage import diff_profile
    from .screen_github_agent_logs import is_production_path, is_source_file, sha256_text
else:
    from materialize_aidev_expansion_pilot import evaluate
    from mine_github_log_lineage import diff_profile
    from screen_github_agent_logs import is_production_path, is_source_file, sha256_text


PRIVACY_FEATURES = {
    "auth_config_data",
    "request_response_data",
    "identity_session_data",
    "whole_object_dump",
    "error_diagnostic_data",
}
AGENT_FIELDS = (
    "pr_id", "pr_key", "pr_url", "repo", "language", "task_type", "agent_product",
    "state", "created_at", "merged_at", "patch_file_rows", "patch_text_rows",
    "patch_missing_rows", "source_file_rows", "source_patch_text_rows",
    "source_patch_missing_rows", "production_source_file_rows",
    "production_patch_text_rows", "production_patch_missing_rows",
    "unique_commits", "proxy_added_lines", "proxy_deleted_lines", "patch_observable",
    "n_logs_all_files", "n_logs_production", "n_privacy_candidates_all_files",
    "n_privacy_candidates_production", "privacy_patterns_production", "evidence_boundary",
)
HUMAN_FIELDS = (
    "pr_id", "pr_key", "pr_url", "repo", "language", "task_type", "human_actor",
    "state", "created_at", "merged_at", "eligible_exact_agent_stratum",
    "cached_final_diff", "diff_sha256", "diff_cache_path", "production_source_files",
    "added_lines", "deleted_lines", "n_logs_all_files", "n_logs_production",
    "n_privacy_candidates_all_files", "n_privacy_candidates_production",
    "privacy_patterns_production", "evidence_boundary",
)
PAIR_FIELDS = (
    "pair_id", "source", "repo", "language", "task_type", "agent_pr_id", "agent_pr_key",
    "agent_pr_url", "agent_created_at", "human_pr_id", "human_pr_key", "human_pr_url",
    "human_created_at", "date_distance_days", "exact_repo", "exact_task_type",
    "exact_language", "agent_diff_cached",
    "human_diff_cached", "agent_diff_sha256", "human_diff_sha256", "agent_size",
    "human_size", "size_ratio", "agent_n_logs", "human_n_logs",
    "agent_n_privacy_candidates", "human_n_privacy_candidates", "agent_has_log",
    "human_has_log", "agent_has_privacy_candidate", "human_has_privacy_candidate",
    "status", "reason",
)
DIST_FIELDS = (
    "provenance", "scope", "pattern", "n_logs", "n_candidates", "rate", "ci_low",
    "ci_high", "effect",
)
META_DIST_FIELDS = ("dimension", "value", "n_prs", "n_merged", "share_of_all")


def read_csv(path: Path) -> list[dict[str, str]]:
    csv.field_size_limit(sys.maxsize)
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def wilson(successes: int, total: int) -> tuple[float, float]:
    if not total:
        return 0.0, 0.0
    z = 1.959963984540054
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return center - margin, center + margin


def cached_diff(cache_dir: Path, pr_url: str) -> tuple[str, Path] | None:
    url = pr_url + ".diff"
    path = cache_dir / (hashlib.sha256(url.encode()).hexdigest() + ".json")
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    data = payload.get("data")
    if payload.get("url") != url or not isinstance(data, str):
        raise ValueError(f"invalid cached diff: {path}")
    return data, path.resolve()


def privacy_metrics(profile: dict) -> dict:
    all_logs = profile["logs"]
    production = [row for row in all_logs if row["path_scope"] == "production"]

    def selected(rows: list[dict]) -> list[dict]:
        return [row for row in rows if set(row["risk_features"]) & PRIVACY_FEATURES]

    candidates_all = selected(all_logs)
    candidates_production = selected(production)
    patterns = Counter(
        feature for row in candidates_production for feature in row["risk_features"]
        if feature in PRIVACY_FEATURES
    )
    return {
        "n_logs_all_files": len(all_logs),
        "n_logs_production": len(production),
        "n_privacy_candidates_all_files": len(candidates_all),
        "n_privacy_candidates_production": len(candidates_production),
        "privacy_patterns_production": ";".join(sorted(patterns)),
    }


def inventory(aidev_dir: Path) -> list[dict]:
    rows = []
    for path in sorted(aidev_dir.glob("*.parquet")):
        parquet = pq.ParquetFile(path)
        rows.append({
            "table": path.stem,
            "rows": parquet.metadata.num_rows,
            "columns": len(parquet.schema_arrow.names),
            "bytes": path.stat().st_size,
            "sha256": file_sha256(path),
        })
    return rows


def metadata_census(aidev_dir: Path) -> tuple[list[dict], int]:
    counters: dict[str, Counter] = defaultdict(Counter)
    merged: dict[str, Counter] = defaultdict(Counter)
    total = 0
    parquet = pq.ParquetFile(aidev_dir / "all_pull_request.parquet")
    for batch in parquet.iter_batches(
        columns=["agent", "state", "created_at", "merged_at"], batch_size=100_000
    ):
        data = batch.to_pydict()
        for agent, state, created_at, merged_at in zip(
            data["agent"], data["state"], data["created_at"], data["merged_at"]
        ):
            total += 1
            values = {
                "agent_product": str(agent or "[missing]"),
                "state": str(state or "[missing]"),
                "created_year": str(created_at or "[missing]")[:4],
            }
            for dimension, value in values.items():
                counters[dimension][value] += 1
                if merged_at:
                    merged[dimension][value] += 1
    rows = []
    for dimension in sorted(counters):
        for value, count in sorted(counters[dimension].items()):
            rows.append({
                "dimension": dimension, "value": value, "n_prs": count,
                "n_merged": merged[dimension][value], "share_of_all": count / total,
            })
    return rows, total


def load_reference_maps(aidev_dir: Path) -> tuple[dict, dict, dict]:
    repositories = {
        str(row["url"]): (str(row["full_name"]), str(row["language"] or ""))
        for row in pq.read_table(
            aidev_dir / "repository.parquet", columns=["url", "full_name", "language"]
        ).to_pylist()
    }
    agent_tasks = {
        int(row["id"]): str(row["type"])
        for row in pq.read_table(aidev_dir / "pr_task_type.parquet", columns=["id", "type"]).to_pylist()
    }
    human_tasks = {
        int(row["id"]): str(row["type"])
        for row in pq.read_table(
            aidev_dir / "human_pr_task_type.parquet", columns=["id", "type"]
        ).to_pylist()
    }
    return repositories, agent_tasks, human_tasks


def aggregate_agent_patches(aidev_dir: Path) -> dict[int, dict]:
    profiles: dict[int, dict] = defaultdict(lambda: {
        "patch_file_rows": 0, "patch_text_rows": 0, "patch_missing_rows": 0,
        "source_file_rows": 0, "source_patch_text_rows": 0, "source_patch_missing_rows": 0,
        "production_source_file_rows": 0, "production_patch_text_rows": 0,
        "production_patch_missing_rows": 0,
        "proxy_added_lines": 0, "proxy_deleted_lines": 0, "commits": set(),
    })
    parquet = pq.ParquetFile(aidev_dir / "pr_commit_details.parquet")
    columns = ["pr_id", "sha", "filename", "additions", "deletions", "patch"]
    for batch in parquet.iter_batches(columns=columns, batch_size=100_000):
        data = batch.to_pydict()
        for pr_id, sha, filename, additions, deletions, patch in zip(*(data[name] for name in columns)):
            profile = profiles[int(pr_id)]
            profile["patch_file_rows"] += 1
            profile["patch_text_rows" if isinstance(patch, str) else "patch_missing_rows"] += 1
            profile["commits"].add(str(sha or ""))
            path = str(filename or "")
            if is_source_file(path):
                profile["source_file_rows"] += 1
                profile["source_patch_text_rows" if isinstance(patch, str) else "source_patch_missing_rows"] += 1
                if is_production_path(path):
                    profile["production_source_file_rows"] += 1
                    profile[
                        "production_patch_text_rows" if isinstance(patch, str)
                        else "production_patch_missing_rows"
                    ] += 1
                    profile["proxy_added_lines"] += int(additions or 0)
                    profile["proxy_deleted_lines"] += int(deletions or 0)
    return profiles


def aggregate_agent_logs(path: Path) -> tuple[dict[int, Counter], Counter]:
    csv.field_size_limit(sys.maxsize)
    by_pr: dict[int, Counter] = defaultdict(Counter)
    totals = Counter()
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["dataset"] != "AIDev":
                continue
            pr_id = int(row["source_id"].split(":")[-1])
            scope = row["scope"]
            features = set(filter(None, row["risk_features"].split(";")))
            by_pr[pr_id]["logs_all_files"] += 1
            totals["logs_all_files"] += 1
            if scope == "production":
                by_pr[pr_id]["logs_production"] += 1
                totals["logs_production"] += 1
            if features & PRIVACY_FEATURES:
                by_pr[pr_id]["privacy_all_files"] += 1
                totals["privacy_all_files"] += 1
                if scope == "production":
                    by_pr[pr_id]["privacy_production"] += 1
                    totals["privacy_production"] += 1
            for feature in features & PRIVACY_FEATURES:
                by_pr[pr_id][f"feature:{scope}:{feature}"] += 1
                totals[f"feature:{scope}:{feature}"] += 1
    return by_pr, totals


def materialize_agents(
    aidev_dir: Path, repositories: dict, tasks: dict, patches: dict, logs: dict,
) -> list[dict]:
    output = []
    for row in pq.read_table(aidev_dir / "pull_request.parquet").to_pylist():
        pr_id = int(row["id"])
        repo, language = repositories.get(
            str(row["repo_url"]),
            (str(row["repo_url"] or "").removeprefix("https://api.github.com/repos/"), ""),
        )
        patch = patches.get(pr_id, {})
        log = logs.get(pr_id, Counter())
        patterns = sorted(
            name.split(":", 2)[-1] for name, count in log.items()
            if count and name.startswith("feature:production:")
        )
        output.append({
            "pr_id": pr_id,
            "pr_key": f"{repo}#{row['number']}",
            "pr_url": row["html_url"],
            "repo": repo,
            "language": language,
            "task_type": tasks.get(pr_id, ""),
            "agent_product": row["agent"],
            "state": row["state"],
            "created_at": row["created_at"],
            "merged_at": row["merged_at"],
            "patch_file_rows": patch.get("patch_file_rows", 0),
            "patch_text_rows": patch.get("patch_text_rows", 0),
            "patch_missing_rows": patch.get("patch_missing_rows", 0),
            "source_file_rows": patch.get("source_file_rows", 0),
            "source_patch_text_rows": patch.get("source_patch_text_rows", 0),
            "source_patch_missing_rows": patch.get("source_patch_missing_rows", 0),
            "production_source_file_rows": patch.get("production_source_file_rows", 0),
            "production_patch_text_rows": patch.get("production_patch_text_rows", 0),
            "production_patch_missing_rows": patch.get("production_patch_missing_rows", 0),
            "unique_commits": len(patch.get("commits", ())),
            "proxy_added_lines": patch.get("proxy_added_lines", 0),
            "proxy_deleted_lines": patch.get("proxy_deleted_lines", 0),
            "patch_observable": bool(patch.get("patch_text_rows", 0)),
            "n_logs_all_files": log["logs_all_files"],
            "n_logs_production": log["logs_production"],
            "n_privacy_candidates_all_files": log["privacy_all_files"],
            "n_privacy_candidates_production": log["privacy_production"],
            "privacy_patterns_production": ";".join(patterns),
            "evidence_boundary": "AIDev commit/file patch; repeated additions across commits may remain; static candidates are not runtime leaks",
        })
    return output


def materialize_humans(
    aidev_dir: Path, repositories: dict, tasks: dict, eligible_ids: set[int], cache_dir: Path,
) -> list[dict]:
    output = []
    for row in pq.read_table(aidev_dir / "human_pull_request.parquet").to_pylist():
        pr_id = int(row["id"])
        repo, language = repositories.get(
            str(row["repo_url"]),
            (str(row["repo_url"] or "").removeprefix("https://api.github.com/repos/"), ""),
        )
        cached = cached_diff(cache_dir, str(row["html_url"]))
        profile = diff_profile(cached[0]) if cached else {
            "logs": [], "production_source_files": 0, "added_lines": 0, "deleted_lines": 0,
        }
        metrics = privacy_metrics(profile)
        output.append({
            "pr_id": pr_id,
            "pr_key": f"{repo}#{row['number']}",
            "pr_url": row["html_url"],
            "repo": repo,
            "language": language,
            "task_type": tasks.get(pr_id, ""),
            "human_actor": row["user"],
            "state": row["state"],
            "created_at": row["created_at"],
            "merged_at": row["merged_at"],
            "eligible_exact_agent_stratum": pr_id in eligible_ids,
            "cached_final_diff": bool(cached),
            "diff_sha256": sha256_text(cached[0]) if cached else "",
            "diff_cache_path": str(cached[1]) if cached else "",
            "production_source_files": profile["production_source_files"],
            "added_lines": profile["added_lines"],
            "deleted_lines": profile["deleted_lines"],
            **metrics,
            "evidence_boundary": (
                "cached GitHub final diff; Human label does not rule out undisclosed AI assistance"
                if cached else "metadata only; no local code patch"
            ),
        })
    return output


def pair_rows(existing_path: Path, expansion_path: Path) -> list[dict]:
    rows = []
    for source, path in (("existing_300", existing_path), ("uncapped_remaining", expansion_path)):
        for row in read_csv(path):
            rows.append({
                "pair_id": row.get("pair_id") or row.get("candidate_id"),
                "source": source,
                "repo": row["repo"],
                "language": row["language"],
                "task_type": row["task_type"],
                "agent_pr_id": row["agent_pr_id"],
                "agent_pr_key": row["agent_pr_key"],
                "agent_pr_url": row["agent_pr_url"],
                "agent_created_at": row["agent_created_at"],
                "human_pr_id": row["human_pr_id"],
                "human_pr_key": row["human_pr_key"],
                "human_pr_url": row["human_pr_url"],
                "human_created_at": row["human_created_at"],
                "date_distance_days": row["date_distance_days"],
                "exact_repo": row.get("exact_repo", "True"),
                "exact_task_type": row.get("exact_task_type", "True"),
                "exact_language": row.get("exact_language", "True"),
            })
    return rows


def audit_pairs(rows: list[dict], cache_dir: Path, max_size_ratio: float) -> list[dict]:
    output = []
    for row in rows:
        agent = cached_diff(cache_dir, row["agent_pr_url"])
        human = cached_diff(cache_dir, row["human_pr_url"])
        base = {
            **row,
            "agent_diff_cached": bool(agent),
            "human_diff_cached": bool(human),
            "agent_diff_sha256": sha256_text(agent[0]) if agent else "",
            "human_diff_sha256": sha256_text(human[0]) if human else "",
        }
        if not agent or not human:
            missing = [side for side, value in (("agent", agent), ("human", human)) if not value]
            output.append({**base, "status": "CACHE_MISSING", "reason": "+".join(missing)})
            continue
        agent_profile, human_profile = diff_profile(agent[0]), diff_profile(human[0])
        agent_privacy, human_privacy = privacy_metrics(agent_profile), privacy_metrics(human_profile)
        metrics, reason = evaluate(agent[0], human[0], max_size_ratio)
        output.append({
            **base,
            "agent_size": metrics["agent_size"],
            "human_size": metrics["human_size"],
            "size_ratio": metrics["size_ratio"],
            "agent_n_logs": agent_privacy["n_logs_production"],
            "human_n_logs": human_privacy["n_logs_production"],
            "agent_n_privacy_candidates": agent_privacy["n_privacy_candidates_production"],
            "human_n_privacy_candidates": human_privacy["n_privacy_candidates_production"],
            "agent_has_log": agent_privacy["n_logs_production"] > 0,
            "human_has_log": human_privacy["n_logs_production"] > 0,
            "agent_has_privacy_candidate": agent_privacy["n_privacy_candidates_production"] > 0,
            "human_has_privacy_candidate": human_privacy["n_privacy_candidates_production"] > 0,
            "status": "ACCEPTED" if not reason else "REJECTED",
            "reason": reason,
        })
    return output


def distribution_rows(
    agent_rows: list[dict], human_rows: list[dict], pair_audit: list[dict], totals: Counter,
) -> list[dict]:
    output = []

    def add(provenance: str, scope: str, pattern: str, total: int, candidates: int, effect="") -> None:
        low, high = wilson(candidates, total)
        output.append({
            "provenance": provenance, "scope": scope, "pattern": pattern,
            "n_logs": total, "n_candidates": candidates,
            "rate": candidates / total if total else 0, "ci_low": low, "ci_high": high,
            "effect": effect,
        })

    add("agent", "production_pr_all_lower_bound", "added_log_presence", len(agent_rows), sum(int(row["n_logs_production"]) > 0 for row in agent_rows))
    add("agent", "production_pr_all_lower_bound", "privacy_candidate_presence", len(agent_rows), sum(int(row["n_privacy_candidates_production"]) > 0 for row in agent_rows))
    observable_agents = [
        row for row in agent_rows
        if int(row["patch_file_rows"]) > 0 and int(row["production_patch_missing_rows"]) == 0
    ]
    add("agent", "production_pr_observable", "added_log_presence", len(observable_agents), sum(int(row["n_logs_production"]) > 0 for row in observable_agents))
    add("agent", "production_pr_observable", "privacy_candidate_presence", len(observable_agents), sum(int(row["n_privacy_candidates_production"]) > 0 for row in observable_agents))
    agent_logs = sum(int(row["n_logs_production"]) for row in agent_rows)
    for feature in sorted(PRIVACY_FEATURES):
        add(
            "agent", "production_log", feature, agent_logs,
            totals[f"feature:production:{feature}"],
        )

    cached_humans = [row for row in human_rows if row["cached_final_diff"]]
    add("human_cached", "production_pr", "added_log_presence", len(cached_humans), sum(int(row["n_logs_production"]) > 0 for row in cached_humans))
    add("human_cached", "production_pr", "privacy_candidate_presence", len(cached_humans), sum(int(row["n_privacy_candidates_production"]) > 0 for row in cached_humans))

    accepted = [row for row in pair_audit if row["status"] == "ACCEPTED"]
    for pattern, field in (
        ("added_log_presence", "has_log"),
        ("privacy_candidate_presence", "has_privacy_candidate"),
    ):
        agent_count = sum(str(row[f"agent_{field}"]).lower() == "true" for row in accepted)
        human_count = sum(str(row[f"human_{field}"]).lower() == "true" for row in accepted)
        effect = (agent_count - human_count) / len(accepted) if accepted else 0
        add("agent_matched_cached", "production_pr", pattern, len(accepted), agent_count, effect)
        add("human_matched_cached", "production_pr", pattern, len(accepted), human_count, effect)
    return output


def report(summary: dict) -> str:
    if summary["pending_diff_urls"]:
        missing_note = (
            f"仍有 {summary['pending_diff_urls']:,} 份尚未成功请求，需继续运行可续跑下载器。"
        )
    else:
        missing_note = (
            f"剩余 {summary['terminal_diff_failures']:,} 份均已由认证 GitHub API 确认为 HTTP 404，"
            f"对应 {summary['pairs_with_terminal_missing_diff']:,} 对不可恢复配对；可访问的匹配证据已处理完。"
        )
    return f"""# AIDev 全量处理与证据覆盖审计

## 结论

AIDev 本地 {summary['table_count']} 张表、{summary['metadata_universe_prs']:,} 条全量 PR 元数据均已盘点；富代码子集的 {summary['agent_prs']:,} 条 Agent PR 均进入逐 PR 特征表。代码证据并不覆盖全部元数据，因此不能把 {summary['metadata_universe_prs']:,} 当成代码分析样本量。

- Agent PR：{summary['agent_prs']:,} 条；有 commit/file patch 文本 {summary['agent_prs_patch_observable']:,} 条；有新增生产日志 {summary['agent_prs_with_production_logs']:,} 条；有宽口径隐私/安全静态候选 {summary['agent_prs_with_privacy_candidates']:,} 条。
- 其中 {summary['agent_prs_production_patch_observable']:,} 条没有缺失生产源代码 patch；全体分母结果只可视为下界，正式 Agent 描述统计应优先使用这一可观测子集。
- Human PR：{summary['human_prs']:,} 条；AIDev 本地原表不带补丁。目前从既有 GitHub 缓存恢复最终 diff {summary['human_prs_cached_final_diff']:,} 条，其余 {summary['human_prs_missing_final_diff']:,} 条仍只有元数据。
- 匹配容量：原 300 对加无仓库上限的剩余队列，共 {summary['metadata_matched_pairs']:,} 对；双方 diff 均已缓存 {summary['pairs_both_diffs_cached']:,} 对；通过生产代码非空和规模比校准 {summary['pairs_accepted_from_cache']:,} 对。

## 如何使用

- `metadata_distribution.csv` 是对 932,791 条全量元数据逐行聚合后的 Agent 产品、状态和年份分布。
- `agent_pr_features.csv` 可做 AIDev Agent 全体的描述性统计和仓库/语言/Agent 产品分层。
- `human_pr_features.csv` 明确区分“有最终 diff”和“只有元数据”，不可把缺失补丁记作零日志。
- `human_missing_diff_queue.csv` 可续跑抓取所有尚未获得代码证据的 Human PR，而不仅是匹配队列。
- `matched_pair_cache_audit.csv` 只把 `ACCEPTED` 行送入配对统计；`CACHE_MISSING` 行保留在待抓队列。
- `feature_distribution.csv` 中所有命中都是静态风险候选，不是真实运行泄露。

## 当前瓶颈

瓶颈不是 AIDev 元数据未读取，而是部分历史 GitHub 对象已不可访问。{missing_note}
Human 全体剩余 {summary['human_prs_missing_final_diff']:,} 份无可用 diff，其中终止失败 {summary['human_terminal_diff_failures']:,} 份、尚待重试 {summary['human_pending_diff_urls']:,} 份。

## 证据边界

- AIDev Agent 补丁是 commit/file 级记录，同一行可能跨 commit 重复出现；主指标优先采用“每个 PR 是否命中”。
- Human 标签不能排除未披露的 AI 辅助。
- 无仓库上限队列用于最大化样本量，正式推断仍需按仓库聚类，并报告仓库集中度敏感性分析。
- 当前缓存子集不是随机缺失，不能把缓存结果当最终总体估计。
"""


def run(args: argparse.Namespace) -> dict:
    args.output_dir.mkdir(parents=True, exist_ok=True)
    tables = inventory(args.aidev_dir)
    metadata_rows, metadata_rows_processed = metadata_census(args.aidev_dir)
    repositories, agent_tasks, human_tasks = load_reference_maps(args.aidev_dir)
    patches = aggregate_agent_patches(args.aidev_dir)
    logs, log_totals = aggregate_agent_logs(args.log_corpus)
    agents = materialize_agents(args.aidev_dir, repositories, agent_tasks, patches, logs)
    eligible_humans = {int(row["pr_id"]) for row in read_csv(args.human_pool)}
    humans = materialize_humans(
        args.aidev_dir, repositories, human_tasks, eligible_humans, args.cache_dir
    )
    pairs = pair_rows(args.existing_pairs, args.expansion_queue)
    pair_audit = audit_pairs(pairs, args.cache_dir, args.max_size_ratio)
    distributions = distribution_rows(agents, humans, pair_audit, log_totals)

    write_csv(args.output_dir / "table_inventory.csv", tables, ("table", "rows", "columns", "bytes", "sha256"))
    write_csv(args.output_dir / "metadata_distribution.csv", metadata_rows, META_DIST_FIELDS)
    write_csv(args.output_dir / "agent_pr_features.csv", agents, AGENT_FIELDS)
    write_csv(args.output_dir / "human_pr_features.csv", humans, HUMAN_FIELDS)
    write_csv(args.output_dir / "matched_pair_cache_audit.csv", pair_audit, PAIR_FIELDS)
    write_csv(args.output_dir / "feature_distribution.csv", distributions, DIST_FIELDS)
    human_terminal_status = {
        row["diff_url"]: row["status"] for row in read_csv(args.human_terminal_failures)
    } if args.human_terminal_failures.is_file() else {}
    human_missing = [{
        "pr_id": row["pr_id"], "pr_key": row["pr_key"], "pr_url": row["pr_url"],
        "diff_url": row["pr_url"] + ".diff",
        "download_status": human_terminal_status.get(
            row["pr_url"] + ".diff", "NOT_ATTEMPTED_OR_TRANSIENT"
        ),
    } for row in humans if not row["cached_final_diff"]]
    write_csv(
        args.output_dir / "human_missing_diff_queue.csv", human_missing,
        ("pr_id", "pr_key", "pr_url", "diff_url", "download_status"),
    )

    failed_downloads = {
        row["diff_url"]: row["status"] for row in read_csv(args.download_failures)
    } if args.download_failures.is_file() else {}
    missing_urls = []
    for row in pair_audit:
        for side in ("agent", "human"):
            if not row[f"{side}_diff_cached"]:
                url = row[f"{side}_pr_url"]
                missing_urls.append({
                    "pair_id": row["pair_id"], "provenance": side,
                    "pr_key": row[f"{side}_pr_key"], "pr_url": url,
                    "diff_url": url + ".diff",
                    "download_status": failed_downloads.get(url + ".diff", "NOT_ATTEMPTED_OR_TRANSIENT"),
                })
    write_csv(
        args.output_dir / "missing_diff_queue.csv", missing_urls,
        ("pair_id", "provenance", "pr_key", "pr_url", "diff_url", "download_status"),
    )

    accepted = [row for row in pair_audit if row["status"] == "ACCEPTED"]
    terminal_failures = sum(row["download_status"] == "HTTP_404" for row in missing_urls)
    terminal_pair_ids = {
        row["pair_id"] for row in missing_urls if row["download_status"] == "HTTP_404"
    }
    pending_diff_urls = len(missing_urls) - terminal_failures
    human_terminal_count = sum(
        row["download_status"] in {"HTTP_404", "HTTP_406", "TOO_LARGE"}
        for row in human_missing
    )
    human_pending_count = len(human_missing) - human_terminal_count
    summary = {
        "status": (
            "FULL_ACCESSIBLE_AIDEV_PROCESSED_TERMINAL_FAILURES_REMAIN"
            if not pending_diff_urls and not human_pending_count
            else "FULL_LOCAL_AIDEV_PROCESSED_EXTERNAL_DIFFS_INCOMPLETE"
        ),
        "table_count": len(tables),
        "metadata_universe_prs": next(row["rows"] for row in tables if row["table"] == "all_pull_request"),
        "metadata_rows_processed": metadata_rows_processed,
        "agent_prs": len(agents),
        "agent_prs_patch_observable": sum(bool(row["patch_observable"]) for row in agents),
        "agent_prs_production_patch_observable": sum(
            int(row["patch_file_rows"]) > 0 and int(row["production_patch_missing_rows"]) == 0
            for row in agents
        ),
        "agent_prs_with_production_logs": sum(int(row["n_logs_production"]) > 0 for row in agents),
        "agent_prs_with_privacy_candidates": sum(int(row["n_privacy_candidates_production"]) > 0 for row in agents),
        "human_prs": len(humans),
        "human_prs_cached_final_diff": sum(bool(row["cached_final_diff"]) for row in humans),
        "human_prs_missing_final_diff": sum(not bool(row["cached_final_diff"]) for row in humans),
        "human_terminal_diff_failures": human_terminal_count,
        "human_pending_diff_urls": human_pending_count,
        "metadata_matched_pairs": len(pairs),
        "pairs_both_diffs_cached": sum(row["status"] != "CACHE_MISSING" for row in pair_audit),
        "pairs_accepted_from_cache": len(accepted),
        "missing_pair_diff_urls": len(missing_urls),
        "terminal_diff_failures": terminal_failures,
        "pairs_with_terminal_missing_diff": len(terminal_pair_ids),
        "pending_diff_urls": pending_diff_urls,
        "max_size_ratio": args.max_size_ratio,
        "privacy_candidate_definition": sorted(PRIVACY_FEATURES),
        "runtime_leak_claim": False,
        "causal_claim": False,
    }
    validation_errors = []
    expected_agent = next(row["rows"] for row in tables if row["table"] == "pull_request")
    expected_human = next(row["rows"] for row in tables if row["table"] == "human_pull_request")
    if len(agents) != expected_agent or len(humans) != expected_human:
        validation_errors.append("PR feature row count differs from source parquet")
    if metadata_rows_processed != summary["metadata_universe_prs"]:
        validation_errors.append("metadata census did not process every all_pull_request row")
    if set(logs) - {int(row["pr_id"]) for row in agents}:
        validation_errors.append("AIDev log corpus contains unknown PR ids")
    if len({row["pair_id"] for row in pairs}) != len(pairs):
        validation_errors.append("duplicate pair ids")
    if len({row["agent_pr_id"] for row in accepted}) != len(accepted):
        validation_errors.append("accepted cohort reuses an Agent PR")
    if len({row["human_pr_id"] for row in accepted}) != len(accepted):
        validation_errors.append("accepted cohort reuses a Human PR")
    if any(
        str(row[name]).lower() not in {"1", "true", "yes"}
        for row in accepted for name in ("exact_repo", "exact_task_type", "exact_language")
    ):
        validation_errors.append("accepted cohort contains an inexact categorical match")
    if any(float(row["date_distance_days"]) > 180 for row in accepted):
        validation_errors.append("accepted cohort exceeds the 180-day caliper")
    summary["validation"] = {"status": "PASS" if not validation_errors else "FAIL", "errors": validation_errors}
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output_dir / "report.md").write_text(report(summary), encoding="utf-8")
    artifacts = (
        "table_inventory.csv", "metadata_distribution.csv", "agent_pr_features.csv", "human_pr_features.csv",
        "matched_pair_cache_audit.csv", "feature_distribution.csv", "missing_diff_queue.csv",
        "human_missing_diff_queue.csv",
        "summary.json", "report.md",
    )
    manifest = {
        "input_sha256": {
            "log_corpus": file_sha256(args.log_corpus),
            "human_pool": file_sha256(args.human_pool),
            "existing_pairs": file_sha256(args.existing_pairs),
            "expansion_queue": file_sha256(args.expansion_queue),
            "download_failures": file_sha256(args.download_failures) if args.download_failures.is_file() else "",
            "human_terminal_failures": file_sha256(args.human_terminal_failures) if args.human_terminal_failures.is_file() else "",
        },
        "script_sha256": file_sha256(Path(__file__)),
        "artifact_sha256": {name: file_sha256(args.output_dir / name) for name in artifacts},
        "deterministic": True,
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if validation_errors:
        raise RuntimeError("; ".join(validation_errors))
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--aidev-dir", type=Path, default=Path("data/repos/AIDev"))
    value.add_argument("--log-corpus", type=Path, default=Path("outputs/multisource_agent_log_corpus/log_rows.csv"))
    value.add_argument("--human-pool", type=Path, default=Path("outputs/aidev_observational_primary_300/eligible_human_pool.csv"))
    value.add_argument("--existing-pairs", type=Path, default=Path("outputs/aidev_observational_primary_300/matched_pairs.csv"))
    value.add_argument("--expansion-queue", type=Path, default=Path("outputs/aidev_full_capacity_v1/aidev_prefetch_queue.csv"))
    value.add_argument("--cache-dir", type=Path, default=Path("data/res/aidev_observational_primary_diffs"))
    value.add_argument("--download-failures", type=Path, default=Path("outputs/aidev_full_coverage_v1/missing_diff_download_failures.csv"))
    value.add_argument("--human-terminal-failures", type=Path, default=Path("outputs/aidev_full_coverage_v1/human_full_terminal_verified.csv"))
    value.add_argument("--output-dir", type=Path, default=Path("outputs/aidev_full_coverage_v1"))
    value.add_argument("--max-size-ratio", type=float, default=10)
    return value


def main() -> int:
    args = parser().parse_args()
    print(json.dumps(run(args), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
