#!/usr/bin/env python3
"""Build an outcome-independent AIDev Agent/Human PR queue and freeze both diffs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import statistics
from collections import Counter, defaultdict
from pathlib import Path

if __package__:
    from .match_aidev_human_prs import _days, _fetch_diff, load_data
    from .mine_github_log_lineage import diff_profile
    from .screen_github_agent_logs import GitHubClient, _atomic_write_text, sha256_text
else:
    from match_aidev_human_prs import _days, _fetch_diff, load_data
    from mine_github_log_lineage import diff_profile
    from screen_github_agent_logs import GitHubClient, _atomic_write_text, sha256_text


PAIR_FIELDS = (
    "pair_id", "cohort", "repo", "language", "task_type",
    "agent_pr_id", "agent_pr_key", "agent_pr_url", "agent_product",
    "agent_created_at", "agent_merged_at", "agent_commit_count",
    "agent_proxy_size", "agent_size", "agent_added_lines", "agent_deleted_lines",
    "agent_n_logs", "agent_n_logs_all_files", "agent_diff_sha256", "agent_diff_path",
    "human_pr_id", "human_pr_key", "human_pr_url", "human_actor",
    "human_created_at", "human_merged_at", "human_size", "human_added_lines",
    "human_deleted_lines", "human_n_logs", "human_n_logs_all_files",
    "human_diff_sha256", "human_diff_path", "date_distance_days", "size_ratio",
    "size_log_distance", "match_score", "exact_repo", "exact_task_type",
    "exact_language", "diff_snapshot_status", "diff_completeness_verification",
    "agent_provenance_tier", "human_provenance_tier", "analysis_eligibility",
    "size_metric", "outcome_conditioned_on_logging",
)
QUEUE_FIELDS = (
    "queue_id", "pair_id", "cohort", "provenance", "repo", "language",
    "task_type", "pr_id", "pr_key", "pr_url", "actor", "created_at", "merged_at",
    "size", "added_lines", "deleted_lines", "n_logs", "n_logs_all_files",
    "diff_sha256", "diff_path", "diff_snapshot_status",
    "diff_completeness_verification", "provenance_tier", "analysis_eligibility",
)
LOG_FIELDS = (
    "dataset", "cohort", "pair_id", "provenance", "repo", "pr_key", "pr_url",
    "task_type", "language", "file", "line", "path_scope", "risk_features",
    "log_concepts", "static_risk_candidate", "log_text_redacted", "diff_sha256",
)
MANIFEST_FIELDS = (
    "pair_id", "provenance", "pr_key", "pr_url", "diff_path", "diff_sha256",
    "utf8_bytes", "production_source_files", "source_files", "added_lines",
    "deleted_lines", "n_logs", "n_logs_all_files",
)
AGENT_POOL_FIELDS = (
    "pr_id", "pr_key", "pr_url", "repo", "language", "task_type", "agent_product",
    "created_at", "merged_at", "commit_count", "proxy_size", "proxy_added_lines",
    "proxy_deleted_lines", "selected",
)
HUMAN_POOL_FIELDS = (
    "pr_id", "pr_key", "pr_url", "repo", "language", "task_type", "human_actor",
    "created_at", "merged_at", "nearest_agent_days", "selected",
)


def _write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _ratio(left: int, right: int) -> float:
    return (max(left, right) + 1) / (min(left, right) + 1)


def ranked_agent_candidates(
    human: dict, agents: list[dict], used: set[int], max_days: float
) -> list[dict]:
    """Rank without looking at either PR's logging outcome."""
    choices = []
    for agent in agents:
        if int(agent["id"]) in used:
            continue
        days = _days(human["created_at"], agent["created_at"])
        if days > max_days:
            continue
        proxy_distance = abs(math.log1p(human["size"]) - math.log1p(agent["size"]))
        choices.append((proxy_distance + days / 365, days, int(agent["id"]), agent))
    return [item[-1] for item in sorted(choices)]


def _profile_row(profile: dict) -> dict:
    production_logs = [row for row in profile["logs"] if row["path_scope"] == "production"]
    return {
        "size": profile["added_lines"] + profile["deleted_lines"],
        "added": profile["added_lines"],
        "deleted": profile["deleted_lines"],
        "n_logs": len(production_logs),
        "n_logs_all_files": len(profile["logs"]),
    }


def _save_diff(output_dir: Path, provenance: str, row: dict, diff: str) -> tuple[Path, str]:
    path = (
        output_dir / "diffs" / provenance
        / f"{row['repo'].replace('/', '__')}__pull_{row['number']}.diff"
    )
    _atomic_write_text(path, diff)
    return path.resolve(), sha256_text(diff)


def _append_logs(output: list[dict], pair: dict, provenance: str, profile: dict) -> None:
    prefix = provenance + "_"
    for log in profile["logs"]:
        output.append({
            "dataset": "AIDev-final-diff",
            "cohort": pair["cohort"],
            "pair_id": pair["pair_id"],
            "provenance": provenance,
            "repo": pair["repo"],
            "pr_key": pair[prefix + "pr_key"],
            "pr_url": pair[prefix + "pr_url"],
            "task_type": pair["task_type"],
            "language": pair["language"],
            **{
                name: ";".join(log[name]) if isinstance(log[name], list) else log[name]
                for name in (
                    "file", "line", "path_scope", "risk_features", "log_concepts",
                    "static_risk_candidate", "log_text_redacted",
                )
            },
            "diff_sha256": pair[prefix + "diff_sha256"],
        })


def _queue_row(pair: dict, provenance: str) -> dict:
    prefix = provenance + "_"
    actor = pair["agent_product"] if provenance == "agent" else pair["human_actor"]
    return {
        "queue_id": f"{pair['pair_id']}:{provenance}",
        "pair_id": pair["pair_id"],
        "cohort": pair["cohort"],
        "provenance": provenance,
        "repo": pair["repo"],
        "language": pair["language"],
        "task_type": pair["task_type"],
        "pr_id": pair[prefix + "pr_id"],
        "pr_key": pair[prefix + "pr_key"],
        "pr_url": pair[prefix + "pr_url"],
        "actor": actor,
        "created_at": pair[prefix + "created_at"],
        "merged_at": pair[prefix + "merged_at"],
        "size": pair[prefix + "size"],
        "added_lines": pair[prefix + "added_lines"],
        "deleted_lines": pair[prefix + "deleted_lines"],
        "n_logs": pair[prefix + "n_logs"],
        "n_logs_all_files": pair[prefix + "n_logs_all_files"],
        "diff_sha256": pair[prefix + "diff_sha256"],
        "diff_path": pair[prefix + "diff_path"],
        "diff_snapshot_status": pair["diff_snapshot_status"],
        "diff_completeness_verification": pair["diff_completeness_verification"],
        "provenance_tier": pair[prefix + "provenance_tier"],
        "analysis_eligibility": pair["analysis_eligibility"],
    }


def _manifest_row(pair: dict, provenance: str, profile: dict) -> dict:
    prefix = provenance + "_"
    return {
        "pair_id": pair["pair_id"],
        "provenance": provenance,
        "pr_key": pair[prefix + "pr_key"],
        "pr_url": pair[prefix + "pr_url"],
        "diff_path": pair[prefix + "diff_path"],
        "diff_sha256": pair[prefix + "diff_sha256"],
        "utf8_bytes": Path(pair[prefix + "diff_path"]).stat().st_size,
        "production_source_files": profile["production_source_files"],
        "source_files": profile["source_files"],
        "added_lines": profile["added_lines"],
        "deleted_lines": profile["deleted_lines"],
        "n_logs": pair[prefix + "n_logs"],
        "n_logs_all_files": pair[prefix + "n_logs_all_files"],
    }


def validate_materialized(
    pairs: list[dict], queue: list[dict], manifest: list[dict], log_rows: list[dict],
    expected_pairs: int, max_days: float, max_size_ratio: float,
) -> dict:
    errors = []
    if len(pairs) != expected_pairs:
        errors.append(f"pair count {len(pairs)} != {expected_pairs}")
    if len(queue) != expected_pairs * 2 or len(manifest) != expected_pairs * 2:
        errors.append("queue or manifest does not contain exactly two rows per pair")
    for side in ("agent", "human"):
        keys = [row[f"{side}_pr_key"] for row in pairs]
        if len(keys) != len(set(keys)):
            errors.append(f"{side} PRs are not unique")
    if {row["agent_pr_url"] for row in pairs} & {row["human_pr_url"] for row in pairs}:
        errors.append("Agent and Human URL sets overlap")
    if any(
        not row["exact_repo"] or not row["exact_task_type"] or not row["exact_language"]
        for row in pairs
    ):
        errors.append("at least one categorical match is not exact")
    if any(float(row["date_distance_days"]) > max_days for row in pairs):
        errors.append("date caliper exceeded")
    if any(float(row["size_ratio"]) > max_size_ratio for row in pairs):
        errors.append("final-diff size caliper exceeded")
    if any(row["outcome_conditioned_on_logging"] not in (False, "False", "false") for row in pairs):
        errors.append("logging-outcome-conditioned row found")

    all_log_counts = Counter((row["provenance"], row["pr_key"]) for row in log_rows)
    production_log_counts = Counter(
        (row["provenance"], row["pr_key"])
        for row in log_rows if row["path_scope"] == "production"
    )
    for row in manifest:
        path = Path(row["diff_path"])
        if not path.is_file():
            errors.append("missing diff: " + str(path))
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != row["diff_sha256"]:
            errors.append("diff hash mismatch: " + str(path))
        key = (row["provenance"], row["pr_key"])
        if int(row["n_logs_all_files"]) != all_log_counts[key]:
            errors.append("all-file log count mismatch: " + row["pr_key"])
        if int(row["n_logs"]) != production_log_counts[key]:
            errors.append("production log count mismatch: " + row["pr_key"])
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "checks": {
            "expected_pairs": expected_pairs,
            "expected_queue_rows": expected_pairs * 2,
            "expected_frozen_diffs": expected_pairs * 2,
            "unique_prs_per_side": True,
            "disjoint_agent_human_urls": True,
            "exact_categorical_matching": True,
            "date_caliper_days": max_days,
            "final_diff_size_ratio_caliper": max_size_ratio,
            "saved_diff_sha256": True,
            "log_counts_recomputed_from_candidates": True,
            "outcome_conditioned_on_logging": False,
        },
    }


def run(args: argparse.Namespace) -> dict:
    agents, humans, input_audit = load_data(
        args.aidev_dir, args.agent_log_corpus, require_agent_logs=False
    )
    agents_by_stratum: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in agents:
        agents_by_stratum[(row["repo"], row["task_type"])].append(row)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    client = GitHubClient(
        "https://api.github.com", args.token, args.cache_dir, args.offline, args.refresh,
        diff_delay=args.diff_delay,
    )
    pairs: list[dict] = []
    queue: list[dict] = []
    evidence: list[dict] = []
    log_rows: list[dict] = []
    manifest: list[dict] = []
    used_agents: set[int] = set()
    fetch_failures = Counter()

    for candidate in humans:
        if len(pairs) >= args.count:
            break
        try:
            human_diff = _fetch_diff(client, candidate["html_url"], args.retry_wait)
        except RuntimeError as exc:
            fetch_failures["human_diff"] += 1
            print(f"[skip human] {candidate['html_url']}: {exc}", flush=True)
            continue
        human_profile = diff_profile(human_diff)
        human_metrics = _profile_row(human_profile)
        if not human_metrics["size"]:
            fetch_failures["human_no_production_source_change"] += 1
            continue
        human = {**candidate, **human_metrics}

        selected = None
        candidates = ranked_agent_candidates(
            human, agents_by_stratum[(human["repo"], human["task_type"])],
            used_agents, args.max_date_days,
        )[: args.agent_candidate_limit]
        for agent in candidates:
            try:
                agent_diff = _fetch_diff(client, agent["html_url"], args.retry_wait)
            except RuntimeError as exc:
                fetch_failures["agent_diff"] += 1
                print(f"[skip agent] {agent['html_url']}: {exc}", flush=True)
                continue
            agent_profile = diff_profile(agent_diff)
            agent_metrics = _profile_row(agent_profile)
            if not agent_metrics["size"]:
                fetch_failures["agent_no_production_source_change"] += 1
                continue
            final_ratio = _ratio(human["size"], agent_metrics["size"])
            if final_ratio > args.max_size_ratio:
                fetch_failures["final_size_caliper"] += 1
                continue
            selected = agent, agent_diff, agent_profile, agent_metrics, final_ratio
            break
        if selected is None:
            continue

        agent, agent_diff, agent_profile, agent_metrics, final_ratio = selected
        used_agents.add(int(agent["id"]))
        pair_id = sha256_text(f"aidev-primary|{agent['id']}|{human['id']}")[:16]
        agent_path, agent_sha = _save_diff(args.output_dir, "agent", agent, agent_diff)
        human_path, human_sha = _save_diff(args.output_dir, "human", human, human_diff)
        days = _days(human["created_at"], agent["created_at"])
        size_log_distance = abs(math.log1p(human["size"]) - math.log1p(agent_metrics["size"]))
        pair = {
            "pair_id": pair_id,
            "cohort": "aidev_observational_primary",
            "repo": human["repo"],
            "language": human["language"],
            "task_type": human["task_type"],
            "agent_pr_id": agent["id"],
            "agent_pr_key": f"{human['repo']}#{agent['number']}",
            "agent_pr_url": agent["html_url"],
            "agent_product": agent["agent"],
            "agent_created_at": agent["created_at"],
            "agent_merged_at": agent["merged_at"],
            "agent_commit_count": agent["commit_count"],
            "agent_proxy_size": agent["size"],
            "agent_size": agent_metrics["size"],
            "agent_added_lines": agent_metrics["added"],
            "agent_deleted_lines": agent_metrics["deleted"],
            "agent_n_logs": agent_metrics["n_logs"],
            "agent_n_logs_all_files": agent_metrics["n_logs_all_files"],
            "agent_diff_sha256": agent_sha,
            "agent_diff_path": str(agent_path),
            "human_pr_id": human["id"],
            "human_pr_key": f"{human['repo']}#{human['number']}",
            "human_pr_url": human["html_url"],
            "human_actor": human["user"],
            "human_created_at": human["created_at"],
            "human_merged_at": human["merged_at"],
            "human_size": human["size"],
            "human_added_lines": human["added"],
            "human_deleted_lines": human["deleted"],
            "human_n_logs": human["n_logs"],
            "human_n_logs_all_files": human["n_logs_all_files"],
            "human_diff_sha256": human_sha,
            "human_diff_path": str(human_path),
            "date_distance_days": round(days, 3),
            "size_ratio": round(final_ratio, 6),
            "size_log_distance": round(size_log_distance, 6),
            "match_score": round(size_log_distance + days / 365, 6),
            "exact_repo": True,
            "exact_task_type": True,
            "exact_language": True,
            "diff_snapshot_status": "github_raw_final_diff_response_saved_both_sides",
            "diff_completeness_verification": "not_compared_to_GitHub_changed_files",
            "agent_provenance_tier": "aidev_agent_labeled_pr",
            "human_provenance_tier": "aidev_human_sampled",
            "analysis_eligibility": "aidev_observational_primary",
            "size_metric": "both_final_diffs_production_source_added_plus_deleted",
            "outcome_conditioned_on_logging": False,
        }
        pairs.append(pair)
        queue.extend((_queue_row(pair, "agent"), _queue_row(pair, "human")))
        manifest.extend((
            _manifest_row(pair, "agent", agent_profile),
            _manifest_row(pair, "human", human_profile),
        ))
        _append_logs(log_rows, pair, "agent", agent_profile)
        _append_logs(log_rows, pair, "human", human_profile)
        evidence.append({
            **pair,
            "agent_selection_basis": "merged AIDev Agent PR; no logging outcome filter",
            "matching_basis": "same repository, task type, language; time and final-diff size calipers",
            "aidev_agent_metadata": agent,
            "aidev_human_metadata": candidate,
        })
        print(f"[matched {len(pairs)}/{args.count}] {pair['agent_pr_key']} ↔ {pair['human_pr_key']}", flush=True)

    if len(pairs) != args.count:
        raise RuntimeError(f"only matched {len(pairs)} of {args.count} requested pairs")

    _write_csv(args.output_dir / "matched_pairs.csv", pairs, PAIR_FIELDS)
    _write_csv(args.output_dir / "pr_analysis_queue.csv", queue, QUEUE_FIELDS)
    _write_csv(args.output_dir / "log_candidates.csv", log_rows, LOG_FIELDS)
    _write_csv(args.output_dir / "diff_manifest.csv", manifest, MANIFEST_FIELDS)
    selected_agent_ids = {int(row["agent_pr_id"]) for row in pairs}
    selected_human_ids = {int(row["human_pr_id"]) for row in pairs}
    agent_pool = [{
        "pr_id": row["id"],
        "pr_key": f"{row['repo']}#{row['number']}",
        "pr_url": row["html_url"],
        "repo": row["repo"],
        "language": row["language"],
        "task_type": row["task_type"],
        "agent_product": row["agent"],
        "created_at": row["created_at"],
        "merged_at": row["merged_at"],
        "commit_count": row["commit_count"],
        "proxy_size": row["size"],
        "proxy_added_lines": row["added"],
        "proxy_deleted_lines": row["deleted"],
        "selected": int(row["id"]) in selected_agent_ids,
    } for row in agents]
    human_pool = [{
        "pr_id": row["id"],
        "pr_key": f"{row['repo']}#{row['number']}",
        "pr_url": row["html_url"],
        "repo": row["repo"],
        "language": row["language"],
        "task_type": row["task_type"],
        "human_actor": row["user"],
        "created_at": row["created_at"],
        "merged_at": row["merged_at"],
        "nearest_agent_days": round(float(row["nearest_agent_days"]), 6),
        "selected": int(row["id"]) in selected_human_ids,
    } for row in humans]
    _write_csv(args.output_dir / "eligible_agent_pool.csv", agent_pool, AGENT_POOL_FIELDS)
    _write_csv(args.output_dir / "eligible_human_pool.csv", human_pool, HUMAN_POOL_FIELDS)
    _atomic_write_text(
        args.output_dir / "pair_evidence.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in evidence),
    )
    dates = [float(row["date_distance_days"]) for row in pairs]
    ratios = [float(row["size_ratio"]) for row in pairs]
    validation = validate_materialized(
        pairs, queue, manifest, log_rows, args.count, args.max_date_days, args.max_size_ratio
    )
    _atomic_write_text(
        args.output_dir / "validation.json",
        json.dumps(validation, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    if validation["status"] != "PASS":
        raise RuntimeError("materialized queue validation failed: " + "; ".join(validation["errors"]))
    summary = {
        "cohort": "aidev_observational_primary",
        "n_pairs": len(pairs),
        "n_prs_in_analysis_queue": len(queue),
        "n_diffs_frozen": len(manifest),
        "n_repositories": len({row["repo"] for row in pairs}),
        "n_eligible_agent_pool": len(agent_pool),
        "n_eligible_human_pool": len(human_pool),
        "n_exact_repo": sum(row["exact_repo"] for row in pairs),
        "n_exact_task_type": sum(row["exact_task_type"] for row in pairs),
        "n_exact_language": sum(row["exact_language"] for row in pairs),
        "median_date_distance_days": round(statistics.median(dates), 3),
        "max_date_distance_days": round(max(dates), 3),
        "median_final_diff_size_ratio": round(statistics.median(ratios), 6),
        "max_final_diff_size_ratio": round(max(ratios), 6),
        "agent_prs_with_added_production_logs": sum(row["agent_n_logs"] > 0 for row in pairs),
        "human_prs_with_added_production_logs": sum(row["human_n_logs"] > 0 for row in pairs),
        "agent_added_production_logs": sum(row["agent_n_logs"] for row in pairs),
        "human_added_production_logs": sum(row["human_n_logs"] for row in pairs),
        "zero_log_agent_prs_retained": sum(row["agent_n_logs"] == 0 for row in pairs),
        "zero_log_human_prs_retained": sum(row["human_n_logs"] == 0 for row in pairs),
        "outcome_conditioned_on_logging": False,
        "by_task_type": dict(sorted(Counter(row["task_type"] for row in pairs).items())),
        "by_language": dict(sorted(Counter(row["language"] for row in pairs).items())),
        "by_agent_product": dict(sorted(Counter(row["agent_product"] for row in pairs).items())),
        "fetch_and_caliper_skips": dict(sorted(fetch_failures.items())),
        "input_audit": input_audit,
        "validation_status": validation["status"],
        "provenance_boundary": (
            "This is the AIDev observational primary cohort, not session-to-PR A/B line-authorship proof. "
            "AIDev's Human label cannot prove that hidden AI assistance was absent."
        ),
        "diff_boundary": (
            "Both raw final .diff responses and SHA-256 hashes are saved. Completeness was not independently "
            "compared with GitHub changed_files because authenticated PR metadata was unavailable."
        ),
    }
    _atomic_write_text(
        args.output_dir / "summary.json",
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    report_path = args.output_dir / "report.md"
    _atomic_write_text(
        report_path,
        "# AIDev 观察性主分析队列\n\n"
        f"- 配对：{summary['n_pairs']}；分析队列 PR：{summary['n_prs_in_analysis_queue']}；仓库：{summary['n_repositories']}\n"
        f"- 固化 diff：{summary['n_diffs_frozen']}（Agent/Human 各 {summary['n_pairs']}）\n"
        f"- 同仓库/同任务类型/同语言：{summary['n_exact_repo']}/{summary['n_exact_task_type']}/{summary['n_exact_language']}\n"
        f"- 时间距离中位数/最大值：{summary['median_date_distance_days']}/{summary['max_date_distance_days']} 天\n"
        f"- 最终 diff 修改规模比中位数/最大值：{summary['median_final_diff_size_ratio']}/{summary['max_final_diff_size_ratio']}\n"
        f"- Agent/Human 含生产日志的 PR：{summary['agent_prs_with_added_production_logs']}/{summary['human_prs_with_added_production_logs']}\n"
        f"- 保留的 Agent/Human 零日志 PR：{summary['zero_log_agent_prs_retained']}/{summary['zero_log_human_prs_retained']}\n\n"
        "## 为什么这是主队列\n\n"
        "Agent PR 从 AIDev 已合并 PR 中选取，选样时不查看是否新增日志；Agent 和 Human 都用 GitHub 最终 diff 重算生产代码修改规模和日志结果，并保留零日志 PR。\n\n"
        "## 证据边界\n\n"
        "这是 AIDev 标签支持的观察性主分析队列，不是会话→PR 的 A/B 行级作者证明。Human 标签不能排除未披露的 AI 辅助。"
        "已固化双方 `.diff` 原文和 SHA-256，但未与 GitHub `changed_files` 独立比对超大 diff 的完整性。\n",
    )
    source_names = (
        "pull_request.parquet", "human_pull_request.parquet", "pr_task_type.parquet",
        "human_pr_task_type.parquet", "repository.parquet", "pr_commit_details.parquet",
    )
    artifact_names = (
        "matched_pairs.csv", "pr_analysis_queue.csv", "log_candidates.csv",
        "diff_manifest.csv", "eligible_agent_pool.csv", "eligible_human_pool.csv",
        "pair_evidence.jsonl", "summary.json", "validation.json", "report.md",
    )
    run_manifest = {
        "cohort": "aidev_observational_primary",
        "hash_algorithm": "SHA-256",
        "parameters": {
            "count": args.count,
            "max_date_days": args.max_date_days,
            "max_size_ratio": args.max_size_ratio,
            "agent_candidate_limit": args.agent_candidate_limit,
            "offline_replay": bool(args.offline),
        },
        "selection": (
            "round-robin across repositories; exact repository/task/language; greedy nearest "
            "date and proxy-size candidate; final date and symmetric final-diff size calipers; "
            "no logging outcome read or filter"
        ),
        "source_data_sha256": {
            name: _file_sha256(args.aidev_dir / name) for name in source_names
        },
        "script_sha256": {
            Path(__file__).name: _file_sha256(Path(__file__)),
            "match_aidev_human_prs.py": _file_sha256(Path(__file__).with_name("match_aidev_human_prs.py")),
        },
        "artifact_sha256": {
            name: _file_sha256(args.output_dir / name) for name in artifact_names
        },
        "validation_status": validation["status"],
    }
    _atomic_write_text(
        args.output_dir / "run_manifest.json",
        json.dumps(run_manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aidev-dir", type=Path, default=Path("data/repos/AIDev"))
    parser.add_argument(
        "--agent-log-corpus", type=Path,
        default=Path("outputs/multisource_agent_log_corpus/log_rows.csv"),
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("outputs/aidev_observational_primary_300")
    )
    parser.add_argument(
        "--cache-dir", type=Path, default=Path("data/res/aidev_observational_primary_diffs")
    )
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--max-date-days", type=float, default=180)
    parser.add_argument("--max-size-ratio", type=float, default=10)
    parser.add_argument("--agent-candidate-limit", type=int, default=8)
    parser.add_argument("--diff-delay", type=float, default=1)
    parser.add_argument("--retry-wait", type=float, default=65)
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    return parser


if __name__ == "__main__":
    print(json.dumps(run(build_parser().parse_args()), ensure_ascii=False, sort_keys=True))
