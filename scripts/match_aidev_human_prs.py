#!/usr/bin/env python3
"""Match 100 AIDev Human PRs to log-bearing AIDev Agent PRs and save raw diffs."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

import pyarrow.parquet as pq

if __package__:
    from .mine_github_log_lineage import _iso, diff_profile
    from .screen_github_agent_logs import (
        GitHubClient, _atomic_write_text, is_production_path, is_source_file, sha256_text,
    )
else:
    from mine_github_log_lineage import _iso, diff_profile
    from screen_github_agent_logs import (
        GitHubClient, _atomic_write_text, is_production_path, is_source_file, sha256_text,
    )


PAIR_FIELDS = (
    "pair_id", "repo", "language", "task_type", "agent_pr_id", "agent_pr_key",
    "agent_pr_url", "agent_product", "agent_created_at", "agent_merged_at",
    "agent_commit_count", "agent_size", "agent_added_lines", "agent_deleted_lines", "agent_n_logs",
    "human_pr_id", "human_pr_key", "human_pr_url", "human_actor", "human_created_at",
    "human_merged_at", "human_size", "human_added_lines", "human_deleted_lines",
    "human_n_logs", "date_distance_days", "size_ratio", "size_log_distance",
    "match_score", "exact_repo", "exact_task_type", "exact_language",
    "human_diff_sha256", "human_diff_path", "human_diff_snapshot_status",
    "human_diff_completeness_verification", "human_provenance_tier",
    "analysis_eligibility", "size_metric",
)
LOG_FIELDS = (
    "dataset", "provenance", "repo", "pr_key", "pr_url", "task_type", "language",
    "file", "line", "path_scope", "risk_features", "log_concepts",
    "static_risk_candidate", "log_text_redacted", "diff_sha256",
)
AI_ASSISTANCE_RE = re.compile(
    r"generated\s+with\s+\[?(?:claude(?:\s+code)?|openai\s+codex|codex|devin|github\s+copilot)"
    r"|co-authored-by:\s*(?:claude|openai|codex|devin|github\s+copilot)|devin-ai-integration",
    re.IGNORECASE,
)


def _repo(url: str) -> str:
    return str(url or "").removeprefix("https://api.github.com/repos/")


def _days(left: str, right: str) -> float:
    return abs((_iso(left) - _iso(right)).total_seconds()) / 86400


def best_match(human: dict, agents: list[dict], used: set[int], max_days: float,
               max_size_ratio: float) -> tuple[dict, dict] | None:
    choices = []
    for agent in agents:
        if agent["id"] in used:
            continue
        days = _days(human["created_at"], agent["created_at"])
        ratio = (max(human["size"], agent["size"]) + 1) / (min(human["size"], agent["size"]) + 1)
        if days > max_days or ratio > max_size_ratio:
            continue
        size_distance = abs(math.log1p(human["size"]) - math.log1p(agent["size"]))
        choices.append((size_distance + days / 365, days, ratio, agent["id"], agent))
    if not choices:
        return None
    score, days, ratio, _, agent = min(choices)
    return agent, {
        "date_distance_days": round(days, 3),
        "size_ratio": round(ratio, 6),
        "size_log_distance": round(abs(math.log1p(human["size"]) - math.log1p(agent["size"])), 6),
        "match_score": round(score, 6),
    }


def _round_robin(rows: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[row["repo"]].append(row)
    for values in grouped.values():
        values.sort(key=lambda row: (row["nearest_agent_days"], row["id"]))
    output = []
    for index in range(max(map(len, grouped.values()), default=0)):
        layer = [values[index] for values in grouped.values() if index < len(values)]
        output.extend(sorted(layer, key=lambda row: (row["nearest_agent_days"], row["repo"], row["id"])))
    return output


def _load_agent_log_counts(path: Path) -> Counter:
    csv.field_size_limit(sys.maxsize)
    counts = Counter()
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["dataset"] == "AIDev" and row["scope"] == "production":
                counts[int(row["source_id"].split(":")[-1])] += 1
    return counts


def human_exclusion_reason(row: dict, agent_urls: set[str]) -> str:
    if row.get("html_url") in agent_urls:
        return "canonical_pr_also_in_agent_table"
    if str(row.get("user") or "").lower().endswith("[bot]"):
        return "bot_login"
    if AI_ASSISTANCE_RE.search(f"{row.get('title') or ''}\n{row.get('body') or ''}"):
        return "explicit_ai_assistance_marker"
    return ""


def load_data(
    aidev: Path, corpus: Path, require_agent_logs: bool = True
) -> tuple[list[dict], list[dict], dict]:
    log_counts = _load_agent_log_counts(corpus) if require_agent_logs else Counter()
    agent_metadata = pq.read_table(aidev / "pull_request.parquet").to_pylist()
    selected_agent_ids = set(log_counts) if require_agent_logs else {
        int(row["id"]) for row in agent_metadata
    }
    tasks = {
        int(row["id"]): str(row["type"])
        for row in pq.read_table(aidev / "pr_task_type.parquet", columns=["id", "type"]).to_pylist()
    }
    human_tasks = {
        int(row["id"]): str(row["type"])
        for row in pq.read_table(aidev / "human_pr_task_type.parquet", columns=["id", "type"]).to_pylist()
    }
    repositories = {
        str(row["url"]): {"repo": str(row["full_name"]), "language": str(row["language"] or "")}
        for row in pq.read_table(aidev / "repository.parquet", columns=["url", "full_name", "language"]).to_pylist()
    }

    patch_profiles: dict[int, dict] = defaultdict(
        lambda: {"shas": set(), "added": 0, "deleted": 0, "files": set(), "extensions": set()}
    )
    patch_file = pq.ParquetFile(aidev / "pr_commit_details.parquet")
    for batch in patch_file.iter_batches(
        columns=["pr_id", "sha", "filename", "additions", "deletions"], batch_size=100_000
    ):
        data = batch.to_pydict()
        for pr_id, sha, filename, additions, deletions in zip(
            data["pr_id"], data["sha"], data["filename"], data["additions"], data["deletions"]
        ):
            pr_id = int(pr_id)
            if pr_id not in selected_agent_ids:
                continue
            profile = patch_profiles[pr_id]
            profile["shas"].add(str(sha or ""))
            path = str(filename or "")
            if is_source_file(path) and is_production_path(path):
                profile["added"] += int(additions or 0)
                profile["deleted"] += int(deletions or 0)
                profile["files"].add(path)
                suffix = PurePosixPath(path.lower()).suffix
                if suffix:
                    profile["extensions"].add(suffix)

    agent_urls = {str(row["html_url"]) for row in agent_metadata}
    agents = []
    for row in agent_metadata:
        pr_id = int(row["id"])
        profile = patch_profiles.get(pr_id)
        repository = repositories.get(str(row["repo_url"]))
        if not (row["merged_at"] and tasks.get(pr_id) and repository and profile and profile["shas"]):
            continue
        agents.append({
            **row,
            **repository,
            "task_type": tasks[pr_id],
            "commit_count": len(profile["shas"]),
            "size": profile["added"] + profile["deleted"],
            "added": profile["added"],
            "deleted": profile["deleted"],
            "n_logs": log_counts.get(pr_id, 0),
        })

    agents_by_stratum: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in agents:
        agents_by_stratum[(row["repo"], row["task_type"])].append(row)

    humans = []
    exclusions = Counter()
    human_metadata = pq.read_table(aidev / "human_pull_request.parquet").to_pylist()
    for row in human_metadata:
        pr_id = int(row["id"])
        repository = repositories.get(str(row["repo_url"]))
        task = human_tasks.get(pr_id)
        candidates = agents_by_stratum.get(((repository or {}).get("repo", ""), task or ""), [])
        if not row["merged_at"]:
            exclusions["not_merged"] += 1
            continue
        reason = human_exclusion_reason(row, agent_urls)
        if reason:
            exclusions[reason] += 1
            continue
        if not (repository and task and candidates):
            exclusions["no_exact_agent_stratum"] += 1
            continue
        humans.append({
            **row,
            **repository,
            "task_type": task,
            "repo": repository["repo"],
            "nearest_agent_days": min(_days(row["created_at"], agent["created_at"]) for agent in candidates),
        })
    return agents, _round_robin(humans), {
        "agent_selection_requires_added_production_log": require_agent_logs,
        "agent_rows_eligible": len(agents),
        "human_rows_total": len(human_metadata),
        "human_rows_eligible": len(humans),
        "excluded": dict(sorted(exclusions.items())),
    }


def _fetch_diff(client: GitHubClient, url: str, retry_wait: float) -> str:
    for attempt in range(3):
        try:
            return client.get_text(url + ".diff")[0]
        except RuntimeError as exc:
            if "HTTP 429" not in str(exc) or attempt == 2:
                raise
            print(f"[rate limit] waiting {retry_wait:.0f}s", flush=True)
            time.sleep(retry_wait)
    raise AssertionError("unreachable")


def _write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run(args: argparse.Namespace) -> dict:
    agents, humans, input_audit = load_data(args.aidev_dir, args.agent_log_corpus)
    agents_by_stratum: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in agents:
        agents_by_stratum[(row["repo"], row["task_type"])].append(row)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    diff_dir = args.output_dir / "diffs"
    diff_dir.mkdir(exist_ok=True)
    client = GitHubClient(
        "https://api.github.com", args.token, args.cache_dir, args.offline, args.refresh,
        diff_delay=args.diff_delay,
    )
    pairs, evidence, log_rows = [], [], []
    used_agents: set[int] = set()
    for candidate in humans:
        if len(pairs) >= args.count:
            break
        if not any(row["id"] not in used_agents for row in agents_by_stratum[(candidate["repo"], candidate["task_type"])]):
            continue
        try:
            diff = _fetch_diff(client, candidate["html_url"], args.retry_wait)
        except RuntimeError as exc:
            print(f"[skip] {candidate['html_url']}: {exc}", flush=True)
            continue
        human_profile = diff_profile(diff)
        human = {
            **candidate,
            "size": human_profile["added_lines"] + human_profile["deleted_lines"],
            "added": human_profile["added_lines"],
            "deleted": human_profile["deleted_lines"],
            "n_logs": len(human_profile["logs"]),
        }
        selected = best_match(
            human, agents_by_stratum[(human["repo"], human["task_type"])], used_agents,
            args.max_date_days, args.max_size_ratio,
        )
        if not selected:
            continue
        agent, metrics = selected
        used_agents.add(int(agent["id"]))
        digest = sha256_text(diff)
        diff_path = diff_dir / f"{human['repo'].replace('/', '__')}__pull_{human['number']}.diff"
        _atomic_write_text(diff_path, diff)
        pair_id = sha256_text(f"{agent['id']}|{human['id']}")[:16]
        pair = {
            "pair_id": pair_id,
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
            "agent_size": agent["size"],
            "agent_added_lines": agent["added"],
            "agent_deleted_lines": agent["deleted"],
            "agent_n_logs": agent["n_logs"],
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
            **metrics,
            "exact_repo": True,
            "exact_task_type": True,
            "exact_language": True,
            "human_diff_sha256": digest,
            "human_diff_path": str(diff_path),
            "human_diff_snapshot_status": "github_raw_diff_response_saved",
            "human_diff_completeness_verification": "not_compared_to_GitHub_changed_files",
            "human_provenance_tier": "aidev_human_sampled",
            "analysis_eligibility": "contemporary_sensitivity_only",
            "size_metric": "production_source_added_plus_deleted; agent_cumulative_commit_files",
        }
        pairs.append(pair)
        evidence.append({**pair, "aidev_human_metadata": candidate})
        for log in human_profile["logs"]:
            log_rows.append({
                "dataset": "AIDev-Human-diff",
                "provenance": "human",
                "repo": human["repo"],
                "pr_key": pair["human_pr_key"],
                "pr_url": human["html_url"],
                "task_type": human["task_type"],
                "language": human["language"],
                **{name: ";".join(log[name]) if isinstance(log[name], list) else log[name]
                   for name in ("file", "line", "path_scope", "risk_features", "log_concepts",
                                "static_risk_candidate", "log_text_redacted")},
                "diff_sha256": digest,
            })
        print(f"[matched {len(pairs)}/{args.count}] {pair['agent_pr_key']} ↔ {pair['human_pr_key']}", flush=True)

    if len(pairs) != args.count:
        raise RuntimeError(f"only matched {len(pairs)} of {args.count} requested pairs")

    _write_csv(args.output_dir / "matched_pairs.csv", pairs, PAIR_FIELDS)
    _write_csv(args.output_dir / "human_log_candidates.csv", log_rows, LOG_FIELDS)
    _atomic_write_text(
        args.output_dir / "human_pr_evidence.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in evidence),
    )
    dates = [float(row["date_distance_days"]) for row in pairs]
    ratios = [float(row["size_ratio"]) for row in pairs]
    summary = {
        "n_pairs": len(pairs),
        "n_repositories": len({row["repo"] for row in pairs}),
        "n_exact_repo": sum(row["exact_repo"] for row in pairs),
        "n_exact_task_type": sum(row["exact_task_type"] for row in pairs),
        "n_exact_language": sum(row["exact_language"] for row in pairs),
        "median_date_distance_days": round(statistics.median(dates), 3),
        "max_date_distance_days": round(max(dates), 3),
        "median_size_ratio": round(statistics.median(ratios), 6),
        "max_size_ratio": round(max(ratios), 6),
        "human_prs_with_added_logs": sum(int(row["human_n_logs"]) > 0 for row in pairs),
        "human_added_logs": len(log_rows),
        "by_task_type": dict(sorted(Counter(row["task_type"] for row in pairs).items())),
        "by_language": dict(sorted(Counter(row["language"] for row in pairs).items())),
        "by_agent_product": dict(sorted(Counter(row["agent_product"] for row in pairs).items())),
        "input_audit": input_audit,
        "provenance_boundary": (
            "AIDev Human label plus public PR diff is a sampled human control, not proof that AI assistance was absent."
        ),
        "diff_boundary": (
            "Raw .diff responses and SHA-256 hashes are saved; completeness is not independently verified "
            "against GitHub changed_files because authenticated PR metadata is unavailable."
        ),
    }
    _atomic_write_text(
        args.output_dir / "summary.json",
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    _atomic_write_text(
        args.output_dir / "report.md",
        "# AIDev Agent–Human 100 对 PR 匹配\n\n"
        f"- 配对：{len(pairs)}；仓库：{summary['n_repositories']}\n"
        f"- 同仓库/同任务类型/同语言：{summary['n_exact_repo']}/{summary['n_exact_task_type']}/{summary['n_exact_language']}\n"
        f"- 时间距离中位数/最大值：{summary['median_date_distance_days']}/{summary['max_date_distance_days']} 天\n"
        f"- 修改规模比中位数/最大值：{summary['median_size_ratio']}/{summary['max_size_ratio']}\n"
        f"- Human PR 含新增日志：{summary['human_prs_with_added_logs']}；新增日志行：{len(log_rows)}\n\n"
        f"- 排除 Agent/Human 表 canonical PR 冲突：{input_audit['excluded'].get('canonical_pr_also_in_agent_table', 0)}\n"
        f"- 排除 bot 登录：{input_audit['excluded'].get('bot_login', 0)}\n"
        f"- 排除显式 AI 协助标记：{input_audit['excluded'].get('explicit_ai_assistance_marker', 0)}\n\n"
        "## 边界\n\n"
        "Agent 侧限定为 AIDev 中已合并且含生产代码新增日志的 PR；其规模来自各 commit 文件修改量累计，Human 规模来自最终 diff，"
        "因此规模匹配是近似控制而非完全同口径。Human 侧的 AIDev 标签不能证明完全没有 AI 辅助。已保存 GitHub `.diff` 原文和 SHA-256，"
        "但未用 `changed_files` 独立核验 GitHub 是否因平台限制省略超大 diff。\n",
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aidev-dir", type=Path, default=Path("data/repos/AIDev"))
    parser.add_argument("--agent-log-corpus", type=Path, default=Path("outputs/multisource_agent_log_corpus/log_rows.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/aidev_agent_human_100"))
    parser.add_argument("--cache-dir", type=Path, default=Path("data/res/aidev_human_diffs"))
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--max-date-days", type=float, default=180)
    parser.add_argument("--max-size-ratio", type=float, default=10)
    parser.add_argument("--diff-delay", type=float, default=1)
    parser.add_argument("--retry-wait", type=float, default=65)
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    return parser


if __name__ == "__main__":
    print(json.dumps(run(build_parser().parse_args()), ensure_ascii=False, sort_keys=True))
