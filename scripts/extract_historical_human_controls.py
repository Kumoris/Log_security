#!/usr/bin/env python3
"""Extract reproducible pre-cutoff human PR controls and their added logs."""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from datetime import date, timedelta
from pathlib import Path

if __package__:
    from .mine_github_log_lineage import _iso, _search_humans, diff_profile
    from .screen_github_agent_logs import GitHubClient, _atomic_write_text, sha256_text
else:
    from mine_github_log_lineage import _iso, _search_humans, diff_profile
    from screen_github_agent_logs import GitHubClient, _atomic_write_text, sha256_text


PR_FIELDS = (
    "dataset", "provenance", "provenance_evidence", "analysis_eligibility",
    "temporal_stratum", "repo_source", "repo", "pr_number", "pr_key", "pr_url",
    "diff_url", "created_at", "merged_at", "actor_login", "actor_type",
    "title", "search_window", "full_diff_sha256", "diff_cache_path", "added_lines",
    "deleted_lines", "production_source_files", "extensions", "n_added_logs",
    "n_production_added_logs", "n_static_risk_candidates",
)
LOG_FIELDS = (
    "dataset", "provenance", "analysis_eligibility", "temporal_stratum", "repo",
    "pr_key", "pr_url", "merged_at", "file", "line", "path_scope", "risk_features",
    "log_concepts", "static_risk_candidate", "log_text_redacted", "full_diff_sha256",
)


def select_candidates(rows: list[dict], cutoff: date, per_repo: int) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        merged_at = row.get("merged_at")
        if merged_at and _iso(merged_at).date() < cutoff:
            grouped[row["repo"]].append(row)
    return [
        row
        for repo in sorted(grouped)
        for row in sorted(grouped[repo], key=lambda item: item["created_at"], reverse=True)[:per_repo]
    ]


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run(args: argparse.Namespace) -> dict:
    repos = [value.strip() for value in args.repos.split(",") if value.strip()]
    if not repos:
        raise ValueError("--repos must contain at least one owner/repo")
    start = date.fromisoformat(args.start)
    cutoff = date.fromisoformat(args.cutoff)
    if start >= cutoff:
        raise ValueError("--start must be earlier than --cutoff")
    end = cutoff - timedelta(days=1)

    client = GitHubClient("https://api.github.com", args.token, args.cache_dir, args.offline, args.refresh)
    anchors = [{"repo": repo, "pr_key": f"{repo}#historical-anchor"} for repo in repos]
    candidates = select_candidates(
        _search_humans(anchors, client, start, end, args.search_delay), cutoff, args.per_repo
    )

    pr_rows, log_rows = [], []
    diff_client = GitHubClient(
        "https://api.github.com", args.token, args.cache_dir / "diffs",
        args.offline, args.refresh, diff_delay=args.diff_delay,
    )
    for index, row in enumerate(candidates, 1):
        try:
            diff, _ = diff_client.get_text(row["diff_url"])
        except RuntimeError as exc:
            print(f"[diff {index}/{len(candidates)}] {row['pr_key']}: {exc}", flush=True)
            continue
        profile = diff_profile(diff)
        digest = sha256_text(diff)
        logs = profile["logs"]
        pr_row = {
            **row,
            "dataset": "GitHub-historical-control",
            "provenance": "human_pre_agent_era",
            "provenance_evidence": "merged_before_cutoff+GitHub_User+no_GitHub_App",
            "analysis_eligibility": "historical_sensitivity_only",
            "temporal_stratum": f"{start.isoformat()}..{end.isoformat()}",
            "repo_source": args.repo_source,
            "full_diff_sha256": digest,
            "diff_cache_path": str(diff_client._cache_path(row["diff_url"])),
            "added_lines": profile["added_lines"],
            "deleted_lines": profile["deleted_lines"],
            "production_source_files": profile["production_source_files"],
            "extensions": ";".join(profile["extensions"]),
            "n_added_logs": len(logs),
            "n_production_added_logs": sum(item["path_scope"] == "production" for item in logs),
            "n_static_risk_candidates": sum(item["static_risk_candidate"] for item in logs),
        }
        pr_rows.append(pr_row)
        for log in logs:
            log_rows.append({
                "dataset": pr_row["dataset"],
                "provenance": pr_row["provenance"],
                "analysis_eligibility": pr_row["analysis_eligibility"],
                "temporal_stratum": pr_row["temporal_stratum"],
                "repo": row["repo"],
                "pr_key": row["pr_key"],
                "pr_url": row["pr_url"],
                "merged_at": row["merged_at"],
                **{name: ";".join(log[name]) if isinstance(log[name], list) else log[name]
                   for name in ("file", "line", "path_scope", "risk_features", "log_concepts",
                                "static_risk_candidate", "log_text_redacted")},
                "full_diff_sha256": digest,
            })
        print(f"[diff {index}/{len(candidates)}] {row['pr_key']}: {len(logs)} logs", flush=True)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(
        args.output_dir / "historical_human_prs.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in pr_rows),
    )
    write_csv(args.output_dir / "historical_human_logs.csv", log_rows, LOG_FIELDS)
    counts = Counter(row["repo"] for row in pr_rows)
    summary = {
        "cutoff_exclusive": cutoff.isoformat(),
        "n_requested_repositories": len(repos),
        "n_repositories_with_controls": len(counts),
        "n_prs": len(pr_rows),
        "n_prs_with_added_logs": sum(row["n_added_logs"] > 0 for row in pr_rows),
        "n_added_logs": len(log_rows),
        "n_production_added_logs": sum(row["path_scope"] == "production" for row in log_rows),
        "n_static_risk_candidates": sum(bool(row["static_risk_candidate"]) for row in log_rows),
        "prs_by_repository": dict(sorted(counts.items())),
        "evidence_boundary": (
            "Historical negative control only: the cutoff strongly reduces modern coding-agent contamination "
            "but does not prove unaided human authorship and introduces temporal confounding."
        ),
    }
    _atomic_write_text(
        args.output_dir / "summary.json",
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    report = f"""# 2020 年前 Human PR 历史对照 PoC

- 截止日期（不含）：`{cutoff.isoformat()}`
- AIDev 同仓库候选集：{len(repos)} 个仓库
- 成功保存：{len(pr_rows)} 个 PR，覆盖 {len(counts)} 个仓库
- 含新增日志的 PR：{summary['n_prs_with_added_logs']} 个
- 新增日志语句：{len(log_rows)} 条，其中生产代码 {summary['n_production_added_logs']} 条
- 静态敏感风险候选：{summary['n_static_risk_candidates']} 条

## 证据边界

这些 PR 满足“在 2020 年前合并、GitHub actor 类型为 User、没有 GitHub App 执行标记”，因此适合作为 `human_pre_agent_era` 历史负对照。它们不能证明作者完全没有使用早期代码补全工具；同时，与 2025–2026 年 Agent PR 比较会受到语言版本、日志框架和项目成熟度变化的影响，所以只进入敏感性分析，不与同期 Human 对照混为一组。
"""
    _atomic_write_text(args.output_dir / "report.md", report)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repos", required=True, help="comma-separated owner/repo values")
    parser.add_argument("--start", default="2019-01-01")
    parser.add_argument("--cutoff", default="2020-01-01")
    parser.add_argument("--per-repo", type=int, default=10)
    parser.add_argument("--repo-source", default="AIDev_repository_overlap")
    parser.add_argument("--cache-dir", type=Path, default=Path("data/res/historical_human_controls"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/historical_human_controls_poc"))
    parser.add_argument("--search-delay", type=float, default=6.2)
    parser.add_argument("--diff-delay", type=float, default=0.15)
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    print(json.dumps(run(args), ensure_ascii=False, sort_keys=True))
