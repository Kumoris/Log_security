#!/usr/bin/env python3
"""Fetch a deterministic AIDev expansion pilot and freeze both final diffs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import time
from collections import Counter
from pathlib import Path

if __package__:
    from .mine_github_log_lineage import diff_profile
    from .screen_github_agent_logs import GitHubClient, _atomic_write_text, sha256_text
else:
    from mine_github_log_lineage import diff_profile
    from screen_github_agent_logs import GitHubClient, _atomic_write_text, sha256_text


DEFAULT_QUEUE = Path("outputs/privacy_cohort_expansion_capacity_v1/aidev_prefetch_queue.csv")
DEFAULT_OUTPUT = Path("outputs/aidev_expansion_diff_pilot_v1")
DEFAULT_CACHE = Path("data/res/aidev_observational_primary_diffs")
AUDIT_FIELDS = (
    "candidate_id", "repo", "language", "task_type", "agent_pr_key", "agent_pr_url",
    "agent_product", "agent_created_at", "agent_merged_at", "human_pr_key", "human_pr_url",
    "human_actor", "human_created_at", "human_merged_at", "date_distance_days",
    "exact_repo", "exact_task_type", "exact_language", "agent_provenance_tier",
    "human_provenance_tier", "agent_line_authorship_proof", "human_agent_assistance_excluded",
    "agent_size", "human_size", "size_ratio", "agent_added_lines", "agent_deleted_lines",
    "human_added_lines", "human_deleted_lines", "agent_production_source_files",
    "human_production_source_files", "agent_n_logs", "human_n_logs", "agent_diff_sha256",
    "human_diff_sha256", "agent_diff_path", "human_diff_path", "status", "reason",
)


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


def wilson(successes: int, total: int) -> tuple[float, float]:
    if not total:
        return 0.0, 0.0
    z = 1.959963984540054
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return center - margin, center + margin


def reason_category(reason: str) -> str:
    if not reason:
        return "accepted"
    if "HTTP 404" in reason:
        return "fetch_http_404"
    if "HTTP 429" in reason:
        return "fetch_http_429"
    if reason.startswith("GitHub diff") or reason.startswith("offline cache miss"):
        return "fetch_other"
    return reason


def profile_metrics(diff: str) -> dict:
    profile = diff_profile(diff)
    production_logs = [row for row in profile["logs"] if row["path_scope"] == "production"]
    return {
        "size": profile["added_lines"] + profile["deleted_lines"],
        "added_lines": profile["added_lines"],
        "deleted_lines": profile["deleted_lines"],
        "production_source_files": profile["production_source_files"],
        "n_logs": len(production_logs),
    }


def evaluate(agent_diff: str, human_diff: str, max_size_ratio: float) -> tuple[dict, str]:
    agent = profile_metrics(agent_diff)
    human = profile_metrics(human_diff)
    ratio = (max(agent["size"], human["size"]) + 1) / (min(agent["size"], human["size"]) + 1)
    metrics = {
        "agent_size": agent["size"], "human_size": human["size"], "size_ratio": round(ratio, 6),
        "agent_added_lines": agent["added_lines"], "agent_deleted_lines": agent["deleted_lines"],
        "human_added_lines": human["added_lines"], "human_deleted_lines": human["deleted_lines"],
        "agent_production_source_files": agent["production_source_files"],
        "human_production_source_files": human["production_source_files"],
        "agent_n_logs": agent["n_logs"], "human_n_logs": human["n_logs"],
    }
    if sha256_text(agent_diff) == sha256_text(human_diff):
        return metrics, "identical_final_diff"
    if not agent["size"]:
        return metrics, "agent_no_production_source_change"
    if not human["size"]:
        return metrics, "human_no_production_source_change"
    if ratio > max_size_ratio:
        return metrics, "final_size_caliper"
    return metrics, ""


def safe_name(pr_key: str) -> str:
    repo, number = pr_key.rsplit("#", 1)
    return f"{repo.replace('/', '__')}__pull_{number}.diff"


def fetch_diff(client: GitHubClient, url: str, retry_attempts: int, retry_wait: float) -> str:
    for attempt in range(retry_attempts):
        try:
            return client.get_text(url + ".diff")[0]
        except RuntimeError as exc:
            if "HTTP 429" not in str(exc) or attempt + 1 == retry_attempts:
                raise
            time.sleep(retry_wait)
    raise AssertionError("unreachable")


def run(args: argparse.Namespace) -> dict:
    candidates = sorted(read_csv(args.queue), key=lambda row: row["candidate_id"])
    selected = candidates[args.offset:args.offset + args.limit]
    if len(selected) != args.limit:
        raise ValueError(f"requested {args.limit} rows at offset {args.offset}, found {len(selected)}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.summarize_existing:
        audit = read_csv(args.output_dir / "candidate_audit.csv")
        if len(audit) != args.limit:
            raise ValueError("existing audit row count does not match --limit")
        selected_by_id = {row["candidate_id"]: row for row in selected}
        for row in audit:
            source = selected_by_id.get(row["candidate_id"], {})
            for name in (
                "agent_created_at", "agent_merged_at", "human_created_at", "human_merged_at",
                "exact_repo", "exact_task_type", "exact_language",
            ):
                row[name] = row.get(name) or source.get(name, "")
            row["agent_provenance_tier"] = "aidev_agent_labeled_pr"
            row["human_provenance_tier"] = "aidev_human_sampled"
            row["agent_line_authorship_proof"] = False
            row["human_agent_assistance_excluded"] = False
    else:
        client = GitHubClient(
            "https://api.github.com", args.token, args.cache_dir, args.offline, False,
            diff_delay=args.diff_delay,
        )
        audit = []
        for index, row in enumerate(selected, 1):
            base = {name: row.get(name, "") for name in AUDIT_FIELDS}
            base.update({
                "agent_provenance_tier": "aidev_agent_labeled_pr",
                "human_provenance_tier": "aidev_human_sampled",
                "agent_line_authorship_proof": False,
                "human_agent_assistance_excluded": False,
            })
            try:
                agent_diff = fetch_diff(client, row["agent_pr_url"], args.retry_attempts, args.retry_wait)
                human_diff = fetch_diff(client, row["human_pr_url"], args.retry_attempts, args.retry_wait)
            except RuntimeError as exc:
                audit.append({**base, "status": "FETCH_FAILED", "reason": str(exc)[:300]})
                print(f"[{index}/{len(selected)}] fetch failed {row['candidate_id']}", flush=True)
                continue
            agent_path = args.output_dir / "diffs" / "agent" / safe_name(row["agent_pr_key"])
            human_path = args.output_dir / "diffs" / "human" / safe_name(row["human_pr_key"])
            _atomic_write_text(agent_path, agent_diff)
            _atomic_write_text(human_path, human_diff)
            metrics, reason = evaluate(agent_diff, human_diff, args.max_size_ratio)
            audit.append({
                **base, **metrics,
                "agent_diff_sha256": sha256_text(agent_diff),
                "human_diff_sha256": sha256_text(human_diff),
                "agent_diff_path": str(agent_path.resolve()),
                "human_diff_path": str(human_path.resolve()),
                "status": "ACCEPTED" if not reason else "REJECTED",
                "reason": reason,
            })
            print(f"[{index}/{len(selected)}] {'accepted' if not reason else reason} {row['candidate_id']}", flush=True)

    write_csv(args.output_dir / "candidate_audit.csv", audit, AUDIT_FIELDS)
    accepted = [row for row in audit if row["status"] == "ACCEPTED"]
    write_csv(args.output_dir / "accepted_pairs.csv", accepted, AUDIT_FIELDS)
    reasons = Counter(reason_category(row["reason"]) for row in audit)
    fetched = [row for row in audit if row["status"] != "FETCH_FAILED"]
    ci_low, ci_high = wilson(len(accepted), len(fetched))
    agent_log_prs = sum(int(row["agent_n_logs"]) > 0 for row in accepted)
    human_log_prs = sum(int(row["human_n_logs"]) > 0 for row in accepted)
    validation_errors = []
    for row in fetched:
        for side in ("agent", "human"):
            path = Path(row[f"{side}_diff_path"])
            if not path.is_file() or sha256(path) != row[f"{side}_diff_sha256"]:
                validation_errors.append(f"{row['candidate_id']}:{side}")
    summary = {
        "status": "MATERIALIZED_DIFF_PILOT" if not validation_errors else "VALIDATION_FAILED",
        "selection": "candidate_id_sha256_order_slice",
        "offset": args.offset,
        "requested_pairs": args.limit,
        "fetched_pairs": len(fetched),
        "accepted_pairs": len(accepted),
        "acceptance_rate_among_fetched": len(accepted) / len(fetched) if fetched else 0,
        "acceptance_wilson_95_ci": [ci_low, ci_high],
        "metadata_pool_pairs": len(candidates),
        "projected_accepted_pairs_at_observed_yield": round(len(candidates) * len(accepted) / len(fetched), 1) if fetched else 0,
        "projection_wilson_range": [round(len(candidates) * ci_low, 1), round(len(candidates) * ci_high, 1)],
        "accepted_agent_prs_with_added_production_logs": agent_log_prs,
        "accepted_human_prs_with_added_production_logs": human_log_prs,
        "reason_counts": dict(sorted(reasons.items())),
        "max_size_ratio": args.max_size_ratio,
        "retry_attempts": args.retry_attempts,
        "retry_wait_seconds": args.retry_wait,
        "outcome_conditioned_on_logging": False,
        "validation_errors": validation_errors,
        "diff_completeness_verification": "raw_final_diff_saved_not_compared_to_GitHub_changed_files",
        "runtime_leak_claim": False,
        "causal_claim": False,
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output_dir / "report.md").write_text(f"""# AIDev 扩展队列 diff 实测小样本

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: run + validate
- Origin Date: 2026-09-03
- Verification Status: {summary['status']}
- Version Label: aidev_expansion_diff_pilot_v1

## 结果

- 预取候选：{args.limit} 对；成功抓取双方 diff：{len(fetched)} 对。
- 通过生产源代码非空、双方 diff 不相同、最终规模比不超过 {args.max_size_ratio:g}：{len(accepted)} 对（抓取成功样本的 {summary['acceptance_rate_among_fetched'] * 100:.1f}%）。
- 上述保留率的 Wilson 95% 区间为 [{ci_low * 100:.1f}%, {ci_high * 100:.1f}%]。若仅作容量规划投影，650 对元数据候选约对应 {summary['projected_accepted_pairs_at_observed_yield']:.0f} 对，区间投影约 {summary['projection_wilson_range'][0]:.0f}--{summary['projection_wilson_range'][1]:.0f} 对。由于抓取失败可能不随机，这不是正式总体置信区间。
- 7 个合格对中，Agent/Human 含新增生产日志的 PR 分别为 {agent_log_prs}/{human_log_prs}；样本太小，不做差异推断。
- 排除原因：{json.dumps(dict(sorted(reasons.items())), ensure_ascii=False)}。
- 选样不查看日志结果；零日志 PR 保留。

## 证据边界

这是元数据候选的 diff 可用性与规模校准实测，不是隐私结果估计。双方原始 `.diff` 和 SHA-256 已保存，但未与 GitHub `changed_files` 独立对账。

## 谬误扫描

- Coverage: 11/11 checked.
- Simpson's paradox: 小样本 yield 不外推为每个仓库的 yield。
- Ecological fallacy: 单位是 PR 对。
- Berkson's paradox: 候选来自先前的元数据可行队列。
- Collider bias: 匹配条件可能是共同结果。
- Base-rate neglect: 不按日志存在与否过滤。
- Regression to the mean: 不按修改规模极值选样。
- Survivorship bias: 只覆盖可获取的已合并开源 PR。
- Look-elsewhere effect: 不检验隐私特征。
- Garden of forking paths: 哈希排序、offset、limit 和 size caliper 固定。
- Correlation != causation: 小样本只是可行性验证。
- Reverse causality: 任务分配仍可影响队列组成。
""", encoding="utf-8")
    artifacts = ("candidate_audit.csv", "accepted_pairs.csv", "summary.json", "report.md")
    manifest = {
        "hash_algorithm": "SHA-256",
        "input_sha256": {args.queue.name: sha256(args.queue)},
        "script_sha256": sha256(Path(__file__)),
        "artifact_sha256": {name: sha256(args.output_dir / name) for name in artifacts},
        "parameters": {
            "offset": args.offset, "limit": args.limit, "max_size_ratio": args.max_size_ratio,
            "offline": args.offline, "summarize_existing": args.summarize_existing,
            "retry_attempts": args.retry_attempts, "retry_wait": args.retry_wait,
        },
        "frozen_diff_sha256": {
            row["candidate_id"]: {"agent": row["agent_diff_sha256"], "human": row["human_diff_sha256"]}
            for row in fetched
        },
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if validation_errors:
        raise RuntimeError("frozen diff validation failed")
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    value.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    value.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    value.add_argument("--offset", type=int, default=0)
    value.add_argument("--limit", type=int, default=50)
    value.add_argument("--max-size-ratio", type=float, default=10)
    value.add_argument("--diff-delay", type=float, default=0.1)
    value.add_argument("--retry-attempts", type=int, default=3)
    value.add_argument("--retry-wait", type=float, default=10)
    value.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    value.add_argument("--offline", action="store_true")
    value.add_argument("--summarize-existing", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    print(json.dumps(run(args), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
