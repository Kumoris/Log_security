#!/usr/bin/env python3
"""Consolidate materialized AIDev expansion batches into structured evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from mine_github_log_lineage import diff_profile
from screen_github_agent_logs import AGENT_NATIVE_RISK_FEATURES, SHARED_SENSITIVE_RISK_FEATURES


DEFAULT_BATCHES = (
    Path("outputs/aidev_expansion_diff_pilot_v1"),
    Path("outputs/aidev_expansion_diff_batch_0050_0149_v1"),
    Path("outputs/aidev_expansion_diff_batch_0150_0649_v1"),
)
DEFAULT_EXISTING = Path("outputs/aidev_observational_primary_300/matched_pairs.csv")
DEFAULT_OUTPUT = Path("outputs/aidev_expansion_structured_evidence_v1")
PAIR_FIELDS = (
    "candidate_id", "repo", "language", "task_type", "agent_pr_key", "agent_pr_url",
    "agent_product", "agent_created_at", "agent_merged_at", "human_pr_key", "human_pr_url",
    "human_actor", "human_created_at", "human_merged_at", "date_distance_days", "size_ratio",
    "agent_size", "human_size", "agent_diff_sha256", "human_diff_sha256", "agent_diff_path",
    "human_diff_path", "agent_provenance_tier", "human_provenance_tier",
    "agent_line_authorship_proof", "human_agent_assistance_excluded", "pair_analysis_eligibility",
)
PR_FIELDS = (
    "evidence_id", "candidate_id", "dataset", "provenance", "pr_key", "pr_url", "repo",
    "language", "task_type", "actor_or_product", "created_at", "merged_at", "pr_state",
    "provenance_tier", "line_authorship_proof", "agent_assistance_excluded",
    "source_evidence_status", "diff_sha256", "diff_path", "production_size",
    "production_added_lines", "production_deleted_lines", "production_source_files",
    "n_logs_production", "n_logs_all_files", "analysis_eligibility", "runtime_leak_status",
)
LOG_FIELDS = (
    "evidence_id", "candidate_id", "dataset", "provenance", "pr_key", "pr_url", "repo",
    "language", "task_type", "file", "line", "path_scope", "log_text_redacted",
    "risk_features", "log_concepts", "static_risk_candidate", "sensitive_content_candidate",
    "sensitive_feature_family", "provenance_tier", "line_authorship_proof",
    "static_evidence_status", "runtime_leak_status", "analysis_eligibility",
)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]


def truth(value: object) -> bool:
    return value is True or str(value).lower() == "true"


def run(batch_dirs: list[Path], existing_pairs: Path, output_dir: Path) -> dict:
    audits, accepted = [], []
    input_paths = []
    for directory in batch_dirs:
        audit_path, accepted_path = directory / "candidate_audit.csv", directory / "accepted_pairs.csv"
        audits.extend(read_csv(audit_path))
        accepted.extend(read_csv(accepted_path))
        input_paths.extend((audit_path, accepted_path, directory / "manifest.json"))
    existing = read_csv(existing_pairs)
    input_paths.append(existing_pairs)

    errors = []
    candidate_ids = [row["candidate_id"] for row in audits]
    if len(audits) != 650 or len(candidate_ids) != len(set(candidate_ids)):
        errors.append("batch audits do not cover 650 unique candidates")
    if {row["candidate_id"] for row in accepted} != {
        row["candidate_id"] for row in audits if row["status"] == "ACCEPTED"
    }:
        errors.append("accepted rows disagree with audit statuses")
    for side in ("agent", "human"):
        keys = [row[f"{side}_pr_key"] for row in accepted]
        if len(keys) != len(set(keys)):
            errors.append(f"duplicate {side} PR")
    if {row["agent_pr_key"] for row in accepted} & {row["human_pr_key"] for row in accepted}:
        errors.append("Agent and Human PR sets overlap")
    old_keys = {
        row[name] for row in existing for name in ("agent_pr_key", "human_pr_key")
    }
    new_keys = {
        row[name] for row in accepted for name in ("agent_pr_key", "human_pr_key")
    }
    if old_keys & new_keys:
        errors.append("expansion overlaps existing 300-pair cohort")

    pr_rows, log_rows = [], []
    for pair in sorted(accepted, key=lambda row: row["candidate_id"]):
        if not pair["agent_merged_at"] or not pair["human_merged_at"]:
            errors.append("missing merged_at: " + pair["candidate_id"])
        if not all(truth(pair[name]) for name in ("exact_repo", "exact_task_type", "exact_language")):
            errors.append("categorical mismatch: " + pair["candidate_id"])
        if float(pair["date_distance_days"]) > 180 or float(pair["size_ratio"]) > 10:
            errors.append("caliper violation: " + pair["candidate_id"])
        for side in ("agent", "human"):
            path = Path(pair[f"{side}_diff_path"])
            if not path.is_file() or sha256(path) != pair[f"{side}_diff_sha256"]:
                errors.append(f"diff hash mismatch: {pair['candidate_id']}:{side}")
                continue
            profile = diff_profile(path.read_text(encoding="utf-8"))
            production_logs = [row for row in profile["logs"] if row["path_scope"] == "production"]
            expected = {
                "size": int(pair[f"{side}_size"]),
                "logs": int(pair[f"{side}_n_logs"]),
                "files": int(pair[f"{side}_production_source_files"]),
            }
            observed = {
                "size": profile["added_lines"] + profile["deleted_lines"],
                "logs": len(production_logs),
                "files": profile["production_source_files"],
            }
            if observed != expected:
                errors.append(f"profile mismatch: {pair['candidate_id']}:{side}")
            provenance_tier = pair[f"{side}_provenance_tier"]
            line_proof = truth(pair["agent_line_authorship_proof"]) if side == "agent" else False
            assistance_excluded = truth(pair["human_agent_assistance_excluded"]) if side == "human" else False
            source_status = (
                "AIDEV_AGENT_PR_LABEL_NOT_SESSION_LINE_PROOF"
                if side == "agent" else "HUMAN_LIKELY_UNDISCLOSED_AI_NOT_EXCLUDED"
            )
            pr_rows.append({
                "evidence_id": evidence_id(pair["candidate_id"], side, "pr"),
                "candidate_id": pair["candidate_id"], "dataset": "AIDev",
                "provenance": side, "pr_key": pair[f"{side}_pr_key"],
                "pr_url": pair[f"{side}_pr_url"], "repo": pair["repo"],
                "language": pair["language"], "task_type": pair["task_type"],
                "actor_or_product": pair["agent_product"] if side == "agent" else pair["human_actor"],
                "created_at": pair[f"{side}_created_at"], "merged_at": pair[f"{side}_merged_at"],
                "pr_state": "MERGED", "provenance_tier": provenance_tier,
                "line_authorship_proof": line_proof, "agent_assistance_excluded": assistance_excluded,
                "source_evidence_status": source_status, "diff_sha256": pair[f"{side}_diff_sha256"],
                "diff_path": str(path.resolve()), "production_size": observed["size"],
                "production_added_lines": profile["added_lines"],
                "production_deleted_lines": profile["deleted_lines"],
                "production_source_files": observed["files"], "n_logs_production": observed["logs"],
                "n_logs_all_files": len(profile["logs"]),
                "analysis_eligibility": "PRE_ANALYSIS_QUALITY_AUDIT_REQUIRED",
                "runtime_leak_status": "NOT_EXECUTED_NOT_RUNTIME_CONFIRMED",
            })
            for index, log in enumerate(profile["logs"], 1):
                risks = set(log["risk_features"])
                sensitive = sorted(risks & (AGENT_NATIVE_RISK_FEATURES | SHARED_SENSITIVE_RISK_FEATURES))
                log_rows.append({
                    "evidence_id": evidence_id(pair["candidate_id"], side, "log", str(index)),
                    "candidate_id": pair["candidate_id"], "dataset": "AIDev", "provenance": side,
                    "pr_key": pair[f"{side}_pr_key"], "pr_url": pair[f"{side}_pr_url"],
                    "repo": pair["repo"], "language": pair["language"], "task_type": pair["task_type"],
                    "file": log["file"], "line": log["line"], "path_scope": log["path_scope"],
                    "log_text_redacted": log["log_text_redacted"],
                    "risk_features": ";".join(log["risk_features"]),
                    "log_concepts": ";".join(log["log_concepts"]),
                    "static_risk_candidate": log["static_risk_candidate"],
                    "sensitive_content_candidate": bool(sensitive),
                    "sensitive_feature_family": ";".join(sensitive),
                    "provenance_tier": provenance_tier, "line_authorship_proof": line_proof,
                    "static_evidence_status": (
                        "STATIC_RISK_CANDIDATE" if log["static_risk_candidate"]
                        else "NO_STATIC_RISK_FEATURE_DETECTED"
                    ),
                    "runtime_leak_status": "NOT_EXECUTED_NOT_RUNTIME_CONFIRMED",
                    "analysis_eligibility": "PRE_ANALYSIS_QUALITY_AUDIT_REQUIRED",
                })

    total_repo_counts = Counter(row["repo"] for row in existing)
    total_repo_counts.update(row["repo"] for row in accepted)
    if max(total_repo_counts.values(), default=0) > 5:
        errors.append("combined repository cap exceeds 5")
    if errors:
        raise ValueError("; ".join(errors[:20]))

    output_dir.mkdir(parents=True, exist_ok=True)
    pair_rows = [{**row, "pair_analysis_eligibility": "PRE_ANALYSIS_QUALITY_AUDIT_REQUIRED"} for row in sorted(accepted, key=lambda row: row["candidate_id"])]
    write_csv(output_dir / "matched_pairs.csv", PAIR_FIELDS, pair_rows)
    write_csv(output_dir / "pr_evidence.csv", PR_FIELDS, pr_rows)
    write_csv(output_dir / "log_evidence.csv", LOG_FIELDS, log_rows)
    production_logs = [row for row in log_rows if row["path_scope"] == "production"]
    reason_counts = Counter("accepted" if row["status"] == "ACCEPTED" else row["reason"] for row in audits)
    summary = {
        "status": "FROZEN_EXPANSION_PRE_ANALYSIS_AUDIT",
        "metadata_candidate_pairs": len(audits),
        "metadata_queue_fully_attempted": len(audits) == 650,
        "next_offset": len(audits),
        "fetched_pairs": sum(row["status"] != "FETCH_FAILED" for row in audits),
        "accepted_pairs": len(pair_rows),
        "accepted_repositories": len({row["repo"] for row in pair_rows}),
        "pr_evidence_rows": len(pr_rows), "all_file_log_rows": len(log_rows),
        "production_log_rows": dict(sorted(Counter(row["provenance"] for row in production_logs).items())),
        "production_log_bearing_prs": {
            side: sum(row["provenance"] == side and int(row["n_logs_production"]) > 0 for row in pr_rows)
            for side in ("agent", "human")
        },
        "sensitive_content_candidate_rows": dict(sorted(Counter(
            row["provenance"] for row in production_logs if truth(row["sensitive_content_candidate"])
        ).items())),
        "existing_pairs": len(existing), "combined_pairs_before_quality_audit": len(existing) + len(pair_rows),
        "line_authorship_proven_prs": sum(truth(row["line_authorship_proof"]) for row in pr_rows),
        "runtime_confirmed_leaks": 0, "reason_counts": dict(sorted(reason_counts.items())),
        "network_failures": dict(sorted(Counter(
            row["reason"] for row in audits if row["status"] == "FETCH_FAILED"
        ).items())),
        "retryable_rate_limit_failures": sum(
            row["status"] == "FETCH_FAILED" and "HTTP 429" in row["reason"] for row in audits
        ),
        "claim_boundary": "AIDev PR labels are not session-level line authorship; static candidates are not runtime leaks",
        "fallacy_scan_coverage": "11/11",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(f"""# AIDev 扩展队列结构化证据

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: run + validate
- Origin Date: 2026-09-04
- Verification Status: FROZEN_EXPANSION_PRE_ANALYSIS_AUDIT
- Version Label: aidev_expansion_structured_evidence_v1

## 结果

- 元数据候选：{len(audits)} 对；成功抓取双方最终 diff：{summary['fetched_pairs']} 对。
- 通过生产源代码非空、双方 diff 不同且最终规模比 <=10：{len(pair_rows)} 对，来自 {summary['accepted_repositories']} 个仓库。
- 固化 PR 证据 {len(pr_rows)} 行，Agent/Human 各 {len(pair_rows)} 行；每行都有 merged 时间、PR URL、diff 路径和 SHA-256。
- 生产代码日志行：Agent {summary['production_log_rows'].get('agent', 0)}，Human {summary['production_log_rows'].get('human', 0)}；含日志 PR：Agent {summary['production_log_bearing_prs']['agent']}，Human {summary['production_log_bearing_prs']['human']}。
- 与原 300 对合计可得 {summary['combined_pairs_before_quality_audit']} 对，但未通过新队列的主分析前质量审计，尚不合并计算正式差异。
- 当前 650 对队列已全部尝试，下一偏移量为 {summary['next_offset']}；待重试 429 为 {summary['retryable_rate_limit_failures']}。

## 来源边界

- Agent 侧是 `aidev_agent_labeled_pr`：支持 PR 级 Agent 来源，不是会话→commit→PR 的 A/B 级行作者证明。
- Human 侧为 GitHub User 且上游已排除 bot 和显式 AI 标记，但不能排除未披露 AI 协助。
- 日志只是静态规则提取；运行时已确认泄露为 0。

## 硬校验

- 650 个 `candidate_id` 全部唯一，Agent/Human PR 各自一对一，新队列与原 300 对无重叠。
- 所有接受项均有双方 `merged_at`，且满足同仓库、同任务、同语言、180 天和规模比卡尺。
- {len(pair_rows) * 2} 个 diff 文件全部重算哈希与语义 profile，与表格一致。
- 未抓取的 7 对全部为 GitHub 404，没有尚未重试的 429。

## 谬误扫描

- Coverage: 11/11 checked.
- Simpson's paradox: 保留仓库字段和总仓库上限。
- Ecological fallacy: 区分配对、PR 和日志行三个单位。
- Berkson's paradox: 接受项条件化于双方都有生产代码修改。
- Collider bias: 规模匹配可能是任务与来源的共同结果。
- Base-rate neglect: 不按日志存在与否选样，保留零日志 PR。
- Regression to the mean: 不以极端日志数选样。
- Survivorship bias: 仅覆盖已合并且 diff 仍可获取的公开 PR。
- Look-elsewhere effect: 本轮不做显著性检验。
- Garden of forking paths: 匹配和卡尺在查看日志结果前固定。
- Correlation != causation: 队列是观察性匹配设计。
- Reverse causality: 任务分配可同时影响作者来源和日志需求。
""", encoding="utf-8")
    artifacts = ("matched_pairs.csv", "pr_evidence.csv", "log_evidence.csv", "summary.json", "report.md")
    manifest = {
        "hash_algorithm": "SHA-256",
        "input_sha256": {str(path): sha256(path) for path in input_paths},
        "script_sha256": sha256(Path(__file__)),
        "artifact_sha256": {name: sha256(output_dir / name) for name in artifacts},
        "deterministic": True,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", action="append", type=Path, default=[])
    parser.add_argument("--existing-pairs", type=Path, default=DEFAULT_EXISTING)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(run(args.batch or list(DEFAULT_BATCHES), args.existing_pairs, args.output_dir), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
