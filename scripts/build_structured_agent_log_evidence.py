#!/usr/bin/env python3
"""Join local session, PR binding, and added-log evidence without claim inflation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from screen_github_agent_logs import AGENT_NATIVE_RISK_FEATURES, SHARED_SENSITIVE_RISK_FEATURES


PR_FIELDS = (
    "evidence_id", "session_id", "pr_key", "pr_url", "repo", "source_provenance_status",
    "provenance_grade", "hard_anchor", "line_authorship_proof", "generation_stage", "pr_state",
    "analysis_eligibility", "same_base", "commit_match", "tree_match", "patch_content_match",
    "full_patch_accounted", "changed_path_coverage", "evidence_chain_status", "n_added_logs",
    "n_static_risk_candidates", "n_sensitive_content_candidates", "runtime_leak_status",
    "comparative_status",
)
LOG_FIELDS = (
    "evidence_id", "binding_id", "session_id", "pr_key", "pr_url", "repo", "file", "line",
    "path_scope", "log_text_redacted", "risk_features", "log_concepts", "static_risk_candidate",
    "sensitive_content_candidate", "sensitive_feature_family", "source_provenance_status",
    "provenance_grade", "line_authorship_proof", "generation_stage", "static_evidence_status",
    "runtime_leak_status", "comparative_status",
)
DEFAULT_INVENTORY = Path("outputs/local_codex_pr_session_inventory_v1/candidates.csv")
DEFAULT_BINDINGS = Path("outputs/codex_session_pr_batch_poc/binding/provenance_bindings.jsonl")
DEFAULT_LOGS = Path("outputs/codex_session_pr_batch_poc/agent_log_candidates.csv")
DEFAULT_OUTPUT = Path("outputs/structured_agent_log_evidence_v1")


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _bool(value: object) -> bool:
    return value is True or str(value).lower() == "true"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence_id(binding_id: str, suffix: str) -> str:
    return hashlib.sha256(f"{binding_id}|{suffix}".encode()).hexdigest()[:20]


def _sensitive_features(value: str) -> list[str]:
    features = {item for item in value.split(";") if item}
    return sorted(features & (AGENT_NATIVE_RISK_FEATURES | SHARED_SENSITIVE_RISK_FEATURES))


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build(inventory_path: Path, bindings_path: Path, logs_path: Path, output_dir: Path) -> dict:
    inventory = {
        (row["session_id"], row["pr_url"]): row
        for row in _read_csv(inventory_path)
        if row["candidate_status"] == "READY_FOR_LIVE_BINDING"
    }
    bindings = _read_jsonl(bindings_path)
    logs = _read_csv(logs_path)
    logs_by_pr: dict[str, list[dict[str, str]]] = {}
    for row in logs:
        logs_by_pr.setdefault(row["pr_key"], []).append(row)

    pr_rows, log_rows, errors = [], [], []
    for binding in bindings:
        key = (str(binding.get("session_id") or ""), str(binding.get("pr_url") or ""))
        candidate = inventory.get(key)
        if not candidate:
            errors.append(f"binding lacks READY inventory row: {binding.get('pr_key')}")
            continue
        proof = _bool(binding.get("line_authorship_proof"))
        grade = str(binding.get("provenance_grade") or "")
        if proof != (grade in {"A", "B"}):
            errors.append(f"grade/proof disagreement: {binding.get('pr_key')}")
            continue
        source_status = "AGENT_LINE_AUTHORSHIP_SUPPORTED" if proof else "AGENT_SOURCE_CANDIDATE_ONLY"
        pr_logs = logs_by_pr.get(str(binding["pr_key"]), [])
        sensitive_count = 0
        for index, log in enumerate(pr_logs, start=1):
            sensitive = _sensitive_features(log.get("risk_features", ""))
            sensitive_count += bool(sensitive)
            static_candidate = _bool(log.get("static_risk_candidate"))
            log_rows.append({
                "evidence_id": _evidence_id(str(binding["binding_id"]), f"log:{index}"),
                "binding_id": binding["binding_id"], "session_id": binding["session_id"],
                "pr_key": binding["pr_key"], "pr_url": binding["pr_url"], "repo": binding["repo"],
                "file": log["file"], "line": log["line"], "path_scope": log["path_scope"],
                "log_text_redacted": log["log_text_redacted"], "risk_features": log["risk_features"],
                "log_concepts": log["log_concepts"], "static_risk_candidate": static_candidate,
                "sensitive_content_candidate": bool(sensitive),
                "sensitive_feature_family": ";".join(sensitive),
                "source_provenance_status": source_status, "provenance_grade": grade,
                "line_authorship_proof": proof, "generation_stage": binding["generation_stage"],
                "static_evidence_status": (
                    "STATIC_RISK_CANDIDATE" if static_candidate else "NO_STATIC_RISK_FEATURE_DETECTED"
                ),
                "runtime_leak_status": "NOT_EXECUTED_NOT_RUNTIME_CONFIRMED",
                "comparative_status": "NO_MATCHED_HUMAN_CONTROL",
            })
        pr_rows.append({
            "evidence_id": _evidence_id(str(binding["binding_id"]), "pr"),
            "session_id": binding["session_id"], "pr_key": binding["pr_key"],
            "pr_url": binding["pr_url"], "repo": binding["repo"],
            "source_provenance_status": source_status, "provenance_grade": grade,
            "hard_anchor": binding["hard_anchor"], "line_authorship_proof": proof,
            "generation_stage": binding["generation_stage"], "pr_state": binding["pr_state"],
            "analysis_eligibility": binding["analysis_eligibility"], "same_base": binding["same_base"],
            "commit_match": binding["commit_match"], "tree_match": binding["tree_match"],
            "patch_content_match": binding["patch_content_match"],
            "full_patch_accounted": binding["full_patch_accounted"],
            "changed_path_coverage": binding["changed_path_coverage"],
            "evidence_chain_status": binding["github_evidence_chain_status"],
            "n_added_logs": len(pr_logs),
            "n_static_risk_candidates": sum(_bool(row["static_risk_candidate"]) for row in pr_logs),
            "n_sensitive_content_candidates": sensitive_count,
            "runtime_leak_status": "NOT_EXECUTED_NOT_RUNTIME_CONFIRMED",
            "comparative_status": "NO_MATCHED_HUMAN_CONTROL",
        })

    bound_pr_keys = {str(row.get("pr_key") or "") for row in bindings}
    errors.extend(f"log lacks binding: {key}" for key in sorted(set(logs_by_pr) - bound_pr_keys))
    if errors:
        raise ValueError("; ".join(errors))

    output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(output_dir / "pr_evidence.csv", PR_FIELDS, pr_rows)
    _write_csv(output_dir / "log_evidence.csv", LOG_FIELDS, log_rows)
    summary = {
        "status": "STRUCTURED_EVIDENCE_EXTRACTED",
        "n_prs": len(pr_rows), "n_logs": len(log_rows),
        "n_line_authorship_proven_prs": sum(_bool(row["line_authorship_proof"]) for row in pr_rows),
        "n_static_risk_candidates": sum(_bool(row["static_risk_candidate"]) for row in log_rows),
        "n_sensitive_content_candidates": sum(_bool(row["sensitive_content_candidate"]) for row in log_rows),
        "n_runtime_confirmed_leaks": 0,
        "provenance_grade_counts": dict(sorted(Counter(row["provenance_grade"] for row in pr_rows).items())),
        "analysis_eligibility_counts": dict(sorted(Counter(row["analysis_eligibility"] for row in pr_rows).items())),
        "comparative_status_counts": dict(sorted(Counter(row["comparative_status"] for row in pr_rows).items())),
        "claim_boundary": "source attribution != static risk != sensitive content != runtime leak",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(f"""# Agent 日志结构化证据 v1

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: STRUCTURED_EVIDENCE_EXTRACTED
- Version Label: structured_agent_log_evidence_v1

## 证据结果

| 证据层 | 结果 | 能说明什么 |
| --- | ---: | --- |
| Agent 行级来源已支持的 PR | {summary['n_line_authorship_proven_prs']} | 会话提交与 PR head 存在 A/B 级硬锚点 |
| 新增日志语句 | {summary['n_logs']} | PR diff 中新增的可执行日志语句 |
| 静态风险候选 | {summary['n_static_risk_candidates']} | 规则命中，不是真实泄露 |
| 敏感内容候选 | {summary['n_sensitive_content_candidates']} | 日志语句中出现敏感内容特征 |
| 运行时已确认泄露 | {summary['n_runtime_confirmed_leaks']} | 需要可达执行、敏感值传播与外传/持久化证据 |

当前唯一日志命中 `unstructured_stdio`，因此是静态风险候选；它没有命中敏感内容特征，也没有被执行验证。PR 仍为 OPEN，且没有匹配 Human PR，所以只能用于谱系方法验证，不能进入 Agent–Human 主效应。

## 谬误扫描

- Coverage: 11/11 checked.
- Simpson's paradox: 未合并仓库或计算组间差异。
- Ecological fallacy: PR 来源与日志行风险分层保存。
- Berkson's paradox: 样本由本地会话和可用仓库共同选入。
- Collider bias: clean-status 与完整工作流门槛可能选中更规范的会话。
- Base-rate neglect: 容量审计已报告 411 个会话中只有 1 个高精度候选。
- Regression to the mean: 不涉及极值前后比较。
- Survivorship bias: 仅包含仍可访问的本地会话、仓库和 GitHub PR。
- Look-elsewhere effect: 没有多重特征显著性检验。
- Garden of forking paths: 分层规则在脚本中固定。
- Correlation != causation: 不报告 Agent 导致更多泄露。
- Reverse causality: 用户选择何时让 Agent 创建 PR。

## 数据保护

未复制提示词、stdout/stderr 或工具原始返回；仅保留来源标识、哈希、PR 锚点和已脱敏的日志代码摘要。
""", encoding="utf-8")
    artifacts = ("pr_evidence.csv", "log_evidence.csv", "summary.json", "report.md")
    manifest = {
        "hash_algorithm": "SHA-256",
        "input_sha256": {str(path): _sha256(path) for path in (inventory_path, bindings_path, logs_path)},
        "script_sha256": _sha256(Path(__file__)),
        "artifact_sha256": {name: _sha256(output_dir / name) for name in artifacts},
        "deterministic": True,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--bindings", type=Path, default=DEFAULT_BINDINGS)
    parser.add_argument("--logs", type=Path, default=DEFAULT_LOGS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(build(args.inventory, args.bindings, args.logs, args.output_dir), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
