#!/usr/bin/env python3
"""Bridge the frozen matched-PR analysis to Ouatiti et al.'s documented RQ1 scope.

This is deliberately a compatibility analysis, not a claim of exact replication:
it applies the paper's published regex/path rules to the already-frozen 300 pairs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path

if __package__:
    from .analyze_aidev_primary_queue import (
        bh_adjust, file_sha256, paired_binary_result, read_csv, truth, write_csv,
    )
    from .screen_github_agent_logs import classify_log
else:
    from analyze_aidev_primary_queue import (
        bh_adjust, file_sha256, paired_binary_result, read_csv, truth, write_csv,
    )
    from screen_github_agent_logs import classify_log


PAPER_PATTERNS = {
    "python": re.compile(
        r"\b(?:logging|logger|_logger)\."
        r"(?P<level>debug|info|warning|warn|error|critical|exception)\s*\(",
        re.IGNORECASE,
    ),
    "java": re.compile(
        r"\b(?:logger|log|LOG|LOGGER)\."
        r"(?P<level>trace|debug|info|warn|warning|error|fatal)\s*\(",
        re.IGNORECASE,
    ),
    "javascript_typescript": re.compile(
        r"\bconsole\.(?P<level>log|info|warn|error|debug)\s*\(",
        re.IGNORECASE,
    ),
}

PR_FIELDS = (
    "pair_id", "provenance", "repo", "pr_key", "pr_url", "queue_language",
    "current_broad_added", "current_structured_added",
    "paper_files_broad_added", "paper_regex_added", "paper_regex_any_change",
    "paper_added_count", "paper_deleted_count", "paper_supported_changed_lines",
    "paper_added_static_risk", "paper_added_risk_features",
)
CHANGE_FIELDS = (
    "pair_id", "provenance", "repo", "pr_key", "pr_url", "file", "language",
    "change_type", "line", "level", "risk_features", "log_concepts",
    "static_risk_candidate", "text_redacted",
)
STAT_FIELDS = (
    "scope", "outcome", "n_pairs", "n_repositories", "agent_n", "human_n",
    "agent_rate", "human_rate", "agent_ci_low", "agent_ci_high", "human_ci_low",
    "human_ci_high", "effect", "effect_ci_low", "effect_ci_high", "effect_type",
    "agent_only", "human_only", "mcnemar_p", "bootstrap_iterations", "seed", "conclusion",
)
RISK_STAT_FIELDS = STAT_FIELDS + ("bh_q", "stable_after_bh")
REPO_FIELDS = (
    "outcome", "repo", "n_pairs", "agent_rate", "human_rate", "normalized_agent_score",
    "direction",
)
REVIEW_FIELDS = CHANGE_FIELDS + (
    "manual_is_sensitive_value", "manual_sensitive_type", "manual_runtime_reachable",
    "manual_notes",
)


def paper_language(path: str) -> str | None:
    """Return the paper language after applying its documented Table 2 filters."""
    clean = path.replace("\\", "/").strip()
    parts = [part.lower() for part in clean.split("/") if part]
    if not parts:
        return None
    name = parts[-1]
    directories = set(parts[:-1])
    if name.endswith(".py"):
        if directories & {"build", "dist", "site-packages", "vendor"}:
            return None
        if name.endswith("_test.py") or (name.startswith("test_") and name.endswith(".py")):
            return None
        return "python"
    if name.endswith(".java"):
        if directories & {"target", "bin", "build"}:
            return None
        if name == "test.java" or name.endswith("test.java"):
            return None
        return "java"
    if name.endswith((".js", ".jsx", ".ts", ".tsx")):
        if directories & {"node_modules", "dist", "public", "vendor"}:
            return None
        if name.endswith((".min.js", ".map", ".gz", ".bundle.js", ".worker.js")):
            return None
        return "javascript_typescript"
    return None


def _diff_sections(diff: str) -> list[tuple[str, str]]:
    output = []
    for section in re.split(r"(?=^diff --git )", diff or "", flags=re.MULTILINE):
        if not section.startswith("diff --git "):
            continue
        new_match = re.search(r"^\+\+\+\s+(.+)$", section, re.MULTILINE)
        old_match = re.search(r"^---\s+(.+)$", section, re.MULTILINE)
        marker = new_match.group(1).strip() if new_match else "/dev/null"
        if marker == "/dev/null" and old_match:
            marker = old_match.group(1).strip()
        if marker == "/dev/null":
            continue
        if marker.startswith(("a/", "b/")):
            marker = marker[2:]
        output.append((marker, section))
    return output


def paper_file_changed_lines(diff: str) -> list[dict]:
    """Extract added/deleted hunk lines from files admitted by the paper filters."""
    output = []
    for path, section in _diff_sections(diff):
        language = paper_language(path)
        if language is None:
            continue
        old_line = new_line = 0
        in_hunk = False
        for raw in section.splitlines():
            match = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
            if match:
                old_line, new_line = int(match.group(1)), int(match.group(2))
                in_hunk = True
                continue
            if not in_hunk:
                continue
            if raw.startswith("+") and not raw.startswith("+++"):
                output.append({
                    "file": path, "language": language, "change_type": "added",
                    "line": new_line, "text": raw[1:],
                })
                new_line += 1
            elif raw.startswith("-") and not raw.startswith("---"):
                output.append({
                    "file": path, "language": language, "change_type": "deleted",
                    "line": old_line, "text": raw[1:],
                })
                old_line += 1
            elif raw.startswith(" "):
                old_line += 1
                new_line += 1
    return output


def paper_match(language: str, text: str) -> re.Match | None:
    # The paper excludes minified code in addition to its named path/suffix filters.
    if len(text) > 1_000:
        return None
    return PAPER_PATTERNS[language].search(text)


def _redact(text: str) -> str:
    value = text[:800]
    for pattern, replacement in (
        (r"\b(?:gh[opsu]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b", "[REDACTED_SECRET]"),
        (r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[REDACTED_EMAIL]"),
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_IP]"),
    ):
        value = re.sub(pattern, replacement, value, flags=re.IGNORECASE)
    return value


def repository_rows(pair_rows: list[dict], outcomes: list[str]) -> tuple[list[dict], dict]:
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for row in pair_rows:
        by_repo[row["repo"]].append(row)
    details, summary = [], {}
    for outcome in outcomes:
        scores = []
        direction = Counter()
        for repo in sorted(by_repo):
            rows = by_repo[repo]
            agent_rate = sum(truth(row[f"agent_{outcome}"]) for row in rows) / len(rows)
            human_rate = sum(truth(row[f"human_{outcome}"]) for row in rows) / len(rows)
            if not agent_rate and not human_rate:
                continue
            score = agent_rate / (agent_rate + human_rate)
            label = "agent_higher" if score > 0.5 else "human_higher" if score < 0.5 else "equal"
            direction[label] += 1
            scores.append(score)
            details.append({
                "outcome": outcome,
                "repo": repo,
                "n_pairs": len(rows),
                "agent_rate": agent_rate,
                "human_rate": human_rate,
                "normalized_agent_score": score,
                "direction": label,
            })
        summary[outcome] = {
            "n_repositories_with_any_touch": len(scores),
            "agent_higher": direction["agent_higher"],
            "human_higher": direction["human_higher"],
            "equal": direction["equal"],
            "median_normalized_agent_score": statistics.median(scores) if scores else None,
        }
    return details, summary


def _report(summary: dict) -> str:
    pair = {row["outcome"]: row for row in summary["pair_statistics"]}
    repo = summary["repository_statistics"]

    def pct(value: float) -> str:
        return f"{value * 100:.1f}%"

    rows = []
    labels = {
        "current_broad_added": "现有广义定义：仅新增",
        "current_structured_added": "现有结构化代理：仅新增",
        "paper_files_broad_added": "论文文件范围 + 广义检测：仅新增",
        "paper_regex_added": "论文正则：仅新增",
        "paper_regex_any_change": "论文正则：新增或删除",
    }
    for key, label in labels.items():
        value = pair[key]
        rows.append(
            f"| {label} | {value['agent_n']}/300 ({pct(value['agent_rate'])}) | "
            f"{value['human_n']}/300 ({pct(value['human_rate'])}) | "
            f"{value['effect'] * 100:+.1f} pp | "
            f"[{value['effect_ci_low'] * 100:+.1f}, {value['effect_ci_high'] * 100:+.1f}] pp | "
            f"{value['mcnemar_p']:.4f} |"
        )
    paper_repo = repo["paper_regex_any_change"]
    risk_rows = [
        f"| {value['risk_feature']} | {value['agent_n']}/300 | {value['human_n']}/300 | "
        f"{value['effect'] * 100:+.1f} pp | "
        f"[{value['effect_ci_low'] * 100:+.1f}, {value['effect_ci_high'] * 100:+.1f}] pp | "
        f"{value['bh_q']:.4f} | {value['stable_after_bh']} |"
        for value in summary["risk_statistics"]
    ]
    return f"""# AIDev 300 对样本：论文估计目标桥接分析

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: {summary['generated_date']}
- Verification Status: VERIFIED
- Version Label: aidev_paper_estimand_bridge_v1

## 目的

在相同的 300 对、600 份冻结 diff 上逐步替换日志定义，区分三类影响：语言与路径过滤、日志 API 正则、以及只看新增还是同时看删除。本分析是**论文文档化方法的兼容性分析**，不是原论文 4,550/3,276 PR 队列的精确复现。

## 配对 PR 结果

| 口径 | Agent | Human | Agent-Human | 仓库分层 bootstrap 95% CI | McNemar p |
|---|---:|---:|---:|---:|---:|
{chr(10).join(rows)}

## 仓库聚合描述

按论文的 `Agent prevalence / (Agent prevalence + Human prevalence)` 计算，但只使用本地 300 对样本：

- 有任意论文正则日志变化的仓库：{paper_repo['n_repositories_with_any_touch']}
- Human 较高：{paper_repo['human_higher']}
- Agent 较高：{paper_repo['agent_higher']}
- 相同：{paper_repo['equal']}
- Agent 归一化得分中位数：{paper_repo['median_normalized_agent_score'] if paper_repo['median_normalized_agent_score'] is not None else 'N/A'}

这些仓库数字不能与论文的 45/77 直接比较，因为每个仓库只抽取了少量匹配 PR，而不是纳入该仓库的全部符合条件 PR。

## 论文口径新增日志中的静态敏感风险

以全部 300 对 PR 为分母；同一 PR 出现某类特征一次即计为命中。`q` 为所有风险类型一起进行的 Benjamini–Hochberg 校正。

| 静态风险特征 | Agent PR | Human PR | Agent-Human | 仓库分层 bootstrap 95% CI | BH q | 稳定差异 |
|---|---:|---:|---:|---:|---:|---:|
{chr(10).join(risk_rows)}

这里的命中只说明日志语句引用了潜在敏感变量或危险输出形态，不代表运行时一定执行、一定包含真实敏感值或已经外泄。

需要语义复核的身份/配置/请求响应/工具与 Agent 控制数据候选共有 {summary['n_semantic_review_candidates']} 条，已写入 `semantic_review_queue.csv`；在人工确认前不进入真实泄露率。

## 解释边界

1. `current_broad_added → paper_files_broad_added` 主要反映语言和文件过滤变化。
2. `paper_files_broad_added → paper_regex_added` 主要反映普通打印、CLI 输出和非论文 logging API 被排除。
3. `paper_regex_added → paper_regex_any_change` 反映纳入删除日志行的影响；最终 diff 无法可靠重建“修改”事件的一对一语义。
4. 结果仍是静态代码变更，不是运行时隐私泄露，也不能证明具体日志由 Agent 单独编写。
5. 精确验证论文仍需要原论文完整 PR 队列、作者代码对应版本和一致的聚合/检验流程。

## 复现

- 固定随机种子：{summary['seed']}
- bootstrap：{summary['bootstrap_iterations']} 次
- 输入 diff 哈希：逐条重新验证
- 统计谬误扫描：11/11；主要风险为聚合层级混用、选择偏差、观察性数据因果化与多分析路径。
"""


def run(input_dir: Path, output_dir: Path, iterations: int, seed: int) -> dict:
    pairs = read_csv(input_dir / "matched_pairs.csv")
    queue = read_csv(input_dir / "pr_analysis_queue.csv")
    logs = read_csv(input_dir / "log_candidates.csv")
    validation = json.loads((input_dir / "validation.json").read_text(encoding="utf-8"))
    if validation.get("status") != "PASS" or len(pairs) != 300 or len(queue) != 600:
        raise ValueError("frozen 300-pair integrity gate failed")

    current_counts = Counter((row["pair_id"], row["provenance"]) for row in logs if row["path_scope"] == "production")
    structured_counts = Counter(
        (row["pair_id"], row["provenance"])
        for row in logs
        if row["path_scope"] == "production" and "unstructured_stdio" not in row["risk_features"].split(";")
    )
    pr_rows, changes = [], []
    for row in queue:
        diff_path = Path(row["diff_path"])
        if file_sha256(diff_path) != row["diff_sha256"]:
            raise ValueError("diff hash mismatch: " + str(diff_path))
        changed = paper_file_changed_lines(diff_path.read_text(encoding="utf-8", errors="replace"))
        broad_added = any(
            item["change_type"] == "added" and classify_log(item["file"], item["text"])[0]
            for item in changed
        )
        matches = []
        added_risk_features = set()
        for item in changed:
            match = paper_match(item["language"], item["text"])
            if not match:
                continue
            _, features, concepts = classify_log(item["file"], item["text"])
            if item["change_type"] == "added":
                added_risk_features.update(features)
            matches.append(item)
            changes.append({
                "pair_id": row["pair_id"],
                "provenance": row["provenance"],
                "repo": row["repo"],
                "pr_key": row["pr_key"],
                "pr_url": row["pr_url"],
                **{name: item[name] for name in ("file", "language", "change_type", "line")},
                "level": match.group("level").lower(),
                "risk_features": ";".join(features),
                "log_concepts": ";".join(concepts),
                "static_risk_candidate": bool(set(features) - {"unstructured_stdio"}),
                "text_redacted": _redact(item["text"]),
            })
        key = (row["pair_id"], row["provenance"])
        pr_rows.append({
            "pair_id": row["pair_id"],
            "provenance": row["provenance"],
            "repo": row["repo"],
            "pr_key": row["pr_key"],
            "pr_url": row["pr_url"],
            "queue_language": row["language"],
            "current_broad_added": current_counts[key] > 0,
            "current_structured_added": structured_counts[key] > 0,
            "paper_files_broad_added": broad_added,
            "paper_regex_added": any(item["change_type"] == "added" for item in matches),
            "paper_regex_any_change": bool(matches),
            "paper_added_count": sum(item["change_type"] == "added" for item in matches),
            "paper_deleted_count": sum(item["change_type"] == "deleted" for item in matches),
            "paper_supported_changed_lines": len(changed),
            "paper_added_static_risk": bool(added_risk_features - {"unstructured_stdio"}),
            "paper_added_risk_features": ";".join(sorted(added_risk_features)),
        })

    pr_index = {(row["pair_id"], row["provenance"]): row for row in pr_rows}
    outcomes = [
        "current_broad_added", "current_structured_added", "paper_files_broad_added",
        "paper_regex_added", "paper_regex_any_change",
    ]
    pair_rows = []
    feature_names = (
        "agent_control_data", "auth_config_data", "request_response_data",
        "identity_session_data", "tool_io_data", "whole_object_dump",
        "error_diagnostic_data", "debug_residue_marker", "unstructured_stdio",
    )
    for pair in pairs:
        item = {"pair_id": pair["pair_id"], "repo": pair["repo"]}
        for outcome in outcomes:
            item[f"agent_{outcome}"] = pr_index[(pair["pair_id"], "agent")][outcome]
            item[f"human_{outcome}"] = pr_index[(pair["pair_id"], "human")][outcome]
        for feature in feature_names:
            for side in ("agent", "human"):
                present = pr_index[(pair["pair_id"], side)]["paper_added_risk_features"].split(";")
                item[f"{side}_risk_{feature}"] = feature in present
        for side in ("agent", "human"):
            item[f"{side}_risk_any_static_risk"] = truth(
                pr_index[(pair["pair_id"], side)]["paper_added_static_risk"]
            )
        pair_rows.append(item)

    statistics_rows = [
        paired_binary_result(
            pair_rows, outcome, "frozen_matched_300",
            lambda item, name=outcome: truth(item[f"agent_{name}"]),
            lambda item, name=outcome: truth(item[f"human_{name}"]),
            iterations, seed,
        )
        for outcome in outcomes
    ]
    repo_details, repo_summary = repository_rows(pair_rows, outcomes)
    risk_features = ("any_static_risk",) + feature_names
    risk_statistics = []
    for feature in risk_features:
        value = paired_binary_result(
            pair_rows, f"risk_{feature}", "paper_regex_added_frozen_matched_300",
            lambda item, name=feature: truth(item[f"agent_risk_{name}"]),
            lambda item, name=feature: truth(item[f"human_risk_{name}"]),
            iterations, seed,
        )
        value["risk_feature"] = feature
        risk_statistics.append(value)
    for value, q_value in zip(
        risk_statistics, bh_adjust([row["mcnemar_p"] for row in risk_statistics])
    ):
        value["bh_q"] = q_value
        value["stable_after_bh"] = bool(
            q_value < 0.05 and (value["effect_ci_low"] > 0 or value["effect_ci_high"] < 0)
        )
    semantic_review_features = {
        "agent_control_data", "auth_config_data", "request_response_data",
        "identity_session_data", "tool_io_data",
    }
    review_queue = []
    for change in changes:
        features = set(change["risk_features"].split(";"))
        if change["change_type"] != "added" or not features & semantic_review_features:
            continue
        review_queue.append({
            **change,
            "manual_is_sensitive_value": "",
            "manual_sensitive_type": "",
            "manual_runtime_reachable": "",
            "manual_notes": "",
        })

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "pr_bridge.csv", pr_rows, PR_FIELDS)
    write_csv(output_dir / "paper_log_changes.csv", changes, CHANGE_FIELDS)
    write_csv(output_dir / "pair_statistics.csv", statistics_rows, STAT_FIELDS)
    write_csv(output_dir / "repository_statistics.csv", repo_details, REPO_FIELDS)
    write_csv(output_dir / "risk_statistics.csv", risk_statistics, ("risk_feature",) + RISK_STAT_FIELDS)
    write_csv(output_dir / "semantic_review_queue.csv", review_queue, REVIEW_FIELDS)
    summary = {
        "generated_date": "2026-09-03",
        "status": "VERIFIED",
        "scope": "paper_documented_method_on_frozen_matched_300",
        "not_exact_replication": True,
        "n_pairs": len(pairs),
        "n_prs": len(pr_rows),
        "n_paper_log_changes": len(changes),
        "n_semantic_review_candidates": len(review_queue),
        "bootstrap_iterations": iterations,
        "seed": seed,
        "pair_statistics": statistics_rows,
        "risk_statistics": risk_statistics,
        "repository_statistics": repo_summary,
        "input_sha256": {
            name: file_sha256(input_dir / name)
            for name in ("matched_pairs.csv", "pr_analysis_queue.csv", "log_candidates.csv", "validation.json")
        },
        "fallacy_scan": {
            "coverage": "11/11",
            "simpsons_paradox": "checked_via_repository_and_pair_views",
            "ecological_fallacy": "guarded_no_repo_to_pr_inference",
            "berksons_paradox": "caution_selected_matched_cohort",
            "collider_bias": "caution_matching_variables_may_be_post_assignment",
            "base_rate_neglect": "checked_rates_and_denominators_reported",
            "regression_to_mean": "not_applicable_no_extreme_preselection",
            "survivorship_bias": "caution_merged_prs_and_frozen_diff_only",
            "look_elsewhere_effect": "guarded_all_five_prespecified_bridge_outcomes_reported",
            "garden_of_forking_paths": "caution_compatibility_proxy_not_preregistered",
            "correlation_not_causation": "guarded_observational_wording",
            "reverse_causality": "not_applicable_provenance_precedes_static_outcome_but_no_causal_claim",
        },
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(_report(summary), encoding="utf-8")
    output_names = (
        "pr_bridge.csv", "paper_log_changes.csv", "pair_statistics.csv",
        "repository_statistics.csv", "risk_statistics.csv", "summary.json", "report.md",
        "semantic_review_queue.csv",
    )
    manifest = {
        "hash_algorithm": "SHA-256",
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "artifact_sha256": {name: file_sha256(output_dir / name) for name in output_names},
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--input-dir", type=Path, default=Path("outputs/aidev_observational_primary_300"))
    value.add_argument(
        "--output-dir", type=Path,
        default=Path("outputs/aidev_observational_primary_300/paper_estimand_bridge"),
    )
    value.add_argument("--bootstrap-iterations", type=int, default=10_000)
    value.add_argument("--seed", type=int, default=20260805)
    return value


def main() -> int:
    args = parser().parse_args()
    summary = run(args.input_dir, args.output_dir, args.bootstrap_iterations, args.seed)
    print(json.dumps({
        "status": summary["status"],
        "n_pairs": summary["n_pairs"],
        "n_paper_log_changes": summary["n_paper_log_changes"],
        "output_dir": str(args.output_dir.resolve()),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
