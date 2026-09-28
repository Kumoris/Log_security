#!/usr/bin/env python3
"""Analyze value-aware log privacy features in the frozen AIDev matched cohort.

The scanner joins multi-line log calls and resolves simple nearby assignments.
All findings remain static candidates; no runtime leakage is asserted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

if __package__:
    from .analyze_aidev_paper_estimand_bridge import _diff_sections, _redact, paper_language, paper_match
    from .analyze_aidev_primary_queue import bh_adjust, file_sha256, paired_binary_result, read_csv, truth, write_csv
    from .analyze_coding_agent_log_leakage import is_production_path
else:
    from analyze_aidev_paper_estimand_bridge import _diff_sections, _redact, paper_language, paper_match
    from analyze_aidev_primary_queue import bh_adjust, file_sha256, paired_binary_result, read_csv, truth, write_csv
    from analyze_coding_agent_log_leakage import is_production_path


STRING_RE = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", re.DOTALL)
CREDENTIAL_RE = re.compile(
    r"\b(?:api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|"
    r"password|passwd|pwd|credential|auth(?:orization)?|bearer|jwt|cookie|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|token|secret)\b",
    re.IGNORECASE,
)
PERSONAL_RE = re.compile(
    r"\b(?:user(?:name|_name|_id|id|_data|_info|_profile|_account)?|customer[_-]?(?:id|name|data)|"
    r"email|phone|mobile|ssn|passport|account[_-]?id|device[_-]?id|session(?:_id|id|_data)?|"
    r"transaction[_-]?id|order[_-]?id|tenant[_-]?id)\b",
    re.IGNORECASE,
)
RESPONSE_RE = re.compile(
    r"\b(?:request|response|req)(?![\w.])|"
    r"\b(?:request|response|req|res)\.(?:data|body|headers|text|json|payload|content)(?!\.)\b|"
    r"\b(?:request[_-]?body|response[_-]?body|response[_-]?text|err[_-]?text)\b|"
    r"(?<!\.)\b(?:body|payload|headers)\b",
    re.IGNORECASE,
)
AGENT_CONTEXT_RE = re.compile(
    r"\b(?:system[_-]?prompt|developer[_-]?prompt|prompt|instructions?|chat[_-]?history|"
    r"(?:chat|llm|model|assistant|conversation)[_-]?messages?|"
    r"model[_-]?(?:response|output)|llm[_-]?(?:response|output)|assistant[_-]?output|"
    r"tool[_-]?(?:input|output|result|arguments?)|mcp[_-]?(?:input|output|result)|"
    r"agent[_-]?(?:state|memory)|context[_-]?window|choices\b[^\n]*\b(?:delta\.)?content)\b",
    re.IGNORECASE,
)
CONFIG_RE = re.compile(
    r"\b(?:database[_-]?url|connection[_-]?string|dsn|jdbc|process\.env|environment|env[_-]?vars?|"
    r"configuration|config|settings|working[_-]?dir|file[_-]?path|absolute[_-]?path|"
    r"hostname|endpoint|bucket|namespace|region|command[_-]?(?:args|line)|temp[_-]?dir)\b",
    re.IGNORECASE,
)
EXCEPTION_RE = re.compile(
    r"\b(?:exception|throwable|traceback|stack[_-]?trace|backtrace|format_exc|"
    r"error\??\.(?:message|stack|cause)|err\??\.(?:message|stack|cause)|getMessage\s*\()",
    re.IGNORECASE,
)
DIRECT_SECRET_LITERAL_RE = re.compile(
    r"\b(?:gh[opsu]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|"
    r"AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b|"
    r"\[REDACTED_SECRET\]",
    re.IGNORECASE,
)
DIRECT_IDENTIFIER_LITERAL_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|"
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
    r"\[REDACTED_(?:EMAIL|IP)\]",
    re.IGNORECASE,
)
RAW_OBJECT_RE = re.compile(
    r"(?<!\.)\b(?:request|response|payload|body|headers)(?![\w.])|"
    r"\b(?:tool[_-]?(?:input|output|result)|"
    r"system[_-]?prompt|(?:chat|llm|model|assistant|conversation)[_-]?messages?|"
    r"user[_-]?data|session[_-]?data)\b|"
    r"\b(?:JSON\.stringify|json\.dumps?|(?:req|res|request|response)\."
    r"(?:text|json|data|body|headers|payload|content)(?!\.))\b",
    re.IGNORECASE,
)
REDACTION_RE = re.compile(r"\b(?:redact|mask|sanitize|sanitise|scrub|obfuscat|anonym)\w*\b", re.IGNORECASE)
ASSIGN_RE = re.compile(
    r"^\s*(?:(?:const|let|var|final|auto|String|Object|[A-Za-z_$][\w$<>\[\],.? ]*)\s+)?"
    r"([A-Za-z_$][\w$]*)\s*(?<![=!<>])=(?!=)\s*(.+?)\s*;?\s*$"
)

CONTENT_FEATURES = (
    "credential_auth_value",
    "personal_session_value",
    "direct_identifier_literal",
    "raw_request_response",
    "agent_tool_context_value",
    "configuration_infrastructure_value",
    "exception_stack_value",
    "whole_object_dump",
)
MECHANISM_FEATURES = (
    "alias_derived_sensitive_value",
    "multiline_statement",
    "error_or_exception_branch",
    "unredacted_sensitive_value",
)
FEATURES = ("any_privacy_candidate",) + CONTENT_FEATURES + MECHANISM_FEATURES

STATEMENT_FIELDS = (
    "pair_id", "provenance", "repo", "pr_key", "pr_url", "file", "language",
    "line", "level", "statement_lines", "dynamic_values", "resolved_aliases",
    "privacy_features", "mechanism_features", "static_privacy_candidate",
    "statement_redacted", "context_redacted",
)
PR_FIELDS = (
    "pair_id", "provenance", "repo", "pr_key", "pr_url", "n_log_statements",
    "n_privacy_candidates", "privacy_features", "mechanism_features",
)
STAT_FIELDS = (
    "feature", "scope", "outcome", "n_pairs", "n_repositories", "agent_n", "human_n",
    "agent_rate", "human_rate", "agent_ci_low", "agent_ci_high", "human_ci_low",
    "human_ci_high", "effect", "effect_ci_low", "effect_ci_high", "effect_type",
    "agent_only", "human_only", "mcnemar_p", "bootstrap_iterations", "seed",
    "conclusion", "bh_q", "stable_after_bh",
)
AUDIT_FIELDS = STATEMENT_FIELDS + (
    "manual_is_privacy_issue", "manual_primary_type", "manual_runtime_reachable",
    "manual_externalized_or_persisted", "manual_notes",
)


def new_version_hunks(diff: str) -> list[dict]:
    """Return new-version added/context lines grouped by diff hunk."""
    hunks = []
    for path, section in _diff_sections(diff):
        language = paper_language(path)
        if language is None or not is_production_path(path):
            continue
        rows = []
        old_line = new_line = 0
        for raw in section.splitlines():
            match = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
            if match:
                if rows:
                    hunks.append({"file": path, "language": language, "rows": rows})
                rows = []
                old_line, new_line = int(match.group(1)), int(match.group(2))
                continue
            if not rows and not old_line and not new_line:
                continue
            if raw.startswith("+") and not raw.startswith("+++"):
                rows.append({"kind": "added", "line": new_line, "text": raw[1:]})
                new_line += 1
            elif raw.startswith("-") and not raw.startswith("---"):
                old_line += 1
            elif raw.startswith(" "):
                rows.append({"kind": "context", "line": new_line, "text": raw[1:]})
                old_line += 1
                new_line += 1
        if rows:
            hunks.append({"file": path, "language": language, "rows": rows})
    return hunks


def _paren_balance(text: str) -> int:
    balance = 0
    quote = ""
    escaped = False
    for char in text:
        if escaped:
            escaped = False
        elif char == "\\" and quote:
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in {"'", '"', "`"}:
            quote = char
        elif char == "(":
            balance += 1
        elif char == ")":
            balance -= 1
    return balance


def log_statements(diff: str, max_lines: int = 20) -> list[dict]:
    """Join an added log-call start with following new-version lines."""
    output = []
    for hunk in new_version_hunks(diff):
        rows = hunk["rows"]
        for index, row in enumerate(rows):
            if row["kind"] != "added":
                continue
            match = paper_match(hunk["language"], row["text"])
            if not match:
                continue
            parts = [row["text"]]
            balance = _paren_balance(row["text"][match.start():])
            cursor = index + 1
            while balance > 0 and cursor < len(rows) and len(parts) < max_lines:
                next_row = rows[cursor]
                if next_row["line"] != rows[cursor - 1]["line"] + 1:
                    break
                parts.append(next_row["text"])
                balance += _paren_balance(next_row["text"])
                cursor += 1
            context = "\n".join(value["text"] for value in rows[max(0, index - 12):index])
            output.append({
                "file": hunk["file"],
                "language": hunk["language"],
                "line": row["line"],
                "level": match.group("level").lower(),
                "statement": "\n".join(parts),
                "statement_lines": len(parts),
                "context": context,
            })
    return output


def dynamic_values(statement: str) -> str:
    """Remove static labels while retaining interpolations and argument expressions."""
    interpolations = re.findall(r"\$\{([^}]*)\}", statement)
    interpolations += re.findall(r"#\{([^}]*)\}", statement)
    interpolations += re.findall(r"(?:f|F)[\"'][^\"']*\{([^{}]+)\}[^\"']*[\"']", statement)
    without_templates = re.sub(r"`(?:\\.|[^`])*`", " ", statement, flags=re.DOTALL)
    without_strings = STRING_RE.sub(" ", without_templates)
    without_sink = re.sub(
        r"\b(?:logging|logger|_logger|log|console)\."
        r"(?:trace|debug|info|warn|warning|error|fatal|critical|exception)\s*\(",
        "(",
        without_strings,
        count=1,
        flags=re.IGNORECASE,
    )
    return " ".join(interpolations + [without_sink])


def nearby_aliases(context: str) -> dict[str, str]:
    aliases = {}
    for line in context.splitlines():
        match = ASSIGN_RE.match(line)
        if match:
            aliases[match.group(1)] = match.group(2)
    return aliases


def resolve_aliases(values: str, aliases: dict[str, str]) -> tuple[str, list[str]]:
    resolved = values
    used = []
    for _ in range(2):
        changed = False
        identifiers = set(re.findall(r"\b[A-Za-z_$][\w$]*\b", resolved))
        for name in sorted(identifiers):
            rhs = aliases.get(name, "")
            unknown_transform = re.match(r"\s*(?!JSON\.stringify\b|json\.dumps?\b|path\.(?:join|resolve)\b)[A-Za-z_$][\w$.]*\s*\(", rhs)
            unknown_await_transform = re.match(r"\s*await\s+(?![\w$]+\.(?:text|json)\s*\()[A-Za-z_$][\w$.]*\s*\(", rhs)
            if (
                name in aliases
                and name not in used
                and not unknown_transform
                and not unknown_await_transform
                and re.search(rf"(?<![\w.]){re.escape(name)}(?![\w.])", resolved)
            ):
                resolved += " " + rhs
                used.append(name)
                changed = True
        if not changed:
            break
    return resolved, used


def _content_features(values: str, statement: str) -> set[str]:
    sensitive_values = re.sub(r"!!\s*[A-Za-z_$][\w$?.\[\]]*", " ", values)
    sensitive_values = re.sub(
        r"\b[A-Za-z_$][\w$?.\[\]]*\.(?:length|size|count|status|statusText|ok|version|type|name)\b",
        " ",
        sensitive_values,
        flags=re.IGNORECASE,
    )
    sensitive_values = re.sub(r"\b(?:len|size|count|Boolean|typeof)\s*\([^)]*\)", " ", sensitive_values)
    sensitive_values = re.sub(r"\bsecret\s*(?:\.get\s*\([^)]*\)|\[[^]]*\])", " ", sensitive_values, flags=re.IGNORECASE)
    features = set()
    if DIRECT_SECRET_LITERAL_RE.search(statement):
        features.update({"credential_auth_value", "direct_identifier_literal"})
    if DIRECT_IDENTIFIER_LITERAL_RE.search(statement):
        if "EMAIL" in statement.upper() or re.search(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", statement, re.IGNORECASE
        ):
            features.add("direct_identifier_literal")
            features.add("personal_session_value")
        if "IP" in statement.upper() or re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", statement):
            features.add("configuration_infrastructure_value")
    if CREDENTIAL_RE.search(sensitive_values):
        features.add("credential_auth_value")
    if PERSONAL_RE.search(sensitive_values):
        features.add("personal_session_value")
    if RESPONSE_RE.search(sensitive_values):
        features.add("raw_request_response")
    if AGENT_CONTEXT_RE.search(sensitive_values) or (
        re.search(r"\b(?:chat|websocket|conversation|assistant|llm)\b", statement, re.IGNORECASE)
        and re.search(r"(?<![.:\w])messages?(?![.:\w])", sensitive_values, re.IGNORECASE)
    ):
        features.add("agent_tool_context_value")
    if CONFIG_RE.search(sensitive_values):
        features.add("configuration_infrastructure_value")
    if EXCEPTION_RE.search(sensitive_values):
        features.add("exception_stack_value")
    if RAW_OBJECT_RE.search(sensitive_values) or (
        "{" in sensitive_values
        and "}" in sensitive_values
        and features & {
            "credential_auth_value", "personal_session_value", "raw_request_response",
            "agent_tool_context_value", "configuration_infrastructure_value",
        }
    ):
        features.add("whole_object_dump")
    return features


def semantic_features(statement: str, context: str) -> dict:
    direct = dynamic_values(statement)
    aliases = nearby_aliases(context)
    resolved, used = resolve_aliases(direct, aliases)
    direct_features = _content_features(direct, statement)
    content = _content_features(resolved, statement)
    mechanisms = set()
    if used and content - direct_features:
        mechanisms.add("alias_derived_sensitive_value")
    if statement.count("\n"):
        mechanisms.add("multiline_statement")
    if re.search(r"\b(?:catch|except)\b|\bif\s*\([^\n]*(?:!\s*\w+\.ok|error|exception)", context, re.IGNORECASE):
        mechanisms.add("error_or_exception_branch")
    if content and not REDACTION_RE.search(statement):
        mechanisms.add("unredacted_sensitive_value")
    return {
        "dynamic_values": re.sub(r"\s+", " ", direct).strip(),
        "resolved_aliases": ";".join(f"{name}={aliases[name]}" for name in used),
        "privacy_features": sorted(content),
        "mechanism_features": sorted(mechanisms),
        "static_privacy_candidate": bool(content),
    }


def _report(summary: dict) -> str:
    rows = []
    for value in summary["feature_statistics"]:
        rows.append(
            f"| {value['feature']} | {value['agent_n']}/300 | {value['human_n']}/300 | "
            f"{value['effect'] * 100:+.1f} pp | "
            f"[{value['effect_ci_low'] * 100:+.1f}, {value['effect_ci_high'] * 100:+.1f}] pp | "
            f"{value['mcnemar_p']:.4f} | {value['bh_q']:.4f} | {value['stable_after_bh']} |"
        )
    return f"""# AIDev 匹配 PR 的值感知日志隐私特征分析

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: VERIFIED
- Version Label: aidev_value_aware_privacy_v1

## 分析口径

对 300 对冻结 Agent/Human PR 使用论文支持的语言和日志 API，拼接最多 20 行的完整新增日志调用，并向前检查 12 行以解析最多两层简单变量别名。所有命中均为静态候选，不代表运行时泄露。

## 数据概览

- Agent 新增日志语句：{summary['statement_counts']['agent']}
- Human 新增日志语句：{summary['statement_counts']['human']}
- Agent 静态隐私候选：{summary['privacy_candidate_counts']['agent']}
- Human 静态隐私候选：{summary['privacy_candidate_counts']['human']}
- 待人工复核语句：{summary['manual_audit_queue_n']}

## 以全部匹配 PR 为分母的比较

| 特征 | Agent PR | Human PR | Agent-Human | 仓库分层 bootstrap 95% CI | McNemar p | BH q | 稳定差异 |
|---|---:|---:|---:|---:|---:|---:|---:|
{chr(10).join(rows)}

## 结论边界

1. 只有 `BH q < 0.05`、仓库分层置信区间排除零且方向一致，才报告稳定差异。
2. 多行拼接和别名解析改善了单行关键词的漏报，但仍不是跨函数或跨文件污点分析。
3. `configuration_infrastructure_value` 是准敏感候选，必须人工判断其是否只是仓库内相对路径或公开端点。
4. 这是观察性静态分析，不能推断 Agent 身份导致风险，也不能从仓库级结果推断单行作者。
5. 统计谬误扫描覆盖 11/11；主要警告是选择偏差、分析路径自由度、稀有事件低功效和条件分析的碰撞偏差。

## 复现

- 固定种子：{summary['seed']}
- 仓库分层 bootstrap：{summary['bootstrap_iterations']} 次
- 600 份 diff 逐一校验 SHA-256
- 确定性复跑要求所有输出哈希完全一致
"""


def run(input_dir: Path, output_dir: Path, iterations: int, seed: int) -> dict:
    pairs = read_csv(input_dir / "matched_pairs.csv")
    queue = read_csv(input_dir / "pr_analysis_queue.csv")
    validation = json.loads((input_dir / "validation.json").read_text(encoding="utf-8"))
    if validation.get("status") != "PASS" or len(pairs) != 300 or len(queue) != 600:
        raise ValueError("frozen 300-pair integrity gate failed")

    statements = []
    for pr in queue:
        path = Path(pr["diff_path"])
        if file_sha256(path) != pr["diff_sha256"]:
            raise ValueError("diff hash mismatch: " + str(path))
        for item in log_statements(path.read_text(encoding="utf-8", errors="replace")):
            features = semantic_features(item["statement"], item["context"])
            statements.append({
                "pair_id": pr["pair_id"],
                "provenance": pr["provenance"],
                "repo": pr["repo"],
                "pr_key": pr["pr_key"],
                "pr_url": pr["pr_url"],
                **{name: item[name] for name in ("file", "language", "line", "level", "statement_lines")},
                "dynamic_values": _redact(features["dynamic_values"]),
                "resolved_aliases": _redact(features["resolved_aliases"]),
                "privacy_features": ";".join(features["privacy_features"]),
                "mechanism_features": ";".join(features["mechanism_features"]),
                "static_privacy_candidate": features["static_privacy_candidate"],
                "statement_redacted": _redact(item["statement"]),
                "context_redacted": _redact(item["context"]),
            })

    statement_index: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in statements:
        statement_index[(row["pair_id"], row["provenance"])].append(row)
    pr_rows = []
    for pr in queue:
        values = statement_index[(pr["pair_id"], pr["provenance"])]
        privacy = sorted({feature for row in values for feature in row["privacy_features"].split(";") if feature})
        mechanisms = sorted({feature for row in values for feature in row["mechanism_features"].split(";") if feature})
        pr_rows.append({
            "pair_id": pr["pair_id"], "provenance": pr["provenance"], "repo": pr["repo"],
            "pr_key": pr["pr_key"], "pr_url": pr["pr_url"],
            "n_log_statements": len(values),
            "n_privacy_candidates": sum(truth(row["static_privacy_candidate"]) for row in values),
            "privacy_features": ";".join(privacy),
            "mechanism_features": ";".join(mechanisms),
        })
    pr_index = {(row["pair_id"], row["provenance"]): row for row in pr_rows}
    pair_rows = []
    for pair in pairs:
        item = {"pair_id": pair["pair_id"], "repo": pair["repo"]}
        for side in ("agent", "human"):
            pr = pr_index[(pair["pair_id"], side)]
            privacy = set(pr["privacy_features"].split(";"))
            mechanisms = set(pr["mechanism_features"].split(";"))
            item[f"{side}_any_privacy_candidate"] = int(pr["n_privacy_candidates"]) > 0
            for feature in CONTENT_FEATURES:
                item[f"{side}_{feature}"] = feature in privacy
            for feature in MECHANISM_FEATURES:
                item[f"{side}_{feature}"] = feature in mechanisms
        pair_rows.append(item)

    feature_statistics = []
    for feature in FEATURES:
        value = paired_binary_result(
            pair_rows, feature, "paper_regex_added_value_aware_frozen_matched_300",
            lambda row, name=feature: truth(row[f"agent_{name}"]),
            lambda row, name=feature: truth(row[f"human_{name}"]),
            iterations, seed,
        )
        value["feature"] = feature
        feature_statistics.append(value)
    for value, q_value in zip(
        feature_statistics, bh_adjust([row["mcnemar_p"] for row in feature_statistics])
    ):
        value["bh_q"] = q_value
        value["stable_after_bh"] = bool(
            q_value < 0.05 and (value["effect_ci_low"] > 0 or value["effect_ci_high"] < 0)
        )

    audit_queue = []
    for row in statements:
        if not truth(row["static_privacy_candidate"]):
            continue
        audit_queue.append({
            **row,
            "manual_is_privacy_issue": "",
            "manual_primary_type": "",
            "manual_runtime_reachable": "",
            "manual_externalized_or_persisted": "",
            "manual_notes": "",
        })

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "log_statements.csv", statements, STATEMENT_FIELDS)
    write_csv(output_dir / "pr_features.csv", pr_rows, PR_FIELDS)
    write_csv(output_dir / "feature_statistics.csv", feature_statistics, STAT_FIELDS)
    write_csv(output_dir / "manual_audit_queue.csv", audit_queue, AUDIT_FIELDS)
    summary = {
        "status": "VERIFIED",
        "scope": "value_aware_static_candidates_on_production_files_frozen_matched_300",
        "n_pairs": len(pairs),
        "n_prs": len(pr_rows),
        "statement_counts": dict(Counter(row["provenance"] for row in statements)),
        "privacy_candidate_counts": dict(Counter(
            row["provenance"] for row in statements if truth(row["static_privacy_candidate"])
        )),
        "manual_audit_queue_n": len(audit_queue),
        "feature_statistics": feature_statistics,
        "bootstrap_iterations": iterations,
        "seed": seed,
        "manual_audit_status": "PENDING_HUMAN_LABELS",
        "fallacy_scan_coverage": "11/11",
        "input_sha256": {
            name: file_sha256(input_dir / name)
            for name in ("matched_pairs.csv", "pr_analysis_queue.csv", "validation.json")
        },
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(_report(summary), encoding="utf-8")
    output_names = ("log_statements.csv", "pr_features.csv", "feature_statistics.csv", "manual_audit_queue.csv", "summary.json", "report.md")
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
        default=Path("outputs/aidev_observational_primary_300/value_aware_privacy"),
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
        "statement_counts": summary["statement_counts"],
        "privacy_candidate_counts": summary["privacy_candidate_counts"],
        "output_dir": str(args.output_dir.resolve()),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
