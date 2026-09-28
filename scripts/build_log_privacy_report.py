import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.analyze_swe_chat_multilingual_logs import risk_for_text


RES_DIR = ROOT / "data" / "res"
OUT_DIR = RES_DIR / "log_privacy_report"

SWE_CANDIDATES = RES_DIR / "swe_chat_multilingual_logs" / "swe_chat_multilingual_log_candidates.csv"
DEVGPT_CANDIDATES = RES_DIR / "devgpt_logs" / "devgpt_log_candidates.csv"
AIDEV_CHANGES_DIR = RES_DIR / "aidev_log_changes"


COMMIT_CATEGORY_PATTERNS = {
    "explicit privacy/leak/sensitive wording": r"\b(privac\w*|pii|personal data|sensitive|leak\w*|expos\w*|gdpr|confidential)\b",
    "redaction/masking/sanitization": r"\b(redact\w*|mask\w*|sanitize\w*|sanitise\w*|anonym\w*|obfuscat\w*)\b",
    "credential/token/auth material": r"\b(secret\w*|token\w*|password\w*|credential\w*|api[_ -]?key\w*|jwt|cookie\w*|authorization|bearer)\b",
    "logging/debug/output mention": r"\b(log|logging|logger|debug|trace|console|print|stdout|stderr)\b",
}

PROMPT_CATEGORY_PATTERNS = {
    "debug/error/logging task": r"\b(debug|error|exception|bug|fix|fail|failure|trace|log|logging|logger|console|print)\b",
    "API/request/response handling": r"\b(api|http|request|response|header|body|payload|endpoint|client|server|webhook|route)\b",
    "auth/secrets/session context": r"\b(auth|oauth|token|secret|password|credential|jwt|cookie|session|api key|bearer)\b",
    "user/account/PII context": r"\b(user|account|email|phone|address|profile|customer|personal|pii)\b",
    "data/file/DB transformation": r"\b(database|sql|db|file|csv|json|upload|download|import|export|etl|pandas|dataframe)\b",
    "observability/instrumentation": r"\b(observability|telemetry|metric|monitor|audit|instrument)\b",
}

MODULE_CATEGORY_PATTERNS = [
    ("auth/security", r"auth|oauth|jwt|token|session|login|password|credential|security|permission|acl|identity|key"),
    ("api/http boundary", r"api|http|request|response|route|controller|handler|endpoint|client|server|middleware|webhook|grpc"),
    ("data/storage/user records", r"database|db|sql|model|entity|repository|store|storage|user|account|profile|customer|email"),
    ("config/env/deploy", r"config|env|secret|setting|docker|kubernetes|helm|deploy|container|infra"),
    ("observability/debugging", r"log|logger|logging|trace|telemetry|metric|monitor|debug"),
    ("tests/examples", r"test|spec|mock|fixture|example|demo|sample"),
    ("cli/tools", r"cli|cmd|command|script|tool|shell"),
]


def read_csv(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, dtype=str).fillna("")


def pct(numerator: int | float, denominator: int | float) -> float:
    return round((float(numerator) * 100.0 / float(denominator)), 2) if denominator else 0.0


def compact(text: object, limit: int = 240) -> str:
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    return value[: limit - 1] + "…" if len(value) > limit else value


def categories_for(text: object, patterns: dict[str, str]) -> list[str]:
    lower = str(text or "").lower()
    return [name for name, pattern in patterns.items() if re.search(pattern, lower)]


def module_category(file_path: object, log_text: object) -> str:
    haystack = f"{file_path or ''} {log_text or ''}".lower()
    for name, pattern in MODULE_CATEGORY_PATTERNS:
        if re.search(pattern, haystack):
            return name
    return "other application code"


def flatten_aidev() -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for path in sorted(AIDEV_CHANGES_DIR.glob("*_log_changes.json")):
        repo = path.name.replace("_log_changes.json", "").replace("__", "/")
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data:
            file_path = item.get("file_path", "")
            base_log = item.get("logging_statement", "")
            for change in item.get("changes", []):
                log_text = change.get("new_content") or change.get("old_content") or base_log
                risk_level, keywords = risk_for_text(log_text or "")
                rows.append(
                    {
                        "dataset": "AIDev",
                        "repo": repo,
                        "file": file_path,
                        "line": change.get("new_content_start_line")
                        or change.get("old_content_start_line")
                        or item.get("logging_statement_begin_line"),
                        "add_remove": change.get("change_type", ""),
                        "attribution": "unknown_git_history",
                        "risk_level": risk_level,
                        "sensitive_keywords": ";".join(keywords),
                        "log_text": log_text or "",
                        "commit": change.get("commit_hash", ""),
                        "commit_message": change.get("commit_message", ""),
                        "author_date": change.get("commit_time", ""),
                    }
                )
    return pd.DataFrame(rows).fillna("")


def risk_distribution(frames: list[pd.DataFrame]) -> list[dict[str, object]]:
    rows = []
    order = ["low", "medium", "high"]
    for df in frames:
        dataset = df["dataset"].iloc[0]
        total = len(df)
        counts = df["risk_level"].value_counts().to_dict()
        for risk in order:
            count = int(counts.get(risk, 0))
            rows.append({"dataset": dataset, "risk_level": risk, "rows": count, "share": pct(count, total)})
    return rows


def ai_source_risk(swe: pd.DataFrame, dev: pd.DataFrame) -> list[dict[str, object]]:
    slices = [
        ("SWE-chat", "agent_only committed patch rows", swe[swe["attribution"] == "agent_only"]),
        ("SWE-chat", "agent_only + mixed patch rows", swe[swe["attribution"].isin(["agent_only", "mixed"])]),
        ("DevGPT", "ChatGPT answer code", dev[dev["attribution"] == "chatgpt_answer"]),
        ("DevGPT", "committed file in DevGPT share", dev[dev["attribution"] == "committed_file"]),
    ]
    rows = []
    for dataset, source, df in slices:
        high = int((df["risk_level"] == "high").sum())
        medhi = int(df["risk_level"].isin(["medium", "high"]).sum())
        rows.append(
            {
                "dataset": dataset,
                "source": source,
                "rows": int(len(df)),
                "medium_or_high": medhi,
                "high": high,
                "medium_or_high_rate": pct(medhi, len(df)),
                "high_rate": pct(high, len(df)),
            }
        )
    return rows


def human_ai_change_summary(swe: pd.DataFrame) -> list[dict[str, object]]:
    labels = [
        "confirmed_by_version_diff_human_removed_ai_log",
        "confirmed_by_version_diff_human_modified_ai_log",
        "likely_human_added_log_in_mixed_file",
        "same_file_agent_log_edit_needs_manual_review",
        "mixed_file_agent_log_unchanged",
    ]
    rows = []
    for label in labels:
        df = swe[swe["manual_review_label"] == label]
        rows.append(
            {
                "label": label,
                "rows": int(len(df)),
                "medium_or_high": int(df["risk_level"].isin(["medium", "high"]).sum()),
                "high": int((df["risk_level"] == "high").sum()),
            }
        )
    return rows


def commit_message_summary(frames: list[pd.DataFrame]) -> list[dict[str, object]]:
    rows = []
    for df in frames:
        dataset = df["dataset"].iloc[0]
        commits = df[(df["commit"].astype(str) != "") | (df["commit_message"].astype(str) != "")]
        commits = commits.drop_duplicates(["commit", "commit_message"]).copy()
        total = len(commits)
        per_category = Counter()
        direct_commit_ids = set()
        related_commit_ids = set()
        for idx, row in commits.reset_index(drop=True).iterrows():
            cats = categories_for(row["commit_message"], COMMIT_CATEGORY_PATTERNS)
            if cats:
                related_commit_ids.add(idx)
            if any(cat != "logging/debug/output mention" for cat in cats):
                direct_commit_ids.add(idx)
            for cat in cats:
                per_category[cat] += 1
        for category, count in per_category.items():
            rows.append(
                {
                    "dataset": dataset,
                    "category": category,
                    "commits": int(count),
                    "total_candidate_commits": int(total),
                    "share_of_candidate_commits": pct(count, total),
                }
            )
        rows.append(
            {
                "dataset": dataset,
                "category": "direct privacy/security-related commit message",
                "commits": int(len(direct_commit_ids)),
                "total_candidate_commits": int(total),
                "share_of_candidate_commits": pct(len(direct_commit_ids), total),
            }
        )
        rows.append(
            {
                "dataset": dataset,
                "category": "any logging/privacy/security-related commit message",
                "commits": int(len(related_commit_ids)),
                "total_candidate_commits": int(total),
                "share_of_candidate_commits": pct(len(related_commit_ids), total),
            }
        )
    return rows


def prompt_category_summary(swe: pd.DataFrame, dev: pd.DataFrame) -> list[dict[str, object]]:
    rows = []
    for dataset, df in [("SWE-chat", swe), ("DevGPT", dev)]:
        prompt_rows = df[df["user_log_reason_excerpt"].astype(str) != ""].copy()
        expanded = []
        for idx, row in prompt_rows.iterrows():
            cats = categories_for(row["user_log_reason_excerpt"], PROMPT_CATEGORY_PATTERNS)
            if not cats:
                cats = ["no explicit prompt pattern"]
            for cat in cats:
                expanded.append({"dataset": dataset, "row_id": idx, "category": cat, "risk_level": row["risk_level"]})
        exp = pd.DataFrame(expanded)
        for category, group in exp.groupby("category", sort=False):
            unique_rows = group["row_id"].nunique()
            medhi = int(group["risk_level"].isin(["medium", "high"]).sum())
            high = int((group["risk_level"] == "high").sum())
            rows.append(
                {
                    "dataset": dataset,
                    "category": category,
                    "rows": int(unique_rows),
                    "medium_or_high": medhi,
                    "high": high,
                    "medium_or_high_rate": pct(medhi, unique_rows),
                }
            )
    return rows


def module_summary(frames: list[pd.DataFrame]) -> list[dict[str, object]]:
    all_rows = []
    for df in frames:
        tmp = df[["dataset", "file", "risk_level", "log_text"]].copy()
        tmp["module"] = tmp.apply(lambda row: module_category(row["file"], row["log_text"]), axis=1)
        all_rows.append(tmp)
    combined = pd.concat(all_rows, ignore_index=True)
    rows = []
    for module, group in combined.groupby("module"):
        medhi = int(group["risk_level"].isin(["medium", "high"]).sum())
        high = int((group["risk_level"] == "high").sum())
        rows.append(
            {
                "module": module,
                "rows": int(len(group)),
                "medium_or_high": medhi,
                "high": high,
                "medium_or_high_rate": pct(medhi, len(group)),
            }
        )
    return sorted(rows, key=lambda row: row["medium_or_high"], reverse=True)


def example_ai_logs(swe: pd.DataFrame, dev: pd.DataFrame) -> list[dict[str, object]]:
    swe_examples = swe[
        (swe["attribution"].isin(["agent_only", "mixed"]))
        & (swe["risk_level"].isin(["high", "medium"]))
    ].copy()
    swe_examples["candidate_source"] = swe_examples["attribution"]
    dev_examples = dev[
        (dev["attribution"] == "chatgpt_answer")
        & (dev["risk_level"].isin(["high", "medium"]))
    ].copy()
    candidates = pd.concat(
        [
            swe_examples.assign(dataset="SWE-chat"),
            dev_examples.assign(dataset="DevGPT"),
        ],
        ignore_index=True,
        sort=False,
    )
    candidates["risk_order"] = candidates["risk_level"].map({"high": 0, "medium": 1, "low": 2}).fillna(9)
    candidates = candidates.sort_values(["risk_order", "dataset", "repo", "file"]).head(12)
    rows = []
    for _, row in candidates.iterrows():
        rows.append(
            {
                "dataset": row.get("dataset", ""),
                "source": row.get("candidate_source", row.get("attribution", "")),
                "risk_level": row.get("risk_level", ""),
                "keywords": compact(row.get("sensitive_keywords", ""), 80),
                "file": compact(row.get("file", ""), 90),
                "log_text": compact(row.get("log_text", ""), 180),
            }
        )
    return rows


def manifest_and_snapshot(tables: dict[str, list[dict[str, object]]]) -> tuple[dict, dict]:
    generated_at = datetime.now(timezone.utc).isoformat()

    def chart_source(dataset: str, description: str) -> dict[str, object]:
        return {
            "id": f"{dataset}_source",
            "label": "Local res aggregation",
            "path": "data/res/log_privacy_report/analysis_tables.json",
            "query": {
                "language": "sql",
                "description": description,
                "sql": f"SELECT * FROM {dataset};",
                "tables_used": [
                    "data/res/aidev_log_changes",
                    "data/res/swe_chat_multilingual_logs/swe_chat_multilingual_log_candidates.csv",
                    "data/res/devgpt_logs/devgpt_log_candidates.csv",
                ],
            },
        }

    manifest = {
        "version": 1,
        "surface": "report",
        "title": "AI 生成日志的隐私风险分析",
        "description": "基于 AIDev、SWE-chat、DevGPT 三套日志分析结果的跨数据集报告。",
        "generatedAt": generated_at,
        "sources": [
            {
                "id": "aidev_log_changes",
                "label": "AIDev log change JSON",
                "path": "data/res/aidev_log_changes",
            },
            {
                "id": "swe_chat_multilingual_logs",
                "label": "SWE-chat multilingual log candidates",
                "path": "data/res/swe_chat_multilingual_logs",
            },
            {
                "id": "devgpt_logs",
                "label": "DevGPT log candidates",
                "path": "data/res/devgpt_logs",
            },
        ],
        "charts": [
            {
                "id": "risk_by_dataset",
                "title": "日志候选的风险等级分布",
                "type": "bar",
                "source": chart_source("risk_by_dataset", "Risk-level row counts by source dataset."),
                "dataset": "risk_by_dataset",
                "encodings": {
                    "x": {"field": "dataset"},
                    "y": {"field": "rows"},
                    "color": {"field": "risk_level"},
                },
                "options": {"orientation": "vertical", "grouping": "stacked"},
            },
            {
                "id": "ai_source_risk",
                "title": "AI 相关日志候选的中高风险占比",
                "type": "bar",
                "source": chart_source("ai_source_risk", "Medium/high risk rates for AI-attributed or AI-associated log candidate slices."),
                "dataset": "ai_source_risk",
                "encodings": {
                    "x": {"field": "source"},
                    "y": {"field": "medium_or_high_rate"},
                    "color": {"field": "dataset"},
                },
                "options": {"orientation": "horizontal", "grouping": "grouped"},
            },
            {
                "id": "commit_privacy",
                "title": "commit message 显式提及隐私或安全相关问题的占比",
                "type": "bar",
                "source": chart_source("commit_privacy_direct", "Share of candidate commits whose commit message directly references privacy or security categories."),
                "dataset": "commit_privacy_direct",
                "encodings": {
                    "x": {"field": "dataset"},
                    "y": {"field": "share_of_candidate_commits"},
                },
                "options": {"orientation": "vertical"},
            },
            {
                "id": "prompt_risk",
                "title": "更容易伴随中高风险日志的 Prompt 类型",
                "type": "bar",
                "source": chart_source("prompt_categories_top", "Prompt category rows ranked by high and medium/high risk concentration."),
                "dataset": "prompt_categories_top",
                "encodings": {
                    "x": {"field": "category"},
                    "y": {"field": "medium_or_high_rate"},
                    "color": {"field": "dataset"},
                },
                "options": {"orientation": "horizontal", "grouping": "grouped"},
            },
            {
                "id": "module_risk",
                "title": "中高风险日志集中的代码模块",
                "type": "bar",
                "source": chart_source("module_summary", "Module categories inferred from file paths and log text, summarized by medium/high risk rows."),
                "dataset": "module_summary",
                "encodings": {
                    "x": {"field": "module"},
                    "y": {"field": "medium_or_high"},
                },
                "options": {"orientation": "horizontal"},
            },
        ],
        "tables": [
            {
                "id": "human_ai_changes",
                "title": "SWE-chat 中人类对 AI 日志的修改证据",
                "source": chart_source("human_ai_changes", "Manual review label counts for SWE-chat mixed attribution rows."),
                "dataset": "human_ai_changes",
                "columns": [
                    {"field": "label", "label": "Review Label", "type": "text"},
                    {"field": "rows", "label": "Rows", "type": "number"},
                    {"field": "medium_or_high", "label": "Medium/High Rows", "type": "number"},
                    {"field": "high", "label": "High Rows", "type": "number"},
                ],
            },
            {
                "id": "example_ai_logs",
                "title": "AI 生成或 AI 相关日志的代表性敏感输出候选",
                "source": chart_source("example_ai_logs", "Representative high and medium risk AI-generated or AI-associated log candidates."),
                "dataset": "example_ai_logs",
                "columns": [
                    {"field": "dataset", "label": "Dataset", "type": "text"},
                    {"field": "source", "label": "Source", "type": "text"},
                    {"field": "risk_level", "label": "Risk", "type": "text"},
                    {"field": "keywords", "label": "Keywords", "type": "text"},
                    {"field": "file", "label": "File", "type": "text"},
                    {"field": "log_text", "label": "Log Text", "type": "text"},
                ],
            },
            {
                "id": "commit_message_categories",
                "title": "commit message 相关分类",
                "source": chart_source("commit_message_categories", "Commit-message keyword categories for commits associated with log candidates."),
                "dataset": "commit_message_categories",
                "columns": [
                    {"field": "dataset", "label": "Dataset", "type": "text"},
                    {"field": "category", "label": "Category", "type": "text"},
                    {"field": "commits", "label": "Commits", "type": "number"},
                    {"field": "total_candidate_commits", "label": "Total Candidate Commits", "type": "number"},
                    {"field": "share_of_candidate_commits", "label": "Share (%)", "type": "number"},
                ],
            },
        ],
        "blocks": [
            {"id": "title", "type": "markdown", "body": "# AI 生成日志的隐私风险分析"},
            {
                "id": "executive_summary",
                "type": "markdown",
                "body": (
                    "## Executive Summary\n\n"
                    "- **人类确实会修改 AI 相关日志，但强证据主要来自 SWE-chat。** 在混合归因文件的人工复核标签中，"
                    "有 312 行确认是人类删除 AI 日志，166 行确认是人类修改 AI 日志；AIDev 只能作为一般 Git 历史对照，"
                    "DevGPT 的 ChatGPT answer code 只能证明 AI 生成过日志候选，不能单独证明被提交。\n"
                    "- **AI 生成日志存在运行时敏感输出风险。** SWE-chat `agent_only` 日志中 23.03% 为 medium/high 风险；"
                    "DevGPT ChatGPT answer code 中 13.75% 为 medium/high 风险，且 high 风险占 1.07%。常见关键词集中在 "
                    "`error`、`response`、`user`、`session`、`token`、`address` 等运行时对象。\n"
                    "- **最容易触发隐私风险的 Prompt 是调试/报错、API 请求响应、auth/session/secrets、user/account/PII 场景。** "
                    "尤其在 DevGPT 中，`auth/secrets/session context` 和 `user/account/PII context` 对应的中高风险率接近六成。\n"
                    "- **commit message 很少直接把问题表述为隐私泄露。** 三套数据中，直接隐私/安全相关 commit message 占比约为 "
                    "AIDev 4.59%、SWE-chat 2.29%、DevGPT 0.20%；更多提交只写 debug/logging/fix，而不是写明 privacy leak。"
                ),
            },
            {
                "id": "scope",
                "type": "markdown",
                "body": (
                    "## 分析口径\n\n"
                    "本报告把日志候选分为三种证据层级：SWE-chat 的 `agent_only` 是提交级 AI 归因强证据，`mixed` 需要依赖人工复核标签；"
                    "DevGPT 的 `chatgpt_answer_code` 是 AI 生成证据，但本地数据没有 patch 链路来证明每一行都进入仓库；"
                    "AIDev 的逐仓库 JSON 记录 Git 历史中的日志增改删，但没有直接 AI attribution，因此主要用于观察人类提交如何改日志和 commit message 如何描述原因。"
                ),
            },
            {
                "id": "risk_chart_intro",
                "type": "markdown",
                "body": (
                    "## 敏感输出风险不是少数孤例\n\n"
                    "三套结果都出现了 medium/high 风险日志候选。medium/high 的含义不是已经泄露真实数据，"
                    "而是日志语句在运行时可能输出 request/response/body/user/session/token 等对象或字段，需要人工确认其上下文、脱敏和日志级别。"
                ),
            },
            {"id": "risk_by_dataset_block", "type": "chart", "chartId": "risk_by_dataset"},
            {
                "id": "ai_source_risk_intro",
                "type": "markdown",
                "body": (
                    "## AI 生成日志的运行时风险主要来自动态对象输出\n\n"
                    "SWE-chat 中，`agent_only` 候选的 medium/high 风险率为 23.03%；如果把 `mixed` 一并纳入 AI 相关候选，"
                    "中高风险率仍为 23.00%。DevGPT 中，ChatGPT answer code 的中高风险率为 13.75%，但 high 风险率更高，"
                    "说明回答代码中更常直接出现 token、secret、address 等敏感词或动态对象。"
                ),
            },
            {"id": "ai_source_risk_block", "type": "chart", "chartId": "ai_source_risk"},
            {
                "id": "human_change_intro",
                "type": "markdown",
                "body": (
                    "## 人类修改 AI 日志的原因更像安全收敛和行为修正\n\n"
                    "SWE-chat 的强证据显示，人类会删除或改写 AI 生成日志，尤其是把可能输出错误对象、会话、token、请求响应上下文的日志改掉。"
                    "这类修改不总在 commit message 中被写成“隐私泄露修复”；更多时候被包装在 bug fix、debug 行为修正、鉴权重构或日志清理中。"
                ),
            },
            {"id": "human_ai_changes_block", "type": "table", "tableId": "human_ai_changes"},
            {
                "id": "examples_intro",
                "type": "markdown",
                "body": (
                    "## 代表性 AI 日志候选需要人工判断脱敏边界\n\n"
                    "下表展示的是 high/medium 风险的代表性候选。它们通常并非把密钥字面量写进源码，"
                    "而是可能在运行时打印包含敏感字段的对象、响应、session、headers 或 token。"
                ),
            },
            {"id": "example_ai_logs_block", "type": "table", "tableId": "example_ai_logs"},
            {
                "id": "prompt_intro",
                "type": "markdown",
                "body": (
                    "## Prompt 风险集中在调试、API 边界和用户数据上下文\n\n"
                    "Prompt 中出现 debug/error/logging 往往会诱导模型添加可观测性输出；"
                    "当任务同时涉及 auth/session/secrets、request/response 或 user/account/PII 时，"
                    "模型更容易把运行时对象放进日志。DevGPT 的 `auth/secrets/session context` 与 `user/account/PII context` "
                    "样本中，中高风险率分别为 58.0% 和 57.3%。"
                ),
            },
            {"id": "prompt_risk_block", "type": "chart", "chartId": "prompt_risk"},
            {
                "id": "commit_intro",
                "type": "markdown",
                "body": (
                    "## commit message 很少直接承认隐私泄露\n\n"
                    "如果只看 commit message，隐私风险会被明显低估。AIDev 中直接隐私/安全相关表述占 4.59%，"
                    "SWE-chat 为 2.29%，DevGPT 为 0.20%。因此，研究中不能只依赖 commit message 标注；"
                    "需要结合日志文本、代码位置、变量名和 patch 方向。"
                ),
            },
            {"id": "commit_privacy_block", "type": "chart", "chartId": "commit_privacy"},
            {"id": "commit_message_categories_block", "type": "table", "tableId": "commit_message_categories"},
            {
                "id": "module_intro",
                "type": "markdown",
                "body": (
                    "## 高风险模块主要在系统边界和身份上下文\n\n"
                    "按路径和日志文本做模块归类后，中高风险数量最多的是 API/HTTP 边界，其次是 auth/security。"
                    "auth/security 的中高风险率最高，达到 37.8%；API/HTTP 边界为 26.2%。"
                    "这些位置天然接触 request、response、headers、token、session、user 等对象，是日志隐私治理的优先审查区域。"
                ),
            },
            {"id": "module_risk_block", "type": "chart", "chartId": "module_risk"},
            {
                "id": "recommendations",
                "type": "markdown",
                "body": (
                    "## Recommended Next Steps\n\n"
                    "1. **把日志审查规则前移到 AI 代码生成阶段。** Prompt 或系统指令中应明确禁止打印完整 request/response/body/header/session/token/user 对象，"
                    "并要求只输出稳定事件名、脱敏 id、计数和错误类别。\n"
                    "2. **对 API 边界和 auth/security 模块做优先人工复核。** 这些模块的风险率和风险数量同时偏高，适合先做抽样审计。\n"
                    "3. **补强 commit message 之外的标注。** privacy leak 很少被直接写进 commit message，后续研究应把代码变量、日志参数、patch 方向、"
                    "人工复核标签合并成最终标签。"
                ),
            },
            {
                "id": "further_questions",
                "type": "markdown",
                "body": (
                    "## Further Questions\n\n"
                    "- DevGPT 中哪些 ChatGPT answer code 最终进入了真实 commit？需要补充 answer-code 到 patch 的匹配链路。\n"
                    "- AIDev 是否能恢复 AI 生成 attribution？如果不能，它只能作为人类日志维护基线，而不能用于 AI 生成日志的因果判断。\n"
                    "- medium 风险中有多少实际经过脱敏或仅输出固定字符串？需要对 high/medium 样本做更细的人审标签。"
                ),
            },
            {
                "id": "caveats",
                "type": "markdown",
                "body": (
                    "## Caveats And Assumptions\n\n"
                    "本报告使用关键词和动态输出启发式识别敏感输出风险；它能发现候选，但不能替代运行时数据流审计。"
                    "AIDev 没有 AI attribution，DevGPT 没有完整 patch 链路，SWE-chat 的 mixed 文件仍有一部分需要人工确认。"
                    "因此结论应理解为日志隐私风险候选分析，而不是已经确认的真实数据泄露事件清单。"
                ),
            },
        ],
    }
    snapshot = {"version": 1, "status": "ready", "generatedAt": generated_at, "datasets": tables}
    return manifest, snapshot


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    swe = read_csv(SWE_CANDIDATES)
    swe["dataset"] = "SWE-chat"
    dev = read_csv(DEVGPT_CANDIDATES)
    dev["dataset"] = "DevGPT"
    aidev = flatten_aidev()

    tables: dict[str, list[dict[str, object]]] = {}
    tables["risk_by_dataset"] = risk_distribution([aidev, swe, dev])
    tables["ai_source_risk"] = ai_source_risk(swe, dev)
    tables["human_ai_changes"] = human_ai_change_summary(swe)
    commit_rows = commit_message_summary([aidev, swe, dev])
    tables["commit_message_categories"] = commit_rows
    tables["commit_privacy_direct"] = [
        row for row in commit_rows if row["category"] == "direct privacy/security-related commit message"
    ]
    prompt_rows = prompt_category_summary(swe, dev)
    tables["prompt_categories"] = prompt_rows
    tables["prompt_categories_top"] = sorted(
        [row for row in prompt_rows if row["category"] != "no explicit prompt pattern"],
        key=lambda row: (row["high"], row["medium_or_high"], row["medium_or_high_rate"]),
        reverse=True,
    )[:10]
    tables["module_summary"] = module_summary([aidev, swe, dev])
    tables["example_ai_logs"] = example_ai_logs(swe, dev)

    manifest, snapshot = manifest_and_snapshot(tables)
    payload = {"manifest": manifest, "snapshot": snapshot, "surface": "report"}

    (OUT_DIR / "report_payload.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT_DIR / "analysis_tables.json").write_text(json.dumps(tables, ensure_ascii=False, indent=2), encoding="utf-8")

    summary = {
        "aidev_rows": int(len(aidev)),
        "swe_rows": int(len(swe)),
        "devgpt_rows": int(len(dev)),
        "swe_confirmed_human_changed_ai_log_rows": int(
            swe["manual_review_label"]
            .isin(
                [
                    "confirmed_by_version_diff_human_removed_ai_log",
                    "confirmed_by_version_diff_human_modified_ai_log",
                ]
            )
            .sum()
        ),
        "outputs": {
            "report_payload": str(OUT_DIR / "report_payload.json"),
            "analysis_tables": str(OUT_DIR / "analysis_tables.json"),
        },
    }
    (OUT_DIR / "analysis_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
