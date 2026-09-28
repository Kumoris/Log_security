#!/usr/bin/env python3
"""Mine reproducible Agent-associated log privacy feature candidates."""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.analyze_coding_agent_log_leakage import (
    benjamini_hochberg,
    is_production_path,
    odds_ratio,
    percentile,
    two_proportion_p,
    wilson_interval,
)
from scripts.analyze_devgpt_logs import is_executable_log_line
from scripts.analyze_swe_chat_multilingual_logs import is_log_line, is_source_file


CONCEPT_ALIASES = {
    "prompt": r"\b(?:system_|developer_)?prompt\b",
    "messages": r"\b(?:system_message|developer_message|chat_messages?|llm_messages?)\b",
    "conversation": r"\b(?:conversation|chat_history)\b",
    "tool_input": r"\btool_(?:input|arguments?)\b",
    "tool_output": r"\btool_(?:result|output)\b",
    "model_output": r"\b(?:model|llm|assistant)_(?:response|output)\b",
    "context": r"\b(?:model_context|context_window|agent_state|agent_memory|long_term_memory)\b",
    "request": r"\brequests?\b",
    "response": r"\bresponses?\b",
    "payload": r"\bpayload\b",
    "body": r"\bbody\b",
    "headers": r"\bheaders?\b",
    "token": r"\b(?:access_|refresh_)?tokens?\b",
    "secret": r"\bsecrets?\b",
    "credential": r"\bcredentials?\b",
    "api_key": r"\bapi[_ -]?keys?\b",
    "password": r"\bpasswords?\b",
    "cookie": r"\bcookies?\b",
    "environment": r"\b(?:env(?:ironment)?(?:_vars?)?|process\.env)\b",
    "config": r"\bconfig(?:uration)?\b",
    "user": r"\b(?:users?|user_id)\b",
    "session": r"\b(?:sessions?|session_id)\b",
    "email": r"\be-?mails?\b",
    "ip": r"\bip(?:_address|addr)?\b",
    "path": r"\b(?:file_)?paths?\b",
    "error": r"\b(?:errors?|exceptions?|tracebacks?|stack_trace)\b",
}

AGENT_CONTROL = {"messages", "tool_input", "tool_output", "model_output", "context"}
BROAD_AGENT_CONTEXT = {"prompt", "conversation"}
TOOL_IO = {"tool_input", "tool_output"}
AUTH_CONFIG = {"token", "secret", "credential", "api_key", "password", "cookie", "environment", "config"}
REQUEST_RESPONSE = {"request", "response", "payload", "body", "headers"}
IDENTITY_SESSION = {"user", "session", "email", "ip", "path"}
OVERLAP_CONCEPTS = AGENT_CONTROL | BROAD_AGENT_CONTEXT | AUTH_CONFIG | REQUEST_RESPONSE | {
    "user", "session", "email", "ip"
}
WHOLE_OBJECT = AGENT_CONTROL | BROAD_AGENT_CONTEXT | {
    "request", "response", "payload", "body", "headers", "token", "secret",
    "credential", "api_key", "password", "cookie", "environment", "config",
    "user", "session", "email", "ip", "path", "error",
}

SESSION_FEATURES = {
    "prompt_requested_logging",
    "nl_log_concept_overlap",
    "tool_result_log_concept_overlap",
    "prompt_tool_log_concept_chain",
    "sensitive_tool_probe_session",
    "secret_probe_then_sensitive_log",
}

FEATURE_ORDER = (
    "agent_control_data",
    "agent_context_data_broad",
    "tool_io_data",
    "prompt_requested_logging",
    "nl_log_concept_overlap",
    "tool_result_log_concept_overlap",
    "prompt_tool_log_concept_chain",
    "sensitive_tool_probe_session",
    "secret_probe_then_sensitive_log",
    "answer_to_file_exact_overlap",
    "auth_config_data",
    "request_response_data",
    "identity_session_data",
    "error_diagnostic_data",
    "whole_object_dump",
    "unstructured_stdio",
    "debug_residue_marker",
)


def feature_hits(text: str) -> set[str]:
    concepts = sensitive_concepts(text)
    outside_literals = re.sub(r"(['\"])(?:\\.|(?!\1).)*\1", "", text or "")
    outside_literals = re.sub(
        r"\b(?:logger\.)?(?:debug|info|warn|warning|error|exception|fatal|critical|trace)\s*\(",
        "(",
        outside_literals,
        flags=re.I,
    )
    hits = set()
    if concepts & BROAD_AGENT_CONTEXT:
        hits.add("agent_context_data_broad")
    if concepts & AGENT_CONTROL or re.search(
        r"\b(?:system|developer)[_ -]?prompt\b", text or "", re.I
    ):
        hits.add("agent_control_data")
    if concepts & TOOL_IO:
        hits.add("tool_io_data")
    if concepts & AUTH_CONFIG:
        hits.add("auth_config_data")
    if concepts & REQUEST_RESPONSE:
        hits.add("request_response_data")
    if concepts & IDENTITY_SESSION:
        hits.add("identity_session_data")
    if "error" in concepts or re.search(r"\b(?:logger\.)?(?:exception|fatal)\s*\(", text or "", re.I):
        hits.add("error_diagnostic_data")
    if sensitive_concepts(outside_literals) & WHOLE_OBJECT:
        hits.add("whole_object_dump")
    if re.search(r"\b(?:print|console\s*\.\s*(?:log|debug|info|warn|error)|fmt\s*\.\s*Print\w*|System\s*\.\s*(?:out|err)\s*\.)", text or "", re.I):
        hits.add("unstructured_stdio")
    if re.search(r"\b(?:DEBUG|TEMP(?:ORARY)?|DIAGNOSE|DUMP)\b", text or "", re.I):
        hits.add("debug_residue_marker")
    return hits


def sensitive_concepts(text: str) -> set[str]:
    return {name for name, pattern in CONCEPT_ALIASES.items() if re.search(pattern, text or "", re.I)}


def is_sensitive_tool_probe(text: str) -> bool:
    value = text or ""
    return bool(
        re.search(r"(?:^|[;&|\s])(?:printenv|env)(?:\s|$|[;&|])", value, re.I)
        or re.search(r"(?:\.env(?:\.|\b)|\.aws[/\\]credentials|\.ssh[/\\]|kubeconfig|credentials?(?:\.json)?)", value, re.I)
        or re.search(r"\$[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASS(?:WORD)?|CREDENTIAL)[A-Z0-9_]*", value)
    )


def is_explicit_logging_prompt(text: str) -> bool:
    value = text or ""
    return bool(
        re.search(
            r"\b(?:add|insert|enable|improve|instrument|write|emit|record)\w*\b.{0,80}"
            r"\b(?:logs?|logging|logger|debug|trace|console|stdout|stderr)\b",
            value,
            re.I | re.S,
        )
        or re.search(
            r"\b(?:print|dump|show)\w*\b.{0,80}"
            r"\b(?:requests?|responses?|headers?|payload|body|tokens?|secrets?|credentials?|"
            r"environment|config|users?|sessions?|errors?|exceptions?|tracebacks?)\b",
            value,
            re.I | re.S,
        )
    )


def normalized_code(text: str) -> str:
    value = re.sub(r"\s*(?://|#)\s*(?:debug|temporary|temp)\s*$", "", text or "", flags=re.I)
    return re.sub(r"\s+", "", value).strip()


def matched_provenance_units(
    frame: pd.DataFrame,
    unit_column: str,
    provenance_column: str,
    required: set[str],
) -> pd.DataFrame:
    observed = frame.groupby(unit_column)[provenance_column].agg(set)
    matched = observed[observed.map(required.issubset)].index
    return frame[frame[unit_column].isin(matched)].copy()


def filter_devgpt_candidates(frame: pd.DataFrame) -> pd.DataFrame:
    return frame[
        frame["candidate_source"].isin(["chatgpt_answer_code", "file_content"])
        & frame["log_text"].map(is_executable_log_line)
    ].copy()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--swe-dir", type=Path, default=Path("data/repos/SWE-chat"))
    parser.add_argument(
        "--swe-candidates",
        type=Path,
        default=Path("data/res/swe_chat_multilingual_logs/swe_chat_multilingual_log_candidates.csv"),
    )
    parser.add_argument("--aidev-dir", type=Path, default=Path("data/repos/AIDev"))
    parser.add_argument(
        "--devgpt-candidates", type=Path, default=Path("data/res/devgpt_logs/devgpt_log_candidates.csv")
    )
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    parser.add_argument("--bootstrap-iterations", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20_260_805)
    args = parser.parse_args()
    if args.bootstrap_iterations < 1:
        parser.error("--bootstrap-iterations must be positive")

    candidate_rows: list[dict[str, object]] = []
    statistics_rows: list[dict[str, object]] = []

    swe_raw = pd.read_csv(args.swe_candidates, keep_default_na=False)
    swe = swe_raw[
        swe_raw["add_remove"].eq("add")
        & swe_raw["attribution"].isin(["agent_only", "human_only", "mixed"])
        & swe_raw["log_text"].map(is_executable_log_line)
    ].copy()
    swe["scope"] = swe["file"].map(lambda value: "production" if is_production_path(str(value)) else "non_production")
    swe["features"] = swe["log_text"].map(feature_hits)
    swe["concepts"] = swe["log_text"].map(sensitive_concepts)

    checkpoints = set(swe["checkpoint_pk"].astype(str)) - {""}
    session_context: dict[str, dict[str, object]] = defaultdict(
        lambda: {"prompt_concepts": set(), "tool_concepts": set(), "explicit_log_prompt": False, "probe": False}
    )
    conv_file = pq.ParquetFile(args.swe_dir / "conversations.parquet")
    for batch in conv_file.iter_batches(
        columns=["checkpoint_pk", "role", "turn_type", "content", "command", "tool_input_json"],
        batch_size=100_000,
    ):
        values = batch.to_pydict()
        for checkpoint, role, turn_type, content, command, tool_input in zip(
            values["checkpoint_pk"],
            values["role"],
            values["turn_type"],
            values["content"],
            values["command"],
            values["tool_input_json"],
        ):
            if checkpoint not in checkpoints:
                continue
            ctx = session_context[str(checkpoint)]
            value = str(content or "")
            if role == "user" and turn_type == "user_prompt":
                ctx["prompt_concepts"].update(sensitive_concepts(value))
                ctx["explicit_log_prompt"] = bool(ctx["explicit_log_prompt"]) or is_explicit_logging_prompt(value)
            elif turn_type == "tool_use":
                tool_value = " ".join(str(part or "") for part in (command, tool_input))
                ctx["probe"] = bool(ctx["probe"]) or is_sensitive_tool_probe(tool_value)
            elif turn_type == "tool_result":
                ctx["tool_concepts"].update(sensitive_concepts(value))

    sensitive_for_probe = AGENT_CONTROL | AUTH_CONFIG | REQUEST_RESPONSE | IDENTITY_SESSION
    for index, row in swe.iterrows():
        features = set(row["features"])
        concepts = set(row["concepts"])
        ctx = session_context.get(str(row["checkpoint_pk"]), {})
        prompt_concepts = set(ctx.get("prompt_concepts", set()))
        tool_concepts = set(ctx.get("tool_concepts", set()))
        prompt_overlap = concepts & prompt_concepts & OVERLAP_CONCEPTS
        tool_overlap = concepts & tool_concepts & OVERLAP_CONCEPTS
        if ctx.get("explicit_log_prompt"):
            features.add("prompt_requested_logging")
        if prompt_overlap:
            features.add("nl_log_concept_overlap")
        if tool_overlap:
            features.add("tool_result_log_concept_overlap")
        if prompt_overlap & tool_overlap:
            features.add("prompt_tool_log_concept_chain")
        if ctx.get("probe"):
            features.add("sensitive_tool_probe_session")
            if concepts & sensitive_for_probe:
                features.add("secret_probe_then_sensitive_log")
        swe.at[index, "features"] = features
        swe.at[index, "context_evidence"] = ";".join(
            filter(
                None,
                [
                    "explicit_log_prompt" if ctx.get("explicit_log_prompt") else "",
                    "sensitive_tool_probe" if ctx.get("probe") else "",
                    "prompt_overlap=" + ",".join(sorted(prompt_overlap)) if prompt_overlap else "",
                    "tool_overlap=" + ",".join(sorted(tool_overlap)) if tool_overlap else "",
                ],
            )
        )

    def add_candidate_rows(frame: pd.DataFrame, dataset: str, provenance_column: str) -> None:
        for row in frame.itertuples(index=False):
            row_data = row._asdict()
            for feature in sorted(row_data["features"], key=lambda name: FEATURE_ORDER.index(name)):
                evidence = row_data.get("evidence_kind", "") or (
                    "session_trace_candidate" if feature in SESSION_FEATURES else "static_content_candidate"
                )
                if feature == "answer_to_file_exact_overlap":
                    evidence = "cross_surface_exact_text_overlap"
                candidate_rows.append(
                    {
                        "dataset": dataset,
                        "provenance": row_data[provenance_column],
                        "scope": row_data.get("scope", "all_files"),
                        "feature": feature,
                        "evidence_kind": evidence,
                        "repo": row_data.get("repo", ""),
                        "commit": row_data.get("commit", row_data.get("sha", "")),
                        "checkpoint": row_data.get("checkpoint_pk", ""),
                        "source_id": row_data.get("share_key", row_data.get("checkpoint_pk", "")),
                        "file": row_data.get("file", row_data.get("filename", "")),
                        "line": row_data.get("line", ""),
                        "log_text": str(row_data.get("log_text", ""))[:800],
                        "context_evidence": row_data.get("context_evidence", ""),
                    }
                )

    add_candidate_rows(swe, "SWE-chat", "attribution")
    intervention_labels = {
        "confirmed_by_version_diff_human_removed_ai_log": "human_removed_agent_log",
        "confirmed_by_version_diff_human_modified_ai_log": "human_modified_agent_log",
    }
    interventions = swe_raw[
        swe_raw["manual_review_label"].isin(intervention_labels)
        & swe_raw["log_text"].map(is_executable_log_line)
    ].copy()
    interventions["intervention"] = interventions["manual_review_label"].map(intervention_labels)
    interventions["scope"] = interventions["file"].map(
        lambda value: "production" if is_production_path(str(value)) else "non_production"
    )
    interventions["features"] = interventions["log_text"].map(feature_hits)
    interventions["context_evidence"] = interventions["manual_review_evidence"]
    interventions["evidence_kind"] = "version_diff_post_generation_intervention"
    add_candidate_rows(interventions, "SWE-chat-intervention", "intervention")

    aidev_pr = pd.read_parquet(args.aidev_dir / "pull_request.parquet", columns=["id", "agent", "repo_url"])
    pr_meta = {
        int(row.id): (str(row.agent), str(row.repo_url).removeprefix("https://api.github.com/repos/"))
        for row in aidev_pr.itertuples(index=False)
    }
    aidev_rows: list[dict[str, object]] = []
    patch_file = pq.ParquetFile(args.aidev_dir / "pr_commit_details.parquet")
    for batch in patch_file.iter_batches(columns=["pr_id", "sha", "filename", "patch"], batch_size=20_000):
        values = batch.to_pydict()
        for pr_id, sha, filename, patch in zip(values["pr_id"], values["sha"], values["filename"], values["patch"]):
            if pr_id not in pr_meta or not isinstance(patch, str) or not is_source_file(str(filename or "")):
                continue
            agent, repo = pr_meta[int(pr_id)]
            for patch_line, raw_line in enumerate(patch.splitlines(), start=1):
                if not raw_line.startswith("+") or raw_line.startswith("+++"):
                    continue
                log_text = raw_line[1:].strip()
                if not is_log_line(log_text) or not is_executable_log_line(log_text):
                    continue
                aidev_rows.append(
                    {
                        "repo": repo,
                        "commit": str(sha or ""),
                        "checkpoint_pk": "",
                        "file": str(filename or ""),
                        "line": patch_line,
                        "agent": agent,
                        "scope": "production" if is_production_path(str(filename or "")) else "non_production",
                        "log_text": log_text,
                        "features": feature_hits(log_text),
                        "context_evidence": "",
                    }
                )
    aidev = pd.DataFrame(aidev_rows)
    if not aidev.empty:
        aidev = aidev.drop_duplicates(subset=["repo", "commit", "file", "line", "log_text"]).reset_index(drop=True)
        add_candidate_rows(aidev, "AIDev", "agent")

    devgpt = pd.read_csv(args.devgpt_candidates, keep_default_na=False)
    devgpt = filter_devgpt_candidates(devgpt)
    devgpt = devgpt.drop_duplicates(
        subset=["chatgpt_url", "source_url", "candidate_source", "repo", "file", "line", "log_text"]
    ).reset_index(drop=True)
    devgpt["provenance_group"] = devgpt["candidate_source"].map(
        {"chatgpt_answer_code": "chatgpt_answer", "file_content": "linked_file_content"}
    )
    devgpt["scope"] = "all_files"
    devgpt["features"] = devgpt["log_text"].map(feature_hits)
    devgpt["concepts"] = devgpt["log_text"].map(sensitive_concepts)
    devgpt["share_key"] = devgpt.apply(
        lambda row: str(row["chatgpt_url"] or row["source_url"]), axis=1
    )
    devgpt = devgpt.drop_duplicates(
        subset=["share_key", "candidate_source", "repo", "file", "line", "log_text"]
    ).reset_index(drop=True)
    file_lines: dict[str, set[str]] = defaultdict(set)
    for row in devgpt[devgpt["candidate_source"].eq("file_content")].itertuples(index=False):
        normalized = normalized_code(str(row.log_text))
        if len(normalized) >= 16 and row.share_key:
            file_lines[str(row.share_key)].add(normalized)
    for index, row in devgpt.iterrows():
        features = set(row["features"])
        prompt = str(row["user_log_reason_excerpt"] or "")
        prompt_concepts = sensitive_concepts(prompt)
        if is_explicit_logging_prompt(prompt):
            features.add("prompt_requested_logging")
        prompt_overlap = set(row["concepts"]) & prompt_concepts & OVERLAP_CONCEPTS
        if prompt_overlap:
            features.add("nl_log_concept_overlap")
        normalized = normalized_code(str(row["log_text"]))
        if (
            row["candidate_source"] == "chatgpt_answer_code"
            and len(normalized) >= 16
            and normalized in file_lines.get(str(row["share_key"]), set())
        ):
            features.add("answer_to_file_exact_overlap")
        devgpt.at[index, "features"] = features
        devgpt.at[index, "context_evidence"] = ";".join(
            filter(
                None,
                [
                    "explicit_log_prompt" if is_explicit_logging_prompt(prompt) else "",
                    "prompt_overlap=" + ",".join(sorted(prompt_overlap)) if prompt_overlap else "",
                    "exact_answer_file_overlap" if "answer_to_file_exact_overlap" in features else "",
                ],
            )
        )
    add_candidate_rows(devgpt, "DevGPT", "provenance_group")

    def append_descriptive_stats(
        frame: pd.DataFrame,
        dataset: str,
        provenance_column: str,
        groups: list[str],
        scopes: list[str],
        baseline: tuple[str, str] | None = None,
        unit: str = "log_line",
        scope_label: str | None = None,
    ) -> None:
        for scope in scopes:
            scoped = frame if scope == "all_files" else frame[frame["scope"].eq("production")]
            present_features = [
                feature for feature in FEATURE_ORDER if any(feature in values for values in scoped["features"])
            ]
            p_values: dict[str, float] = {}
            if baseline:
                agent_name, human_name = baseline
                agent_rows = scoped[scoped[provenance_column].eq(agent_name)]
                human_rows = scoped[scoped[provenance_column].eq(human_name)]
                for feature in present_features:
                    a = sum(feature in values for values in agent_rows["features"])
                    h = sum(feature in values for values in human_rows["features"])
                    p_values[feature] = two_proportion_p(a, len(agent_rows), h, len(human_rows))
            q_values = benjamini_hochberg(p_values) if p_values else {}
            for feature in present_features:
                paired_effect = paired_low = paired_high = math.nan
                paired_repos = 0
                if baseline and dataset == "SWE-chat":
                    agent_name, human_name = baseline
                    repo_differences = []
                    for _, repo_group in scoped.groupby("repo"):
                        a_group = repo_group[repo_group[provenance_column].eq(agent_name)]
                        h_group = repo_group[repo_group[provenance_column].eq(human_name)]
                        if len(a_group) and len(h_group):
                            repo_differences.append(
                                sum(feature in values for values in a_group["features"]) / len(a_group)
                                - sum(feature in values for values in h_group["features"]) / len(h_group)
                            )
                    if repo_differences:
                        paired_effect = statistics.fmean(repo_differences)
                        paired_repos = len(repo_differences)
                        rng = random.Random(args.seed + FEATURE_ORDER.index(feature))
                        boot = [
                            statistics.fmean(rng.choice(repo_differences) for _ in repo_differences)
                            for _ in range(args.bootstrap_iterations)
                        ]
                        paired_low = percentile(boot, 0.025)
                        paired_high = percentile(boot, 0.975)
                for group in groups:
                    group_rows = scoped[scoped[provenance_column].eq(group)]
                    hits = sum(feature in values for values in group_rows["features"])
                    low, high = wilson_interval(hits, len(group_rows))
                    effect = "descriptive_only"
                    if baseline and group == baseline[0]:
                        human_rows = scoped[scoped[provenance_column].eq(baseline[1])]
                        human_hits = sum(feature in values for values in human_rows["features"])
                        pooled_diff = hits / len(group_rows) - human_hits / len(human_rows) if len(group_rows) and len(human_rows) else math.nan
                        stable = (
                            not math.isnan(paired_effect)
                            and not (paired_low <= 0 <= paired_high)
                            and pooled_diff * paired_effect > 0
                            and q_values.get(feature, 1.0) <= 0.05
                        )
                        effect = (
                            f"pooled_diff={pooled_diff:.6f};"
                            f"odds_ratio={odds_ratio(hits,len(group_rows),human_hits,len(human_rows)):.6f};"
                            f"bh_q={q_values.get(feature,1.0):.6f};"
                            f"mean_repo_diff={paired_effect:.6f};"
                            f"bootstrap95%=[{paired_low:.6f},{paired_high:.6f}];"
                            f"paired_repos={paired_repos};stable={str(stable).lower()}"
                        )
                    elif baseline and group == baseline[1]:
                        effect = "reference"
                    evidence_boundary = (
                        "session_trace_candidate_not_value_leak"
                        if feature in SESSION_FEATURES
                        else "static_code_candidate_not_runtime_leak"
                    )
                    if feature == "answer_to_file_exact_overlap":
                        evidence_boundary = "exact_text_overlap_not_authorship_proof"
                    statistics_rows.append(
                        {
                            "dataset": dataset,
                            "scope": scope_label or scope,
                            "unit": unit,
                            "feature": feature,
                            "provenance": group,
                            "n_logs": len(group_rows),
                            "n_hits": hits,
                            "rate": f"{hits / len(group_rows):.6f}" if len(group_rows) else "0.000000",
                            "ci_low": f"{low:.6f}",
                            "ci_high": f"{high:.6f}",
                            "effect": effect,
                            "evidence_boundary": evidence_boundary,
                        }
                    )

    append_descriptive_stats(
        swe,
        "SWE-chat",
        "attribution",
        ["agent_only", "human_only", "mixed"],
        ["production", "all_files"],
        baseline=("agent_only", "human_only"),
    )
    for base_scope in ("production", "all_files"):
        base = swe if base_scope == "all_files" else swe[swe["scope"].eq("production")]
        checkpoint_units = (
            base.groupby(["repo", "checkpoint_pk", "attribution"], as_index=False)["features"]
            .agg(lambda values: set().union(*values))
        )
        append_descriptive_stats(
            checkpoint_units,
            "SWE-chat",
            "attribution",
            ["agent_only", "human_only", "mixed"],
            ["all_files"],
            baseline=("agent_only", "human_only"),
            unit="checkpoint_provenance",
            scope_label=f"{base_scope}_checkpoint_units",
        )
        matched_units = matched_provenance_units(
            checkpoint_units,
            "checkpoint_pk",
            "attribution",
            {"agent_only", "human_only"},
        )
        append_descriptive_stats(
            matched_units,
            "SWE-chat",
            "attribution",
            ["agent_only", "human_only"],
            ["all_files"],
            baseline=("agent_only", "human_only"),
            unit="matched_checkpoint_provenance",
            scope_label=f"{base_scope}_matched_checkpoint_units",
        )
    append_descriptive_stats(
        interventions,
        "SWE-chat-intervention",
        "intervention",
        ["human_removed_agent_log", "human_modified_agent_log"],
        ["production", "all_files"],
    )
    if not aidev.empty:
        aidev_all = aidev.copy()
        aidev_all["agent_group"] = aidev_all["agent"]
        append_descriptive_stats(
            aidev_all,
            "AIDev",
            "agent_group",
            sorted(aidev_all["agent_group"].unique()),
            ["production", "all_files"],
        )
    append_descriptive_stats(
        devgpt,
        "DevGPT",
        "provenance_group",
        ["chatgpt_answer", "linked_file_content"],
        ["all_files"],
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    stats_path = args.output_dir / "agent_unique_log_feature_statistics.csv"
    candidates_path = args.output_dir / "agent_unique_log_feature_candidates.csv"
    review_path = args.output_dir / "agent_unique_log_feature_review_sample.csv"
    pd.DataFrame(statistics_rows).to_csv(stats_path, index=False)
    candidate_frame = pd.DataFrame(candidate_rows)
    candidate_frame.to_csv(candidates_path, index=False)
    review_features = {
        "agent_control_data",
        "nl_log_concept_overlap",
        "tool_result_log_concept_overlap",
        "prompt_tool_log_concept_chain",
        "secret_probe_then_sensitive_log",
        "answer_to_file_exact_overlap",
        "auth_config_data",
        "identity_session_data",
    }
    review_pool = candidate_frame[candidate_frame["feature"].isin(review_features)].drop_duplicates(
        subset=["dataset", "provenance", "feature", "source_id", "repo", "file", "line", "log_text"]
    )
    review_sample = (
        review_pool.groupby(["dataset", "provenance", "feature"], group_keys=False)
        .apply(lambda group: group.sample(min(20, len(group)), random_state=args.seed), include_groups=False)
        .reset_index(drop=True)
    )
    review_sample["manual_label"] = ""
    review_sample["manual_notes"] = ""
    review_sample.to_csv(review_path, index=False)

    summary = {
        "seed": args.seed,
        "bootstrap_iterations": args.bootstrap_iterations,
        "datasets": {
            "SWE-chat": {
                "added_logs": int(len(swe)),
                "by_provenance": {key: int(value) for key, value in swe["attribution"].value_counts().items()},
                "checkpoints_with_context": len(session_context),
                "post_generation_interventions": {
                    key: int(value) for key, value in interventions["intervention"].value_counts().items()
                },
            },
            "AIDev": {
                "agent_prs": len(pr_meta),
                "added_logs": int(len(aidev)),
                "by_agent": {key: int(value) for key, value in aidev["agent"].value_counts().items()} if not aidev.empty else {},
                "human_patch_control_available": False,
            },
            "DevGPT": {
                "log_rows": int(len(devgpt)),
                "by_source": {key: int(value) for key, value in devgpt["provenance_group"].value_counts().items()},
                "human_control_available": False,
            },
        },
        "outputs": {
            "statistics": str(stats_path),
            "candidates": str(candidates_path),
            "review_sample": str(review_path),
        },
        "boundaries": [
            "All matches are static or trace candidates, not confirmed runtime privacy leaks.",
            "SWE-chat is the only local source with Agent/human file provenance that can be inherited by log lines.",
            "AIDev has Agent patches but its human control table has no code patches.",
            "DevGPT exact answer/file overlap does not prove ChatGPT authorship or causal adoption.",
        ],
    }
    summary_path = args.output_dir / "agent_unique_log_feature_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
