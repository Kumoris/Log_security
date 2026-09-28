#!/usr/bin/env python3
"""Extract and evaluate PR-level log features for matched Agent/human PRs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import itertools
import json
import math
import random
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

if __package__:
    from .analyze_coding_agent_log_leakage import benjamini_hochberg, percentile, wilson_interval
    from .mine_github_log_lineage import diff_profile
    from .screen_github_agent_logs import LOG_RE, SHELL_LOG_RE, _atomic_write_text
else:
    from analyze_coding_agent_log_leakage import benjamini_hochberg, percentile, wilson_interval
    from mine_github_log_lineage import diff_profile
    from screen_github_agent_logs import LOG_RE, SHELL_LOG_RE, _atomic_write_text


OUTPUT_NAMES = (
    "pr_features.csv",
    "feature_statistics.csv",
    "threshold_performance.csv",
    "oof_predictions.csv",
    "summary.json",
    "report.md",
)
SCORE_FEATURES = (
    "n_production_logs",
    "log_density_per_100_added_lines",
    "log_file_coverage",
    "duplicate_template_share",
    "risk_candidate_share",
    "error_share",
    "whole_object_share",
    "unstructured_share",
    "debug_share",
)
STRUCTURAL_FEATURES = (
    "has_production_log",
    "n_production_logs",
    "log_density_per_100_added_lines",
    "log_file_coverage",
)
COMPOSITION_FEATURES = (
    "duplicate_template_share",
    "risk_candidate_share",
    "error_share",
    "whole_object_share",
    "unstructured_share",
    "debug_share",
    "auth_config_share",
    "identity_session_share",
    "request_response_share",
    "agent_control_share",
)
FORBIDDEN_PREDICTORS = (
    "label",
    "provenance",
    "provenance_evidence",
    "evidence_level",
    "adoption_evidence",
    "agent",
    "agent_name",
    "actor_login",
    "actor_type",
    "actor_app_url",
    "source_app_slug",
    "performed_via_app_slug",
    "repo",
    "pr_key",
    "pr_url",
    "pr_number",
    "source_url",
    "title",
    "pair_id",
    "match_tier",
    "match_score",
    "matching_method",
    "created_at",
    "merged_at",
    "merge_latency_minutes",
    "file_path",
    "file",
    "log_text",
    "log_text_redacted",
    "log_text_hash",
    "normalized_template_hash",
    "diff_completeness",
    "diff_completeness_qc",
    "detail_source",
    "query_window",
    "search_window",
    "api_diff_incomplete",
    "patch_missing_files",
    "file_pages",
    "files_returned",
    "base_sha",
    "head_sha",
    "merge_commit_sha",
    "session_id",
    "checkpoint_pk",
    "exact_survival_share",
    "lineage_rows",
)
ATTRIBUTION_SCORE_SPEC = {
    "version": "session_pr_binding_v1",
    "purpose": "evidence_prioritization_not_calibrated_probability",
    "hard_anchor_required": True,
    "no_hard_anchor_score_cap": 49,
    "total_score_cap": 100,
    "high_confidence_threshold": 80,
    "aggregation": "min(100, max(hard_anchor_points) + sum(supporting_points)); hard_failure=>0; no_anchor=>cap_49",
    "hard_anchors": [
        {
            "id": "session_commit_equals_pr_head_commit",
            "points": 100,
            "requires": [
                "same_repository", "known_clean_base", "commit_created_in_session",
                "session_event_precedes_or_creates_pr",
            ],
        },
        {
            "id": "session_tree_and_base_equal_pr_tree_and_base",
            "points": 90,
            "requires": ["same_repository", "known_clean_base", "session_event_precedes_or_creates_pr"],
        },
        {
            "id": "canonical_full_patch_bidirectional_exact",
            "points": 80,
            "requires": ["same_repository", "same_base", "temporal_order_valid", "session_pr_binding"],
        },
        {
            "id": "tool_write_full_added_line_coverage",
            "points": 70,
            "requires": [
                "same_repository", "same_base", "temporal_order_valid", "session_pr_binding",
                "frozen_pr_head", "unambiguous_path_line_match",
            ],
        },
    ],
    "supporting_signals": [
        {"id": "trace_references_pr_url_and_head", "points": 15},
        {"id": "trace_contains_commit_or_push_event", "points": 10},
        {"id": "github_agent_app_pr_provenance", "points": 20},
        {"id": "partial_path_aware_added_line_match", "points_max": 10},
    ],
    "hard_failures": [
        "repository_or_base_mismatch",
        "session_artifact_created_after_pr_head",
        "unaccounted_pre_session_worktree_changes",
        "claimed_added_line_already_present_in_base",
        "hash_or_patch_mismatch_for_claimed_exact_binding",
    ],
    "labels": {
        "high_confidence": "score>=80 AND at_least_one_hard_anchor",
        "manual_review": "hard_anchor AND 50<=score<80 AND no_hard_failure",
        "insufficient_for_automatic_attribution": "no_hard_anchor OR score<50 OR hard_failure",
    },
}


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def read_cached_diff(cache_dir: Path, url: str) -> str:
    path = cache_dir / (hashlib.sha256(url.encode("utf-8")).hexdigest() + ".json")
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("url") != url:
        raise ValueError(f"cached URL mismatch for {url}")
    if not isinstance(record.get("data"), str):
        raise ValueError(f"cached diff is not text for {url}")
    return record["data"]


def normalize_log_template(text: str) -> str:
    value = re.sub(r"\s*(?://|#)\s*(?:debug|temporary|temp)\s*$", "", text or "", flags=re.I)
    shell = SHELL_LOG_RE.search(value)
    if shell:
        message = value[shell.end() :].lower()
        message = re.sub(r"\$\([^)]*\)|\$\{[^{}]*\}|\$[a-z_][a-z0-9_]*", "<slot>", message)
        message = re.sub(r"%\([^)]+\)[#0 +\-]?[0-9.]*[a-z]", "<slot>", message)
        message = re.sub(r"%(?:[#0 +\-]?[0-9.]*)?[a-z]", "<slot>", message)
        message = re.sub(r"['\"`]", "", message)
        return value[shell.start() : shell.end()].strip().lower() + "|" + re.sub(r"\s+", " ", message).strip()
    sink = LOG_RE.search(value)
    start = sink.start() if sink else 0
    opening = value.rfind("(", start, sink.end()) if sink else value.find("(")
    if opening < 0:
        return re.sub(r"\s+", "", value).lower()
    call = re.sub(r"\s+", "", value[start:opening]).lower()
    quote = ""
    escaped = False
    depth = 0
    end = len(value)
    for index, character in enumerate(value[opening + 1 :], start=opening + 1):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
        elif character in "'\"`":
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}":
            if character == ")" and depth == 0:
                end = index
                break
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            end = index
            break
    argument = value[opening + 1 : end]
    literals = []
    index = 0
    while index < len(argument):
        if argument[index] not in "'\"`":
            index += 1
            continue
        quote = argument[index]
        index += 1
        content = []
        while index < len(argument):
            character = argument[index]
            if character == "\\" and index + 1 < len(argument):
                content.extend((character, argument[index + 1]))
                index += 2
            elif character == quote:
                index += 1
                break
            else:
                content.append(character)
                index += 1
        message = "".join(content).lower()
        message = re.sub(r"%\([^)]+\)[#0 +\-]?[0-9.]*[a-z]", "<slot>", message)
        message = re.sub(r"%(?:[#0 +\-]?[0-9.]*)?[a-z]", "<slot>", message)
        message = re.sub(r"\$?\{[^{}]*\}", "<slot>", message)
        literals.append(re.sub(r"\s+", " ", message).strip())
    return call + "|" + ("|".join(literals) if literals else "<dynamic>")


def build_pr_features(
    *,
    pair_id: str,
    match_tier: str,
    provenance: str,
    repo: str,
    pr_key: str,
    created_at: str,
    merged_at: str,
    profile: dict,
    lineage_rows: list[dict],
) -> dict[str, object]:
    production_logs = [row for row in profile["logs"] if row["path_scope"] == "production"]
    nonproduction_logs = [row for row in profile["logs"] if row["path_scope"] != "production"]
    feature_counts = Counter(feature for row in production_logs for feature in row["risk_features"])
    templates = Counter(
        hashlib.sha256(normalize_log_template(str(row["_exact_text"])).encode("utf-8")).hexdigest()
        for row in production_logs
    )
    duplicate_count = sum(count - 1 for count in templates.values())
    log_files = {str(row["file"]) for row in production_logs}
    statuses = Counter(str(row.get("lineage_status") or "") for row in lineage_rows)
    evaluable_statuses = {"PRESENT_AT_CURRENT_HEAD", "MODIFIED_AFTER_MERGE", "DELETED_AFTER_MERGE"}
    n_evaluable = sum(statuses[status] for status in evaluable_statuses)
    n_unknown = len(lineage_rows) - n_evaluable
    n_logs = len(production_logs)
    return {
        "pair_id": pair_id,
        "match_tier": match_tier,
        "provenance": provenance,
        "label": 1 if provenance == "agent" else 0,
        "repo": repo,
        "pr_key": pr_key,
        "created_at": created_at,
        "merged_at": merged_at,
        "diff_source": "cached_github_raw_diff",
        "diff_completeness_qc": "unknown_raw_diff_limits",
        "merge_latency_minutes": (_iso(merged_at) - _iso(created_at)).total_seconds() / 60,
        "production_added_lines": int(profile["added_lines"]),
        "deleted_lines": int(profile["deleted_lines"]),
        "production_source_files": int(profile["production_source_files"]),
        "extensions": ";".join(profile["extensions"]),
        "n_production_logs": n_logs,
        "has_production_log": int(n_logs > 0),
        "batch_log_addition": int(n_logs >= 2),
        "n_nonproduction_logs": len(nonproduction_logs),
        "n_production_log_files": len(log_files),
        "log_density_per_100_added_lines": (
            100 * n_logs / int(profile["added_lines"]) if int(profile["added_lines"]) else None
        ),
        "log_file_coverage": (
            len(log_files) / int(profile["production_source_files"])
            if int(profile["production_source_files"]) else None
        ),
        "duplicate_template_share": _ratio(duplicate_count, n_logs),
        "risk_candidate_share": _ratio(sum(bool(row["risk_features"]) for row in production_logs), n_logs),
        "error_share": _ratio(feature_counts["error_diagnostic_data"], n_logs),
        "whole_object_share": _ratio(feature_counts["whole_object_dump"], n_logs),
        "unstructured_share": _ratio(feature_counts["unstructured_stdio"], n_logs),
        "debug_share": _ratio(feature_counts["debug_residue_marker"], n_logs),
        "auth_config_share": _ratio(feature_counts["auth_config_data"], n_logs),
        "identity_session_share": _ratio(feature_counts["identity_session_data"], n_logs),
        "request_response_share": _ratio(feature_counts["request_response_data"], n_logs),
        "agent_control_share": _ratio(feature_counts["agent_control_data"], n_logs),
        "exact_survival_share": _ratio(statuses["PRESENT_AT_CURRENT_HEAD"], n_evaluable) if n_evaluable else None,
        "lineage_evaluable_rows": n_evaluable,
        "lineage_unknown_rows": n_unknown,
        "lineage_fully_observed": int(bool(lineage_rows) and n_unknown == 0),
        "lineage_rows": len(lineage_rows),
    }


def _balanced_accuracy(labels: list[int], predictions: list[int]) -> float:
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return 0.0
    sensitivity = sum(label == prediction == 1 for label, prediction in zip(labels, predictions)) / positives
    specificity = sum(label == prediction == 0 for label, prediction in zip(labels, predictions)) / negatives
    return (sensitivity + specificity) / 2


def _apply_rule(value: float, rule: dict[str, object]) -> int:
    threshold = float(rule["threshold"])
    return int(value >= threshold) if rule["direction"] == "ge" else int(value <= threshold)


def fit_stump(rows: list[dict[str, object]], feature: str) -> dict[str, object]:
    values = sorted({float(row[feature]) for row in rows if math.isfinite(float(row[feature]))})
    labels = [int(row["label"]) for row in rows]
    if not values or not labels or len(set(labels)) < 2:
        return {"feature": feature, "direction": "ge", "threshold": 0.0, "balanced_accuracy": 0.0}
    span = max(1.0, values[-1] - values[0])
    thresholds = [values[0] - span]
    thresholds.extend((left + right) / 2 for left, right in zip(values, values[1:]))
    thresholds.append(values[-1] + span)
    candidates = []
    for direction in ("ge", "le"):
        for threshold in thresholds:
            rule = {"feature": feature, "direction": direction, "threshold": threshold}
            predictions = [_apply_rule(float(row[feature]), rule) for row in rows]
            candidates.append(
                {
                    **rule,
                    "balanced_accuracy": _balanced_accuracy(labels, predictions),
                }
            )
    return min(
        candidates,
        key=lambda rule: (
            -float(rule["balanced_accuracy"]),
            0 if rule["direction"] == "ge" else 1,
            abs(float(rule["threshold"]) - statistics.median(values)),
            float(rule["threshold"]),
        ),
    )


def _score_row(row: dict[str, object], rules: list[dict[str, object]]) -> float:
    return 100 * statistics.fmean(_apply_rule(float(row[str(rule["feature"])]), rule) for rule in rules)


def leave_one_repository_out(
    rows: list[dict[str, object]], features: tuple[str, ...] = SCORE_FEATURES
) -> list[dict[str, object]]:
    repositories = sorted({str(row["repo"]) for row in rows})
    output = []
    for held_out in repositories:
        train = [row for row in rows if row["repo"] != held_out]
        test = [row for row in rows if row["repo"] == held_out]
        if len({int(row["label"]) for row in train}) < 2:
            continue
        rules = [fit_stump(train, feature) for feature in features]
        train_scored = [{**row, "_score": _score_row(row, rules)} for row in train]
        score_rule = fit_stump(train_scored, "_score")
        for row in test:
            score = _score_row(row, rules)
            output.append(
                {
                    "pr_key": row["pr_key"],
                    "repo": row["repo"],
                    "held_out_repo": held_out,
                    "label": int(row["label"]),
                    "score": score,
                    "score_direction": score_rule["direction"],
                    "score_threshold": score_rule["threshold"],
                    "prediction": _apply_rule(score, score_rule),
                }
            )
    return output


def mcnemar_exact(agent_only_positive: int, human_only_positive: int) -> float:
    discordant = agent_only_positive + human_only_positive
    if not discordant:
        return 1.0
    tail = sum(math.comb(discordant, value) for value in range(min(agent_only_positive, human_only_positive) + 1))
    return min(1.0, 2 * tail / (2 ** discordant))


def _cluster_sign_flip_p(repo_differences: list[list[float]], iterations: int, seed: int) -> float:
    if not repo_differences or not any(value for group in repo_differences for value in group):
        return 1.0
    observed = abs(statistics.fmean(statistics.fmean(group) for group in repo_differences))
    if len(repo_differences) <= 20:
        values = [
            abs(statistics.fmean(sign * statistics.fmean(group) for sign, group in zip(signs, repo_differences)))
            for signs in itertools.product((-1, 1), repeat=len(repo_differences))
        ]
        return sum(value >= observed - 1e-15 for value in values) / len(values)
    rng = random.Random(seed)
    extreme = 0
    for _ in range(iterations):
        value = abs(
            statistics.fmean(rng.choice((-1, 1)) * statistics.fmean(group) for group in repo_differences)
        )
        extreme += value >= observed - 1e-15
    return (extreme + 1) / (iterations + 1)


def paired_feature_statistics(
    rows: list[dict[str, object]],
    features: tuple[str, ...],
    scope: str,
    bootstrap_iterations: int,
    seed: int,
    cluster_field: str = "repo",
) -> list[dict[str, object]]:
    pairs: dict[str, dict[str, dict[str, object]]] = defaultdict(dict)
    for row in rows:
        pairs[str(row["pair_id"])][str(row["provenance"])] = row
    complete = [value for value in pairs.values() if {"agent", "human"} <= value.keys()]
    results = []
    for index, feature in enumerate(features):
        eligible = [
            pair for pair in complete
            if pair["agent"].get(feature) is not None and pair["human"].get(feature) is not None
        ]
        differences = [float(pair["agent"][feature]) - float(pair["human"][feature]) for pair in eligible]
        agent_values = [float(pair["agent"][feature]) for pair in eligible]
        human_values = [float(pair["human"][feature]) for pair in eligible]
        by_repo: dict[str, list[float]] = defaultdict(list)
        for pair, difference in zip(eligible, differences):
            by_repo[str(pair["agent"][cluster_field])].append(difference)
        repo_differences = [by_repo[repo] for repo in sorted(by_repo)]
        rng = random.Random(seed + index)
        boot = []
        if repo_differences:
            for _ in range(bootstrap_iterations):
                sampled = [rng.choice(repo_differences) for _ in repo_differences]
                boot.append(statistics.fmean(statistics.fmean(group) for group in sampled))
        pair_weighted = statistics.fmean(differences) if differences else math.nan
        repo_weighted = (
            statistics.fmean(statistics.fmean(group) for group in repo_differences)
            if repo_differences else math.nan
        )
        fold_effects = []
        for repository in sorted(by_repo):
            retained = [group for repo, group in by_repo.items() if repo != repository]
            if retained:
                fold_effects.append((repository, statistics.fmean(statistics.fmean(group) for group in retained)))
        if repo_weighted == 0 or not fold_effects:
            direction_consistency = 0.0
        else:
            direction_consistency = sum(value * repo_weighted > 0 for _, value in fold_effects) / len(fold_effects)
        standard_deviation = statistics.stdev(differences) if len(differences) > 1 else 0.0
        standardized = pair_weighted / standard_deviation if standard_deviation else None
        binary = all(value in {0.0, 1.0} for value in agent_values + human_values)
        agent_only = sum(agent == 1 and human == 0 for agent, human in zip(agent_values, human_values)) if binary else 0
        human_only = sum(agent == 0 and human == 1 for agent, human in zip(agent_values, human_values)) if binary else 0
        results.append(
            {
                "scope": scope,
                "cluster_unit": cluster_field,
                "feature": feature,
                "n_pairs": len(eligible),
                "n_repositories": len(repo_differences),
                "agent_mean": statistics.fmean(agent_values) if agent_values else math.nan,
                "human_mean": statistics.fmean(human_values) if human_values else math.nan,
                "mean_difference": pair_weighted,
                "equal_repo_mean_difference": repo_weighted,
                "median_difference": statistics.median(differences) if differences else math.nan,
                "bootstrap_ci_low": percentile(boot, 0.025),
                "bootstrap_ci_high": percentile(boot, 0.975),
                "permutation_p": _cluster_sign_flip_p(repo_differences, bootstrap_iterations, seed + index),
                "loro_direction_consistency": direction_consistency,
                "loro_effect_min": min((value for _, value in fold_effects), default=math.nan),
                "loro_effect_max": max((value for _, value in fold_effects), default=math.nan),
                "max_influence_repository": max(
                    fold_effects,
                    key=lambda item: abs(item[1] - repo_weighted),
                    default=("", math.nan),
                )[0],
                "paired_standardized_effect": standardized,
                "agent_only_positive_pairs": agent_only if binary else "",
                "human_only_positive_pairs": human_only if binary else "",
                "mcnemar_exact_p": mcnemar_exact(agent_only, human_only) if binary else "",
            }
        )
    q_values = benjamini_hochberg({str(row["feature"]): float(row["permutation_p"]) for row in results})
    for row in results:
        low, high = float(row["bootstrap_ci_low"]), float(row["bootstrap_ci_high"])
        row["bh_q"] = q_values[str(row["feature"])]
        row["stable"] = bool(
            row["n_pairs"]
            and not (low <= 0 <= high)
            and float(row["bh_q"]) <= 0.05
            and float(row["mean_difference"]) * float(row["equal_repo_mean_difference"]) > 0
            and int(row["n_pairs"]) >= 10
            and int(row["n_repositories"]) >= 5
            and float(row["loro_direction_consistency"]) == 1.0
            and row["paired_standardized_effect"] is not None
            and abs(float(row["paired_standardized_effect"])) >= 0.2
        )
    return results


def classification_performance(
    predictions: list[dict[str, object]], bootstrap_iterations: int = 0, seed: int = 20_260_805
) -> dict[str, object]:
    tp = sum(int(row["label"]) == int(row["prediction"]) == 1 for row in predictions)
    tn = sum(int(row["label"]) == int(row["prediction"]) == 0 for row in predictions)
    fp = sum(int(row["label"]) == 0 and int(row["prediction"]) == 1 for row in predictions)
    fn = sum(int(row["label"]) == 1 and int(row["prediction"]) == 0 for row in predictions)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    precision_low, precision_high = wilson_interval(tp, tp + fp) if tp + fp else (None, None)
    recall_low, recall_high = wilson_interval(tp, tp + fn) if tp + fn else (None, None)
    specificity_low, specificity_high = wilson_interval(tn, tn + fp) if tn + fp else (None, None)
    joint_z = 2.241402727604947
    recall_joint_low = wilson_interval(tp, tp + fn, joint_z)[0] if tp + fn else None
    specificity_joint_low = wilson_interval(tn, tn + fp, joint_z)[0] if tn + fp else None
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denominator if denominator else None
    repo_accuracies = []
    by_repo: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in predictions:
        by_repo[str(row.get("repo") or row.get("held_out_repo") or "")].append(row)
    for repo in sorted(by_repo):
        group = by_repo[repo]
        if group:
            repo_accuracies.append(sum(int(row["label"]) == int(row["prediction"]) for row in group) / len(group))
    balanced = (recall + specificity) / 2 if recall is not None and specificity is not None else None
    cluster_bootstrap = []
    repositories = [by_repo[repo] for repo in sorted(by_repo)]
    if bootstrap_iterations and repositories:
        rng = random.Random(seed)
        for _ in range(bootstrap_iterations):
            sampled = [row for _ in repositories for row in rng.choice(repositories)]
            labels = [int(row["label"]) for row in sampled]
            if len(set(labels)) == 2:
                cluster_bootstrap.append(
                    _balanced_accuracy(labels, [int(row["prediction"]) for row in sampled])
                )
    loro_balanced = []
    for repo in sorted(by_repo):
        retained = [row for other, group in by_repo.items() if other != repo for row in group]
        labels = [int(row["label"]) for row in retained]
        if len(set(labels)) == 2:
            loro_balanced.append(_balanced_accuracy(labels, [int(row["prediction"]) for row in retained]))
    both_class_rows = [
        row for group in by_repo.values() if {int(row["label"]) for row in group} == {0, 1} for row in group
    ]
    both_class_balanced = None
    if both_class_rows:
        both_class_balanced = _balanced_accuracy(
            [int(row["label"]) for row in both_class_rows],
            [int(row["prediction"]) for row in both_class_rows],
        )
    cluster_sizes = [len(group) for group in repositories]
    effective_repositories = (
        sum(cluster_sizes) ** 2 / sum(size * size for size in cluster_sizes) if cluster_sizes else 0.0
    )
    prevalence_ppv = {}
    for prevalence in (0.001, 0.01, 0.05, 0.10):
        denominator_ppv = (
            recall * prevalence + (1 - specificity) * (1 - prevalence)
            if recall is not None and specificity is not None else 0
        )
        prevalence_ppv[f"ppv_at_{prevalence:g}"] = (
            recall * prevalence / denominator_ppv if denominator_ppv else None
        )
        conservative_denominator = (
            recall_joint_low * prevalence + (1 - specificity_joint_low) * (1 - prevalence)
            if recall_joint_low is not None and specificity_joint_low is not None else 0
        )
        prevalence_ppv[f"ppv_lower_at_{prevalence:g}"] = (
            recall_joint_low * prevalence / conservative_denominator
            if conservative_denominator else None
        )
    return {
        "n": len(predictions),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "precision_ci_low": precision_low,
        "precision_ci_high": precision_high,
        "recall": recall,
        "recall_ci_low": recall_low,
        "recall_ci_high": recall_high,
        "specificity": specificity,
        "specificity_ci_low": specificity_low,
        "specificity_ci_high": specificity_high,
        "balanced_accuracy": balanced,
        "mcc": mcc,
        "lr_positive": recall / (1 - specificity) if recall is not None and specificity not in {None, 1.0} else None,
        "lr_negative": (1 - recall) / specificity if recall is not None and specificity not in {None, 0.0} else None,
        "repo_accuracy_min": min(repo_accuracies, default=None),
        "repo_accuracy_max": max(repo_accuracies, default=None),
        "effective_repositories": effective_repositories,
        "largest_repository_share": max(cluster_sizes, default=0) / len(predictions) if predictions else None,
        "cluster_bootstrap_ba_ci_low": percentile(cluster_bootstrap, 0.025) if cluster_bootstrap else None,
        "cluster_bootstrap_ba_ci_high": percentile(cluster_bootstrap, 0.975) if cluster_bootstrap else None,
        "cluster_bootstrap_valid_replicates": len(cluster_bootstrap),
        "loro_ba_min": min(loro_balanced, default=None),
        "loro_ba_max": max(loro_balanced, default=None),
        "both_class_repositories": sum(
            {int(row["label"]) for row in group} == {0, 1} for group in by_repo.values()
        ),
        "both_class_repositories_ba": both_class_balanced,
        "interval_method": "naive_binomial_wilson_reference_not_cluster_adjusted",
        "projected_ppv_lower_method": "bonferroni_joint_95_wilson_lower_reference_not_cluster_adjusted",
        **prevalence_ppv,
    }


def analyze_feature_rows(
    feature_rows: list[dict[str, object]], bootstrap_iterations: int, seed: int
) -> dict[str, object]:
    same_repo = [row for row in feature_rows if row["match_tier"] == "same_repository"]
    cross_repo = [row for row in feature_rows if row["match_tier"] == "cross_repository"]
    statistics_rows = paired_feature_statistics(
        same_repo,
        (*STRUCTURAL_FEATURES, "batch_log_addition"),
        "same_repo_all_pairs",
        bootstrap_iterations,
        seed,
    )
    by_pair: dict[str, dict[str, dict[str, object]]] = defaultdict(dict)
    for row in same_repo:
        by_pair[str(row["pair_id"])][str(row["provenance"])] = row
    both_log_pairs = {
        pair_id for pair_id, pair in by_pair.items()
        if {"agent", "human"} <= pair.keys()
        and int(pair["agent"]["n_production_logs"]) > 0
        and int(pair["human"]["n_production_logs"]) > 0
    }
    statistics_rows.extend(
        paired_feature_statistics(
            [row for row in same_repo if row["pair_id"] in both_log_pairs],
            COMPOSITION_FEATURES,
            "same_repo_both_log_pairs",
            bootstrap_iterations,
            seed + 100,
        )
    )
    cross_pairs: dict[str, dict[str, dict[str, object]]] = defaultdict(dict)
    for row in cross_repo:
        cross_pairs[str(row["pair_id"])][str(row["provenance"])] = row
    parents: dict[str, str] = {}

    def find(repository: str) -> str:
        parents.setdefault(repository, repository)
        while parents[repository] != repository:
            parents[repository] = parents[parents[repository]]
            repository = parents[repository]
        return repository

    for pair in cross_pairs.values():
        if {"agent", "human"} <= pair.keys():
            left, right = find(str(pair["agent"]["repo"])), find(str(pair["human"]["repo"]))
            if left != right:
                parents[max(left, right)] = min(left, right)
    cross_clustered = [{**row, "repo_component": find(str(row["repo"]))} for row in cross_repo]
    statistics_rows.extend(
        paired_feature_statistics(
            cross_clustered,
            (*STRUCTURAL_FEATURES, "batch_log_addition"),
            "cross_repo_sensitivity_only",
            bootstrap_iterations,
            seed + 200,
            cluster_field="repo_component",
        )
    )
    statistics_rows.extend(
        paired_feature_statistics(
            same_repo,
            ("merge_latency_minutes",),
            "acquisition_confounded_not_predictor",
            bootstrap_iterations,
            seed + 300,
        )
    )
    primary = [
        row for row in same_repo
        if int(row["n_production_logs"]) > 0
        and all(row.get(feature) is not None for feature in SCORE_FEATURES)
    ]
    performance_rows = []
    model_specs = [((feature,), f"feature:{feature}") for feature in SCORE_FEATURES]
    model_specs.append((SCORE_FEATURES, "composite"))
    for model_index, (feature_set, model) in enumerate(model_specs):
        predictions = leave_one_repository_out(primary, tuple(feature_set))
        performance = classification_performance(
            predictions, bootstrap_iterations=bootstrap_iterations, seed=seed + 1_000 + model_index
        )
        performance_rows.append(
            {
                "model": model,
                "scope": "same_repo_log_bearing_repository_holdout",
                "n_repositories": len({str(row["repo"]) for row in primary}),
                "score_status": "exploratory_not_calibrated",
                **performance,
            }
        )
    oof = leave_one_repository_out(primary, SCORE_FEATURES)
    final_rules = [fit_stump(primary, feature) for feature in SCORE_FEATURES] if primary else []
    final_scored = [{**row, "_score": _score_row(row, final_rules)} for row in primary] if final_rules else []
    score_rule = fit_stump(final_scored, "_score") if final_scored else {}
    exported_rules = [
        {key: rule[key] for key in ("feature", "direction", "threshold")} for rule in final_rules
    ]
    exported_score_rule = (
        {key: score_rule[key] for key in ("direction", "threshold")} if score_rule else {}
    )
    return {
        "feature_statistics": statistics_rows,
        "threshold_performance": performance_rows,
        "oof_predictions": oof,
        "model": {
            "name": "equal_vote_univariate_stumps_v1",
            "status": "exploratory_not_calibrated",
            "training_scope": "same_repo_log_bearing_prs",
            "rules": exported_rules,
            "score_rule": exported_score_rule,
            "full_sample_fit_is_training_only": True,
            "deployment_allowed": False,
            "forbidden_predictors": list(FORBIDDEN_PREDICTORS),
        },
        "n_same_repo_pairs": len({row["pair_id"] for row in same_repo}),
        "n_cross_repo_pairs": len({row["pair_id"] for row in cross_repo}),
        "n_same_repo_both_log_pairs": len(both_log_pairs),
        "n_primary_classifier_rows": len(primary),
        "n_primary_classifier_repositories": len({str(row["repo"]) for row in primary}),
    }


def _write_csv(path: Path, rows: list[dict[str, object]], fields: list[str] | None = None) -> None:
    if fields is None:
        fields = list(rows[0]) if rows else []
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    _atomic_write_text(path, buffer.getvalue())


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _fmt(value: object, digits: int = 3) -> str:
    if value is None:
        return "NA"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    return "NA" if math.isnan(number) else f"{number:.{digits}f}"


def _report(
    summary: dict[str, object], statistics_rows: list[dict[str, object]], performance_rows: list[dict[str, object]]
) -> str:
    main_stats = [row for row in statistics_rows if row["scope"] == "same_repo_all_pairs"]
    composition = [row for row in statistics_rows if row["scope"] == "same_repo_both_log_pairs"]
    composite = next((row for row in performance_rows if row["model"] == "composite"), {})
    ranked = sorted(
        (row for row in performance_rows if str(row["model"]).startswith("feature:")),
        key=lambda row: float(row["balanced_accuracy"] or 0),
        reverse=True,
    )[:3]
    rules_by_feature = {
        str(rule["feature"]): rule for rule in summary["model"]["rules"]
    }
    stable = summary["stable_features"]
    lines = [
        "## Material Passport",
        "",
        "- Origin Skill: experiment-agent",
        "- Origin Mode: validate",
        "- Origin Date: 2026-08-20",
        "- Verification Status: ANALYZED",
        "- Version Label: github_pr_log_feature_screening_v1",
        "",
        "# GitHub Agent / Human PR 日志特征与筛选分 PoC",
        "",
        "## 结论",
        "",
        f"- {summary['n_pairs']}+{summary['n_pairs']} 配对 PR 中，生产日志 PR 为 Agent {summary['agent_log_bearing_prs']} 个、人类 {summary['human_log_bearing_prs']} 个；同仓库主分析为 {summary['n_same_repo_pairs']} 对。",
        f"- 通过预设稳健性门槛的特征：{', '.join(stable) if stable else '无'}。",
        f"- 来源筛选器只剩 {summary['n_primary_classifier_rows']} 个同仓库日志 PR、{summary['n_primary_classifier_repositories']} 个仓库可做留一仓库评估，因此状态是 `{summary['score_status']}`。",
        f"- 组合分的仓库外 balanced accuracy 为 {_fmt(composite.get('balanced_accuracy'))}，仓库 bootstrap 95% CI [{_fmt(composite.get('cluster_bootstrap_ba_ci_low'))}, {_fmt(composite.get('cluster_bootstrap_ba_ci_high'))}]；这不是逐行作者概率。",
        "",
        "## 样本与分析单位",
        "",
        "| 指标 | 数量 |",
        "| --- | ---: |",
        f"| 配对 PR | {summary['n_pairs']} |",
        f"| 同仓库配对 | {summary['n_same_repo_pairs']} |",
        f"| 跨仓库配对（仅敏感性） | {summary['n_cross_repo_pairs']} |",
        f"| 同仓库且双方都有生产日志的配对 | {summary['n_same_repo_both_log_pairs']} |",
        f"| Agent 生产日志行 | {summary['agent_production_logs']} |",
        f"| 人类生产日志行 | {summary['human_production_logs']} |",
        "",
        "主比较以 PR 为单位并保持配对；行级比例仅作组成描述。仓库整体重采样和整体符号翻转用于处理同仓库聚类。",
        "所有结构特征都是‘在本地缓存的 GitHub raw diff 中观察到的值’。由于 raw diff 完整性为 `unknown_raw_diff_limits`，0 只表示未观察到，不是已证明整个 PR 中不存在该日志特征。",
        "",
        "## 同仓库配对特征",
        "",
        "| 特征 | 配对 | Agent 均值 | 人类均值 | 配对差 | 等仓库差 | 仓库 bootstrap 95% CI | p | BH q | LORO 方向一致 | 稳健 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- |",
    ]
    for row in main_stats + composition:
        lines.append(
            f"| {row['feature']} | {row['n_pairs']} | {_fmt(row['agent_mean'])} | {_fmt(row['human_mean'])} | "
            f"{_fmt(row['mean_difference'])} | {_fmt(row['equal_repo_mean_difference'])} | "
            f"[{_fmt(row['bootstrap_ci_low'])}, {_fmt(row['bootstrap_ci_high'])}] | "
            f"{_fmt(row['permutation_p'])} | {_fmt(row['bh_q'])} | "
            f"{_fmt(row['loro_direction_consistency'])} | {'是' if row['stable'] else '否'} |"
        )
    lines.extend(
        [
            "",
            "组成比例只在同一 pair 双方都新增生产日志时比较；当前样本极小，不能把缺少日志的 PR 当成比例为 0。",
            "",
            "## 仓库外筛选性能",
            "",
            "| 模型 | n | Balanced accuracy | 仓库 bootstrap 95% CI | LORO BA 范围 | 双类仓库 BA | π=1% PPV 点估计 / 保守下界 |",
            "| --- | ---: | ---: | --- | --- | ---: | --- |",
        ]
    )
    for row in [*ranked, composite]:
        if not row:
            continue
        lines.append(
            f"| {row['model']} | {row['n']} | {_fmt(row['balanced_accuracy'])} | "
            f"[{_fmt(row['cluster_bootstrap_ba_ci_low'])}, {_fmt(row['cluster_bootstrap_ba_ci_high'])}] | "
            f"[{_fmt(row['loro_ba_min'])}, {_fmt(row['loro_ba_max'])}] | "
            f"{_fmt(row['both_class_repositories_ba'])} | "
            f"{_fmt(row['ppv_at_0.01'])} / {_fmt(row['ppv_lower_at_0.01'])} |"
        )
    lines.extend(
        [
            "",
            f"每个 held-out 仓库的 feature、方向、阈值都只用其他仓库选择。一个仓库占分类样本的 {_fmt(composite.get('largest_repository_share'))}，Kish 有效仓库数仅 {_fmt(composite.get('effective_repositories'))}；因此组合分不能声称高于随机或可泛化。",
            "PPV 保守下界使用 sensitivity 和 specificity 的 Bonferroni 联合 95% Wilson 下界，仍未做仓库聚类校正。π 指‘新增生产日志的候选 PR 中 Agent 来源的比例’，不是所有 GitHub PR 的比例。当前是匹配且条件化于有生产日志的富集样本。",
            "",
            "## 下一轮可冻结的内容筛选假设",
            "",
            "以下条件只用于分层抽样新仓库，不能当作 Agent 标签；新数据必须同时抽取未命中的负对照。阈值是当前全样本训练拟合，下一轮应锁定不变后在新仓库验证：",
            "",
        ]
    )
    for row in ranked:
        feature = str(row["model"]).split(":", 1)[1]
        rule = rules_by_feature.get(feature, {})
        operator = "≥" if rule.get("direction") == "ge" else "≤"
        lines.append(
            f"- `{feature} {operator} {_fmt(rule.get('threshold'))}`：OOF balanced accuracy "
            f"{_fmt(row['balanced_accuracy'])}，仓库 CI [{_fmt(row['cluster_bootstrap_ba_ci_low'])}, "
            f"{_fmt(row['cluster_bootstrap_ba_ci_high'])}]。"
        )
    lines.extend(
        [
            "",
            "这三项是对 9 个内容特征使用同一 OOF 结果事后排序得到的，其区间没有校正‘选中最佳特征’的选择偏差。",
            "建议把这三个条件做成 high/low 分层字段，不要只保留 high。只有独立新仓库上的仓库聚类区间排除 0.5、方向一致且完成人工金标，才能进入阈值校准。",
            "",
            "## 可用于扩库的特征角色",
            "",
            "| 用途 | 允许的不可逆 PR 内聚合特征 | 能否自动标注 Agent 来源 |",
            "| --- | --- | --- |",
            "| 召回‘新增日志’候选 | 是否有生产日志、数量、每 100 新增行密度、日志文件覆盖率、批量新增 | 否 |",
            "| 排序隐私/安全复核 | 风险候选、error、完整对象、stdout、debug 等比例 | 否 |",
            "| 探索来源假设 | 上述结构聚合 + 模板/error/对象/stdout/debug 比例 | 否，仅用于新仓库 high/low 分层 |",
            "| 来源归因 | 数据集标签、App/会话/提交/工具轨迹证据 | 仅按证据等级，不进入内容模型 |",
            "",
            "允许由 path 和日志文本计算上述聚合数，但不保留可让模型记住项目的原始 path、文本、模板哈希或 PR 标识。本轮 `stable_features=[]`，所以没有内容特征可直接自动标注 Agent。",
            "",
            "## 会话补丁→PR 新增行：如何形成可证明链",
            "",
            "1. 冻结同一会话的 `session_id`、仓库、base SHA、最终 commit/tree SHA、补丁与时间戳；同时冻结 PR 的 base/head SHA。",
            "2. 优先比较 Git 对象：会话 commit SHA 等于 PR head SHA 是最强的 commit 绑定；或者在同 base 下 tree SHA 一致。",
            "3. 没有 Git 对象时，对两侧使用同一 Git diff 方法，按 `new_path + hunk + 行序` 比较新增与删除行。只统一换行符，不删空白、不改标识符。",
            "4. 同时要求双向完整：`precision=session 行中进入 PR 的比例=1` 且 `recall=PR 新增行由会话覆盖的比例=1`；重复行按路径和多重集计数。",
            "5. 最后校验时间顺序和轨迹中的 commit/push/PR URL。仅‘文本一样’只能证明内容重合，不能单独证明作者。敏感行用项目隔离 HMAC 比较，不把原值写入分析表。",
            "",
            "## 归因证据分（与内容筛选分分离）",
            "",
            "- 100 分：会话 commit SHA = PR head SHA。",
            "- 90 分：同 base 下会话 tree SHA = PR head tree SHA。",
            "- 80 分：完整规范化 patch 双向精确一致，且有会话—PR 绑定和正确时序。",
            "- 70 分：工具 write/edit 轨迹路径感知地覆盖全部 PR 新增行；需叠加 PR/head 绑定才能达高信心。",
            "- 支持证据：轨迹引用 PR URL/head +15，commit/push 事件 +10，Agent App PR 级来源 +20，部分行匹配最多 +10。内容筛选分完全不计入归因证据分。",
            "",
            "只有 `score >= 80` 且至少一个硬锚时，才标记 `HIGH_CONFIDENCE_AGENT_ORIGIN_CANDIDATE`；没有硬锚时总分封顶 49。这是证据强度分，不是‘80% 概率’；要称为概率，必须用新仓库人工金标定标。当前 100+100 数据没有会话补丁或工具轨迹，因此不能对它们计算该分。",
            "",
            "## 禁止进入内容来源筛选分的字段",
            "",
            "`provenance/app/actor` 是标签或外部证据；`repo/URL/PR ID/path/text` 会记忆项目；创建和合并时间在 Agent 样本中集中于同一天；lineage 是未来信息。它们只用于独立的证据归因、分组、质量控制或后验结局，不用来训练内容指纹。",
            "",
            "## Fallacy Scan",
            "",
            "覆盖：11/11。",
            "",
            "| 谬误 | 状态 | 处理 |",
            "| --- | --- | --- |",
            "| Simpson's paradox | CAUTION | 分开同仓库主分析、跨仓库敏感性和条件日志组成 |",
            "| Ecological fallacy | CAUTION | 以 PR 为推断单位，不把行级比例当独立 PR 结论 |",
            "| Berkson's paradox | CAUTION | 样本限定 merged Agent App PR 和匹配人类 PR |",
            "| Collider bias | CAUTION | 日志组成分析条件化于双方都有日志，单独标记 |",
            "| Base rate neglect | CAUTION | 给出 0.1%、1%、5%、10% prevalence 投影 PPV |",
            "| Regression to the mean | NOTE | 无前后极端值干预比较 |",
            "| Survivorship bias | CAUTION | 只包含 merged PR；lineage 不进入预测分 |",
            "| Look-elsewhere effect | CAUTION | 特征族使用 BH，探索分仍未校准 |",
            "| Garden of forking paths | CAUTION | 本轮是探索性 PoC，阈值必须在新仓库锁定复核 |",
            "| Correlation != causation | CAUTION | 只报告来源关联，不写 Agent 导致差异 |",
            "| Reverse causality | NOTE | 不对来源关联作因果方向解释 |",
            "",
            "## 证据边界",
            "",
            "- `AGENT_SOURCE_CANDIDATE` 是 GitHub App 的 PR 级来源证据，不是逐行作者金标准。",
            "- `actor_type=User` 不能证明代码完全由人独立编写。",
            "- 风险特征是静态候选，不证明日志被执行、包含真实敏感值或被外发。",
            "- 当前没有可绑定 PR 的会话补丁或工具轨迹；这些字段没有被虚构进评分。",
            "- 缓存 raw diff 的完整性未被 API 文件清单交叉证明；密度、覆盖率和日志数是观察值。",
            "- 日志识别仍以新增行为单位；跨行调用的首行可能只被归一为 dynamic，因此重复模板比例仅是探索特征。",
            "- `pr_features.csv` 中的 lineage 汇总只纳入 production scope，且不进入来源模型。",
            "- 当前 HEAD 精确字符串保留是右删失后验结局，不进入来源筛选器。",
            "",
            "## 可复核产物",
            "",
            "- `pr_features.csv`：逐 PR 特征。",
            "- `feature_statistics.csv`：配对/仓库聚类结果。",
            "- `threshold_performance.csv`：单特征与组合分的仓库外性能。",
            "- `oof_predictions.csv`：组合分的逐 PR out-of-fold 预测。",
            "- `summary.json`：规则、排除字段和证据边界。",
            "",
        ]
    )
    return "\n".join(lines)


def extract_feature_rows(
    *,
    pairs_path: Path,
    lineage_path: Path,
    agent_cache: Path,
    human_cache: Path,
    expected_pairs: int,
) -> tuple[list[dict[str, str]], list[dict[str, object]]]:
    pairs = _read_csv(pairs_path)
    if len(pairs) != expected_pairs:
        raise ValueError(f"pair count {len(pairs)} != {expected_pairs}")
    lineage_by_pr: dict[str, list[dict]] = defaultdict(list)
    for row in _read_csv(lineage_path):
        if row.get("path_scope", "production") == "production":
            lineage_by_pr[row["pr_key"]].append(row)
    feature_rows = []
    for pair in pairs:
        inputs = (
            (
                "agent", pair["repo"], pair["agent_pr_key"], pair["agent_pr_url"],
                pair["agent_created_at"], pair["agent_merged_at"], agent_cache,
            ),
            (
                "human", pair["human_repo"], pair["human_pr_key"], pair["human_pr_url"],
                pair["human_created_at"], pair["human_merged_at"], human_cache,
            ),
        )
        for provenance, repo, pr_key, pr_url, created_at, merged_at, cache_dir in inputs:
            diff = read_cached_diff(cache_dir, pr_url + ".diff")
            feature_rows.append(
                build_pr_features(
                    pair_id=pair["pair_id"],
                    match_tier=pair["match_tier"],
                    provenance=provenance,
                    repo=repo,
                    pr_key=pr_key,
                    created_at=created_at,
                    merged_at=merged_at,
                    profile=diff_profile(diff),
                    lineage_rows=lineage_by_pr.get(pr_key, []),
                )
            )
    return pairs, feature_rows


def run_analysis(
    *,
    pairs_path: Path,
    lineage_path: Path,
    agent_cache: Path,
    human_cache: Path,
    output_dir: Path,
    expected_pairs: int = 100,
    bootstrap_iterations: int = 10_000,
    seed: int = 20_260_805,
) -> dict[str, object]:
    pairs, feature_rows = extract_feature_rows(
        pairs_path=pairs_path,
        lineage_path=lineage_path,
        agent_cache=agent_cache,
        human_cache=human_cache,
        expected_pairs=expected_pairs,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    analysis = analyze_feature_rows(feature_rows, bootstrap_iterations, seed)
    statistics_rows = analysis["feature_statistics"]
    performance_rows = analysis["threshold_performance"]
    oof_rows = analysis["oof_predictions"]
    _write_csv(output_dir / "pr_features.csv", feature_rows)
    _write_csv(output_dir / "feature_statistics.csv", statistics_rows)
    _write_csv(output_dir / "threshold_performance.csv", performance_rows)
    _write_csv(
        output_dir / "oof_predictions.csv",
        oof_rows,
        None if oof_rows else [
            "pr_key", "repo", "held_out_repo", "label", "score",
            "score_direction", "score_threshold", "prediction",
        ],
    )
    stable_features = sorted(
        {
            str(row["feature"])
            for row in statistics_rows
            if row["scope"] in {"same_repo_all_pairs", "same_repo_both_log_pairs"} and row["stable"]
        }
    )
    composite = next(row for row in performance_rows if row["model"] == "composite")
    summary = {
        "study": "GitHub matched PR log-source feature analysis",
        "seed": seed,
        "bootstrap_iterations": bootstrap_iterations,
        "n_pairs": len(pairs),
        "n_pr_rows": len(feature_rows),
        "n_same_repo_pairs": analysis["n_same_repo_pairs"],
        "n_cross_repo_pairs": analysis["n_cross_repo_pairs"],
        "n_same_repo_both_log_pairs": analysis["n_same_repo_both_log_pairs"],
        "n_primary_classifier_rows": analysis["n_primary_classifier_rows"],
        "n_primary_classifier_repositories": analysis["n_primary_classifier_repositories"],
        "agent_log_bearing_prs": sum(row["provenance"] == "agent" and int(row["n_production_logs"]) > 0 for row in feature_rows),
        "human_log_bearing_prs": sum(row["provenance"] == "human" and int(row["n_production_logs"]) > 0 for row in feature_rows),
        "agent_production_logs": sum(int(row["n_production_logs"]) for row in feature_rows if row["provenance"] == "agent"),
        "human_production_logs": sum(int(row["n_production_logs"]) for row in feature_rows if row["provenance"] == "human"),
        "score_status": analysis["model"]["status"],
        "stable_features": stable_features,
        "model": analysis["model"],
        "attribution_score_spec": ATTRIBUTION_SCORE_SPEC,
        "feature_usage_policy": {
            "candidate_recall_aggregates": [*STRUCTURAL_FEATURES, "batch_log_addition"],
            "risk_review_priority_aggregates": list(COMPOSITION_FEATURES),
            "exploratory_source_hypothesis_aggregates": list(SCORE_FEATURES),
            "automatic_source_label_features": stable_features,
            "raw_identity_fields_forbidden": [
                "repository_identity", "pr_identity", "raw_path", "raw_log_text", "template_hash"
            ],
        },
        "diff_source": "cached_github_raw_diff",
        "diff_completeness_qc": "unknown_raw_diff_limits",
        "classifier_oof": composite,
        "provenance_granularity": "pull_request",
        "line_authorship_proof": False,
        "runtime_leak_claim": False,
        "boundaries": [
            "PR-level GitHub App evidence is not line-level authorship proof",
            "static risk candidates are not confirmed runtime leaks",
            "lineage is a right-censored outcome and is excluded from source prediction",
            "cross-repository pairs are sensitivity analysis only",
        ],
    }
    _atomic_write_text(
        output_dir / "summary.json",
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
    )
    _atomic_write_text(output_dir / "report.md", _report(summary, statistics_rows, performance_rows))
    errors = verify_outputs(
        output_dir,
        expected_pairs=expected_pairs,
        pairs_path=pairs_path,
        lineage_path=lineage_path,
        agent_cache=agent_cache,
        human_cache=human_cache,
        expected_bootstrap_iterations=bootstrap_iterations,
        expected_seed=seed,
    )
    if errors:
        raise RuntimeError("; ".join(errors))
    return summary


def verify_outputs(
    output_dir: Path,
    expected_pairs: int = 100,
    *,
    pairs_path: Path | None = None,
    lineage_path: Path | None = None,
    agent_cache: Path | None = None,
    human_cache: Path | None = None,
    expected_bootstrap_iterations: int | None = None,
    expected_seed: int | None = None,
) -> list[str]:
    errors = [f"missing output: {name}" for name in OUTPUT_NAMES if not (output_dir / name).exists()]
    if errors:
        return errors
    rows = _read_csv(output_dir / "pr_features.csv")
    if len(rows) != expected_pairs * 2:
        errors.append(f"feature row count {len(rows)} != {expected_pairs * 2}")
    if len({row.get("pr_key") for row in rows}) != len(rows):
        errors.append("duplicate PR feature rows")
    if {row.get("provenance") for row in rows} != {"agent", "human"}:
        errors.append("provenance groups are not mutually present")
    by_pair: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_pair[row.get("pair_id", "")].append(row)
    if len(by_pair) != expected_pairs or any(
        len(group) != 2 or {row.get("provenance") for row in group} != {"agent", "human"}
        for group in by_pair.values()
    ):
        errors.append("each pair must contain exactly one agent and one human PR")
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    if summary.get("n_pairs") != expected_pairs or summary.get("n_pr_rows") != len(rows):
        errors.append("summary counts do not match feature rows")
    if summary.get("runtime_leak_claim") is not False:
        errors.append("runtime_leak_claim must remain false")
    if summary.get("line_authorship_proof") is not False:
        errors.append("line_authorship_proof must remain false")
    if expected_bootstrap_iterations is not None and summary.get("bootstrap_iterations") != expected_bootstrap_iterations:
        errors.append("bootstrap iteration count does not match requested verification")
    if expected_seed is not None and summary.get("seed") != expected_seed:
        errors.append("random seed does not match requested verification")
    if summary.get("diff_completeness_qc") != "unknown_raw_diff_limits" or any(
        row.get("diff_completeness_qc") != "unknown_raw_diff_limits" for row in rows
    ):
        errors.append("raw diff completeness boundary is missing")
    score_spec = summary.get("attribution_score_spec") or {}
    if score_spec != ATTRIBUTION_SCORE_SPEC:
        errors.append("attribution score specification was modified")
    if score_spec.get("hard_anchor_required") is not True or score_spec.get("high_confidence_threshold") != 80:
        errors.append("attribution score must require a hard anchor at the documented threshold")
    if any(
        signal.get("id") == "exploratory_content_screen"
        for signal in score_spec.get("supporting_signals", [])
    ):
        errors.append("content screen must not contribute to provenance evidence")
    tool_anchors = [
        anchor for anchor in score_spec.get("hard_anchors", [])
        if anchor.get("id") == "tool_write_full_added_line_coverage"
    ]
    if len(tool_anchors) != 1 or "session_pr_binding" not in tool_anchors[0].get("requires", []):
        errors.append("tool-write anchor must bind the session to the PR")
    expected_agent_prs = sum(
        row.get("provenance") == "agent" and int(row.get("n_production_logs") or 0) > 0 for row in rows
    )
    expected_human_prs = sum(
        row.get("provenance") == "human" and int(row.get("n_production_logs") or 0) > 0 for row in rows
    )
    if summary.get("agent_log_bearing_prs") != expected_agent_prs:
        errors.append("agent log-bearing PR count does not match features")
    if summary.get("human_log_bearing_prs") != expected_human_prs:
        errors.append("human log-bearing PR count does not match features")
    for provenance in ("agent", "human"):
        expected_logs = sum(
            int(row.get("n_production_logs") or 0) for row in rows if row.get("provenance") == provenance
        )
        if summary.get(f"{provenance}_production_logs") != expected_logs:
            errors.append(f"{provenance} production log count does not match features")
    if summary.get("n_same_repo_pairs") != len(
        {row.get("pair_id") for row in rows if row.get("match_tier") == "same_repository"}
    ) or summary.get("n_cross_repo_pairs") != len(
        {row.get("pair_id") for row in rows if row.get("match_tier") == "cross_repository"}
    ):
        errors.append("match-tier pair counts do not match features")
    model = summary.get("model") or {}
    rule_features = {str(rule.get("feature")) for rule in model.get("rules", [])}
    if not rule_features <= set(SCORE_FEATURES) or rule_features & set(FORBIDDEN_PREDICTORS):
        errors.append("model contains a forbidden or unknown predictor")
    if model.get("deployment_allowed") is not False:
        errors.append("exploratory content model must not be marked deployable")
    statistics_rows = _read_csv(output_dir / "feature_statistics.csv")
    if not any(row.get("scope") == "same_repo_all_pairs" for row in statistics_rows):
        errors.append("same-repository primary statistics are missing")
    for row in statistics_rows:
        try:
            q_value = float(row.get("bh_q", "nan"))
        except ValueError:
            errors.append("invalid BH q-value")
            break
        if math.isfinite(q_value) and not 0 <= q_value <= 1:
            errors.append("BH q-value outside [0, 1]")
            break
    stable_features = sorted(
        {
            row.get("feature", "") for row in statistics_rows
            if row.get("scope") in {"same_repo_all_pairs", "same_repo_both_log_pairs"}
            and row.get("stable") == "True"
        }
    )
    if summary.get("stable_features") != stable_features:
        errors.append("stable feature summary does not match statistics")
    expected_feature_policy = {
        "candidate_recall_aggregates": [*STRUCTURAL_FEATURES, "batch_log_addition"],
        "risk_review_priority_aggregates": list(COMPOSITION_FEATURES),
        "exploratory_source_hypothesis_aggregates": list(SCORE_FEATURES),
        "automatic_source_label_features": stable_features,
        "raw_identity_fields_forbidden": [
            "repository_identity", "pr_identity", "raw_path", "raw_log_text", "template_hash"
        ],
    }
    if summary.get("feature_usage_policy") != expected_feature_policy:
        errors.append("feature usage policy does not match the analysis contract")
    performance_rows = _read_csv(output_dir / "threshold_performance.csv")
    if not any(row.get("model") == "composite" for row in performance_rows):
        errors.append("composite threshold performance is missing")
    oof_rows = _read_csv(output_dir / "oof_predictions.csv")
    if len({row.get("pr_key") for row in oof_rows}) != len(oof_rows):
        errors.append("duplicate out-of-fold predictions")
    feature_by_key = {row.get("pr_key"): row for row in rows}
    if any(
        row.get("pr_key") not in feature_by_key
        or feature_by_key[row.get("pr_key")].get("match_tier") != "same_repository"
        or int(feature_by_key[row.get("pr_key")].get("n_production_logs") or 0) <= 0
        for row in oof_rows
    ):
        errors.append("out-of-fold predictions escaped the same-repository log-bearing scope")
    numeric_fields = {
        "label", "merge_latency_minutes", "production_added_lines", "deleted_lines",
        "production_source_files", "n_production_logs", "has_production_log",
        "batch_log_addition", "n_nonproduction_logs", "n_production_log_files",
        "log_density_per_100_added_lines", "log_file_coverage", *COMPOSITION_FEATURES,
    }
    typed_rows = []
    for row in rows:
        typed = dict(row)
        for field in numeric_fields:
            value = row.get(field, "")
            typed[field] = None if value == "" else float(value)
        typed_rows.append(typed)
    recomputed = analyze_feature_rows(
        typed_rows,
        bootstrap_iterations=int(summary.get("bootstrap_iterations") or 0),
        seed=int(summary.get("seed") or 0),
    )

    def csv_cells(expected: list[dict[str, object]]) -> list[dict[str, str]]:
        return [
            {key: "" if value is None else str(value) for key, value in row.items()}
            for row in expected
        ]

    if statistics_rows != csv_cells(recomputed["feature_statistics"]):
        errors.append("feature statistics do not match recomputation")
    if performance_rows != csv_cells(recomputed["threshold_performance"]):
        errors.append("threshold performance does not match recomputation")
    if oof_rows != csv_cells(recomputed["oof_predictions"]):
        errors.append("out-of-fold predictions do not match recomputation")
    expected_composite = next(
        row for row in recomputed["threshold_performance"] if row["model"] == "composite"
    )
    if summary.get("model") != recomputed["model"] or summary.get("classifier_oof") != expected_composite:
        errors.append("summary model does not match recomputation")
    source_arguments = (pairs_path, lineage_path, agent_cache, human_cache)
    if any(value is not None for value in source_arguments):
        if not all(value is not None for value in source_arguments):
            errors.append("source verification requires pairs, lineage, and both diff caches")
        else:
            _, source_feature_rows = extract_feature_rows(
                pairs_path=pairs_path,
                lineage_path=lineage_path,
                agent_cache=agent_cache,
                human_cache=human_cache,
                expected_pairs=expected_pairs,
            )
            if rows != csv_cells(source_feature_rows):
                errors.append("PR features do not match source recomputation")
    report = (output_dir / "report.md").read_text(encoding="utf-8")
    if report != _report(summary, recomputed["feature_statistics"], recomputed["threshold_performance"]):
        errors.append("report does not match recomputation")
    if (
        "Fallacy Scan" not in report
        or "## 证据边界" not in report
        or "会话补丁→PR 新增行" not in report
    ):
        errors.append("report is missing fallacy or evidence-boundary sections")
    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=Path, default=Path("outputs/github_log_lineage_poc/matched_prs.csv"))
    parser.add_argument("--lineage", type=Path, default=Path("outputs/github_log_lineage_poc/log_lineage.csv"))
    parser.add_argument("--agent-cache", type=Path, default=Path("data/res/github_agent_logs"))
    parser.add_argument("--human-cache", type=Path, default=Path("data/res/github_log_lineage/diffs"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/github_agent_human_feature_analysis"))
    parser.add_argument("--expected-pairs", type=int, default=100)
    parser.add_argument("--bootstrap-iterations", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20_260_805)
    parser.add_argument("--verify-only", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.verify_only:
        errors = verify_outputs(
            args.output_dir,
            args.expected_pairs,
            pairs_path=args.pairs,
            lineage_path=args.lineage,
            agent_cache=args.agent_cache,
            human_cache=args.human_cache,
            expected_bootstrap_iterations=args.bootstrap_iterations,
            expected_seed=args.seed,
        )
        print(json.dumps({"ok": not errors, "errors": errors}, ensure_ascii=False))
        return int(bool(errors))
    summary = run_analysis(
        pairs_path=args.pairs,
        lineage_path=args.lineage,
        agent_cache=args.agent_cache,
        human_cache=args.human_cache,
        output_dir=args.output_dir,
        expected_pairs=args.expected_pairs,
        bootstrap_iterations=args.bootstrap_iterations,
        seed=args.seed,
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
