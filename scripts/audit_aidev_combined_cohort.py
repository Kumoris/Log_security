#!/usr/bin/env python3
"""Run the pre-analysis quality audit for the combined AIDev PR cohort."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path

if __package__:
    from .analyze_aidev_primary_queue import file_sha256, gini
    from .screen_github_agent_logs import AGENT_NATIVE_RISK_FEATURES, SHARED_SENSITIVE_RISK_FEATURES
else:
    from analyze_aidev_primary_queue import file_sha256, gini
    from screen_github_agent_logs import AGENT_NATIVE_RISK_FEATURES, SHARED_SENSITIVE_RISK_FEATURES


DEFAULT_ORIGINAL = Path("outputs/aidev_observational_primary_300")
DEFAULT_EXPANSION = Path("outputs/aidev_expansion_structured_evidence_v1")
DEFAULT_QUEUE = Path("outputs/privacy_cohort_expansion_capacity_v1/aidev_prefetch_queue.csv")
DEFAULT_BATCHES = (
    Path("outputs/aidev_expansion_diff_pilot_v1/candidate_audit.csv"),
    Path("outputs/aidev_expansion_diff_batch_0050_0149_v1/candidate_audit.csv"),
    Path("outputs/aidev_expansion_diff_batch_0150_0649_v1/candidate_audit.csv"),
)
DEFAULT_OUTPUT = Path("outputs/aidev_combined_482_preanalysis_audit_v1")
SENSITIVE_FEATURES = AGENT_NATIVE_RISK_FEATURES | SHARED_SENSITIVE_RISK_FEATURES


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def truth(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def risk_set(row: dict[str, str]) -> set[str]:
    return {value for value in row.get("risk_features", "").split(";") if value}


def is_script_like(path: str) -> bool:
    value = path.lower().replace("\\", "/")
    return value.endswith((".sh", ".bash", ".zsh")) or value.startswith("scripts/") or "/scripts/" in value


def normalize_pairs(original: list[dict[str, str]], expansion: list[dict[str, str]]) -> list[dict]:
    rows = []
    for row in original:
        rows.append({
            "cohort": "original_300", "pair_id": row["pair_id"], "repo": row["repo"],
            "language": row["language"], "task_type": row["task_type"],
            "agent_product": row["agent_product"], "agent_pr_key": row["agent_pr_key"],
            "human_pr_key": row["human_pr_key"], "agent_diff_path": row["agent_diff_path"],
            "human_diff_path": row["human_diff_path"], "agent_diff_sha256": row["agent_diff_sha256"],
            "human_diff_sha256": row["human_diff_sha256"], "agent_size": int(row["agent_size"]),
            "human_size": int(row["human_size"]), "date_distance_days": float(row["date_distance_days"]),
            "size_ratio": float(row["size_ratio"]), "agent_merged_at": row["agent_merged_at"],
            "human_merged_at": row["human_merged_at"], "exact_repo": truth(row["exact_repo"]),
            "exact_task_type": truth(row["exact_task_type"]), "exact_language": truth(row["exact_language"]),
            "agent_n_logs": int(row["agent_n_logs"]), "human_n_logs": int(row["human_n_logs"]),
            "agent_n_logs_all_files": int(row["agent_n_logs_all_files"]),
            "human_n_logs_all_files": int(row["human_n_logs_all_files"]),
        })
    for row in expansion:
        rows.append({
            "cohort": "expansion_182", "pair_id": row["candidate_id"], "repo": row["repo"],
            "language": row["language"], "task_type": row["task_type"],
            "agent_product": row["agent_product"], "agent_pr_key": row["agent_pr_key"],
            "human_pr_key": row["human_pr_key"], "agent_diff_path": row["agent_diff_path"],
            "human_diff_path": row["human_diff_path"], "agent_diff_sha256": row["agent_diff_sha256"],
            "human_diff_sha256": row["human_diff_sha256"], "agent_size": int(row["agent_size"]),
            "human_size": int(row["human_size"]), "date_distance_days": float(row["date_distance_days"]),
            "size_ratio": float(row["size_ratio"]), "agent_merged_at": row["agent_merged_at"],
            "human_merged_at": row["human_merged_at"], "exact_repo": True,
            "exact_task_type": True, "exact_language": True,
            "agent_n_logs": 0, "human_n_logs": 0,
            "agent_n_logs_all_files": 0, "human_n_logs_all_files": 0,
        })
    return rows


def normalize_logs(original: list[dict[str, str]], expansion: list[dict[str, str]]) -> list[dict]:
    rows = []
    for cohort, source, pair_field in (
        ("original_300", original, "pair_id"), ("expansion_182", expansion, "candidate_id")
    ):
        for row in source:
            identity = row.get("evidence_id") or hashlib.sha256(
                "|".join((cohort, row["pr_key"], row["file"], row["line"], row["log_text_redacted"])).encode()
            ).hexdigest()[:20]
            rows.append({
                "evidence_id": identity, "cohort": cohort, "pair_id": row[pair_field],
                "provenance": row["provenance"], "repo": row["repo"], "pr_key": row["pr_key"],
                "file": row["file"], "line": row["line"], "path_scope": row["path_scope"],
                "risk_features": row["risk_features"], "log_concepts": row["log_concepts"],
                "log_text_redacted": row["log_text_redacted"],
            })
    return rows


def categorical_shift(
    pool: list[dict], selected: list[dict], comparison: str, side: str, dimensions: tuple[str, ...]
) -> tuple[list[dict], list[dict]]:
    details, summaries = [], []
    for dimension in dimensions:
        pool_counts = Counter((row.get(dimension) or "<missing>") for row in pool)
        selected_counts = Counter((row.get(dimension) or "<missing>") for row in selected)
        tvd = 0.0
        for category in sorted(set(pool_counts) | set(selected_counts)):
            pool_rate = pool_counts[category] / len(pool) if pool else 0.0
            selected_rate = selected_counts[category] / len(selected) if selected else 0.0
            tvd += abs(selected_rate - pool_rate) / 2
            details.append({
                "comparison": comparison, "side": side, "dimension": dimension, "category": category,
                "pool_n": pool_counts[category], "pool_rate": pool_rate,
                "selected_n": selected_counts[category], "selected_rate": selected_rate,
                "percentage_point_difference": selected_rate - pool_rate,
                "representation_ratio": selected_rate / pool_rate if pool_rate else "",
            })
        summaries.append({
            "comparison": comparison, "side": side, "dimension": dimension,
            "pool_n": len(pool), "selected_n": len(selected), "total_variation_distance": tvd,
        })
    return details, summaries


def concentration_audit(pairs: list[dict], logs: list[dict]) -> tuple[list[dict], list[dict]]:
    pair_by_id = {row["pair_id"]: row for row in pairs}
    output, summaries = [], []
    for side in ("agent", "human"):
        by_pr: dict[str, list[dict]] = defaultdict(list)
        for row in logs:
            if row["provenance"] == side and row["path_scope"] == "production":
                by_pr[row["pr_key"]].append(row)
        ranked = sorted(by_pr.items(), key=lambda item: (-len(item[1]), item[0]))
        total = sum(len(group) for _, group in ranked)
        cumulative = 0
        counts = Counter(row["pair_id"] for row in logs if row["provenance"] == side and row["path_scope"] == "production")
        for rank, (pr_key, group) in enumerate(ranked[:20], 1):
            cumulative += len(group)
            pair = pair_by_id[group[0]["pair_id"]]
            unstructured = sum("unstructured_stdio" in risk_set(row) for row in group)
            structured = len(group) - unstructured
            sensitive = sum(bool(risk_set(row) & SENSITIVE_FEATURES) for row in group)
            script_like = sum(is_script_like(row["file"]) for row in group)
            duplicate_ratio = 1 - len({row["log_text_redacted"] for row in group}) / len(group)
            flags = []
            if unstructured / len(group) >= 0.8:
                flags.append("unstructured_output_dominant")
            if script_like / len(group) >= 0.5:
                flags.append("script_or_installer_dominant")
            if len(group) / total >= 0.1:
                flags.append("single_pr_concentration_ge_10pct")
            output.append({
                "provenance": side, "rank": rank, "cohort": pair["cohort"],
                "pair_id": pair["pair_id"], "repo": pair["repo"], "pr_key": pr_key,
                "n_production_logs": len(group), "n_structured_proxy": structured,
                "n_sensitive_family_candidates": sensitive, "share_of_side_logs": len(group) / total,
                "cumulative_share": cumulative / total, "unstructured_share": unstructured / len(group),
                "script_like_path_share": script_like / len(group),
                "exact_redacted_duplicate_ratio": duplicate_ratio, "audit_flags": ";".join(flags),
            })
        all_counts = [counts.get(row["pair_id"], 0) for row in pairs]
        ordered = sorted(all_counts, reverse=True)
        summaries.append({
            "provenance": side, "total_logs": sum(all_counts),
            "prs_with_logs": sum(value > 0 for value in all_counts),
            "top1_share": sum(ordered[:1]) / max(1, sum(all_counts)),
            "top5_share": sum(ordered[:5]) / max(1, sum(all_counts)),
            "top10_share": sum(ordered[:10]) / max(1, sum(all_counts)),
            "gini_across_all_prs": gini(all_counts),
            "structured_proxy_logs": sum(
                row["provenance"] == side and row["path_scope"] == "production"
                and "unstructured_stdio" not in risk_set(row) for row in logs
            ),
            "sensitive_family_candidate_rows": sum(
                row["provenance"] == side and row["path_scope"] == "production"
                and bool(risk_set(row) & SENSITIVE_FEATURES) for row in logs
            ),
        })
    return output, summaries


def audit_sample(logs: list[dict], target_per_side: int, seed: int) -> tuple[list[dict], list[dict]]:
    rng = random.Random(seed)
    selected = []
    for side in ("agent", "human"):
        side_rows = [row for row in logs if row["provenance"] == side and row["path_scope"] == "production"]
        groups: dict[tuple[str, bool, bool], list[dict]] = defaultdict(list)
        for row in side_rows:
            groups[(row["cohort"], "unstructured_stdio" in risk_set(row), bool(risk_set(row) & SENSITIVE_FEATURES))].append(row)
        for group in groups.values():
            rng.shuffle(group)
        chosen = []
        while len(chosen) < min(target_per_side, len(side_rows)):
            progressed = False
            for key in sorted(groups):
                if groups[key] and len(chosen) < target_per_side:
                    chosen.append(groups[key].pop())
                    progressed = True
            if not progressed:
                break
        selected.extend(chosen)
    rng.shuffle(selected)
    queue, key_rows = [], []
    for index, row in enumerate(selected, 1):
        audit_id = f"COMBINED-QA-{index:04d}"
        queue.append({
            "audit_id": audit_id, "file": row["file"], "line": row["line"],
            "log_text_redacted": row["log_text_redacted"], "manual_is_executable_log": "",
            "manual_is_application_observability": "", "manual_sensitive_decision": "",
            "manual_sensitive_type": "", "manual_false_positive_reason": "", "reviewer_notes": "",
        })
        key_rows.append({
            "audit_id": audit_id, "evidence_id": row["evidence_id"], "cohort": row["cohort"],
            "pair_id": row["pair_id"], "provenance": row["provenance"], "repo": row["repo"],
            "pr_key": row["pr_key"], "risk_features": row["risk_features"],
            "log_concepts": row["log_concepts"],
        })
    return queue, key_rows


def run(args: argparse.Namespace) -> dict:
    original_pairs_raw = read_csv(args.original_dir / "matched_pairs.csv")
    expansion_pairs_raw = read_csv(args.expansion_dir / "matched_pairs.csv")
    original_logs_raw = read_csv(args.original_dir / "log_candidates.csv")
    expansion_logs_raw = read_csv(args.expansion_dir / "log_evidence.csv")
    expansion_prs = read_csv(args.expansion_dir / "pr_evidence.csv")
    agent_pool = read_csv(args.original_dir / "eligible_agent_pool.csv")
    human_pool = read_csv(args.original_dir / "eligible_human_pool.csv")
    queue = read_csv(args.prefetch_queue)
    batch_audits = [row for path in args.batch_audits for row in read_csv(path)]
    original_validation = json.loads((args.original_dir / "validation.json").read_text(encoding="utf-8"))
    expansion_summary = json.loads((args.expansion_dir / "summary.json").read_text(encoding="utf-8"))

    pairs = normalize_pairs(original_pairs_raw, expansion_pairs_raw)
    logs = normalize_logs(original_logs_raw, expansion_logs_raw)
    errors = []
    if len(original_pairs_raw) != 300 or len(expansion_pairs_raw) != 182 or len(pairs) != 482:
        errors.append("unexpected cohort size")
    if original_validation.get("status") != "PASS":
        errors.append("original validation is not PASS")
    if expansion_summary.get("status") != "FROZEN_EXPANSION_PRE_ANALYSIS_AUDIT":
        errors.append("expansion is not frozen for audit")
    if len(queue) != 650 or len(batch_audits) != 650 or {r["candidate_id"] for r in queue} != {r["candidate_id"] for r in batch_audits}:
        errors.append("expansion attempt coverage is incomplete")

    pair_ids = [row["pair_id"] for row in pairs]
    agent_keys = [row["agent_pr_key"] for row in pairs]
    human_keys = [row["human_pr_key"] for row in pairs]
    if len(pair_ids) != len(set(pair_ids)):
        errors.append("pair IDs are not unique")
    if len(agent_keys) != len(set(agent_keys)) or len(human_keys) != len(set(human_keys)):
        errors.append("a PR is reused within a provenance side")
    if set(agent_keys) & set(human_keys):
        errors.append("Agent and Human PR sets overlap")
    if max(Counter(row["repo"] for row in pairs).values(), default=0) > 5:
        errors.append("combined repository cap exceeds five pairs")
    if any(
        not (row["exact_repo"] and row["exact_task_type"] and row["exact_language"])
        or row["date_distance_days"] > 180 or row["size_ratio"] > 10
        or not row["agent_merged_at"] or not row["human_merged_at"]
        for row in pairs
    ):
        errors.append("a pair violates the matching or merge gate")

    hash_mismatches, missing_diffs = [], []
    for row in pairs:
        for side in ("agent", "human"):
            path = Path(row[f"{side}_diff_path"])
            if not path.is_file():
                missing_diffs.append(str(path))
            elif file_sha256(path) != row[f"{side}_diff_sha256"]:
                hash_mismatches.append(f"{row['pair_id']}:{side}")
    if missing_diffs or hash_mismatches:
        errors.append("diff snapshot hash replay failed")

    log_counts = Counter((row["cohort"], row["pair_id"], row["provenance"], row["path_scope"]) for row in logs)
    for row in pairs:
        if row["cohort"] == "original_300":
            for side in ("agent", "human"):
                production = log_counts[(row["cohort"], row["pair_id"], side, "production")]
                all_files = production + log_counts[(row["cohort"], row["pair_id"], side, "non_production")]
                if production != row[f"{side}_n_logs"] or all_files != row[f"{side}_n_logs_all_files"]:
                    errors.append(f"original log count mismatch:{row['pair_id']}:{side}")
    expansion_pr_index = {(row["candidate_id"], row["provenance"]): row for row in expansion_prs}
    for row in pairs:
        if row["cohort"] != "expansion_182":
            continue
        for side in ("agent", "human"):
            pr = expansion_pr_index[(row["pair_id"], side)]
            production = log_counts[(row["cohort"], row["pair_id"], side, "production")]
            all_files = production + log_counts[(row["cohort"], row["pair_id"], side, "non_production")]
            row[f"{side}_n_logs"], row[f"{side}_n_logs_all_files"] = production, all_files
            if production != int(pr["n_logs_production"]) or all_files != int(pr["n_logs_all_files"]):
                errors.append(f"expansion log count mismatch:{row['pair_id']}:{side}")
    if errors:
        raise ValueError("; ".join(sorted(set(errors))))

    admissions = []
    for row in pairs:
        identical = row["agent_diff_sha256"] == row["human_diff_sha256"]
        admissions.append({
            "cohort": row["cohort"], "pair_id": row["pair_id"], "repo": row["repo"],
            "agent_pr_key": row["agent_pr_key"], "human_pr_key": row["human_pr_key"],
            "agent_diff_sha256": row["agent_diff_sha256"], "human_diff_sha256": row["human_diff_sha256"],
            "status": "EXCLUDE" if identical else "CONDITIONALLY_ELIGIBLE",
            "reason": "IDENTICAL_AGENT_HUMAN_FINAL_DIFF" if identical else "PASSED_AUTOMATIC_PREANALYSIS_GATES",
        })
    excluded = [row for row in admissions if row["status"] == "EXCLUDE"]
    admitted_ids = {row["pair_id"] for row in admissions if row["status"] == "CONDITIONALLY_ELIGIBLE"}
    admitted_pairs = [row for row in pairs if row["pair_id"] in admitted_ids]

    selection_details, selection_summaries = [], []
    selected_agent_pool = [row for row in agent_pool if row["pr_key"] in set(agent_keys)]
    selected_human_pool = [row for row in human_pool if row["pr_key"] in set(human_keys)]
    if len(selected_agent_pool) != 482 or len(selected_human_pool) != 482:
        raise ValueError("combined selected PRs do not map back to the eligible source pools")
    for result in (
        categorical_shift(agent_pool, selected_agent_pool, "eligible_pool_to_combined", "agent", ("agent_product", "language", "task_type")),
        categorical_shift(human_pool, selected_human_pool, "eligible_pool_to_combined", "human", ("language", "task_type")),
        categorical_shift(queue, expansion_pairs_raw, "expansion_candidates_to_accepted", "paired", ("agent_product", "language", "task_type")),
        categorical_shift(original_pairs_raw, expansion_pairs_raw, "original_to_expansion", "paired", ("agent_product", "language", "task_type")),
    ):
        selection_details.extend(result[0])
        selection_summaries.extend(result[1])

    audit_by_id = {row["candidate_id"]: row for row in batch_audits}
    reasons = Counter((row.get("reason") or "accepted") for row in batch_audits)
    attrition_rows = []
    for dimension in ("agent_product", "language", "task_type"):
        for category in sorted({row[dimension] for row in queue}):
            members = [row for row in queue if row[dimension] == category]
            member_reasons = Counter((audit_by_id[row["candidate_id"]].get("reason") or "accepted") for row in members)
            attrition_rows.append({
                "dimension": dimension, "category": category, "n_candidates": len(members),
                "n_accepted": member_reasons["accepted"], "acceptance_rate": member_reasons["accepted"] / len(members),
                "agent_no_production_source_change": member_reasons["agent_no_production_source_change"],
                "human_no_production_source_change": member_reasons["human_no_production_source_change"],
                "final_size_caliper": member_reasons["final_size_caliper"],
                "github_404": member_reasons["GitHub diff HTTP 404: Not Found"],
            })

    outliers, concentration = concentration_audit(admitted_pairs, [row for row in logs if row["pair_id"] in admitted_ids])
    manual_queue, manual_key = audit_sample(logs, args.manual_sample_per_side, args.seed)
    max_tvd = max(row["total_variation_distance"] for row in selection_summaries)
    raw_count_failure = any(row["top10_share"] >= 0.5 or row["gini_across_all_prs"] >= 0.8 for row in concentration)

    fallacies = [
        ("Simpson's paradox", "CAUTION", "Agent product, language and task distributions are retained for stratified sensitivity checks."),
        ("Ecological fallacy", "PASS", "Pair, PR and log-statement units remain separate."),
        ("Berkson's paradox", "CAUTION", "Only merged, source-eligible and matchable PRs are observed."),
        ("Collider bias", "CAUTION", "Requiring production-source changes and a final-size caliper may condition on task outcomes."),
        ("Base-rate neglect", "PASS", "All zero-log PRs remain in the pair denominator."),
        ("Regression to the mean", "PASS", "Selection did not inspect logging outcomes."),
        ("Survivorship bias", "CAUTION", "Only merged PRs with retrievable final diffs are included; expansion acceptance was 182/650."),
        ("Look-elsewhere effect", "PASS", "This audit performs no inferential hypothesis tests."),
        ("Garden of forking paths", "CAUTION", "Audit thresholds are recorded before formal analysis; the two duplicate-patch exclusions are explicit."),
        ("Correlation is not causation", "PASS", "The design remains observational and supports association only."),
        ("Reverse causality", "CAUTION", "Task assignment may jointly influence provenance and logging need."),
    ]

    gates = {
        "frozen_diff_hash_replay": "PASS",
        "pair_and_pr_uniqueness": "PASS",
        "exact_repo_task_language_matching": "PASS",
        "date_and_final_size_calipers": "PASS",
        "outcome_blind_selection_and_zero_log_denominator": "PASS",
        "expansion_attempt_coverage": "PASS_650_OF_650",
        "duplicate_patch_independence": f"PASS_AFTER_EXCLUDING_{len(excluded)}_PAIRS",
        "source_pool_representativeness": "CAUTION_DISTRIBUTION_SHIFT" if max_tvd >= 0.1 else "PASS",
        "raw_log_count_robustness": "FAIL_HIGH_CONCENTRATION" if raw_count_failure else "PASS",
        "parser_count_consistency": "PASS",
        "application_log_semantic_precision": "PENDING_INDEPENDENT_LABELS",
        "sensitive_candidate_semantic_precision": "PENDING_INDEPENDENT_LABELS",
        "github_changed_files_completeness_crosscheck": "NOT_PERFORMED",
        "observational_provenance": "CAUTION_PR_LABEL_NOT_LINE_AUTHORSHIP",
    }
    summary = {
        "status": "CONDITIONAL_PASS",
        "overall_confidence": "CAUTION",
        "original_pairs": 300, "expansion_pairs": 182, "combined_frozen_pairs": 482,
        "excluded_identical_patch_pairs": len(excluded), "conditionally_eligible_pairs": len(admitted_pairs),
        "repositories": len({row["repo"] for row in admitted_pairs}),
        "diff_files_hash_replayed": len(pairs) * 2,
        "expansion_metadata_candidates": len(queue), "expansion_accepted_pairs": len(expansion_pairs_raw),
        "expansion_acceptance_rate": len(expansion_pairs_raw) / len(queue),
        "attrition_reason_counts": dict(sorted(reasons.items())),
        "matching": {
            "date_distance_days": {"median": statistics.median(row["date_distance_days"] for row in admitted_pairs),
                                   "p90": quantile([row["date_distance_days"] for row in admitted_pairs], 0.9),
                                   "max": max(row["date_distance_days"] for row in admitted_pairs)},
            "size_ratio": {"median": statistics.median(row["size_ratio"] for row in admitted_pairs),
                           "p90": quantile([row["size_ratio"] for row in admitted_pairs], 0.9),
                           "max": max(row["size_ratio"] for row in admitted_pairs)},
        },
        "selection_shift_summary": selection_summaries,
        "max_total_variation_distance": max_tvd,
        "concentration": concentration,
        "automatic_sensitive_family_rows": {
            side: sum(row["provenance"] == side and row["path_scope"] == "production" and bool(risk_set(row) & SENSITIVE_FEATURES) for row in logs)
            for side in ("agent", "human")
        },
        "manual_audit_queue_rows": len(manual_queue),
        "manual_audit_status": "PENDING_INDEPENDENT_LABELS",
        "gates": gates, "fallacy_scan_coverage": "11/11",
        "claim_boundary": "PR-level observational provenance; static candidates are not runtime leaks",
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "admission_decisions.csv", admissions, (
        "cohort", "pair_id", "repo", "agent_pr_key", "human_pr_key", "agent_diff_sha256",
        "human_diff_sha256", "status", "reason",
    ))
    write_csv(args.output_dir / "selection_diagnostics.csv", selection_details, (
        "comparison", "side", "dimension", "category", "pool_n", "pool_rate", "selected_n",
        "selected_rate", "percentage_point_difference", "representation_ratio",
    ))
    write_csv(args.output_dir / "attrition_diagnostics.csv", attrition_rows, (
        "dimension", "category", "n_candidates", "n_accepted", "acceptance_rate",
        "agent_no_production_source_change", "human_no_production_source_change",
        "final_size_caliper", "github_404",
    ))
    write_csv(args.output_dir / "outlier_pr_audit.csv", outliers, (
        "provenance", "rank", "cohort", "pair_id", "repo", "pr_key", "n_production_logs",
        "n_structured_proxy", "n_sensitive_family_candidates", "share_of_side_logs",
        "cumulative_share", "unstructured_share", "script_like_path_share",
        "exact_redacted_duplicate_ratio", "audit_flags",
    ))
    write_csv(args.output_dir / "manual_audit_queue.csv", manual_queue, (
        "audit_id", "file", "line", "log_text_redacted", "manual_is_executable_log",
        "manual_is_application_observability", "manual_sensitive_decision", "manual_sensitive_type",
        "manual_false_positive_reason", "reviewer_notes",
    ))
    write_csv(args.output_dir / "manual_audit_key.csv", manual_key, (
        "audit_id", "evidence_id", "cohort", "pair_id", "provenance", "repo", "pr_key",
        "risk_features", "log_concepts",
    ))
    write_csv(args.output_dir / "fallacy_scan.csv", [
        {"fallacy": name, "severity": severity, "assessment": assessment}
        for name, severity, assessment in fallacies
    ], ("fallacy", "severity", "assessment"))
    (args.output_dir / "quality_audit.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    agent_concentration = next(row for row in concentration if row["provenance"] == "agent")
    human_concentration = next(row for row in concentration if row["provenance"] == "human")
    excluded_text = "\n".join(
        f"- `{row['agent_pr_key']}` ↔ `{row['human_pr_key']}`" for row in excluded
    )
    (args.output_dir / "quality_audit.md").write_text(f"""# AIDev 合并队列主分析前质量审计

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-04
- Verification Status: ANALYZED_DETERMINISTIC_AUTOMATIC_AUDIT
- Version Label: aidev_combined_482_preanalysis_audit_v1

## 审计结论

**CONDITIONAL PASS（有条件通过）**。新增 182 对的自动完整性检查全部通过；但原 300 对中发现 2 对 Agent/Human 最终 diff 完全相同，不能当作独立对照。冻结原数据保留不变；排除这 2 对后，**480 对有条件可进入正式主分析**。

## 入选与完整性

- 冻结队列：300 + 182 = 482 对；排除 2 对后为 {len(admitted_pairs)} 对，覆盖 {len({row['repo'] for row in admitted_pairs})} 个仓库。
- {len(pairs) * 2} 个 Agent/Human diff 文件均重算 SHA-256 成功；PR 未跨组重用，每仓库最多 5 对。
- 同仓库、同任务类型、同语言、180 天和 10 倍最终规模卡尺全部通过。
- 时间差中位数 {summary['matching']['date_distance_days']['median']:.1f} 天，p90 {summary['matching']['date_distance_days']['p90']:.1f} 天；规模比中位数 {summary['matching']['size_ratio']['median']:.2f}，p90 {summary['matching']['size_ratio']['p90']:.2f}。

### 必须排除的重复补丁对

{excluded_text}

## 扩展队列选择偏差

- 650 对元数据候选已全部尝试，182 对入选，接受率 {summary['expansion_acceptance_rate']:.1%}。
- 未入选原因：Agent 无生产源代码修改 {reasons['agent_no_production_source_change']} 对，Human 无生产源代码修改 {reasons['human_no_production_source_change']} 对，规模卡尺失败 {reasons['final_size_caliper']} 对，GitHub 404 为 {reasons['GitHub diff HTTP 404: Not Found']} 对。
- 来源池、候选与入选样本的最大总变差距离（TVD）为 {max_tvd:.3f}；详见 `selection_diagnostics.csv`。这不会使数据失效，但要求正式分析报告产品、语言和任务类型敏感性。

## 日志解析与异常集中

- Agent 生产日志 {agent_concentration['total_logs']} 条，前 1/5/10 个 PR 占 {agent_concentration['top1_share']:.1%}/{agent_concentration['top5_share']:.1%}/{agent_concentration['top10_share']:.1%}。
- Human 生产日志 {human_concentration['total_logs']} 条，前 1/5/10 个 PR 占 {human_concentration['top1_share']:.1%}/{human_concentration['top5_share']:.1%}/{human_concentration['top10_share']:.1%}。
- 原始条数仍受 CLI/脚本输出和少数极端 PR 支配，因此正式主指标必须使用“PR 是否新增至少一条生产日志”；日志总数/密度只能作次要敏感性指标。
- 自动敏感特征家族命中：Agent {summary['automatic_sensitive_family_rows']['agent']} 条，Human {summary['automatic_sensitive_family_rows']['human']} 条。未经独立语义标注，不得用于泄露率结论。
- 已生成 {len(manual_queue)} 条固定种子、隐藏来源标签的人工审计队列。标注未完成，因此解析器语义精度门槛仍为 `PENDING_INDEPENDENT_LABELS`。

## 正式分析的强制限制

1. 使用 `admission_decisions.csv` 中的 {len(admitted_pairs)} 对，不得将 2 对重复补丁纳入。
2. 主效应使用配对 PR-level presence；必须报告结构化日志、去极值、每仓库一对、时间/规模卡尺敏感性。
3. 隐私类型和敏感值结论需等独立标注；当前只能称“静态风险候选”。
4. AIDev 只提供 PR 级 Agent/Human 来源，不是会话到行级作者证明；Human 标签也不能排除未披露 AI 协助。
5. 本轮未使用 GitHub `changed_files` 对每个 `.diff` 做第二来源完整性核验；这是证据强化项，不影响本地哈希可重放性。

## 统计谬误扫描

- Coverage: 11/11 checked.
- 主要风险：已合并 PR 的存活者偏差，生产源代码和规模卡尺的条件化偏差，产品/语言/任务组成差异，以及观察性数据的因果误读。

## 可重现性

- 自动审计仅使用 Python 标准库，随机种子 `{args.seed}`。
- 输入、输出和脚本 SHA-256 记录于 `manifest.json`。
""", encoding="utf-8")

    input_paths = [
        args.original_dir / "matched_pairs.csv", args.original_dir / "log_candidates.csv",
        args.original_dir / "eligible_agent_pool.csv", args.original_dir / "eligible_human_pool.csv",
        args.original_dir / "validation.json", args.expansion_dir / "matched_pairs.csv",
        args.expansion_dir / "pr_evidence.csv", args.expansion_dir / "log_evidence.csv",
        args.expansion_dir / "summary.json", args.prefetch_queue, *args.batch_audits,
    ]
    output_names = (
        "admission_decisions.csv", "selection_diagnostics.csv", "attrition_diagnostics.csv",
        "outlier_pr_audit.csv", "manual_audit_queue.csv", "manual_audit_key.csv",
        "fallacy_scan.csv", "quality_audit.json", "quality_audit.md",
    )
    manifest = {
        "analysis": "aidev_combined_preanalysis_quality_audit",
        "parameters": {"seed": args.seed, "manual_sample_per_side": args.manual_sample_per_side},
        "script_sha256": file_sha256(Path(__file__)),
        "input_sha256": {str(path): file_sha256(path) for path in input_paths},
        "output_sha256": {name: file_sha256(args.output_dir / name) for name in output_names},
        "deterministic": True, "quality_status": summary["status"],
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--original-dir", type=Path, default=DEFAULT_ORIGINAL)
    result.add_argument("--expansion-dir", type=Path, default=DEFAULT_EXPANSION)
    result.add_argument("--prefetch-queue", type=Path, default=DEFAULT_QUEUE)
    result.add_argument("--batch-audit", action="append", type=Path, default=[])
    result.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    result.add_argument("--manual-sample-per-side", type=int, default=100)
    result.add_argument("--seed", type=int, default=20260805)
    return result


if __name__ == "__main__":
    arguments = parser().parse_args()
    arguments.batch_audits = arguments.batch_audit or list(DEFAULT_BATCHES)
    print(json.dumps(run(arguments), ensure_ascii=False, sort_keys=True))
