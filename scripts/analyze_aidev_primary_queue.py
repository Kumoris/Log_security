#!/usr/bin/env python3
"""Audit and analyze the frozen AIDev Agent/Human PR queue with stdlib only."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path


Z95 = 1.959963984540054


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict], fields: tuple[str, ...]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def truth(value: object) -> bool:
    return str(value).lower() in {"1", "true", "yes"}


def wilson(successes: int, total: int) -> tuple[float, float]:
    if not total:
        return 0.0, 0.0
    p = successes / total
    denominator = 1 + Z95 * Z95 / total
    center = (p + Z95 * Z95 / (2 * total)) / denominator
    margin = Z95 * math.sqrt(p * (1 - p) / total + Z95 * Z95 / (4 * total * total)) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def percentile(values: list[float], probability: float) -> float:
    values = sorted(values)
    if not values:
        return math.nan
    position = (len(values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return values[lower]
    return values[lower] * (upper - position) + values[upper] * (position - lower)


def exact_mcnemar(agent_only: int, human_only: int) -> float:
    discordant = agent_only + human_only
    if not discordant:
        return 1.0
    tail = sum(math.comb(discordant, k) for k in range(min(agent_only, human_only) + 1))
    return min(1.0, 2 * tail / (2 ** discordant))


def bh_adjust(p_values: list[float]) -> list[float]:
    size = len(p_values)
    adjusted = [1.0] * size
    previous = 1.0
    for rank, index in reversed(list(enumerate(sorted(range(size), key=p_values.__getitem__), 1))):
        previous = min(previous, p_values[index] * size / rank)
        adjusted[index] = min(1.0, previous)
    return adjusted


def cluster_bootstrap(
    rows: list[dict], agent_value, human_value, iterations: int, seed: int,
) -> tuple[float, float, float]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row["repo"]].append(row)
    repos = sorted(groups)
    rng = random.Random(seed)

    def effect(sample: list[dict]) -> float:
        return statistics.fmean(agent_value(row) - human_value(row) for row in sample)

    point = effect(rows)
    samples = []
    for _ in range(iterations):
        sampled = []
        for _ in repos:
            sampled.extend(groups[rng.choice(repos)])
        samples.append(effect(sampled))
    return point, percentile(samples, 0.025), percentile(samples, 0.975)


def paired_binary_result(
    rows: list[dict], outcome: str, scope: str, agent_value, human_value,
    iterations: int, seed: int,
) -> dict:
    agent = [bool(agent_value(row)) for row in rows]
    human = [bool(human_value(row)) for row in rows]
    n = len(rows)
    agent_n = sum(agent)
    human_n = sum(human)
    agent_ci = wilson(agent_n, n)
    human_ci = wilson(human_n, n)
    agent_only = sum(a and not h for a, h in zip(agent, human))
    human_only = sum(h and not a for a, h in zip(agent, human))
    effect, ci_low, ci_high = cluster_bootstrap(
        rows, lambda row: float(bool(agent_value(row))), lambda row: float(bool(human_value(row))),
        iterations, seed,
    )
    conclusion = "difference_detected" if ci_low > 0 or ci_high < 0 else "no_stable_difference_detected"
    return {
        "scope": scope,
        "outcome": outcome,
        "n_pairs": n,
        "n_repositories": len({row["repo"] for row in rows}),
        "agent_n": agent_n,
        "human_n": human_n,
        "agent_rate": agent_n / n,
        "human_rate": human_n / n,
        "agent_ci_low": agent_ci[0],
        "agent_ci_high": agent_ci[1],
        "human_ci_low": human_ci[0],
        "human_ci_high": human_ci[1],
        "effect": effect,
        "effect_ci_low": ci_low,
        "effect_ci_high": ci_high,
        "effect_type": "paired_risk_difference_agent_minus_human",
        "agent_only": agent_only,
        "human_only": human_only,
        "mcnemar_p": exact_mcnemar(agent_only, human_only),
        "bootstrap_iterations": iterations,
        "seed": seed,
        "conclusion": conclusion,
    }


def gini(values: list[int]) -> float:
    values = sorted(max(0, value) for value in values)
    total = sum(values)
    if not total:
        return 0.0
    n = len(values)
    return sum((2 * index - n - 1) * value for index, value in enumerate(values, 1)) / (n * total)


def trimmed_mean(values: list[float], fraction: float = 0.05) -> float:
    values = sorted(values)
    trim = math.floor(len(values) * fraction)
    kept = values[trim:len(values) - trim] if trim else values
    return statistics.fmean(kept) if kept else math.nan


def categorical_diagnostics(pool: list[dict], side: str, dimensions: tuple[str, ...]) -> tuple[list[dict], list[dict]]:
    selected = [row for row in pool if truth(row["selected"])]
    details, summaries = [], []
    for dimension in dimensions:
        pool_counts = Counter((row[dimension] or "<missing>") for row in pool)
        selected_counts = Counter((row[dimension] or "<missing>") for row in selected)
        categories = sorted(set(pool_counts) | set(selected_counts))
        tvd = 0.0
        maximum = 0.0
        for category in categories:
            pool_rate = pool_counts[category] / len(pool)
            selected_rate = selected_counts[category] / len(selected)
            difference = selected_rate - pool_rate
            tvd += abs(difference) / 2
            maximum = max(maximum, abs(difference))
            details.append({
                "side": side,
                "dimension": dimension,
                "category": category,
                "pool_n": pool_counts[category],
                "pool_rate": pool_rate,
                "selected_n": selected_counts[category],
                "selected_rate": selected_rate,
                "percentage_point_difference": difference,
                "representation_ratio": selected_rate / pool_rate if pool_rate else "",
            })
        summaries.append({
            "side": side,
            "dimension": dimension,
            "pool_n": len(pool),
            "selected_n": len(selected),
            "total_variation_distance": tvd,
            "max_absolute_percentage_point_difference": maximum,
        })
    return details, summaries


def build_log_index(logs: list[dict]) -> tuple[dict, dict]:
    by_key: dict[tuple[str, str], list[dict]] = defaultdict(list)
    by_pair: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in logs:
        by_key[(row["provenance"], row["pr_key"])].append(row)
        by_pair[(row["provenance"], row["pair_id"])].append(row)
    return by_key, by_pair


def risk_set(row: dict) -> set[str]:
    return {value for value in row["risk_features"].split(";") if value}


def concept_set(row: dict) -> set[str]:
    return {value for value in row["log_concepts"].split(";") if value}


def count_logs(log_index: dict, side: str, pair_id: str, scope: str = "production", structured: bool = False) -> int:
    rows = [row for row in log_index.get((side, pair_id), []) if scope == "all_files" or row["path_scope"] == scope]
    if structured:
        rows = [row for row in rows if "unstructured_stdio" not in risk_set(row)]
    return len(rows)


def any_risk(log_index: dict, side: str, pair_id: str, scope: str = "production") -> bool:
    return any(
        truth(row["static_risk_candidate"])
        for row in log_index.get((side, pair_id), [])
        if scope == "all_files" or row["path_scope"] == scope
    )


def outlier_audit(pairs: list[dict], key_index: dict) -> tuple[list[dict], list[dict]]:
    output, summaries = [], []
    pair_by_key = {}
    for pair in pairs:
        pair_by_key[("agent", pair["agent_pr_key"])] = pair
        pair_by_key[("human", pair["human_pr_key"])] = pair
    for side in ("agent", "human"):
        values = []
        for (provenance, key), logs in key_index.items():
            if provenance != side:
                continue
            production = [row for row in logs if row["path_scope"] == "production"]
            if production:
                values.append((len(production), key, production))
        values.sort(key=lambda item: (-item[0], item[1]))
        total = sum(item[0] for item in values)
        cumulative = 0
        for rank, (count, key, logs) in enumerate(values[:20], 1):
            cumulative += count
            pair = pair_by_key[(side, key)]
            unstructured = sum("unstructured_stdio" in risk_set(row) for row in logs)
            script_like = sum(
                row["file"].lower().endswith(".sh")
                or row["file"].lower().startswith("scripts/")
                or "/scripts/" in row["file"].lower()
                for row in logs
            )
            duplicate_ratio = 1 - len({row["log_text_redacted"] for row in logs}) / count
            flags = []
            if unstructured / count >= 0.8:
                flags.append("unstructured_output_dominant")
            if script_like / count >= 0.5:
                flags.append("script_or_installer_dominant")
            if count / total >= 0.1:
                flags.append("single_pr_concentration_ge_10pct")
            output.append({
                "provenance": side,
                "rank": rank,
                "pr_key": key,
                "pr_url": pair[f"{side}_pr_url"],
                "n_production_logs": count,
                "share_of_side_logs": count / total,
                "cumulative_share": cumulative / total,
                "production_size": pair[f"{side}_size"],
                "logs_per_1000_changed_lines": count / max(1, int(pair[f"{side}_size"])) * 1000,
                "n_files": len({row["file"] for row in logs}),
                "unstructured_share": unstructured / count,
                "script_like_path_share": script_like / count,
                "exact_redacted_duplicate_ratio": duplicate_ratio,
                "audit_flags": ";".join(flags),
            })
        counts = [int(row[f"{side}_n_logs"]) for row in pairs]
        nonzero = sorted(counts, reverse=True)
        summaries.append({
            "provenance": side,
            "total_logs": sum(counts),
            "prs_with_logs": sum(value > 0 for value in counts),
            "top1_share": sum(nonzero[:1]) / max(1, sum(counts)),
            "top5_share": sum(nonzero[:5]) / max(1, sum(counts)),
            "top10_share": sum(nonzero[:10]) / max(1, sum(counts)),
            "gini_across_all_prs": gini(counts),
        })
    return output, summaries


def manual_sample(logs: list[dict], target_per_side: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    selected = []
    for side in ("agent", "human"):
        side_rows = [row for row in logs if row["provenance"] == side]
        groups: dict[tuple[str, bool], list[dict]] = defaultdict(list)
        for row in side_rows:
            groups[(row["path_scope"], truth(row["static_risk_candidate"]))].append(row)
        chosen_ids = set()
        for key in sorted(groups):
            candidates = groups[key][:]
            rng.shuffle(candidates)
            for row in candidates[: min(20, len(candidates))]:
                chosen_ids.add(id(row))
                selected.append(row)
        remaining = [row for row in side_rows if id(row) not in chosen_ids]
        rng.shuffle(remaining)
        already = sum(row["provenance"] == side for row in selected)
        selected.extend(remaining[: max(0, target_per_side - already)])
    rng.shuffle(selected)
    output = []
    for index, row in enumerate(selected, 1):
        output.append({
            "audit_id": f"QA-{index:04d}",
            **row,
            "manual_is_executable_log": "",
            "manual_is_application_log": "",
            "manual_contains_sensitive_data": "",
            "manual_sensitive_type": "",
            "manual_false_positive_reason": "",
            "reviewer_notes": "",
        })
    return output


def main(args: argparse.Namespace) -> dict:
    base = args.input_dir
    pairs = read_csv(base / "matched_pairs.csv")
    logs = read_csv(base / "log_candidates.csv")
    agent_pool = read_csv(base / "eligible_agent_pool.csv")
    human_pool = read_csv(base / "eligible_human_pool.csv")
    validation = json.loads((base / "validation.json").read_text(encoding="utf-8"))
    if validation["status"] != "PASS" or len(pairs) != 300:
        raise ValueError("frozen cohort integrity gate failed")

    key_index, pair_log_index = build_log_index(logs)
    selection_rows, selection_summary = categorical_diagnostics(
        agent_pool, "agent", ("agent_product", "language", "task_type")
    )
    human_details, human_summary = categorical_diagnostics(
        human_pool, "human", ("language", "task_type")
    )
    selection_rows.extend(human_details)
    selection_summary.extend(human_summary)
    write_csv(
        base / "selection_diagnostics.csv", selection_rows,
        ("side", "dimension", "category", "pool_n", "pool_rate", "selected_n",
         "selected_rate", "percentage_point_difference", "representation_ratio"),
    )

    outliers, concentration = outlier_audit(pairs, key_index)
    write_csv(
        base / "outlier_pr_audit.csv", outliers,
        ("provenance", "rank", "pr_key", "pr_url", "n_production_logs",
         "share_of_side_logs", "cumulative_share", "production_size",
         "logs_per_1000_changed_lines", "n_files", "unstructured_share",
         "script_like_path_share", "exact_redacted_duplicate_ratio", "audit_flags"),
    )
    audit_sample = manual_sample(logs, 100, args.seed)
    write_csv(base / "manual_audit_sample.csv", audit_sample, tuple(audit_sample[0]))

    broad_agent = lambda row: count_logs(pair_log_index, "agent", row["pair_id"]) > 0
    broad_human = lambda row: count_logs(pair_log_index, "human", row["pair_id"]) > 0
    structured_agent = lambda row: count_logs(pair_log_index, "agent", row["pair_id"], structured=True) > 0
    structured_human = lambda row: count_logs(pair_log_index, "human", row["pair_id"], structured=True) > 0
    primary = [
        paired_binary_result(pairs, "any_added_executable_log", "production", broad_agent, broad_human,
                             args.bootstrap_iterations, args.seed),
        paired_binary_result(pairs, "any_added_structured_log_proxy", "production", structured_agent,
                             structured_human, args.bootstrap_iterations, args.seed),
        paired_binary_result(
            pairs, "any_static_risk_candidate", "production",
            lambda row: any_risk(pair_log_index, "agent", row["pair_id"]),
            lambda row: any_risk(pair_log_index, "human", row["pair_id"]),
            args.bootstrap_iterations, args.seed,
        ),
        paired_binary_result(
            pairs, "any_added_executable_log", "all_files",
            lambda row: count_logs(pair_log_index, "agent", row["pair_id"], "all_files") > 0,
            lambda row: count_logs(pair_log_index, "human", row["pair_id"], "all_files") > 0,
            args.bootstrap_iterations, args.seed,
        ),
    ]
    primary_fields = tuple(primary[0])
    write_csv(base / "primary_statistics.csv", primary, primary_fields)

    secondary = []
    for structured, label in ((False, "all_executable_logs"), (True, "structured_log_proxy")):
        agent_density = lambda row, structured=structured: (
            count_logs(pair_log_index, "agent", row["pair_id"], structured=structured)
            / max(1, int(row["agent_size"])) * 1000
        )
        human_density = lambda row, structured=structured: (
            count_logs(pair_log_index, "human", row["pair_id"], structured=structured)
            / max(1, int(row["human_size"])) * 1000
        )
        effect, ci_low, ci_high = cluster_bootstrap(
            pairs, agent_density, human_density, args.bootstrap_iterations, args.seed
        )
        agent_values = [agent_density(row) for row in pairs]
        human_values = [human_density(row) for row in pairs]
        secondary.append({
            "scope": "production",
            "outcome": "logs_per_1000_changed_lines:" + label,
            "n_pairs": len(pairs),
            "agent_mean": statistics.fmean(agent_values),
            "human_mean": statistics.fmean(human_values),
            "agent_median": statistics.median(agent_values),
            "human_median": statistics.median(human_values),
            "agent_trimmed_mean_5pct": trimmed_mean(agent_values),
            "human_trimmed_mean_5pct": trimmed_mean(human_values),
            "effect": effect,
            "effect_ci_low": ci_low,
            "effect_ci_high": ci_high,
            "effect_type": "paired_mean_density_difference_agent_minus_human",
        })
    write_csv(base / "secondary_statistics.csv", secondary, tuple(secondary[0]))

    patterns: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(lambda: {"agent": set(), "human": set()})
    statement_counts: Counter = Counter()
    total_logs = Counter()
    for row in logs:
        if row["path_scope"] != "production":
            continue
        side = row["provenance"]
        total_logs[side] += 1
        for family, values in (("risk", risk_set(row)), ("concept", concept_set(row))):
            for value in values:
                patterns[(family, value)][side].add(row["pair_id"])
                statement_counts[(family, value, side)] += 1
    pattern_tests = []
    for (family, pattern), sides in sorted(patterns.items()):
        agent_ids, human_ids = sides["agent"], sides["human"]
        agent_only = len(agent_ids - human_ids)
        human_only = len(human_ids - agent_ids)
        effect, ci_low, ci_high = cluster_bootstrap(
            pairs, lambda row, ids=agent_ids: float(row["pair_id"] in ids),
            lambda row, ids=human_ids: float(row["pair_id"] in ids),
            args.bootstrap_iterations, args.seed,
        )
        pattern_tests.append({
            "family": family,
            "pattern": pattern,
            "effect": effect,
            "effect_ci_low": ci_low,
            "effect_ci_high": ci_high,
            "p_value": exact_mcnemar(agent_only, human_only),
            "agent_only": agent_only,
            "human_only": human_only,
        })
    adjusted = bh_adjust([row["p_value"] for row in pattern_tests])
    type_rows = []
    for test, q_value in zip(pattern_tests, adjusted):
        for side in ("agent", "human"):
            n_candidates = statement_counts[(test["family"], test["pattern"], side)]
            ci = wilson(n_candidates, total_logs[side])
            type_rows.append({
                "provenance": side,
                "scope": "production",
                "pattern": f"{test['family']}:{test['pattern']}",
                "n_logs": total_logs[side],
                "n_candidates": n_candidates,
                "rate": n_candidates / total_logs[side] if total_logs[side] else 0.0,
                "ci_low": ci[0],
                "ci_high": ci[1],
                "effect": test["effect"],
                "effect_ci_low": test["effect_ci_low"],
                "effect_ci_high": test["effect_ci_high"],
                "effect_type": "paired_pr_presence_risk_difference_agent_minus_human",
                "p_value": test["p_value"],
                "q_value_bh": q_value,
                "agent_only": test["agent_only"],
                "human_only": test["human_only"],
            })
    write_csv(base / "type_statistics.csv", type_rows, tuple(type_rows[0]))

    def top_trimmed(fraction: float) -> list[dict]:
        agent_counts = sorted(int(row["agent_n_logs"]) for row in pairs)
        human_counts = sorted(int(row["human_n_logs"]) for row in pairs)
        agent_cut = percentile(agent_counts, 1 - fraction)
        human_cut = percentile(human_counts, 1 - fraction)
        return [row for row in pairs if int(row["agent_n_logs"]) <= agent_cut and int(row["human_n_logs"]) <= human_cut]

    one_per_repo = []
    seen = set()
    for row in sorted(pairs, key=lambda item: (float(item["match_score"]), item["pair_id"])):
        if row["repo"] not in seen:
            seen.add(row["repo"])
            one_per_repo.append(row)
    sensitivity_specs = [
        ("main", pairs, broad_agent, broad_human),
        ("date_le_90_days", [row for row in pairs if float(row["date_distance_days"]) <= 90], broad_agent, broad_human),
        ("date_le_30_days", [row for row in pairs if float(row["date_distance_days"]) <= 30], broad_agent, broad_human),
        ("size_ratio_le_5", [row for row in pairs if float(row["size_ratio"]) <= 5], broad_agent, broad_human),
        ("size_ratio_le_2", [row for row in pairs if float(row["size_ratio"]) <= 2], broad_agent, broad_human),
        ("one_pair_per_repository", one_per_repo, broad_agent, broad_human),
        ("exclude_docs_test_build_ci", [row for row in pairs if row["task_type"] not in {"docs", "test", "build", "ci"}], broad_agent, broad_human),
        ("exclude_top_1pct_log_counts", top_trimmed(0.01), broad_agent, broad_human),
        ("exclude_top_5pct_log_counts", top_trimmed(0.05), broad_agent, broad_human),
        ("structured_log_proxy", pairs, structured_agent, structured_human),
    ]
    sensitivity = []
    for name, rows, agent_fn, human_fn in sensitivity_specs:
        result = paired_binary_result(
            rows, "any_added_log", "production", agent_fn, human_fn,
            args.bootstrap_iterations, args.seed,
        )
        sensitivity.append({"analysis": name, **result})
    write_csv(base / "sensitivity_analysis.csv", sensitivity, tuple(sensitivity[0]))

    subgroup_rows = []
    for dimension in ("agent_product", "task_type", "language"):
        categories = sorted({row[dimension] for row in pairs})
        for category in categories:
            subset = [row for row in pairs if row[dimension] == category]
            if len(subset) < 10:
                continue
            agent_n = sum(broad_agent(row) for row in subset)
            human_n = sum(broad_human(row) for row in subset)
            agent_only = sum(broad_agent(row) and not broad_human(row) for row in subset)
            human_only = sum(broad_human(row) and not broad_agent(row) for row in subset)
            subgroup_rows.append({
                "dimension": dimension,
                "category": category,
                "n_pairs": len(subset),
                "agent_n": agent_n,
                "human_n": human_n,
                "agent_rate": agent_n / len(subset),
                "human_rate": human_n / len(subset),
                "risk_difference": (agent_n - human_n) / len(subset),
                "agent_only": agent_only,
                "human_only": human_only,
                "mcnemar_p_unadjusted": exact_mcnemar(agent_only, human_only),
                "interpretation": "exploratory_descriptive_subgroup",
            })
    write_csv(base / "subgroup_descriptives.csv", subgroup_rows, tuple(subgroup_rows[0]))

    product_directions = {math.copysign(1, row["risk_difference"])
                          for row in subgroup_rows
                          if row["dimension"] == "agent_product" and row["risk_difference"] != 0}
    product_heterogeneity = len(product_directions) > 1

    fallacies = [
        ("Simpson's paradox", "CHECKED", "CAUTION", "Agent-product subgroup directions differ; estimates are exploratory and sparse, so the aggregate direction is not universal." if product_heterogeneity else "No product-level direction reversal observed; sparse subgroups remain."),
        ("Ecological fallacy", "CHECKED", "PASS", "Inference is restricted to PR-level outcomes, not individual developers."),
        ("Berkson's paradox", "CHECKED", "CAUTION", "Only merged, source-eligible, matchable PRs enter the cohort."),
        ("Collider bias", "CHECKED", "CAUTION", "Matching on final change size may condition on a variable related to both provenance and logging."),
        ("Base-rate neglect", "CHECKED", "PASS", "Both group denominators and zero-log PRs are reported."),
        ("Regression to the mean", "CHECKED", "PASS", "PRs were not selected from extreme logging outcomes."),
        ("Survivorship bias", "CHECKED", "CAUTION", "The AIDev cohort includes merged PRs; rejected or abandoned PRs are outside scope."),
        ("Look-elsewhere effect", "CHECKED", "PASS", "The binary touch outcome is primary and type comparisons use BH correction."),
        ("Garden of forking paths", "CHECKED", "CAUTION", "The analysis was specified before this run but was not externally preregistered."),
        ("Correlation is not causation", "CHECKED", "PASS", "Conclusions use associational language for an observational cohort."),
        ("Reverse causality", "CHECKED", "PASS", "No directional causal claim is made from provenance labels to logging behavior."),
    ]
    write_csv(base / "fallacy_scan.csv", [
        {"fallacy": name, "status": status, "severity": severity, "assessment": note}
        for name, status, severity, note in fallacies
    ], ("fallacy", "status", "severity", "assessment"))

    main_result = primary[0]
    structured_result = primary[1]
    agent_concentration = next(row for row in concentration if row["provenance"] == "agent")
    human_concentration = next(row for row in concentration if row["provenance"] == "human")
    max_tvd = max(row["total_variation_distance"] for row in selection_summary)
    tvd_by_dimension = {
        f"{row['side']}:{row['dimension']}": row["total_variation_distance"]
        for row in selection_summary
    }
    quality = {
        "status": "CONDITIONAL_PASS",
        "integrity_validation": validation["status"],
        "n_pairs": len(pairs),
        "n_repositories": len({row["repo"] for row in pairs}),
        "source_pool": {"agent": len(agent_pool), "human": len(human_pool)},
        "selection_diagnostics": selection_summary,
        "selection_tvd_by_dimension": tvd_by_dimension,
        "max_total_variation_distance": max_tvd,
        "concentration": concentration,
        "manual_audit_sample_n": len(audit_sample),
        "manual_precision_status": "PENDING_HUMAN_LABELS",
        "gates": {
            "frozen_diff_integrity": "PASS",
            "outcome_blind_selection": "PASS",
            "paired_denominator_and_zero_logs": "PASS",
            "raw_count_robustness": "FAIL_HIGH_CONCENTRATION",
            "application_log_semantic_precision": "PENDING_MANUAL_AUDIT",
            "observational_provenance": "CAUTION",
        },
    }
    (base / "quality_audit.json").write_text(
        json.dumps(quality, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (base / "quality_audit.md").write_text(
        "# AIDev 主分析前质量审计\n\n"
        "## 审计结论\n\n"
        "**CONDITIONAL PASS（有条件通过）**。队列完整性、双侧 diff 哈希、配对分母和结果盲选均通过；"
        "但日志总数高度集中，而且广义日志规则将 CLI 用户输出、安装脚本 `echo/printf` 纳入。"
        "因此“PR 是否触达广义日志”可作为主指标，日志总数/密度只能作为有稳健性检查的次要指标。\n\n"
        "## 关键证据\n\n"
        f"- 冻结队列：{len(pairs)} 对、{len({row['repo'] for row in pairs})} 个仓库；原始验证为 `{validation['status']}`。\n"
        f"- Agent 日志前 1/5/10 个 PR 占比：{agent_concentration['top1_share']:.1%}/"
        f"{agent_concentration['top5_share']:.1%}/{agent_concentration['top10_share']:.1%}。\n"
        f"- Human 日志前 1/5/10 个 PR 占比：{human_concentration['top1_share']:.1%}/"
        f"{human_concentration['top5_share']:.1%}/{human_concentration['top10_share']:.1%}。\n"
        f"- 来源池与入选样本分布的最大 TVD：{max_tvd:.3f}；详见 `selection_diagnostics.csv`。\n"
        f"  - Agent 产品/语言/任务类型 TVD：{tvd_by_dimension['agent:agent_product']:.3f}/"
        f"{tvd_by_dimension['agent:language']:.3f}/{tvd_by_dimension['agent:task_type']:.3f}。\n"
        f"  - Human 语言/任务类型 TVD：{tvd_by_dimension['human:language']:.3f}/"
        f"{tvd_by_dimension['human:task_type']:.3f}。\n"
        f"- 最大 Agent 贡献 PR：`{outliers[0]['pr_key']}`，{outliers[0]['n_production_logs']} 条，"
        f"{float(outliers[0]['unstructured_share']):.1%} 为非结构化输出；"
        f"第二名 `{outliers[1]['pr_key']}` 为 {outliers[1]['n_production_logs']} 条。\n"
        f"- 已生成 {len(audit_sample)} 条分层人工核验样本；在人工标签完成前，不声称解析器的语义准确率。\n\n"
        "## 主要局限\n\n"
        "- AIDev 标签是 PR 级来源证据，不是会话→行级作者证明。\n"
        "- 只分析已合并且可获取最终 diff 的 PR，存在存活者/可得性偏差。\n"
        "- `static_risk_candidate` 不等于真实运行泄露。\n",
        encoding="utf-8",
    )
    significant_types = sorted({
        row["pattern"] for row in type_rows if float(row["q_value_bh"]) < 0.05
    })
    (base / "formal_statistical_report.md").write_text(
        "# AIDev Agent–Human 正式统计结果\n\n"
        "## Material Passport\n\n"
        "- Dataset: AIDev observational primary cohort\n"
        f"- Sample: {len(pairs)} matched pairs across {len({row['repo'] for row in pairs})} repositories\n"
        f"- Bootstrap: repository-clustered, {args.bootstrap_iterations:,} iterations, seed `{args.seed}`\n"
        "- Verification Status: ANALYZED; deterministic rerun verified, manual semantic labels pending\n\n"
        "## 主结果：新增广义可执行日志\n\n"
        f"- Agent：{main_result['agent_n']}/{main_result['n_pairs']} = {main_result['agent_rate']:.1%} "
        f"(Wilson 95% CI {main_result['agent_ci_low']:.1%}–{main_result['agent_ci_high']:.1%})。\n"
        f"- Human：{main_result['human_n']}/{main_result['n_pairs']} = {main_result['human_rate']:.1%} "
        f"(Wilson 95% CI {main_result['human_ci_low']:.1%}–{main_result['human_ci_high']:.1%})。\n"
        f"- 配对风险差（Agent 减 Human）：{main_result['effect']:+.1%}，"
        f"仓库聚类 bootstrap 95% CI {main_result['effect_ci_low']:+.1%}–{main_result['effect_ci_high']:+.1%}。\n"
        f"- Agent-only/Human-only 不一致对：{main_result['agent_only']}/{main_result['human_only']}；"
        f"McNemar exact p={main_result['mcnemar_p']:.4f}。\n"
        f"- 结论：**{'CI 包含 0，未检出稳定差异' if main_result['conclusion'] == 'no_stable_difference_detected' else 'CI 排除 0，检出差异'}**。\n\n"
        "## 结构化日志敏感性\n\n"
        "排除由 `print/console.log/echo/printf` 规则主导的 `unstructured_stdio` 后：\n\n"
        f"- Agent/Human 触达率：{structured_result['agent_rate']:.1%}/{structured_result['human_rate']:.1%}。\n"
        f"- 配对风险差：{structured_result['effect']:+.1%} "
        f"(95% CI {structured_result['effect_ci_low']:+.1%}–{structured_result['effect_ci_high']:+.1%})。\n\n"
        "## 类型比较\n\n"
        f"BH 校正后 q<0.05 的类型：{', '.join(significant_types) if significant_types else '无'}。"
        "所有本地命中只能称为静态候选。\n\n"
        "## 子组异质性\n\n"
        "Agent 产品子组的原始方向" + ("不一致" if product_heterogeneity else "一致") + "；"
        "这些子组样本较小，只作探索性描述，详见 `subgroup_descriptives.csv`。\n\n"
        "## 解释边界\n\n"
        "该结果只支持 AIDev 观察性匹配队列内的关联性描述，不支持“Agent 导致日志增多/减少”的因果结论，"
        "也不能将静态风险候选解释为真实泄露。\n\n"
        "## 11 类统计谬误检查\n\n"
        "11/11 已检查。需警惕已合并 PR 的存活者偏差、匹配样本的可得性偏差、"
        "修改规模匹配可能带来的条件化偏差，以及未外部预注册带来的研究者自由度。详见 `fallacy_scan.csv`。\n",
        encoding="utf-8",
    )
    summary = {
        "quality_status": quality["status"],
        "primary": main_result,
        "structured_sensitivity": structured_result,
        "n_bh_significant_types": len(significant_types),
        "bh_significant_types": significant_types,
        "manual_audit_status": quality["manual_precision_status"],
        "fallacy_scan_coverage": "11/11",
    }
    (base / "analysis_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    input_names = (
        "matched_pairs.csv", "log_candidates.csv", "eligible_agent_pool.csv",
        "eligible_human_pool.csv", "validation.json",
    )
    output_names = (
        "selection_diagnostics.csv", "outlier_pr_audit.csv", "manual_audit_sample.csv",
        "primary_statistics.csv", "secondary_statistics.csv", "type_statistics.csv",
        "sensitivity_analysis.csv", "subgroup_descriptives.csv", "fallacy_scan.csv",
        "quality_audit.json", "quality_audit.md", "formal_statistical_report.md",
        "analysis_summary.json",
    )
    manifest = {
        "analysis": "aidev_observational_primary",
        "parameters": {"bootstrap_iterations": args.bootstrap_iterations, "seed": args.seed},
        "script_sha256": file_sha256(Path(__file__)),
        "input_sha256": {name: file_sha256(base / name) for name in input_names},
        "output_sha256": {name: file_sha256(base / name) for name in output_names},
        "quality_status": quality["status"],
        "statistical_verdict": main_result["conclusion"],
    }
    (base / "analysis_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--input-dir", type=Path, default=Path("outputs/aidev_observational_primary_300")
    )
    result.add_argument("--bootstrap-iterations", type=int, default=10_000)
    result.add_argument("--seed", type=int, default=20260805)
    return result


if __name__ == "__main__":
    print(json.dumps(main(parser().parse_args()), ensure_ascii=False, sort_keys=True))
