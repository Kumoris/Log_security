#!/usr/bin/env python3
"""Compare static secure-logging candidates in SWE-chat agent and human additions."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path, PurePosixPath


PATTERNS = ("IL-At", "IL-Pa", "IL-Lv", "SS-Cr", "SS-Cf", "SS-Ur", "RM-Ms", "RM-Ft", "EE-Ex", "EE-St")
PROVENANCES = ("human_only", "agent_only", "mixed")
OUTPUT_FIELDS = ("provenance", "scope", "pattern", "n_logs", "n_candidates", "rate", "ci_low", "ci_high", "effect")
EXCLUDED_PARTS = {
    "test", "tests", "testing", "__tests__", "fixture", "fixtures", "example", "examples",
    "sample", "samples", "generated", "vendor", "vendors", "node_modules", "dist", "build",
    "target", ".cache",
}


def is_production_path(value: str) -> bool:
    path = PurePosixPath(value.replace("\\", "/"))
    parts = {part.lower() for part in path.parts}
    if parts & EXCLUDED_PARTS:
        return False
    name = path.name.lower()
    stem_parts = name.split(".")
    return not (
        name.startswith("test_")
        or name.endswith("_test.py")
        or "test" in stem_parts[1:-1]
        or "spec" in stem_parts[1:-1]
        or name.endswith(".snap")
    )


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return center - margin, center + margin


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return math.nan
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] * (upper - position) + ordered[upper] * (position - lower)


def parse_candidate(value: str) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    raise ValueError(f"invalid security_issue_candidate value: {value!r}")


def load_rows(path: Path) -> list[dict[str, object]]:
    required = {"dataset", "repo", "file", "add_remove", "attribution", "security_issue_candidate", "primary_pattern"}
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"missing input columns: {', '.join(sorted(missing))}")
        raw_rows = list(reader)
    validate_source_summary(path, raw_rows)
    selected = []
    for row in raw_rows:
        if row["dataset"] != "SWE-chat" or row["add_remove"] != "add" or row["attribution"] not in PROVENANCES:
            continue
        candidate = parse_candidate(row["security_issue_candidate"])
        pattern = row["primary_pattern"]
        if candidate and pattern not in PATTERNS:
            raise ValueError(f"candidate row has non-taxonomy primary pattern: {pattern!r}")
        selected.append({**row, "candidate": candidate})
    return selected


def validate_source_summary(path: Path, rows: list[dict[str, str]]) -> None:
    summary_path = path.with_name("summary.json")
    if not summary_path.exists():
        return
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    expected_total = summary.get("overall", {}).get("total_log_candidates")
    if expected_total is not None and len(rows) != expected_total:
        raise ValueError(f"input row count {len(rows)} != summary total {expected_total}")
    actual = defaultdict(int)
    for row in rows:
        actual[row["dataset"]] += 1
    for item in summary.get("by_dataset", []):
        if actual[item["dataset"]] != item["total_log_candidates"]:
            raise ValueError(f"dataset total mismatch for {item['dataset']}")


def paired_repo_effect(
    rows: list[dict[str, object]], iterations: int, seed: int, pattern: str = "ALL"
) -> tuple[float, float, float, int]:
    grouped: dict[str, dict[str, list[bool]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        if row["attribution"] in {"human_only", "agent_only"}:
            matched = bool(row["candidate"]) and (pattern == "ALL" or row["primary_pattern"] == pattern)
            grouped[str(row["repo"])][str(row["attribution"])].append(matched)
    differences = []
    for values in grouped.values():
        if values["human_only"] and values["agent_only"]:
            human_rate = sum(values["human_only"]) / len(values["human_only"])
            agent_rate = sum(values["agent_only"]) / len(values["agent_only"])
            differences.append(agent_rate - human_rate)
    if not differences:
        return math.nan, math.nan, math.nan, 0
    point = statistics.fmean(differences)
    rng = random.Random(seed)
    boot = [statistics.fmean(rng.choice(differences) for _ in differences) for _ in range(iterations)]
    return point, percentile(boot, 0.025), percentile(boot, 0.975), len(differences)


def two_proportion_p(a: int, n_a: int, h: int, n_h: int) -> float:
    if not n_a or not n_h:
        return 1.0
    pooled = (a + h) / (n_a + n_h)
    variance = pooled * (1 - pooled) * (1 / n_a + 1 / n_h)
    if variance == 0:
        return 1.0
    z = (a / n_a - h / n_h) / math.sqrt(variance)
    return math.erfc(abs(z) / math.sqrt(2))


def odds_ratio(a: int, n_a: int, h: int, n_h: int) -> float:
    cells = [a, n_a - a, h, n_h - h]
    if any(cell == 0 for cell in cells):
        cells = [cell + 0.5 for cell in cells]
    return (cells[0] * cells[3]) / (cells[1] * cells[2])


def benjamini_hochberg(p_values: dict[str, float]) -> dict[str, float]:
    ordered = sorted(p_values, key=p_values.get)
    adjusted: dict[str, float] = {}
    running = 1.0
    total = len(ordered)
    for rank in range(total, 0, -1):
        key = ordered[rank - 1]
        running = min(running, p_values[key] * total / rank)
        adjusted[key] = running
    return adjusted


def fmt(value: float) -> str:
    return "NA" if math.isnan(value) else f"{value:.6f}"


def analyze_rows(rows: list[dict[str, object]], iterations: int, seed: int) -> list[dict[str, object]]:
    output = []
    for scope in ("production", "all_files"):
        scoped = [row for row in rows if scope == "all_files" or is_production_path(str(row["file"]))]
        by_provenance = {key: [row for row in scoped if row["attribution"] == key] for key in PROVENANCES}
        point, low, high, paired_repos = paired_repo_effect(scoped, iterations, seed)
        human = by_provenance["human_only"]
        agent = by_provenance["agent_only"]
        p_values = {}
        for pattern in PATTERNS:
            agent_count = sum(row["candidate"] and row["primary_pattern"] == pattern for row in agent)
            human_count = sum(row["candidate"] and row["primary_pattern"] == pattern for row in human)
            p_values[pattern] = two_proportion_p(agent_count, len(agent), human_count, len(human))
        q_values = benjamini_hochberg(p_values)

        for provenance in PROVENANCES:
            group = by_provenance[provenance]
            for pattern in ("ALL", *PATTERNS):
                count = sum(
                    bool(row["candidate"]) and (pattern == "ALL" or row["primary_pattern"] == pattern)
                    for row in group
                )
                ci_low, ci_high = wilson_interval(count, len(group))
                if provenance == "human_only":
                    effect = "reference"
                elif provenance == "mixed":
                    effect = "descriptive_only"
                elif pattern == "ALL":
                    effect = (
                        f"mean_repo_risk_difference={fmt(point)};"
                        f"bootstrap95%=[{fmt(low)},{fmt(high)}];paired_repos={paired_repos}"
                    )
                else:
                    human_count = sum(row["candidate"] and row["primary_pattern"] == pattern for row in human)
                    pattern_point, pattern_low, pattern_high, pattern_repos = paired_repo_effect(
                        scoped, iterations, seed, pattern
                    )
                    effect = (
                        f"odds_ratio_vs_human={odds_ratio(count, len(group), human_count, len(human)):.6f};"
                        f"bh_q={q_values[pattern]:.6f};"
                        f"mean_repo_risk_difference={fmt(pattern_point)};"
                        f"bootstrap95%=[{fmt(pattern_low)},{fmt(pattern_high)}];paired_repos={pattern_repos}"
                    )
                output.append(
                    {
                        "provenance": provenance,
                        "scope": scope,
                        "pattern": pattern,
                        "n_logs": len(group),
                        "n_candidates": count,
                        "rate": f"{count / len(group):.6f}" if group else "0.000000",
                        "ci_low": f"{ci_low:.6f}",
                        "ci_high": f"{ci_high:.6f}",
                        "effect": effect,
                    }
                )
        overall = {row["attribution"]: sum(r["candidate"] for r in by_provenance[row["attribution"]]) for row in scoped}
        for provenance in PROVENANCES:
            pattern_total = sum(
                row["n_candidates"] for row in output
                if row["scope"] == scope and row["provenance"] == provenance and row["pattern"] != "ALL"
            )
            if pattern_total != overall[provenance]:
                raise AssertionError(f"pattern counts do not reconcile for {scope}/{provenance}")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--bootstrap-iterations", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20_260_805)
    args = parser.parse_args()
    if args.bootstrap_iterations < 1:
        parser.error("--bootstrap-iterations must be positive")
    rows = load_rows(args.input_csv)
    results = analyze_rows(rows, args.bootstrap_iterations, args.seed)
    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.output_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(results)
    print(f"wrote {len(results)} rows from {len(rows)} SWE-chat added logs to {args.output_csv}")


if __name__ == "__main__":
    main()
