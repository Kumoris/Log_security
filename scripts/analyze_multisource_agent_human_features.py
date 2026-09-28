#!/usr/bin/env python3
"""Extract and compare evidence-aware log features across three local sources."""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import random
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

from analyze_coding_agent_log_leakage import benjamini_hochberg, percentile


csv.field_size_limit(sys.maxsize)

SEED = 20_260_805
FEATURES = (
    "structured_logger_sink",
    "unstructured_stdio",
    "severity_debug",
    "severity_info",
    "severity_warn",
    "severity_error",
    "severity_fatal",
    "severity_trace",
    "severity_neutral",
    "dynamic_value",
    "multiple_dynamic_values",
    "literal_only",
    "key_value_message",
    "structured_metadata_argument",
    "long_literal_message",
    "static_risk_candidate",
    "error_diagnostic_data",
    "whole_object_dump",
    "debug_residue_marker",
    "auth_config_data",
    "identity_session_data",
    "request_response_data",
    "agent_control_data",
    "tool_io_data",
)

RISK_MAP = {
    "error_diagnostic_data": "error_diagnostic_data",
    "whole_object_dump": "whole_object_dump",
    "debug_residue_marker": "debug_residue_marker",
    "auth_config_data": "auth_config_data",
    "identity_session_data": "identity_session_data",
    "request_response_data": "request_response_data",
    "agent_control_data": "agent_control_data",
    "tool_io_data": "tool_io_data",
}
STRING_RE = re.compile(r"(?i)(?:[rubf]{0,2})(['\"`])(?:\\.|(?!\1).)*\1")
UNSTRUCTURED_RE = re.compile(
    r"(?i)(?<![.\w])print\s*\(|\bconsole\s*\.|\bfmt\s*\.\s*(?:Print|Fprint)"
    r"|\bSystem\s*\.\s*(?:out|err)|^\s*(?:echo|printf)\b|\b(?:println|eprintln|dbg)!\s*\("
)
STRUCTURED_RE = re.compile(
    r"(?i)\b(?:logger|logging|log)\s*\.\s*(?:debug|info|warn|warning|error|exception|critical|trace|fatal)\s*\("
    r"|\blog\s*\.\s*(?:Print|Printf|Println|Fatal|Fatalf|Panic|Panicf)\s*\("
    r"|\b(?:debug|info|warn|error|trace)!\s*\("
)
SLOT_RE = re.compile(
    r"%(?:\([^)]+\))?[#0 +\-]?[0-9.*]*[a-zA-Z]|\$\{[^{}]+\}|\{[a-zA-Z_][^{}]*\}|\{\}"
)


def literal_text(text: str) -> str:
    values = []
    for match in STRING_RE.finditer(text or ""):
        token = match.group(0)
        quote = next(candidate for candidate in ('"', "'", "`") if candidate in token)
        start, end = token.find(quote), token.rfind(quote)
        if 0 <= start < end:
            values.append(token[start + 1 : end])
    return " ".join(values)


def severity(text: str) -> str:
    value = text or ""
    ordered = (
        ("fatal", r"(?i)\b(?:fatal|critical|panic|panicf)\b"),
        ("error", r"(?i)\b(?:error|exception|eprintln)\b|System\s*\.\s*err"),
        ("warn", r"(?i)\b(?:warn|warning)\b"),
        ("debug", r"(?i)\b(?:debug|dbg)\b"),
        ("trace", r"(?i)\btrace\b"),
        ("info", r"(?i)\binfo\b"),
    )
    for name, pattern in ordered:
        if re.search(pattern, value):
            return name
    return "neutral"


def extract_features(text: str, risk_features: str = "") -> dict[str, int]:
    value = text or ""
    literals = literal_text(value)
    risk = {item for item in (risk_features or "").split(";") if item}
    without_literals = STRING_RE.sub('""', value)
    slots = len(SLOT_RE.findall(literals))
    extra_arg = bool(re.search(r"['\"]\s*,\s*(?!\s*(?:end|file|flush)\s*=)[^)]", value))
    interpolation = bool(re.search(r"\$\{[^{}]+\}|\{[a-zA-Z_][^{}]*\}", literals))
    concatenation = bool(re.search(r"\+\s*[a-zA-Z_]|\.format\s*\(", without_literals))
    dynamic = slots > 0 or extra_arg or interpolation or concatenation
    extra_commas = len(re.findall(r",", without_literals))
    level = severity(value)
    output = {name: 0 for name in FEATURES}
    output["structured_logger_sink"] = int(bool(STRUCTURED_RE.search(value)))
    output["unstructured_stdio"] = int(bool(UNSTRUCTURED_RE.search(value)))
    output[f"severity_{level}"] = 1
    output["dynamic_value"] = int(dynamic)
    output["multiple_dynamic_values"] = int(slots >= 2 or extra_commas >= 2)
    output["literal_only"] = int(not dynamic)
    output["key_value_message"] = int(bool(re.search(r"\b[a-zA-Z_][\w.-]*\s*(?:=|:)\s*", literals)))
    output["structured_metadata_argument"] = int(
        bool(
            re.search(r"['\"]\s*,\s*[\[{]", value)
            or re.search(r"(?i),\s*(?:extra|context|fields|metadata)\s*=", value)
        )
    )
    output["long_literal_message"] = int(len(literals) >= 80)
    output["static_risk_candidate"] = int(bool(risk))
    for feature, source_name in RISK_MAP.items():
        output[feature] = int(source_name in risk)
    return output


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_github_pairs(path: Path) -> dict[str, tuple[str, str]]:
    mapping = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            pair_id, tier = row["pair_id"], row["match_tier"]
            mapping[row["agent_pr_key"]] = (pair_id, tier)
            mapping[row["human_pr_key"]] = (pair_id, tier)
    return mapping


def pair_for_row(row: dict[str, str], github_pairs: dict[str, tuple[str, str]]) -> tuple[str, str]:
    if row["dataset"] == "SWE-chat" and row["provenance"] in {"agent", "human"}:
        return f"swe:{row['repo']}:{row['source_id']}", "same_checkpoint"
    if row["dataset"] == "GitHub-matched-PR":
        return github_pairs.get(row["source_id"], ("", ""))
    return "", ""


def read_and_extract(
    input_path: Path, line_path: Path, github_pairs: dict[str, tuple[str, str]]
) -> tuple[list[dict[str, object]], Counter]:
    base_fields = (
        "dataset", "provenance", "dataset_provenance", "repo", "source_id", "pr_key",
        "commit", "checkpoint", "file", "line", "scope", "analysis_pair_id", "match_tier",
        "binding_id", "binding_status", "provenance_grade", "generation_stage",
        "analysis_eligibility", "line_authorship_proof",
    )
    units: dict[tuple[str, ...], dict[str, object]] = {}
    counts = Counter()
    with input_path.open(newline="", encoding="utf-8") as source, line_path.open(
        "w", newline="", encoding="utf-8"
    ) as destination:
        reader = csv.DictReader(source)
        writer = csv.DictWriter(destination, fieldnames=base_fields + FEATURES, lineterminator="\n")
        writer.writeheader()
        for row in reader:
            features = extract_features(row["log_text"], row["risk_features"])
            pair_id, tier = pair_for_row(row, github_pairs)
            writer.writerow(
                {
                    **{field: row.get(field, "") for field in base_fields if field not in {"analysis_pair_id", "match_tier"}},
                    "analysis_pair_id": pair_id,
                    "match_tier": tier,
                    **features,
                }
            )
            counts[f"lines:{row['dataset']}:{row['scope']}:{row['provenance']}"] += 1
            if row["scope"] != "production":
                continue
            key = (
                row["dataset"], row["repo"], row["source_id"], row["provenance"],
                row["dataset_provenance"], pair_id, tier, row.get("binding_id", ""),
                row.get("provenance_grade", "C"), row.get("analysis_eligibility", "sensitivity_only"),
            )
            unit = units.setdefault(
                key,
                {
                    "dataset": row["dataset"],
                    "repo": row["repo"],
                    "source_id": row["source_id"],
                    "provenance": row["provenance"],
                    "dataset_provenance": row["dataset_provenance"],
                    "analysis_pair_id": pair_id,
                    "match_tier": tier,
                    "binding_id": row.get("binding_id", ""),
                    "binding_status": row.get("binding_status", "not_evaluated"),
                    "provenance_grade": row.get("provenance_grade", "C"),
                    "generation_stage": row.get("generation_stage", ""),
                    "analysis_eligibility": row.get("analysis_eligibility", "sensitivity_only"),
                    "line_authorship_proof": row.get("line_authorship_proof", "false"),
                    "n_logs": 0,
                    "feature_counts": Counter(),
                },
            )
            unit["n_logs"] = int(unit["n_logs"]) + 1
            unit["feature_counts"].update(name for name, hit in features.items() if hit)
    output = []
    for unit in units.values():
        n_logs = int(unit["n_logs"])
        feature_counts = unit.pop("feature_counts")
        output.append(
            {
                **unit,
                **{feature: feature_counts[feature] / n_logs for feature in FEATURES},
            }
        )
    output.sort(key=lambda row: (str(row["dataset"]), str(row["repo"]), str(row["source_id"]), str(row["provenance"])))
    return output, counts


def sign_flip_p(values: list[float], iterations: int, seed: int) -> float:
    observed = abs(statistics.fmean(values)) if values else 0.0
    if not values or observed == 0:
        return 1.0
    if len(values) <= 18:
        means = (
            abs(statistics.fmean(sign * value for sign, value in zip(signs, values)))
            for signs in itertools.product((-1, 1), repeat=len(values))
        )
        samples = list(means)
        return sum(value >= observed - 1e-15 for value in samples) / len(samples)
    rng = random.Random(seed)
    exceed = 0
    for _ in range(iterations):
        value = abs(statistics.fmean((1 if rng.random() < 0.5 else -1) * item for item in values))
        exceed += value >= observed - 1e-15
    return (exceed + 1) / (iterations + 1)


def paired_statistics(
    units: list[dict[str, object]], dataset: str, iterations: int, seed: int,
    *, primary_only: bool = False, analysis_scope: str = "main",
) -> dict[str, dict[str, object]]:
    eligible = [
        row for row in units
        if row["dataset"] == dataset
        and row["provenance"] in {"agent", "human"}
        and row["analysis_pair_id"]
        and (dataset != "GitHub-matched-PR" or row["match_tier"] == "same_repository")
        and (not primary_only or row.get("analysis_eligibility") == "provenance_primary")
    ]
    pairs: dict[str, dict[str, dict[str, object]]] = defaultdict(dict)
    for row in eligible:
        pairs[str(row["analysis_pair_id"])][str(row["provenance"])] = row
    complete = {key: value for key, value in pairs.items() if {"agent", "human"} <= set(value)}
    results = {}
    p_values = {}
    for index, feature in enumerate(FEATURES):
        diffs_by_repo: dict[str, list[float]] = defaultdict(list)
        agent_values, human_values = [], []
        for values in complete.values():
            agent, human = values["agent"], values["human"]
            agent_values.append(float(agent[feature]))
            human_values.append(float(human[feature]))
            diffs_by_repo[str(agent["repo"])].append(float(agent[feature]) - float(human[feature]))
        repo_diffs = [statistics.fmean(values) for values in diffs_by_repo.values()]
        effect = statistics.fmean(repo_diffs) if repo_diffs else math.nan
        rng = random.Random(seed + index + (0 if dataset == "SWE-chat" else 10_000))
        boot = [
            statistics.fmean(rng.choice(repo_diffs) for _ in repo_diffs)
            for _ in range(iterations)
        ] if repo_diffs else []
        p = sign_flip_p(repo_diffs, iterations, seed + index)
        p_values[feature] = p
        results[feature] = {
            "dataset": dataset,
            "feature": feature,
            "analysis_scope": analysis_scope,
            "n_pairs": len(complete),
            "n_repositories": len(repo_diffs),
            "agent_mean": statistics.fmean(agent_values) if agent_values else math.nan,
            "human_mean": statistics.fmean(human_values) if human_values else math.nan,
            "equal_repo_effect": effect,
            "ci_low": percentile(boot, 0.025),
            "ci_high": percentile(boot, 0.975),
            "p": p,
        }
    q_values = benjamini_hochberg(p_values)
    for feature, result in results.items():
        result["bh_q"] = q_values[feature]
    return results


def aidev_support(units: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    rows = [row for row in units if row["dataset"] == "AIDev"]
    products = sorted({str(row["dataset_provenance"]) for row in rows})
    output = {}
    for feature in FEATURES:
        rates = {}
        for product in products:
            values = [float(row[feature]) for row in rows if row["dataset_provenance"] == product]
            rates[product] = statistics.fmean(values) if values else math.nan
        output[feature] = {
            "n_units": len(rows),
            "mean_share": statistics.fmean(float(row[feature]) for row in rows),
            "product_coverage_ge_1pct": sum(rate >= 0.01 for rate in rates.values()),
            "n_products": len(products),
            "min_product_mean_share": min(rates.values()) if rates else math.nan,
            "product_rates": rates,
        }
    return output


def excludes_zero(low: float, high: float) -> bool:
    return not math.isnan(low) and (low > 0 or high < 0)


def cross_source_screen(
    swe: dict[str, dict[str, object]], github: dict[str, dict[str, object]], aidev: dict[str, dict[str, object]]
) -> list[dict[str, object]]:
    rows = []
    for feature in FEATURES:
        left, right, support = swe[feature], github[feature], aidev[feature]
        swe_effect = float(left["equal_repo_effect"])
        github_effect = float(right["equal_repo_effect"])
        same_direction = swe_effect * github_effect > 0
        enough_repos = int(left["n_repositories"]) >= 10 and int(right["n_repositories"]) >= 10
        stable = (
            enough_repos
            and same_direction
            and excludes_zero(float(left["ci_low"]), float(left["ci_high"]))
            and excludes_zero(float(right["ci_low"]), float(right["ci_high"]))
            and float(left["bh_q"]) <= 0.05
            and float(right["bh_q"]) <= 0.05
            and int(support["product_coverage_ge_1pct"]) >= 4
        )
        exploratory = (
            same_direction
            and abs(swe_effect) >= 0.02
            and abs(github_effect) >= 0.02
            and int(support["product_coverage_ge_1pct"]) >= 4
        )
        rows.append(
            {
                "feature": feature,
                "swe_effect": swe_effect,
                "swe_ci_low": left["ci_low"],
                "swe_ci_high": left["ci_high"],
                "swe_bh_q": left["bh_q"],
                "swe_pairs": left["n_pairs"],
                "swe_repositories": left["n_repositories"],
                "github_effect": github_effect,
                "github_ci_low": right["ci_low"],
                "github_ci_high": right["ci_high"],
                "github_bh_q": right["bh_q"],
                "github_pairs": right["n_pairs"],
                "github_repositories": right["n_repositories"],
                "direction_consistent": same_direction,
                "aidev_mean_share": support["mean_share"],
                "aidev_product_coverage_ge_1pct": support["product_coverage_ge_1pct"],
                "aidev_products": support["n_products"],
                "strict_stable": stable,
                "exploratory_hypothesis": exploratory and not stable,
            }
        )
    rows.sort(
        key=lambda row: (
            not bool(row["strict_stable"]),
            not bool(row["exploratory_hypothesis"]),
            -min(abs(float(row["swe_effect"])), abs(float(row["github_effect"]))),
            str(row["feature"]),
        )
    )
    return rows


def write_csv(path: Path, rows: list[dict[str, object]], fields: tuple[str, ...] | None = None) -> None:
    fields = fields or tuple(rows[0])
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def fmt(value: object) -> str:
    number = float(value)
    return "NA" if math.isnan(number) else f"{number:.3f}"


def report(summary: dict, screen: list[dict[str, object]]) -> str:
    exploratory = [row for row in screen if row["exploratory_hypothesis"]]
    stable = [row for row in screen if row["strict_stable"]]
    lines = [
        "## Material Passport",
        "",
        "- Origin Skill: experiment-agent",
        "- Origin Mode: validate",
        "- Origin Date: 2026-08-27",
        "- Verification Status: VERIFIED",
        "- Version Label: multisource_log_feature_retry_v1",
        "",
        "# 三来源 Agent / Human 日志特征重新提取",
        "",
        "## 结论",
        "",
        "- Overall Confidence: CAUTION",
        f"- 严格跨来源稳定特征：{len(stable)} 个。",
        f"- 可进入下一轮预注册验证的方向一致探索假设：{len(exploratory)} 个。",
        "- AIDev 没有人类 patch 对照，只用于确认特征是否覆盖多个 Agent 产品，不参与 Agent−Human 效应估计。",
        "- 所有结果是代码内容或日志形态关联，不是逐行作者证明，也不是运行时泄露证明。",
        "",
        "## 分析单位",
        "",
        "| 数据来源 | 主用途 | 生产日志来源单元 | 严格配对 | 仓库 |",
        "| --- | --- | ---: | ---: | ---: |",
        f"| SWE-chat | 同 checkpoint Agent/Human 对照 | {summary['unit_counts']['SWE-chat']} | {summary['matched_pairs']['SWE-chat']} | {summary['matched_repositories']['SWE-chat']} |",
        f"| GitHub 匹配 PR | 已合并 A/B Agent + 已核验人类主分析 | {summary['unit_counts']['GitHub-matched-PR']} | {summary['matched_pairs']['GitHub-matched-PR']} | {summary['matched_repositories']['GitHub-matched-PR']} |",
        f"| AIDev | Agent-only 跨产品覆盖复核 | {summary['unit_counts']['AIDev']} | 不适用 | {summary['repository_counts']['AIDev']} |",
        "",
        "分析只纳入生产路径。每个来源单元先计算特征占其日志的比例，再在配对内计算 Agent−Human 差；置信区间按仓库等权 bootstrap 10,000 次，p 值按仓库符号翻转并进行 BH 校正。",
        "",
        "## 跨来源筛选结果",
        "",
        "| 特征 | SWE-chat 差值 [95% CI] / q | GitHub 差值 [95% CI] / q | AIDev 产品覆盖 | 判定 |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for row in screen:
        if not (row["strict_stable"] or row["exploratory_hypothesis"]):
            continue
        verdict = "严格稳定" if row["strict_stable"] else "探索假设"
        lines.append(
            f"| {row['feature']} | {fmt(row['swe_effect'])} [{fmt(row['swe_ci_low'])}, {fmt(row['swe_ci_high'])}] / {fmt(row['swe_bh_q'])} "
            f"| {fmt(row['github_effect'])} [{fmt(row['github_ci_low'])}, {fmt(row['github_ci_high'])}] / {fmt(row['github_bh_q'])} "
            f"| {row['aidev_product_coverage_ge_1pct']}/{row['aidev_products']} | {verdict} |"
        )
    if not stable:
        lines.extend(
            [
                "",
                f"严格稳定集仍为空。GitHub A/B 主分析有 {summary['matched_pairs']['GitHub-matched-PR']} 个完整配对；"
                f"C/D 级敏感性分析有 {summary['sensitivity_matched_pairs']['GitHub-matched-PR']} 个配对。"
                "未达到来源证据与仓库数量门槛的结果不能提升为 Agent 指纹。",
            ]
        )
    lines.extend(
        [
            "",
            "## 稳健性门槛",
            "",
            "一个特征只有同时满足以下条件才进入严格稳定集：两个对照来源方向一致；两个仓库 bootstrap 区间均排除 0；两个 BH q≤0.05；每个来源至少 10 个配对仓库；AIDev 至少 4/5 个 Agent 产品的平均占比达到 1%。",
            "",
            "## Fallacy Scan",
            "",
            "- Coverage: 11/11",
            "",
            "| 谬误 | 状态 | 本次处理 |",
            "| --- | --- | --- |",
            "| Simpson's paradox | CAUTION | 分来源分析，不汇总为一个总体 Agent/Human 比例 |",
            "| Ecological fallacy | CAUTION | 推断单位限定为 checkpoint/PR 来源单元，不外推到单行作者 |",
            "| Berkson's paradox | CAUTION | GitHub 是 merged Agent App 富集样本，SWE-chat 也是选择性语料 |",
            "| Collider bias | CAUTION | 内容比较条件化于双方都有生产日志，单独标明 |",
            "| Base rate neglect | CAUTION | 不报告作者分类概率或 PPV |",
            "| Regression to the mean | NOTE | 无按极端值选择后的前后比较 |",
            "| Survivorship bias | CAUTION | GitHub 仅含 merged PR，AIDev 为丰富子集 |",
            "| Look-elsewhere effect | CAUTION | 全部特征保留并使用 BH 校正 |",
            "| Garden of forking paths | CAUTION | 本轮为探索性重提取；稳定门槛已写入脚本 |",
            "| Correlation != causation | CAUTION | 只报告来源关联，不使用因果语言 |",
            "| Reverse causality | NOTE | 来源先于内容，但人类后处理仍可能影响 Agent PR patch |",
            "",
            "## 证据边界",
            "",
            "- `strict_stable=false` 的特征不能用于自动标注 Agent。",
            "- AIDev 的产品覆盖不能替代 Human control。",
            "- GitHub 主分析只接受同仓库、已合并 A/B Agent 与 `human_verified` 配对；开放 A/B 只验证谱系，C/D 与 `human_likely` 只进入敏感性分析。",
            "- SWE-chat 仍是文件版本归因，不是逐行作者金标准。",
            "- 静态风险候选不证明日志执行、敏感值传播或外发。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("outputs/multisource_agent_log_corpus/log_rows.csv"))
    parser.add_argument("--github-pairs", type=Path, default=Path("outputs/github_log_lineage_poc/matched_prs.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/multisource_agent_human_feature_retry"))
    parser.add_argument("--bootstrap-iterations", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    if args.bootstrap_iterations < 1:
        parser.error("--bootstrap-iterations must be positive")
    for path in (args.input, args.github_pairs):
        if not path.exists():
            parser.error(f"missing input: {path}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    github_pairs = load_github_pairs(args.github_pairs)
    line_path = args.output_dir / "line_features.csv"
    units, line_counts = read_and_extract(args.input, line_path, github_pairs)
    unit_fields = (
        "dataset", "repo", "source_id", "provenance", "dataset_provenance",
        "analysis_pair_id", "match_tier", "binding_id", "binding_status", "provenance_grade",
        "generation_stage", "analysis_eligibility", "line_authorship_proof", "n_logs",
    ) + FEATURES
    write_csv(args.output_dir / "unit_features.csv", units, unit_fields)

    swe = paired_statistics(units, "SWE-chat", args.bootstrap_iterations, args.seed)
    github = paired_statistics(
        units, "GitHub-matched-PR", args.bootstrap_iterations, args.seed,
        primary_only=True, analysis_scope="provenance_primary",
    )
    github_sensitivity = paired_statistics(
        units, "GitHub-matched-PR", args.bootstrap_iterations, args.seed,
        analysis_scope="all_pr_level_candidates_sensitivity",
    )
    support = aidev_support(units)
    stats = (
        [swe[feature] for feature in FEATURES]
        + [github[feature] for feature in FEATURES]
        + [github_sensitivity[feature] for feature in FEATURES]
    )
    write_csv(args.output_dir / "feature_statistics.csv", stats)
    screen = cross_source_screen(swe, github, support)
    write_csv(args.output_dir / "cross_source_screen.csv", screen)

    unit_counts = Counter(str(row["dataset"]) for row in units)
    for dataset in ("SWE-chat", "GitHub-matched-PR", "AIDev"):
        unit_counts.setdefault(dataset, 0)
    repo_counts = {
        dataset: len({str(row["repo"]) for row in units if row["dataset"] == dataset})
        for dataset in unit_counts
    }
    summary = {
        "seed": args.seed,
        "bootstrap_iterations": args.bootstrap_iterations,
        "input_sha256": sha256(args.input),
        "github_pairs_sha256": sha256(args.github_pairs),
        "production_only_main_analysis": True,
        "line_counts": dict(sorted(line_counts.items())),
        "unit_counts": dict(sorted(unit_counts.items())),
        "repository_counts": dict(sorted(repo_counts.items())),
        "matched_pairs": {
            "SWE-chat": next(iter(swe.values()))["n_pairs"],
            "GitHub-matched-PR": next(iter(github.values()))["n_pairs"],
        },
        "matched_repositories": {
            "SWE-chat": next(iter(swe.values()))["n_repositories"],
            "GitHub-matched-PR": next(iter(github.values()))["n_repositories"],
        },
        "sensitivity_matched_pairs": {
            "GitHub-matched-PR": next(iter(github_sensitivity.values()))["n_pairs"],
        },
        "sensitivity_matched_repositories": {
            "GitHub-matched-PR": next(iter(github_sensitivity.values()))["n_repositories"],
        },
        "features_tested": list(FEATURES),
        "strict_stable_features": [row["feature"] for row in screen if row["strict_stable"]],
        "exploratory_hypotheses": [row["feature"] for row in screen if row["exploratory_hypothesis"]],
        "strict_gate": {
            "direction_consistent": True,
            "both_cluster_bootstrap_cis_exclude_zero": True,
            "both_bh_q_lte": 0.05,
            "minimum_repositories_per_comparison_source": 10,
            "minimum_aidev_products_at_1pct": 4,
        },
        "boundaries": {
            "aidev_human_metadata_control_available": True,
            "aidev_human_patch_control_available": False,
            "line_authorship_proof_for_all_rows": False,
            "github_main_requires_both_pair_sides_provenance_primary": True,
            "runtime_leak_claim": False,
            "deployment_allowed": False,
        },
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output_dir / "report.md").write_text(report(summary, screen), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
