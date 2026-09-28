import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.classify_log_security_issues import (
    DEFAULT_AIDEV_DIR,
    DEFAULT_DEVGPT_CSV,
    DEFAULT_SWE_CSV,
    TAXONOMY,
    classify_log,
    flatten_aidev,
    read_csv,
)


DEFAULT_OUTPUT_DIR = Path("data/res/privacy_log_sample_500")
DEFAULT_SAMPLE_SIZE = 500
DEFAULT_RANDOM_SEED = 20260617


PAPER_TAXONOMY_ROWS = [
    ("IL", "Insecure Log Storage and Access Control", "IL-At", "Risk of Log Injection Attacks", "Log entries lack filtering, enabling attackers to inject malicious content."),
    ("IL", "Insecure Log Storage and Access Control", "IL-Pa", "Publicly Accessible Logs", "Log files or output channels are open to unauthorized access."),
    ("IL", "Insecure Log Storage and Access Control", "IL-Lv", "Insecure Logging Level Configuration", "Improper log levels capture sensitive data or system specifics."),
    ("SS", "Sensitive Information Exposure", "SS-Cr", "Credentials Leakage", "Logs capture accounts, passwords, API keys, OAuth tokens, cookies, or similar auth material."),
    ("SS", "Sensitive Information Exposure", "SS-Cf", "Configuration Data Exposure", "Logs expose database URLs, file paths, environment variables, command arguments, or system configuration."),
    ("SS", "Sensitive Information Exposure", "SS-Ur", "User Private Data Leakage", "Logs expose user cookies, usernames, passwords, phone numbers, transaction records, or other personal data."),
    ("RM", "Improper Redaction or Masking", "RM-Ms", "Missing Masking/Redaction", "Sensitive details are left exposed, or excessive raw content is dumped before masking."),
    ("RM", "Improper Redaction or Masking", "RM-Ft", "Faulty Masking/Obfuscation", "Masking exists but defects allow sensitive content to pass through."),
    ("EE", "Error and Exception Message Exposure", "EE-Ex", "Exception Leakage", "Exception messages include keys, file paths, config parameters, raw rows, or other sensitive details."),
    ("EE", "Error and Exception Message Exposure", "EE-St", "Stack Trace Leakage", "Stack traces reveal call chains, class names, library versions, or architecture details."),
]


PRIVACY_TYPE_LABELS = {
    "PR-CRED": "Credential/auth material",
    "PR-USER": "User personal/contact/account data",
    "PR-CONFIG": "Configuration, path, endpoint, or infrastructure data",
    "PR-RAW-DUMP": "Raw payload/object/request/response dump",
    "PR-ERROR": "Exception, stack trace, or internal workflow detail",
    "PR-REDACTION": "Missing/faulty masking or redaction",
    "PR-LOG-INTEGRITY": "Log access/injection/level security risk",
}


TYPE_PRIORITY = [
    "PR-CRED",
    "PR-USER",
    "PR-RAW-DUMP",
    "PR-REDACTION",
    "PR-CONFIG",
    "PR-ERROR",
    "PR-LOG-INTEGRITY",
]


def compact(value: object, limit: int = 1800) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[: limit - 1] + "..." if len(text) > limit else text


def as_series(df: pd.DataFrame, name: str) -> pd.Series:
    if name in df.columns:
        return df[name].fillna("")
    return pd.Series([""] * len(df), index=df.index)


def standardize_source(path: Path, dataset: str) -> pd.DataFrame:
    df = read_csv(path)
    out = pd.DataFrame(
        {
            "dataset": dataset,
            "repo": as_series(df, "repo"),
            "commit": as_series(df, "commit"),
            "file": as_series(df, "file"),
            "line": as_series(df, "line"),
            "add_remove": as_series(df, "add_remove"),
            "attribution": as_series(df, "attribution"),
            "risk_level": as_series(df, "risk_level"),
            "sensitive_keywords": as_series(df, "sensitive_keywords"),
            "log_text": as_series(df, "log_text"),
            "commit_message": as_series(df, "commit_message"),
            "author_date": as_series(df, "author_date"),
            "source_url": as_series(df, "source_url"),
            "chatgpt_url": as_series(df, "chatgpt_url"),
            "candidate_source": as_series(df, "candidate_source"),
            "prompt_intents": as_series(df, "prompt_intents"),
            "prompt_pushbacks": as_series(df, "prompt_pushbacks"),
            "user_log_reason_excerpt": as_series(df, "user_log_reason_excerpt"),
            "answer_log_excerpt": as_series(df, "answer_log_excerpt"),
            "manual_review_label": as_series(df, "manual_review_label"),
            "manual_review_evidence": as_series(df, "manual_review_evidence"),
        }
    )
    return out.fillna("")


def build_combined(aidev_dir: Path, swe_csv: Path, devgpt_csv: Path) -> pd.DataFrame:
    aidev = flatten_aidev(aidev_dir)
    for col in [
        "author_date",
        "source_url",
        "chatgpt_url",
        "candidate_source",
        "prompt_intents",
        "prompt_pushbacks",
        "user_log_reason_excerpt",
        "answer_log_excerpt",
        "manual_review_label",
        "manual_review_evidence",
    ]:
        aidev[col] = ""
    swe = standardize_source(swe_csv, "SWE-chat")
    devgpt = standardize_source(devgpt_csv, "DevGPT")
    combined = pd.concat([aidev, swe, devgpt], ignore_index=True).fillna("")
    combined.insert(0, "global_row_id", combined.index + 1)
    return combined


def privacy_types(row: pd.Series, taxonomy: dict[str, str]) -> tuple[list[str], list[str]]:
    """Derive review-aid PR labels from paper taxonomy only.

    These labels no longer perform independent keyword matching. A row marked
    OUT by the Yuan et al. taxonomy remains OUT/PR-NONE here.
    """
    security_issue = taxonomy.get("security_issue_candidate") == "True"
    labels: set[str] = set()
    reasons: list[str] = []

    def add(label: str, reason: str) -> None:
        labels.add(label)
        reasons.append(reason)

    if not security_issue:
        return [], []

    patterns = {p for p in taxonomy.get("all_patterns", "").split(";") if p}
    if "SS-Cr" in patterns:
        add("PR-CRED", "credential/auth value (SS-Cr)")
    if "SS-Ur" in patterns:
        add("PR-USER", "user/private-data value (SS-Ur)")
    if "SS-Cf" in patterns:
        add("PR-CONFIG", "configuration/path/infra value (SS-Cf)")
    if patterns & {"RM-Ms", "RM-Ft"}:
        add("PR-RAW-DUMP", "raw object/payload/config/request logging (RM)")
    if patterns & {"RM-Ms", "RM-Ft"}:
        add("PR-REDACTION", "missing/faulty masking concern (RM)")
    if patterns & {"EE-Ex", "EE-St"}:
        add("PR-ERROR", "exception/error message or stack leak (EE)")
    if patterns & {"IL-At", "IL-Pa", "IL-Lv"}:
        add("PR-LOG-INTEGRITY", "log injection/access/level concern (IL)")

    ordered = [label for label in TYPE_PRIORITY if label in labels]
    return ordered, reasons


def confidence(row: pd.Series, privacy_labels: list[str], taxonomy: dict[str, str]) -> str:
    if not privacy_labels:
        return "low"
    if row.get("risk_level") == "high" or taxonomy.get("classification_confidence") == "high":
        return "high"
    if taxonomy.get("security_issue_candidate") == "True" or row.get("risk_level") == "medium":
        return "medium"
    return "low"


def classify_rows(sample: pd.DataFrame) -> pd.DataFrame:
    records: list[dict[str, object]] = []
    for _, row in sample.iterrows():
        taxonomy = classify_log(row["log_text"], row["risk_level"], row.get("file", ""))
        p_labels, p_reasons = privacy_types(row, taxonomy)
        security_issue = taxonomy["security_issue_candidate"] == "True"
        scope = "paper taxonomy candidate" if security_issue else "no candidate"
        primary_privacy = p_labels[0] if p_labels else "PR-NONE"
        records.append(
            {
                **row.to_dict(),
                **taxonomy,
                "privacy_security_issue_candidate": "True" if security_issue else "False",
                "issue_scope": scope,
                "primary_privacy_leak_type": primary_privacy,
                "primary_privacy_leak_label": PRIVACY_TYPE_LABELS.get(primary_privacy, "No privacy/security issue candidate"),
                "all_privacy_leak_types": ";".join(p_labels),
                "privacy_classification_confidence": confidence(row, p_labels, taxonomy),
                "privacy_classification_reason": " | ".join(dict.fromkeys(p_reasons)),
                "log_text_for_review": compact(row["log_text"], 2000),
                "log_text_length": len(str(row["log_text"])),
                "log_text_truncated": "True" if len(str(row["log_text"])) > 2000 else "False",
                "source_locator": f"{row.get('dataset','')}::{row.get('repo','')}::{row.get('commit','')}::{row.get('file','')}:{row.get('line','')}",
                "manual_review_status": "not reviewed",
                "human_final_issue": "",
                "human_final_taxonomy_pattern": "",
                "human_final_privacy_type": "",
                "human_notes": "",
            }
        )
    return pd.DataFrame(records).fillna("")


def count_rows(df: pd.DataFrame, column: str) -> list[dict[str, object]]:
    rows = []
    counts = Counter()
    for value in df[column].astype(str):
        for part in [p for p in value.split(";") if p]:
            counts[part] += 1
    for key, count in counts.most_common():
        rows.append({"label": key, "name": PRIVACY_TYPE_LABELS.get(key, ""), "rows": count})
    return rows


def summarize(classified: pd.DataFrame, combined_total: int, sample_size: int, seed: int) -> dict[str, object]:
    privacy = classified[classified["privacy_security_issue_candidate"] == "True"]
    security = classified[classified["security_issue_candidate"] == "True"]

    by_dataset = []
    for dataset, group in classified.groupby("dataset", sort=True):
        by_dataset.append(
            {
                "dataset": dataset,
                "sample_rows": int(len(group)),
                "privacy_security_candidates": int((group["privacy_security_issue_candidate"] == "True").sum()),
                "security_taxonomy_candidates": int((group["security_issue_candidate"] == "True").sum()),
            }
        )

    return {
        "method": {
            "sample_method": "uniform random sample from all extracted log candidate rows across AIDev, SWE-chat, and DevGPT",
            "random_seed": seed,
            "sample_size": sample_size,
            "source_rows": combined_total,
            "paper": "Yuan et al. 2026, Towards Secure Logging: Characterizing and Benchmarking Logging Code Security Issues with LLMs",
            "paper_taxonomy": "4 categories / 10 patterns: IL, SS, RM, EE",
            "caveat": "All row labels are candidate annotations from log text plus available metadata and require manual confirmation.",
        },
        "overall": {
            "sample_rows": int(len(classified)),
            "privacy_security_candidates": int(len(privacy)),
            "security_taxonomy_candidates": int(len(security)),
            "privacy_security_candidate_rate_percent": round(len(privacy) / len(classified) * 100, 2) if len(classified) else 0,
        },
        "by_dataset": by_dataset,
        "by_taxonomy_pattern": [
            {"pattern": key, "name": TAXONOMY.get(key, "Out of taxonomy"), "rows": int(value)}
            for key, value in classified["primary_pattern"].value_counts().items()
        ],
        "by_privacy_type": count_rows(classified, "all_privacy_leak_types"),
    }


def write_outputs(classified: pd.DataFrame, summary: dict[str, object], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    sample_csv = output_dir / "privacy_log_sample_500.csv"
    summary_json = output_dir / "summary.json"
    taxonomy_csv = output_dir / "paper_taxonomy_reference.csv"
    legacy_new_categories_csv = output_dir / "new_category_candidates_summary.csv"
    builder_json = output_dir / "workbook_payload.json"

    export_columns = [
        "sample_order",
        "global_row_id",
        "manual_review_status",
        "human_final_issue",
        "human_final_taxonomy_pattern",
        "human_final_privacy_type",
        "human_notes",
        "privacy_security_issue_candidate",
        "issue_scope",
        "primary_privacy_leak_type",
        "primary_privacy_leak_label",
        "all_privacy_leak_types",
        "privacy_classification_confidence",
        "privacy_classification_reason",
        "primary_pattern",
        "out_subtype",
        "taxonomy_label",
        "primary_category",
        "all_patterns",
        "classification_confidence",
        "classification_reason",
        "dataset",
        "repo",
        "commit",
        "file",
        "line",
        "add_remove",
        "attribution",
        "risk_level",
        "sensitive_keywords",
        "log_text_for_review",
        "log_text_length",
        "log_text_truncated",
        "commit_message",
        "author_date",
        "source_url",
        "chatgpt_url",
        "candidate_source",
        "prompt_intents",
        "prompt_pushbacks",
        "user_log_reason_excerpt",
        "answer_log_excerpt",
        "manual_review_label",
        "manual_review_evidence",
        "source_locator",
    ]
    classified[export_columns].to_csv(sample_csv, index=False)
    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    pd.DataFrame(
        [
            {
                "category_code": category,
                "category_label": category_label,
                "pattern_code": pattern,
                "pattern_label": pattern_label,
                "paper_definition_for_annotation": definition,
            }
            for category, category_label, pattern, pattern_label, definition in PAPER_TAXONOMY_ROWS
        ]
    ).to_csv(taxonomy_csv, index=False)

    pd.DataFrame(
        [
            {
                "status": "removed",
                "note": "No paper-external candidate categories are emitted; classification is limited to the 10 Yuan et al. taxonomy patterns plus OUT.",
            }
        ]
    ).to_csv(legacy_new_categories_csv, index=False)

    payload = {
        "summary": summary,
        "sample_rows": classified[export_columns].to_dict(orient="records"),
        "taxonomy_rows": pd.read_csv(taxonomy_csv).to_dict(orient="records"),
        "privacy_type_rows": [
            {"code": code, "label": label}
            for code, label in PRIVACY_TYPE_LABELS.items()
        ],
    }
    builder_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(summary["overall"], ensure_ascii=False, indent=2))
    print(f"wrote {sample_csv}")
    print(f"wrote {summary_json}")
    print(f"wrote {builder_json}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sample and classify logs for privacy/security manual review.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--aidev-dir", type=Path, default=DEFAULT_AIDEV_DIR)
    parser.add_argument("--swe-csv", type=Path, default=DEFAULT_SWE_CSV)
    parser.add_argument("--devgpt-csv", type=Path, default=DEFAULT_DEVGPT_CSV)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--random-seed", type=int, default=DEFAULT_RANDOM_SEED)
    args = parser.parse_args()

    combined = build_combined(args.aidev_dir, args.swe_csv, args.devgpt_csv)
    if args.sample_size > len(combined):
        raise ValueError(f"sample size {args.sample_size} exceeds available rows {len(combined)}")

    sample = combined.sample(n=args.sample_size, random_state=args.random_seed, replace=False).reset_index(drop=True)
    sample.insert(0, "sample_order", range(1, len(sample) + 1))
    classified = classify_rows(sample)
    summary = summarize(classified, len(combined), args.sample_size, args.random_seed)
    write_outputs(classified, summary, args.output_dir)


if __name__ == "__main__":
    main()
