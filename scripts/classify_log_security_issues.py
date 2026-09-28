import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.analyze_swe_chat_multilingual_logs import (
    STRING_LITERAL_RE,
    has_dynamic_output,
    risk_for_text,
    strip_string_literals,
)


DEFAULT_OUTPUT_DIR = Path("data/res/log_security_issue_classification")
DEFAULT_AIDEV_DIR = Path("data/res/aidev_log_changes")
DEFAULT_SWE_CSV = Path("data/res/swe_chat_multilingual_logs/swe_chat_multilingual_log_candidates.csv")
DEFAULT_DEVGPT_CSV = Path("data/res/devgpt_logs/devgpt_log_candidates.csv")


TAXONOMY = {
    "IL-At": "Risk of Log Injection Attacks",
    "IL-Pa": "Publicly Accessible Logs",
    "IL-Lv": "Insecure Logging Level Configuration",
    "SS-Cr": "Credentials Leakage",
    "SS-Cf": "Configuration Data Exposure",
    "SS-Ur": "User Private Data Leakage",
    "RM-Ms": "Missing Masking/Redaction",
    "RM-Ft": "Faulty Masking/Obfuscation",
    "EE-Ex": "Exception Leakage",
    "EE-St": "Stack Trace Leakage",
}

CATEGORY = {
    "IL": "Insecure Log Storage and Access Control",
    "SS": "Sensitive Information Exposure",
    "RM": "Improper Redaction or Masking",
    "EE": "Error and Exception Message Exposure",
    "OUT": "Out of taxonomy / manual review",
}

# ---------------------------------------------------------------------------
# Value-aware patterns. These are matched against the *dynamic logged value*
# (interpolations / concatenated variables / call arguments) rather than the
# whole statement, so that a sensitive English word appearing only inside a
# static label string does not trigger a (wrong) classification. See
# dynamic_values() below.  (Addresses review suggestions 1, 2, 4.)
# ---------------------------------------------------------------------------

# SS-Cr: actual credential / auth material in the logged value.
CRED_RE = re.compile(
    r"(secret(?!properties)|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credential|auth[_-]?token|refresh[_-]?token|"
    r"access[_-]?token|id[_-]?token|purchase[_-]?token|continuation[_-]?token|bearer|"
    r"\boauth|\bjwt\b|keystore|\bcookie|session[_-]?data[_-]?key|session[_-]?key|"
    r"auth[_-]?cookie|token(?!iz))",
    re.I,
)
# SS-Ur: direct user / personal data in the logged value. Bare "address" is
# intentionally excluded (matches Modbus register / memory / network addresses);
# only qualified addresses count.
USER_RE = re.compile(
    r"(user[_-]?name|username|user[_-]?data|userdata|user[_-]?info|user[_-]?profile|"
    r"user[_-]?account|user[_-]?id|userid|\buser_did\b|\bcurrent[_-]?user\b|"
    r"\bcustomer[_-]?(?:id|name|data)\b|\bemail\b|e-?mail|\bphone\b|mobile[_-]?no|"
    r"msisdn|first[_-]?name|last[_-]?name|nick[_-]?name|\bssn\b|passport|"
    r"pesel|home[_-]?address|mail(?:ing)?[_-]?address|billing[_-]?address|street|"
    r"account[_-]?id|device[_-]?id|transaction[_-]?id|txn[_-]?id|order[_-]?id|invoice[_-]?id)",
    re.I,
)
# SS-Cf: configuration / path / endpoint / infrastructure value.
CONFIG_RE = re.compile(
    r"(database[_-]?url|connection[_-]?string|conn[_-]?str|jdbc|\bdsn\b|environment|\benv\b|"
    r"\bconfig\b|\bconfiguration\b|(?<!secret)properties|settings|working[_-]?dir|out[_-]?file|file[_-]?path|"
    r"filepath|get[_-]?absolute[_-]?path|\bpath\b|\burl\b|backend[_-]?url|\bhost(?:name)?\b|"
    r"\bport\b|endpoint|bucket|namespace|\bregion\b|\bcommand\b|command[_-]?args?|"
    r"command[_-]?line|cli[_-]?args?|temp[_-]?dir|tempdir)",
    re.I,
)
# RM-Ms/RM-Ft: a whole object / body / payload is dumped raw.
RAWDUMP_RE = re.compile(
    r"(json\.?stringify|jsonutils\.encode|\.encode\(|\bdump\b|"
    r"getresponsetext|get[_-]?body|\.body\b|responsetext|\.content\(\)|prettystring|"
    r"to[_-]?json|getentity|\.payload\b|var_export|print_r|\.inspect\(\)|\.entries\(\))",
    re.I,
)
# Object-ish identifiers that, when printed bare, indicate a raw dump.
OBJECT_WORD_RE = re.compile(
    r"\b(request|response|payload|body|results?|data|obj|object|config|props|params|entity|"
    r"model|dto|record|message|profile|account|prompt)\b",
    re.I,
)
STACK_RE = re.compile(
    r"(print[_-]?stack[_-]?trace|get[_-]?stack[_-]?trace|\.stack\b|traceback|format_exc|"
    r"backtrace|stack\s*trace|\.exception\s*\()",
    re.I,
)
REDACT_RE = re.compile(
    r"\b(redact|mask|masked|masking|sanitize|sanitise|obfuscat|scrub|filtersensitive|anonym)\b",
    re.I,
)
ERRORCTX_RE = re.compile(r"\b(exception|error|err|throwable|panic|fatal|failure|failed)\b", re.I)
# Extra signals that an error/exception log actually carries sensitive runtime data.
EEX_EXTRA_RE = re.compile(
    r"(get[_-]?message\(\)|getlocalizedmessage|argument[_-]?string|argumentstring|"
    r"row[_-]?string|rowstring|user[_-]?input|raw[_-]?input|request[_-]?body|input[_-]?value)",
    re.I,
)
# A decoded credential (Base64/atob of a token/secret) being logged is a real leak.
DECODED_CRED_RE = re.compile(r"(base64|\.decode\(|atob\(|fromcharcode)", re.I)
DECODED_CRED_KW_RE = re.compile(r"(token|secret|password|api[_-]?key|credential|private[_-]?key)", re.I)

# Logging sinks. Used to confirm the line is actually a log statement.
SINK_RE = re.compile(
    r"(console\.(?:log|error|warn|info|debug|trace)|\blogger?\b|System\.out|System\.err|"
    r"\bprint(?:ln|f|_r|stacktrace)?\s*\(|fmt\.(?:Print|Fprint|Errorf|Sprintf|Printf|Println|Fprintf)|"
    r"e?println!|e?print!|\bslog\b|\bzap\b|\blog!|\bwarn!|\binfo!|\bdebug!|\btrace!|\berror!|"
    r"\.error\s*\(|\.warn\s*\(|\.info\s*\(|\.debug\s*\(|\.trace\s*\(|\.fatal\w*\s*\(|\becho\b|\.exception\s*\()",
    re.I,
)
# Lines that are not log statements (control flow / object literal / assignment).
NONLOG_SYNTAX_RE = re.compile(
    r"^\s*(if|else|elif|for|while|switch|case|return|assert|func\b|def\b|class\b|@|//|/\*|\*\s|#\s|"
    r"import\b|package\b|using\b|[\w\.\[\]\"']+\s*[:=!<>]=?\s*[\"'`])"
)
# Minified / bundled front-end assets (suggestion 3).
ASSET_FILE_RE = re.compile(
    r"(\.min\.(?:js|css)|/dist/|-dist/|gui-dist|/assets/[^/]+-[a-z0-9_]{6,}\.(?:js|css)|"
    r"/vendor/|/build/|\.bundle\.)",
    re.I,
)
LEVEL_RE = re.compile(r"\b(trace|debug|info)\b", re.I)
# Exception-object identifiers; logging only one of these (plus a static message)
# is ordinary error logging, not a security issue.
EXC_IDENT_RE = re.compile(
    r"^(e|e2|err|err2|error|error2|ex|exc|exception|throwable|t|t2|cause|reason|fault|axisfault)$",
    re.I,
)


def dynamic_values(text: str) -> str:
    """Return only the dynamic / logged-value portion of a log statement.

    Captures interpolations (``${..}``, ``#{..}``, f-string ``{var}``) and the
    code that remains after stripping every string literal (concatenation
    operands, format arguments, bare print arguments). Static label text inside
    quotes is dropped, so a keyword that only appears as a human-readable label
    does not leak into classification.
    """
    interps = re.findall(r"\$\{([^}]*)\}", text)
    interps += re.findall(r"#\{([^}]*)\}", text)
    interps += re.findall(r"\{([A-Za-z_][\w\.\[\]'\"]*)\}", text)
    code = re.sub(r"`(?:\\.|[^`])*`", " ", text)  # strip backtick template strings
    code = STRING_LITERAL_RE.sub(" ", code)  # strip '...' and "..." literals
    return " ".join(interps) + " " + code


def _no_issue(out_subtype: str, reason: str) -> dict[str, str]:
    return {
        "security_issue_candidate": "False",
        "primary_pattern": "OUT",
        "primary_category": "OUT",
        "out_subtype": out_subtype,
        "all_patterns": "",
        "taxonomy_label": "No taxonomy match",
        "classification_confidence": "low",
        "classification_reason": reason,
    }


def read_csv(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, dtype=str).fillna("")


def compact(value: object, limit: int = 500) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[: limit - 1] + "…" if len(text) > limit else text


def pattern_hits(text: str, patterns: dict[str, list[str]]) -> list[str]:
    hits = []
    for pattern_id, regexes in patterns.items():
        if any(re.search(regex, text, re.I) for regex in regexes):
            hits.append(pattern_id)
    return hits


def _bare_print_arg(outside: str) -> str:
    """If the statement is ``sink(identifier)`` return that bare identifier."""
    m = re.search(
        r"(?:println!?|print!?|printf|puts|echo|console\.(?:log|error|warn|info|debug|trace)|"
        r"System\.(?:out|err)\.print(?:ln)?|fmt\.[A-Za-z]*[Pp]rint[A-Za-z]*|"
        r"[A-Za-z_]\w*\.(?:log|error|warn|info|debug|trace))\s*\(\s*([A-Za-z_]\w*)\s*\)",
        outside,
    )
    return m.group(1) if m else ""


def classify_log(text: str, risk_level: str = "low", file: str = "") -> dict[str, str]:
    original = str(text or "")
    outside = strip_string_literals(original)
    values = dynamic_values(original)  # dynamic / logged values only
    dynamic = has_dynamic_output(original)

    # --- (Suggestion 3) Filter lines that are not real logging statements. ---
    is_asset = bool(ASSET_FILE_RE.search(str(file)))
    is_notebook = str(file).lower().endswith(".ipynb")
    minified = len(original) > 1500 and len(
        re.findall(r"(function\s*\(|=>|Symbol\.for\(|;var |\|\||&&)", original)
    ) >= 5
    no_sink = not SINK_RE.search(outside)
    if is_asset or minified or no_sink:
        if no_sink and is_notebook and not is_asset and not minified and re.match(r"\s*[\"']\s*print\s*\(", original):
            return _no_issue("OUT-Low", "No sensitive value detected in notebook cell text")
        return _no_issue("OUT-NonLog", "Not a logging statement (control-flow / object literal / minified asset)")

    labels: list[str] = []
    reasons: list[str] = []

    def add(label: str, why: str) -> None:
        if label not in labels:
            labels.append(label)
            reasons.append(f"{label}: {why}")

    bare_arg = _bare_print_arg(outside)
    has_cred = bool(CRED_RE.search(values))
    has_user = bool(USER_RE.search(values))
    has_config = bool(CONFIG_RE.search(values))
    has_rawdump = (
        bool(RAWDUMP_RE.search(values))
        or bool(OBJECT_WORD_RE.search(bare_arg))
        # a whole request/response/payload object passed as a value is a raw dump
        or bool(re.search(r"\b(request|response|payload|req_?body|res_?body)\b", values, re.I))
    )
    redaction = bool(REDACT_RE.search(original))
    error_ctx = bool(ERRORCTX_RE.search(original))
    stack = bool(STACK_RE.search(original))

    # --- (Suggestions 2 & 4) Classify by the value actually logged. ---
    if has_cred or bool(CRED_RE.search(bare_arg)):
        add("SS-Cr", "credential / auth material in logged value")
    if DECODED_CRED_RE.search(original) and DECODED_CRED_KW_RE.search(original):
        add("SS-Cr", "decoded credential/token value logged")
    if has_user or bool(USER_RE.search(bare_arg)):
        add("SS-Ur", "user / personal data in logged value")
    if has_config:
        add("SS-Cf", "configuration / path / endpoint value in logged value")
    if has_rawdump:
        if redaction:
            add("RM-Ft", "masking present but raw object/value still logged")
        else:
            add("RM-Ms", "raw object / body / payload dumped without masking")
    elif redaction and dynamic:
        add("RM-Ft", "masking/redaction mentioned but dynamic data still appears")

    # --- (Suggestion 1) Error/exception is only an EE issue when it carries data. ---
    if stack:
        add("EE-St", "stack trace logged")
    only_exception = bool(bare_arg) and bool(EXC_IDENT_RE.match(bare_arg))
    carries_data = bool(EEX_EXTRA_RE.search(values)) or (
        dynamic and (has_rawdump or has_cred or has_user or has_config) and not only_exception
    )
    if error_ctx and not stack:
        if carries_data and "EE-Ex" not in labels:
            add("EE-Ex", "exception/error message carries sensitive runtime data")
        # plain "log.error('static message', e)" -> ordinary error logging, not an issue

    # --- Log injection (IL-At): unescaped user-controlled input with newline/CRLF. ---
    if re.search(r"(crlf|log\s*injection|log[\s-]*forg\w*|forged|forging|forgery|%0a|%0d|\bxss\b)", original, re.I) or (
        re.search(r"(\\n|\\r)", original)
        and re.search(r"\b(input|param|parameter|request|userinput|body|payload|header)\b", outside, re.I)
    ):
        add("IL-At", "potential log injection from unescaped input")

    if not labels:
        return _no_issue("OUT-Low", "No sensitive value detected in the logged output")

    # --- IL-Lv: a sensitive candidate captured at trace/debug/info level. ---
    if LEVEL_RE.search(outside) and any(l.split("-", 1)[0] in {"SS", "RM", "EE"} for l in labels):
        add("IL-Lv", "sensitive candidate logged at trace/debug/info level")

    order = {
        "SS-Cr": 0, "SS-Ur": 1, "SS-Cf": 2, "RM-Ft": 3, "RM-Ms": 4,
        "EE-St": 5, "EE-Ex": 6, "IL-At": 7, "IL-Lv": 8, "IL-Pa": 9,
    }
    labels = sorted(set(labels), key=lambda l: order.get(l, 99))
    primary = labels[0]
    category = primary.split("-", 1)[0]

    strong = primary in {"SS-Cr", "SS-Ur", "SS-Cf", "RM-Ms", "RM-Ft"}
    if risk_level == "high" and strong:
        confidence = "high"
    elif primary in {"EE-Ex", "IL-Lv"}:
        confidence = "low" if risk_level == "low" else "medium"
    else:
        confidence = "medium"

    return {
        "security_issue_candidate": "True",
        "primary_pattern": primary,
        "primary_category": category,
        "out_subtype": "",
        "all_patterns": ";".join(labels),
        "taxonomy_label": TAXONOMY.get(primary, ""),
        "classification_confidence": confidence,
        "classification_reason": " | ".join(reasons),
    }


def flatten_aidev(aidev_dir: Path) -> pd.DataFrame:
    rows = []
    for path in sorted(aidev_dir.glob("*_log_changes.json")):
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
                        "commit": change.get("commit_hash", ""),
                        "file": file_path,
                        "line": change.get("new_content_start_line")
                        or change.get("old_content_start_line")
                        or item.get("logging_statement_begin_line"),
                        "add_remove": change.get("change_type", ""),
                        "attribution": "unknown_git_history",
                        "risk_level": risk_level,
                        "sensitive_keywords": ";".join(keywords),
                        "log_text": log_text or "",
                        "commit_message": change.get("commit_message", ""),
                    }
                )
    return pd.DataFrame(rows).fillna("")


def standardize_swe(path: Path) -> pd.DataFrame:
    df = read_csv(path)
    return pd.DataFrame(
        {
            "dataset": "SWE-chat",
            "repo": df.get("repo", ""),
            "commit": df.get("commit", ""),
            "file": df.get("file", ""),
            "line": df.get("line", ""),
            "add_remove": df.get("add_remove", ""),
            "attribution": df.get("attribution", ""),
            "risk_level": df.get("risk_level", ""),
            "sensitive_keywords": df.get("sensitive_keywords", ""),
            "log_text": df.get("log_text", ""),
            "commit_message": df.get("commit_message", ""),
        }
    ).fillna("")


def standardize_devgpt(path: Path) -> pd.DataFrame:
    df = read_csv(path)
    return pd.DataFrame(
        {
            "dataset": "DevGPT",
            "repo": df.get("repo", ""),
            "commit": df.get("commit", ""),
            "file": df.get("file", ""),
            "line": df.get("line", ""),
            "add_remove": df.get("add_remove", ""),
            "attribution": df.get("attribution", ""),
            "risk_level": df.get("risk_level", ""),
            "sensitive_keywords": df.get("sensitive_keywords", ""),
            "log_text": df.get("log_text", ""),
            "commit_message": df.get("commit_message", ""),
        }
    ).fillna("")


def summarize(classified: pd.DataFrame) -> dict:
    total = len(classified)
    issue = classified[classified["security_issue_candidate"] == "True"]

    def ratio(n: int, d: int) -> float:
        return round(n / d * 100, 2) if d else 0.0

    by_dataset = []
    for dataset, group in classified.groupby("dataset", sort=True):
        issue_group = group[group["security_issue_candidate"] == "True"]
        by_dataset.append(
            {
                "dataset": dataset,
                "total_log_candidates": int(len(group)),
                "security_issue_candidates": int(len(issue_group)),
                "security_issue_rate_percent": ratio(len(issue_group), len(group)),
                "high_priority_rows": int((group["risk_level"] == "high").sum()),
                "medium_or_high_priority_rows": int(group["risk_level"].isin(["medium", "high"]).sum()),
            }
        )

    by_pattern = []
    for pattern, group in issue.groupby("primary_pattern"):
        category = pattern.split("-", 1)[0]
        by_pattern.append(
            {
                "primary_category": category,
                "primary_category_label": CATEGORY.get(category, ""),
                "primary_pattern": pattern,
                "pattern_label": TAXONOMY.get(pattern, ""),
                "rows": int(len(group)),
                "share_of_security_issue_candidates_percent": ratio(len(group), len(issue)),
                "share_of_all_log_candidates_percent": ratio(len(group), total),
            }
        )
    by_pattern.sort(key=lambda row: row["rows"], reverse=True)

    by_category = []
    for category, group in issue.groupby("primary_category"):
        by_category.append(
            {
                "primary_category": category,
                "category_label": CATEGORY.get(category, ""),
                "rows": int(len(group)),
                "share_of_security_issue_candidates_percent": ratio(len(group), len(issue)),
                "share_of_all_log_candidates_percent": ratio(len(group), total),
            }
        )
    by_category.sort(key=lambda row: row["rows"], reverse=True)

    cross_dataset_pattern = []
    for (dataset, pattern), group in issue.groupby(["dataset", "primary_pattern"]):
        cross_dataset_pattern.append(
            {
                "dataset": dataset,
                "primary_pattern": pattern,
                "pattern_label": TAXONOMY.get(pattern, ""),
                "rows": int(len(group)),
            }
        )
    cross_dataset_pattern.sort(key=lambda row: (row["dataset"], -row["rows"]))

    out = {
        "method": {
            "basis": "Heuristic mapping to Yuan et al. 2026 secure logging taxonomy: IL, SS, RM, EE with 10 patterns.",
            "score_definition": "security_issue_rate_percent = rows matched to at least one taxonomy pattern / all extracted log candidate rows.",
            "caveat": "This is candidate classification from log text, file, and available metadata. IL-Pa and many RM/IL-Lv cases require repository context and should be manually reviewed.",
        },
        "overall": {
            "total_log_candidates": int(total),
            "security_issue_candidates": int(len(issue)),
            "security_issue_rate_percent": ratio(len(issue), total),
            "high_priority_rows": int((classified["risk_level"] == "high").sum()),
            "medium_or_high_priority_rows": int(classified["risk_level"].isin(["medium", "high"]).sum()),
        },
        "by_dataset": by_dataset,
        "by_category": by_category,
        "by_pattern": by_pattern,
        "cross_dataset_pattern": cross_dataset_pattern,
    }
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Classify log candidates into secure logging issue taxonomy.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--aidev-dir", type=Path, default=DEFAULT_AIDEV_DIR)
    parser.add_argument("--swe-csv", type=Path, default=DEFAULT_SWE_CSV)
    parser.add_argument("--devgpt-csv", type=Path, default=DEFAULT_DEVGPT_CSV)
    args = parser.parse_args()

    aidev = flatten_aidev(args.aidev_dir)
    swe = standardize_swe(args.swe_csv)
    devgpt = standardize_devgpt(args.devgpt_csv)
    combined = pd.concat([aidev, swe, devgpt], ignore_index=True).fillna("")

    classifications = combined.apply(
        lambda r: classify_log(r["log_text"], r["risk_level"], r.get("file", "")), axis=1
    )
    class_df = pd.DataFrame(list(classifications))
    result = pd.concat([combined, class_df], axis=1)
    result["log_text"] = result["log_text"].map(compact)
    result["commit_message"] = result["commit_message"].map(lambda x: compact(x, 300))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    candidates_path = args.output_dir / "log_security_issue_classification.csv"
    summary_path = args.output_dir / "summary.json"
    summary_md_path = args.output_dir / "summary.md"
    result.to_csv(candidates_path, index=False)

    summary = summarize(result)
    summary["outputs"] = {"classification_csv": str(candidates_path), "summary_json": str(summary_path)}
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# Log Security Issue Classification Summary",
        "",
        f"- Total log candidates: {summary['overall']['total_log_candidates']}",
        f"- Security issue candidates: {summary['overall']['security_issue_candidates']} ({summary['overall']['security_issue_rate_percent']}%)",
        f"- Medium/high priority rows: {summary['overall']['medium_or_high_priority_rows']}",
        "",
        "## By Dataset",
        "",
        "| Dataset | Total | Security Candidates | Rate | Medium/High Priority |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in summary["by_dataset"]:
        lines.append(
            f"| {row['dataset']} | {row['total_log_candidates']} | {row['security_issue_candidates']} | "
            f"{row['security_issue_rate_percent']}% | {row['medium_or_high_priority_rows']} |"
        )
    lines.extend(
        [
            "",
            "## By Taxonomy Pattern",
            "",
            "| Pattern | Label | Rows | Share of Security Candidates | Share of All Logs |",
            "|---|---|---:|---:|---:|",
        ]
    )
    for row in summary["by_pattern"]:
        lines.append(
            f"| {row['primary_pattern']} | {row['pattern_label']} | {row['rows']} | "
            f"{row['share_of_security_issue_candidates_percent']}% | {row['share_of_all_log_candidates_percent']}% |"
        )
    summary_md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(summary["overall"], ensure_ascii=False, indent=2))
    print(f"wrote {candidates_path}")
    print(f"wrote {summary_path}")


if __name__ == "__main__":
    main()
