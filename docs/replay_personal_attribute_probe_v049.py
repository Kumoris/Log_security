"""Replay a fixed, finite probe selection; export labels and positions only."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import json
import re
import sys
import time

from agentlog_unified import content_scan, content_repair, content_types, taxonomy

ROOT = Path(__file__).resolve().parents[1]
TYPE = {
    "birth_date": "birth_date", "age": "age", "sex_gender": "sex_gender",
    "ethnicity_race": "ethnicity", "religion_belief": "religious_belief",
    "education_history": "education", "employment_profile": "employment",
}
# These fixed forms describe a value's shape, not personal ownership or truth.
ENUMS = {
    "sex_gender": {"male", "female", "other", "nonbinary", "non-binary", "unknown", "男", "女"},
    "ethnicity_race": {"white", "black", "asian", "hispanic", "latino", "latina", "mixed", "caucasian", "african american", "native american", "other"},
    "religion_belief": {"christian", "christianity", "muslim", "islam", "buddhist", "buddhism", "hindu", "hinduism", "jewish", "judaism", "catholic", "protestant", "sikh", "atheist", "agnostic", "none", "other"},
    "education_history": {"primary", "secondary", "high school", "undergraduate", "graduate", "bachelor", "bachelor's", "bachelors", "master", "master's", "masters", "doctorate", "phd", "college", "university", "other"},
    "employment_profile": {"employed", "unemployed", "student", "retired", "engineer", "doctor", "teacher", "developer", "software engineer", "manager", "self-employed", "full-time", "part-time", "other"},
}
TYPE_WORDS = {"int", "integer", "float", "double", "str", "string", "number", "bool", "boolean", "date", "datetime", "any", "object", "optional"}
ATTRIBUTE_LABELS = {
    "birthdate", "dateofbirth", "dob", "age", "ageinyears", "gender", "sex", "biologicalsex", "genderidentity",
    "ethnicity", "ethnicorigin", "racialidentity", "religion", "religiousbelief", "religiousaffiliation",
    "educationlevel", "educationalattainment", "educationhistory", "highestdegree", "employmentstatus",
    "employmenthistory", "employername", "occupation", "出生日期", "年龄", "性别", "种族", "民族", "宗教信仰", "学历", "教育经历", "就业状况", "职业",
}


def normalized(value):
    return re.sub(r"[\s_.-]", "", value).lower()


def role_hint(text, item):
    value = text[item["value_start"]:item["value_end"]]
    key = text[item["key_start"]:item["key_end"]]
    lower = value.lower().strip()
    kind = item["evidence_kind"]
    if not value.strip():
        role = "empty_value"
    elif kind == "null_value":
        role = "null_value"
    elif kind == "container_not_scalar":
        role = "container"
    elif kind == "placeholder_or_example":
        role = "placeholder_or_example"
    elif lower in TYPE_WORDS or normalized(value) in ATTRIBUTE_LABELS or normalized(value) == normalized(key):
        role = "key_name_or_type_restatement"
    elif kind in {"reference_or_expression", "unquoted_identifier_ambiguous", "type_declaration"}:
        role = "reference_or_declaration"
    elif item["semantic_label"] == "birth_date" and re.fullmatch(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}", value):
        role = "date_like_literal"
    elif item["semantic_label"] == "age" and re.fullmatch(r"\d+(?:\.\d+)?", value):
        role = "numeric_age_field_literal"
    elif lower in ENUMS.get(item["semantic_label"], set()):
        role = "fixed_attribute_enum_shape"
    else:
        role = "other_literal_unresolved"
    context = text[max(0, item["key_start"] - 256):min(len(text), item["value_end"] + 256)]
    return {
        "value_role_hint": role,
        "nearby_ui_localization_marker": bool(re.search(r"\b(?:i18n|locale|localization|translation|translate|label|caption)\b", context, re.I)),
        "nearby_schema_declaration_marker": bool(re.search(r"\b(?:schema|properties|interface|struct|enum|type)\b", context, re.I)),
        "nearby_fixture_documentation_marker": bool(re.search(r"\b(?:fixture|example|sample|mock|test|tests|testing)\b", context, re.I)),
    }


def main():
    started = time.monotonic()
    docs = ROOT / "docs"
    selection_path = docs / "personal_attribute_probe_v049_replay_selection.json"
    selection = json.loads(selection_path.read_text())
    assert content_repair._digest(docs / "personal_attribute_probe_v049_evidence.jsonl") == selection["probe_evidence_sha256"]
    dataset, manifest_sha, table_rows = content_scan._inventory(ROOT / "inputs/aidev-full-v2")
    assert dataset == "aidev" and manifest_sha == selection["source_manifest_sha256"]
    assert [{key: t[key] for key in ("path", "bytes", "sha256")} for t in table_rows] == selection["source_inputs"]
    tables = {t["path"]: t for t in table_rows}
    verified = {t["path"]: tuple(t["source_stat"]) for t in table_rows}
    modules = [Path(m.__file__) for m in (content_scan, content_repair, content_types, taxonomy)]
    implementation = {p.name: content_repair._digest(p) for p in modules}
    per_cell = defaultdict(list)
    for item in selection["selected"]:
        per_cell[item["table_path"], item["column_name"], item["source_row"]].append(item)
    cells = [{"table_path": table, "column_name": col, "source_row": row} for table, col, row in per_cell]
    records, cell_audit = [], []
    for cell, text, path, before in content_repair._selected_values(cells, tables, started + 180, verified):
        assert len(text) <= content_types.MAX_SOURCE_CHARS
        parsed = content_types.classify_text(text, max_matches=1000)
        cell_audit.append({**cell, "classifier_truncated": parsed["truncated"], "returned_matches": len(parsed["matches"])})
        for item in per_cell[cell["table_path"], cell["column_name"], cell["source_row"]]:
            start, end = item["value_start"], item["value_end"]
            assert 0 <= item["key_start"] < item["key_end"] <= start <= end <= len(text)
            expected = TYPE[item["semantic_label"]]
            exact = [m for m in parsed["matches"] if (m["start"], m["end"]) == (start, end)]
            matches = [m for m in exact if (m["category"], m["subtype"]) == ("PII", expected)]
            key = text[item["key_start"]:item["key_end"]]
            mapped_key = any(row[:2] == ("PII", expected) for row in taxonomy._matches(key))
            miss_reason = None if matches else "empty_value_not_emitted" if start == end else "non_ascii_key_unrecognized" if not key.isascii() else "key_not_mapped_to_expected_type" if not mapped_key else "span_or_assignment_recognition_difference"
            records.append({**item, **role_hint(text, item), "expected_category": "PII", "expected_subtype": expected,
                "expected_type_at_exact_value_span": bool(matches), "miss_reason": miss_reason,
                "same_span_types": sorted({str(m["category"]) + "." + str(m["subtype"]) for m in exact}),
                "expected_match_statuses": sorted({m["candidate_status"] for m in matches}),
                "classifier_truncated": parsed["truncated"], "taxonomy_change_applied": True,
                "human_review_status": "pending", "source_values_exported": False})
    assert len(cell_audit) == len(cells) and len(records) == selection["selected_records"]
    assert all(content_scan._stat(Path(t["absolute_path"])) == verified[t["path"]] for t in table_rows)
    assert content_repair._digest(ROOT / "inputs/aidev-full-v2/manifest.json") == manifest_sha
    assert implementation == {p.name: content_repair._digest(p) for p in modules}
    records.sort(key=lambda r: r["probe_record_1based"])
    evidence_path = docs / "personal_attribute_replay_v049_evidence.jsonl"
    evidence_path.write_text("".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in records))
    by_label = []
    for label in TYPE:
        group = [r for r in records if r["semantic_label"] == label]
        by_label.append({"probe_label": label, "expected_subtype": TYPE[label], "selected_records": len(group),
            "exact_value_span_type_hits": sum(r["expected_type_at_exact_value_span"] for r in group),
            "value_role_hints": dict(Counter(r["value_role_hint"] for r in group)),
            "miss_reasons": dict(Counter(r["miss_reason"] for r in group if r["miss_reason"]))})
    literal = [r for r in records if r["selection_role"] == "syntax_literal_candidate_requires_semantic_review"]
    summary = {
        "completed_utc": datetime.now(timezone.utc).isoformat(), "elapsed_seconds": round(time.monotonic() - started, 3),
        "command": [sys.executable, str(Path(__file__).resolve())], "helper_sha256": content_repair._digest(Path(__file__)),
        "selection_sha256": content_repair._digest(selection_path), "probe_evidence_sha256": selection["probe_evidence_sha256"],
        "source_manifest_sha256": manifest_sha, "frozen_source_inputs": selection["source_inputs"],
        "implementation_sha256": implementation, "taxonomy_version": taxonomy.TAXONOMY_VERSION,
        "content_detector_version": content_types.CONTENT_DETECTOR_VERSION, "inputs_and_code_unchanged": True,
        "selected_records": len(records), "distinct_source_cells": len(cells),
        "exact_value_span_type_hits": sum(r["expected_type_at_exact_value_span"] for r in records),
        "cell_audit": cell_audit, "by_label": by_label,
        "role_hint_counts": dict(Counter(r["value_role_hint"] for r in records)),
        "literal_selected_records": len(literal),
        "literal_key_name_or_type_restatement_records": sum(r["value_role_hint"] == "key_name_or_type_restatement" for r in literal),
        "nearby_ui_localization_marker_records": sum(r["nearby_ui_localization_marker"] for r in records),
        "evidence_path": evidence_path.name, "evidence_sha256": content_repair._digest(evidence_path),
        "source_values_exported": False, "dynamic_keys_exported": False, "value_hashes_exported": False,
        "human_review_status": "pending", "personal_ownership_confirmed": False, "sensitivity_confirmed": False,
        "limitations": ["Fixed purposive selection is not representative; ratios apply only to these records.",
            "Value-role hints use finite syntax/dictionary tests; enum shapes and nearby markers do not establish real personal attributes or localization roles.",
            "Source cell selections are 1-based table/column/row references. Arrow decoding may read intervening rows; only the 23 selected scalar values are materialized and classified.",
            "The old probe fingerprint remains in the old report; this report records the new classifier implementation.",
            "No additional complete body scan, network request, target execution, or human confirmation occurred."]}
    (docs / "personal_attribute_replay_v049.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({key: summary[key] for key in ("elapsed_seconds", "selected_records", "distinct_source_cells", "exact_value_span_type_hits", "by_label", "role_hint_counts", "literal_selected_records", "literal_key_name_or_type_restatement_records", "nearby_ui_localization_marker_records", "inputs_and_code_unchanged")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
