"""Finite schema-context hints over frozen Parquet; values never leave memory."""
from __future__ import annotations

from collections import Counter
import csv
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import time

import pyarrow as pa
import pyarrow.parquet as pq

from agentlog_unified import aidev, content_scan, content_types, storage, swechat, taxonomy

VERSION = "schema-context-1"
SCOPE = {"observation_scope": "dataset_schema_context", "evidence_basis": "schema_context",
         "human_review_status": "pending", "confidence": "low", "runtime_confirmed": False,
         "personal_ownership_confirmed": False, "sensitivity_confirmed": False,
         "application_log_evidence": False, "new_type_status": "not_established"}
# An explicit table/entity registry avoids classifying repository names and every id.
ROLES = {
    **{("aidev", t, "user_id"): ("numeric_account_id", "QID", "user_identifier")
       for t in ("all_pull_request", "human_pull_request", "pr_comments", "pull_request")},
    **{("aidev", t, "id"): ("numeric_account_id", "QID", "user_identifier") for t in ("user", "all_user")},
    **{("aidev", t, "login"): ("account_login", "QID", "user_identifier") for t in ("user", "all_user")},
    # Exact AIDev account-reference columns already linked by the importer.
    **{("aidev", t, "user"): ("account_reference", "QID", "user_identifier")
       for t in ("all_pull_request", "human_pull_request", "issue", "pr_comments",
                 "pr_review_comments", "pr_review_comments_v2", "pr_reviews", "pull_request")},
    ("aidev", "pr_timeline", "actor"): ("account_reference", "QID", "user_identifier"),
    **{("aidev", t, column): ("account_login_join", "QID", "user_identifier")
       for t in ("pr_commits", "pr_commit_details") for column in ("author", "committer")},
    ("aidev", "pr_timeline", "assignee"): ("account_login_join", "QID", "user_identifier"),
    ("swe-chat", "commits", "author_name"): ("author_name", "PII", "person_name"),
    ("swe-chat", "commits", "author_email"): ("author_email", "PII", "email"),
    ("swe-chat", "commits", "github_username"): ("account_login", "QID", "user_identifier"),
    **{("swe-chat", t, "user_id"): ("account_reference", "QID", "user_identifier")
       for t in ("checkpoints", "commits", "conversations", "sessions")},
    **{("swe-chat", t, "session_id"): ("session_reference", "QID", "session_identifier")
       for t in ("sessions", "session_logs", "conversations")},
}
TYPE_KEYS = {(c["category"], s["subtype"]) for c in taxonomy.taxonomy_catalog()["categories"] for s in c["subtypes"]}
assert all((category, subtype) in TYPE_KEYS for _, category, subtype in ROLES.values())


def _sources():
    paths = [Path(__file__)] + [Path(m.__file__) for m in (aidev, content_scan, content_types, storage, swechat, taxonomy)]
    return {p.name: aidev._digest(p) for p in paths}


def _inventory(import_dir):
    dataset, manifest_sha, tables = content_scan._inventory(import_dir)
    fields = []
    for table in tables:
        parquet = pq.ParquetFile(table["absolute_path"])
        for arrow_field in parquet.schema_arrow:
            name, dtype = arrow_field.name, arrow_field.type
            scalar = not pa.types.is_nested(dtype)
            role = ROLES.get((dataset, table["table"], name)) if scalar else None
            chunks = [parquet.metadata.row_group(g).column(i)
                      for g in range(parquet.metadata.num_row_groups)
                      for i in range(parquet.metadata.row_group(g).num_columns)
                      if parquet.metadata.row_group(g).column(i).path_in_schema == name]
            null_known = len(chunks) == parquet.metadata.num_row_groups and all(c.statistics is not None and c.statistics.has_null_count for c in chunks)
            fields.append({"field_id": storage.stable_id(VERSION, manifest_sha, table["path"], name),
                "dataset": dataset, "table_path": table["path"], "table": table["table"], "column_name": name,
                "native_type": str(dtype), "is_scalar": scalar, "source_rows": table["rows"],
                "source_table_sha256": table["sha256"], "source_manifest_sha256": manifest_sha,
                "selected_for_value_scan": role is not None,
                "schema_role": role[0] if role else None, "category": role[1] if role else None,
                "subtype": role[2] if role else None,
                "footer_null_count": sum(c.statistics.null_count for c in chunks) if null_known else None})
    return dataset, manifest_sha, tables, fields


def _quality(value, role):
    """Return finite quality labels, not the original value or a value digest."""
    if value is None:
        return "null", "arrow_null"
    if isinstance(value, str) and not value.strip():
        return "empty", "empty_or_whitespace_text"
    if role == "numeric_account_id":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return "invalid", "expected_numeric_account_id"
        if isinstance(value, float):
            if not math.isfinite(value): return "invalid", "nonfinite_numeric_id"
            if not value.is_integer(): return "invalid", "nonintegral_numeric_id"
            if abs(value) >= 2**53: return "invalid", "floating_id_precision_unverifiable"
        if value <= 0: return "invalid", "nonpositive_numeric_id"
        return "schema_context_candidate", "explicit_numeric_account_field"
    if not isinstance(value, str):
        return "invalid", "expected_text_schema_field"
    if any(ord(c) < 32 for c in value):
        return "invalid", "control_characters_in_metadata"
    if value.lstrip().startswith(("{", "[")):
        return "invalid", "structured_metadata_requires_interpretation"
    if content_types._example(value, 0, len(value)):
        return "placeholder_or_example", "example_shaped_metadata_not_validated"
    if role == "author_email" and not content_types._EMAIL.fullmatch(value.strip()):
        return "invalid", "email_field_shape_unresolved"
    return "schema_context_candidate", "explicit_" + role + "_field"


def _account_references(tables, *, decode, batch_size):
    """Build an exact in-memory lookup; export only reference-source counts."""
    values = set(); sources = []
    for name in ("user", "all_user"):
        matches = [t for t in tables if t["table"] == name]
        item = {"table": name, "column_name": "login", "values_decoded": False}
        sources.append(item)
        if len(matches) != 1:
            item["status"] = "missing_table" if not matches else "ambiguous_table"
            continue
        table = matches[0]; path = Path(table["absolute_path"]); parquet = pq.ParquetFile(path)
        item.update(table_path=table["path"], source_sha256=table["sha256"], source_rows=table["rows"])
        if "login" not in parquet.schema_arrow.names:
            item["status"] = "missing_column"; continue
        dtype = parquet.schema_arrow.field("login").type
        item["native_type"] = str(dtype)
        if not (pa.types.is_string(dtype) or pa.types.is_large_string(dtype)):
            item["status"] = "unsupported_type"; continue
        item["status"] = "not_decoded"
        if not decode: continue
        counts = Counter()
        try:
            for batch in parquet.iter_batches(columns=["login"], batch_size=batch_size, use_threads=False):
                for value in batch.column(0).to_pylist():
                    counts["reference_cells_decoded"] += 1
                    if value is None: counts["null"] += 1
                    elif value == "": counts["empty_string"] += 1
                    else: counts["nonempty_string"] += 1; values.add(value)
        except Exception:
            raise ValueError("Frozen account reference could not be read") from None
        if counts["reference_cells_decoded"] != table["rows"] or content_scan._stat(path) != tuple(table["source_stat"]):
            raise ValueError("Frozen account reference changed during schema scan")
        item.update(status="complete", values_decoded=True, counts=dict(counts))
    available = sum(s["status"] in {"complete", "not_decoded"} for s in sources)
    status = "unavailable" if not available else "partial" if available < 2 else "not_decoded" if not decode else "complete" if values else "empty"
    return values, {"status": status, "sources": sources,
        "reference_cells_decoded": sum(s.get("counts", {}).get("reference_cells_decoded", 0) for s in sources),
        "distinct_nonempty_reference_strings": len(values) if decode else None,
        "comparison": "exact_string_equality_no_trim_casefold_or_unicode_normalization",
        "reference_values_or_value_hashes_exported": False,
        "count_unit": "Reference table cells read for lookup setup; separate from classified source cells."}


def _joined_account_quality(value, references, coverage):
    status, reason = _quality(value, "account_reference")
    if status != "schema_context_candidate": return status, reason
    if value in references: return "schema_context_candidate", "exact_frozen_account_login_match"
    reason = ("account_login_not_found_in_frozen_references" if coverage["status"] == "complete" else
              "account_reference_contains_no_values" if coverage["status"] == "empty" else
              "account_reference_sources_unavailable_or_incomplete")
    return "unresolved", reason


def _write_rows(output, stem, rows, columns):
    js_tmp, csv_tmp = output / (stem + ".jsonl.tmp"), output / (stem + ".csv.tmp")
    count = 0
    with js_tmp.open("w") as js, csv_tmp.open("w", newline="") as cs:
        os.chmod(js_tmp, 0o600); os.chmod(csv_tmp, 0o600)
        writer = csv.DictWriter(cs, fieldnames=columns); writer.writeheader()
        for row in rows:
            js.write(storage.canonical(row) + "\n")
            writer.writerow({key: storage.csv_cell(row.get(key)) for key in columns}); count += 1
    os.replace(js_tmp, output / (stem + ".jsonl")); os.replace(csv_tmp, output / (stem + ".csv"))
    return count


def _export(db, output, manifest):
    fields = {f["field_id"]: f for f in manifest["fields"]}
    progress = {r["field_id"]: dict(r) for r in db.execute("SELECT * FROM fields")}
    total = Counter(); summaries = Counter(); coverage_fields = []
    for fid, f in fields.items():
        row = progress[fid]; stats = json.loads(row.pop("stats")); total.update(stats)
        coverage_fields.append({**f, **row, "counts": stats,
            "null_count": stats.get("null", 0) if f["selected_for_value_scan"] else None,
            "empty_count": stats.get("empty", 0) if f["selected_for_value_scan"] else None,
            "invalid_count": stats.get("invalid", 0) if f["selected_for_value_scan"] else None,
            "values_decoded": row["next_row"] > 0, **SCOPE})
        if f["selected_for_value_scan"]:
            summaries[(f["category"], f["subtype"])] += stats.get("schema_context_candidate", 0)
    columns = ["id", "field_id", "dataset", "table_path", "column_name", "native_type", "schema_role",
        "source_manifest_sha256", "source_table_sha256", "start_row", "end_row", "row_count",
        "status", "reason", "category", "subtype", "candidate_status", *SCOPE]
    def ranges(candidate_only=False):
        for raw in db.execute("SELECT * FROM ranges" + (" WHERE status='schema_context_candidate'" if candidate_only else "") + " ORDER BY field_id,start_row"):
            row = dict(raw); f = fields[row["field_id"]]
            unclassified = f["schema_role"] == "account_login_join" and row["status"] != "schema_context_candidate"
            yield {**{k: f[k] for k in ("dataset", "table_path", "column_name", "native_type", "schema_role", "source_manifest_sha256", "source_table_sha256", "category", "subtype")},
                **row, "row_count": row["end_row"] - row["start_row"] + 1,
                **({"category": None, "subtype": None} if unclassified else {}),
                "candidate_status": "schema_context_candidate" if row["status"] == "schema_context_candidate" else None, **SCOPE}
    candidate_records = _write_rows(output, "schema_context_candidates", ranges(True), columns)
    review_records = _write_rows(output, "schema_context_review_queue", ranges(), columns)
    def unresolved():
        for f in fields.values():
            if f["selected_for_value_scan"]: continue
            yield {**f, "start_row": 1 if f["source_rows"] else None, "end_row": f["source_rows"] or None,
                   "row_count": f["source_rows"], "record_kind": "unread_source_field_range", "values_decoded": False,
                   "empty_count": None, "invalid_count": None,
                   "status": "schema_semantics_unresolved" if f["is_scalar"] else "nested_schema_unresolved", **SCOPE}
    unresolved_columns = ["field_id", "dataset", "table_path", "column_name", "native_type", "is_scalar", "start_row", "end_row", "row_count", "footer_null_count", "empty_count", "invalid_count", "status", "values_decoded", "source_manifest_sha256", "source_table_sha256", *SCOPE]
    unresolved_records = _write_rows(output, "schema_unresolved_fields", unresolved(), unresolved_columns)
    done = all(row["state"] == "complete" for row in progress.values() if fields[row["field_id"]]["selected_for_value_scan"])
    summary = [{"category": c, "subtype": s, "candidate_source_cells": n, "candidate_status": "schema_context_candidate", **SCOPE} for (c, s), n in sorted(summaries.items())]
    storage.atomic_write(output / "schema_type_summary.json", storage.canonical({"taxonomy_version": taxonomy.TAXONOMY_VERSION, "summary": summary, **SCOPE}) + "\n")
    summary_columns = ["category", "subtype", "candidate_source_cells", "candidate_status", *SCOPE]
    _write_rows(output, "schema_type_summary", iter(summary), summary_columns)
    result = {"status": "complete_with_schema_gaps" if done else "partial", "all_selected_fields_visited": done,
        "all_dataset_values_classified": False, "dataset": manifest["dataset"], "source_manifest_sha256": manifest["source_manifest_sha256"],
        "fields": coverage_fields, "all_fields": len(fields), "scalar_fields": sum(f["is_scalar"] for f in fields.values()),
        "selected_fields": sum(f["selected_for_value_scan"] for f in fields.values()), "counts": dict(total),
        "candidate_range_records": candidate_records, "review_range_records": review_records, "unresolved_field_records": unresolved_records,
        "range_count_unit": "Consecutive source rows of one table/column/quality status; counts are source cells, not people.",
        "limitations": ["Only the 32 explicit field roles can produce schema hints; remaining fields are unresolved.",
            "Hints describe field meaning, not real-person ownership, valid credentials, confirmed sensitivity or disclosure.",
            "Null, empty, invalid and example-shaped metadata are retained with distinct statuses and exact source-row ranges.",
            "Commit author/committer and timeline assignee candidates require exact frozen account-reference membership; nonmatches remain unresolved, not invalid or safe.",
            "Unselected fields have footer null counts where available; empty/invalid counts remain unknown because values were not decoded.",
            "No general identifier/name rule, structure parsing, Git history evidence or new taxonomy subtype is introduced."],
        "exit_code": 2, **SCOPE}
    if "account_reference_coverage" in manifest:
        result["account_reference_coverage"] = manifest["account_reference_coverage"]
    storage.atomic_write(output / "schema_coverage.json", storage.canonical(result) + "\n")
    return result


def scan_schema_context(import_dir, output_dir, *, resume=False, dry_run=False, batch_size=4096, max_seconds=None):
    """Scan the finite schema registry without modifying imports, Git or remotes."""
    if (type(batch_size) is not int or batch_size <= 0 or
            (max_seconds is not None and (type(max_seconds) not in (int, float) or not math.isfinite(max_seconds) or max_seconds <= 0))):
        raise ValueError("Schema scan budgets must be positive")
    started = time.monotonic(); imported, output = Path(import_dir).resolve(), Path(output_dir).resolve()
    dataset, manifest_sha, tables, fields = _inventory(imported)
    if output == imported or output.is_relative_to(imported) or any(output == Path(t["absolute_path"]).parent or output.is_relative_to(Path(t["absolute_path"]).parent) for t in tables):
        raise ValueError("Schema output must be separate from frozen sources/imports")
    fingerprint = {"version": VERSION, "source_import": str(imported), "source_manifest_sha256": manifest_sha,
        "inputs": [{k: t[k] for k in ("path", "sha256", "bytes")} for t in tables],
        "source_sha256": _sources(), "pyarrow_version": pa.__version__, "taxonomy_version": taxonomy.TAXONOMY_VERSION}
    needs_references = any(f["schema_role"] == "account_login_join" for f in fields)
    if dry_run:
        return {"status": "dry_run", "dataset": dataset, "all_fields": len(fields), "scalar_fields": sum(f["is_scalar"] for f in fields),
            "selected_fields": sum(f["selected_for_value_scan"] for f in fields), "fields": fields,
            **({"account_reference_coverage": _account_references(tables, decode=False, batch_size=batch_size)[1]} if needs_references else {}),
            "files_written": False, "values_decoded": False, "exit_code": 0, **SCOPE}
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (output / ".schema.lock").open("a") as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError("Schema scan already has an active writer") from None
        mp = output / "manifest.json"
        if mp.exists():
            manifest = json.loads(mp.read_text())
            if not resume or manifest["fingerprint"] != fingerprint:
                raise ValueError("Schema resume requires identical frozen inputs and implementation")
        else:
            if any(p.name != ".schema.lock" for p in output.iterdir()): raise ValueError("Schema output directory is not empty")
            manifest = {"dataset": dataset, "source_manifest_sha256": manifest_sha, "fingerprint": fingerprint, "fields": fields, **SCOPE}
        references, reference_coverage = _account_references(tables, decode=True, batch_size=batch_size) if needs_references else (set(), None)
        if reference_coverage is not None:
            if mp.exists() and manifest.get("account_reference_coverage") != reference_coverage:
                raise ValueError("Frozen account reference coverage differs on resume")
            manifest["account_reference_coverage"] = reference_coverage
        if not mp.exists():
            storage.atomic_write(mp, storage.canonical(manifest) + "\n")
        db = sqlite3.connect(output / "schema.sqlite"); os.chmod(output / "schema.sqlite", 0o600); db.row_factory = sqlite3.Row
        db.executescript("""CREATE TABLE IF NOT EXISTS fields(field_id TEXT PRIMARY KEY,next_row INTEGER DEFAULT 0,next_row_group INTEGER DEFAULT 0,state TEXT,stats TEXT DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS ranges(id TEXT PRIMARY KEY,field_id TEXT,start_row INTEGER,end_row INTEGER,status TEXT,reason TEXT);
            CREATE INDEX IF NOT EXISTS range_tail ON ranges(field_id,end_row);""")
        stopped = False; table_by_path = {t["path"]: t for t in tables}
        try:
            with db:
                for f in fields: db.execute("INSERT OR IGNORE INTO fields(field_id,state) VALUES(?,?)", (f["field_id"], "pending" if f["selected_for_value_scan"] else "schema_semantics_unresolved"))
            for f in fields:
                if not f["selected_for_value_scan"]: continue
                progress = db.execute("SELECT * FROM fields WHERE field_id=?", (f["field_id"],)).fetchone()
                if progress["state"] == "complete": continue
                t = table_by_path[f["table_path"]]; path = Path(t["absolute_path"]); parquet = pq.ParquetFile(path)
                stats = Counter(json.loads(progress["stats"])); next_row = progress["next_row"]
                last = db.execute("SELECT * FROM ranges WHERE field_id=? ORDER BY end_row DESC LIMIT 1", (f["field_id"],)).fetchone()
                tail = dict(last) if last else None
                if not f["source_rows"]:
                    with db: db.execute("UPDATE fields SET state='complete' WHERE field_id=?", (f["field_id"],))
                group_start = 0
                for group in range(parquet.metadata.num_row_groups):
                    group_end = group_start + parquet.metadata.row_group(group).num_rows
                    if group_end <= next_row: group_start = group_end; continue
                    row_number = group_start
                    for batch in parquet.iter_batches(batch_size=batch_size, row_groups=[group], columns=[f["column_name"]]):
                        with db:
                            for value in batch.column(0).to_pylist():
                                row_number += 1
                                if row_number <= next_row: continue
                                if max_seconds is not None and time.monotonic() - started >= max_seconds:
                                    stopped = True; break
                                status, reason = (_joined_account_quality(value, references, reference_coverage)
                                    if f["schema_role"] == "account_login_join" else _quality(value, f["schema_role"]))
                                if tail and tail["end_row"] == row_number - 1 and tail["status"] == status and tail["reason"] == reason:
                                    tail["end_row"] = row_number
                                else:
                                    tail = {"id": storage.stable_id(VERSION, f["field_id"], row_number, status, reason), "field_id": f["field_id"], "start_row": row_number, "end_row": row_number, "status": status, "reason": reason}
                                db.execute("INSERT OR REPLACE INTO ranges VALUES(?,?,?,?,?,?)", tuple(tail[k] for k in ("id", "field_id", "start_row", "end_row", "status", "reason")))
                                stats["cells_decoded"] += 1; stats[status] += 1; next_row = row_number
                            db.execute("UPDATE fields SET next_row=?,next_row_group=?,state=?,stats=? WHERE field_id=?", (next_row, group + int(next_row == group_end), "complete" if next_row == f["source_rows"] else "partial", storage.canonical(stats), f["field_id"]))
                        if stopped: break
                    group_start = group_end
                    if stopped: break
                if content_scan._stat(path) != tuple(t["source_stat"]): raise ValueError("Frozen source changed during schema scan")
                if stopped: break
            if needs_references and any(content_scan._stat(Path(t["absolute_path"])) != tuple(t["source_stat"])
                                        for t in tables if t["table"] in {"user", "all_user"}):
                raise ValueError("Frozen account reference changed during schema scan")
            result = _export(db, output, manifest)
            result.update(stop_reason="time_budget" if stopped else None, resumed=resume, elapsed_seconds=round(time.monotonic()-started,3), network_accessed=False, target_code_executed=False)
            storage.atomic_write(output / "schema_coverage.json", storage.canonical(result) + "\n")
            return result
        finally: db.close()
