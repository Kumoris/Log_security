"""Resumable scans of frozen dataset text, separate from Git/log observations."""
from __future__ import annotations

from collections import Counter
import csv
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import time

from .aidev import CONTENT_FIELDS as AIDEV_CONTENT, _digest
from .swechat import CONTENT_FIELDS as SWECHAT_CONTENT
from .storage import atomic_write, canonical, csv_cell, stable_id
from .taxonomy import TAXONOMY_VERSION, taxonomy_catalog

SCOPE = {"observation_scope": "dataset_text_cells", "runtime_confirmed": False,
         "human_review_status": "pending", "new_type_status": "not_established",
         "full_dataset_coverage_claim": False, "application_log_evidence": False}
MATCH_FIELDS = {"start", "end", "category", "subtype", "rule", "basis", "confidence", "value_status", "candidate_status"}
TYPE_KEYS = {(category["category"], subtype["subtype"]) for category in taxonomy_catalog()["categories"] for subtype in category["subtypes"]}


def _inventory(import_dir: Path):
    import pyarrow as pa
    import pyarrow.parquet as pq
    manifest_path = import_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("status") != "complete":
        raise ValueError("Content scanning requires a completed frozen dataset import")
    signature = manifest["source_signature"]
    source = Path(signature["source_dir"]).resolve()
    dataset = "aidev" if "aidev.sqlite" in manifest["outputs"] else "swe-chat" if "swechat.sqlite" in manifest["outputs"] else None
    if dataset is None:
        raise ValueError("Unrecognized dataset import")
    tables = []
    for item in signature["inputs"]:
        path = (source / item["path"]).resolve()
        if not path.is_relative_to(source) or path.suffix != ".parquet":
            raise ValueError("Dataset source path escapes the frozen Parquet directory")
        if path.stat().st_size != item["bytes"] or _digest(path) != item["sha256"]:
            raise ValueError("Frozen dataset source hash changed")
        parquet = pq.ParquetFile(path)
        fields = [{"column": field.name, "arrow_type": str(field.type),
                   "selected": pa.types.is_string(field.type) or pa.types.is_large_string(field.type),
                   "field_scope": "content" if field.name in AIDEV_CONTENT | SWECHAT_CONTENT else "metadata"}
                  for field in parquet.schema_arrow]
        tables.append({**item, "table": Path(item["path"]).stem, "rows": parquet.metadata.num_rows,
                       "columns": fields, "absolute_path": str(path),
                       "source_stat": list(_stat(path))})
    if not tables or len({t["path"] for t in tables}) != len(tables):
        raise ValueError("Empty or duplicate frozen table list")
    return dataset, _digest(manifest_path), tables


def _stat(path):
    s = path.stat()
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def _export_rows(db, output, stem, query, columns, transform=lambda row: dict(row)):
    # The SQLite checkpoint is authoritative; interrupted exports are rebuilt on resume.
    json_tmp, csv_tmp = output / (stem + ".jsonl.tmp"), output / (stem + ".csv.tmp")
    count = 0
    with json_tmp.open("w", encoding="utf-8") as js, csv_tmp.open("w", newline="", encoding="utf-8") as cs:
        os.chmod(json_tmp, 0o600); os.chmod(csv_tmp, 0o600)
        writer = csv.DictWriter(cs, fieldnames=columns)
        writer.writeheader()
        for raw in db.execute(query):
            row = transform(raw)
            js.write(canonical(row) + "\n")
            writer.writerow({key: csv_cell(row.get(key)) for key in columns})
            count += 1
    os.replace(json_tmp, output / (stem + ".jsonl"))
    os.replace(csv_tmp, output / (stem + ".csv"))
    return count


def export_content(db, output, manifest):
    from .content_types import detector_catalog
    tables = [dict(row) for row in db.execute("SELECT * FROM tables ORDER BY path")]
    for table in tables:
        table["stats"] = json.loads(table["stats"])
    cell_counts = Counter({row[0]: row[1] for row in db.execute("SELECT status,COUNT(*) FROM cells GROUP BY status")})
    occurrence_columns = ["id", "cell_id", "table_path", "source_row", "column_name", "field_scope", "start", "end", "category", "subtype", "rule", "basis", "confidence", "value_status", "candidate_status", "observation_scope", "human_review_status", "runtime_confirmed"]
    query = "SELECT m.*,c.table_path,c.source_row,c.column_name,c.field_scope FROM matches m JOIN cells c ON c.id=m.cell_id"
    def occurrence(row):
        item = dict(row)
        detail = json.loads(item.pop("details"))
        return {**item, **detail, **SCOPE}
    candidate_count = _export_rows(db, output, "content_type_occurrences", query + " WHERE m.excluded=0 ORDER BY m.id", occurrence_columns, occurrence)
    excluded_count = _export_rows(db, output, "content_excluded", query + " WHERE m.excluded=1 ORDER BY m.id", occurrence_columns, occurrence)
    cell_columns = ["id", "table_path", "source_row", "column_name", "field_scope", "characters", "scanned_characters", "text_hmac_sha256", "status", "reason", "observation_scope", "human_review_status"]
    unknown_count = sum(cell_counts.values()) + db.execute("SELECT COALESCE(SUM(end_row-start_row+1),0) FROM review_ranges").fetchone()[0]
    cell_columns += ["record_kind", "start_row", "end_row", "row_count"]
    review_query = """SELECT id,table_path,source_row,column_name,field_scope,characters,scanned_characters,text_hmac_sha256,status,'cell' record_kind,source_row start_row,source_row end_row,1 row_count FROM cells
        UNION ALL SELECT id,table_path,NULL,column_name,field_scope,characters,characters,NULL,'unclassified_text','source_row_range',start_row,end_row,end_row-start_row+1 FROM review_ranges"""
    review_records = _export_rows(db, output, "content_unknown_type_review_queue", review_query, cell_columns,
        lambda row: {**dict(row), **SCOPE, "reason": "text_semantics_and_sensitive_type_completeness_unresolved"})
    labels = {(row[0], row[1]): (row[2], row[3]) for row in db.execute("SELECT category,subtype,COUNT(*),COUNT(DISTINCT cell_id) FROM matches WHERE excluded=0 AND category IS NOT NULL GROUP BY category,subtype")}
    categories = {row[0]: (row[1], row[2]) for row in db.execute("SELECT category,COUNT(*),COUNT(DISTINCT cell_id) FROM matches WHERE excluded=0 AND category IS NOT NULL GROUP BY category")}
    evidence = {}
    for category, subtype, status, count in db.execute("SELECT category,subtype,json_extract(details,'$.candidate_status'),COUNT(*) FROM matches WHERE excluded=0 GROUP BY category,subtype,3"):
        evidence.setdefault((category, subtype), Counter())[status] = count
    summary = []
    for category in taxonomy_catalog()["categories"]:
        count, cells = categories.get(category["category"], (0, 0))
        category_evidence = Counter()
        for (parent, subtype), values in evidence.items():
            if parent == category["category"]: category_evidence.update(values)
        summary.append({"summary_level": "category", "category": category["category"], "subtype": None, "label": category["label"],
                        "occurrence_count": count, "distinct_cell_count": cells, "cell_denominator": unknown_count,
                        "evidence_status_counts": dict(category_evidence), **SCOPE})
        for subtype in category["subtypes"]:
            key = category["category"], subtype["subtype"]
            count, cells = labels.get(key, (0, 0))
            summary.append({"summary_level": "subtype", "category": key[0], "subtype": key[1], "label": subtype["label"], "occurrence_count": count, "distinct_cell_count": cells, "cell_denominator": unknown_count, "evidence_status_counts": dict(evidence.get(key, {})), **SCOPE})
    atomic_write(output / "content_type_summary.json", canonical({"taxonomy_version": TAXONOMY_VERSION, "occurrence_unit": "source cell + span + rule + type; not unique values or people", "summary": summary, **SCOPE}) + "\n")
    with (output / "content_type_summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summary[0])); writer.writeheader()
        writer.writerows({key: csv_cell(value) for key, value in row.items()} for row in summary)
    totals = Counter()
    for table in tables:
        totals.update(table["stats"])
    complete = all(t["status"] == "complete" for t in tables)
    coverage = {"status": "complete_with_semantic_gaps" if complete else "partial", "all_selected_text_rows_visited": complete,
                "all_available_text_characters_scanned": complete and not totals.get("truncated_cells", 0),
                "dataset": manifest["dataset"], "source_manifest_sha256": manifest["source_manifest_sha256"],
                "source_rows": sum(t["rows"] for t in manifest["tables"]), "processed_rows": sum(t["next_row"] for t in tables),
                "distinct_rows_decoded": totals.get("rows_decoded", 0),
                "character_count_semantics": "characters_scanned counts the prefix passed to rules; a match cap can stop rule evaluation, so truncated cells are not complete scans",
                "tables": tables, "cell_status_counts": dict(cell_counts), "counts": dict(totals),
                "candidate_occurrences": candidate_count, "excluded_occurrences": excluded_count,
                "unknown_type_review_cells": unknown_count, "unknown_type_review_export_records": review_records, "observed_subtypes": len(labels),
                "non_text_columns": [{"table": t["table"], **f} for t in manifest["tables"] for f in t["columns"] if not f["selected"]],
                "limitations": ["Finite text rules cannot establish all semantic sensitive types.",
                    "Patterns identify unverified value shapes or named-value hints; no credential validity or disclosure is checked.",
                    "Non-text columns and text beyond recorded character/match limits remain coverage gaps.",
                    "Each nonempty text cell remains reviewable; consecutive no-match cells use exact source-row ranges to avoid duplicating millions of records.",
                    "PR/chat/patch occurrences are not application-log sinks or PyDriller history evidence.",
                    "Source rows and repeated text are retained as separate observations; counts are not people or unique secrets."],
                "detector": detector_catalog(), "exit_code": 2, **SCOPE}
    atomic_write(output / "content_coverage.json", canonical(coverage) + "\n")
    return coverage


def scan_content(import_dir, output_dir, *, resume=False, dry_run=False, batch_size=64,
                 max_seconds=None, max_source_chars=1024 * 1024, max_matches=1000):
    from .content_types import MAX_SOURCE_CHARS, classify_text
    import pyarrow
    import pyarrow.parquet as pq
    if batch_size <= 0 or max_source_chars <= 0 or max_matches <= 0 or (max_seconds is not None and max_seconds <= 0):
        raise ValueError("Content scan budgets must be positive")
    if max_source_chars > MAX_SOURCE_CHARS:
        raise ValueError("Content character limit exceeds the classifier bound")
    started = time.monotonic()
    source_import, output = Path(import_dir).resolve(), Path(output_dir).resolve()
    if output == source_import or output.is_relative_to(source_import):
        raise ValueError("Content output must be separate from the frozen import")
    dataset, manifest_sha, tables = _inventory(source_import)
    if any(output == Path(t["absolute_path"]).parent or output.is_relative_to(Path(t["absolute_path"]).parent) for t in tables):
        raise ValueError("Content output must be separate from frozen source tables")
    fingerprint = {"dataset": dataset, "source_import": str(source_import), "source_manifest_sha256": manifest_sha,
                   "inputs": [{k: t[k] for k in ("path", "sha256", "bytes")} for t in tables],
                   "source_sha256": {name: _digest(Path(__file__).with_name(name)) for name in ("content_scan.py", "content_types.py", "taxonomy.py", "storage.py")},
                   "pyarrow_version": pyarrow.__version__, "max_source_chars": max_source_chars, "max_matches": max_matches}
    if dry_run:
        return {"status": "dry_run", "dataset": dataset, "tables": tables, "source_manifest_sha256": manifest_sha,
                "source_rows": sum(t["rows"] for t in tables), "files_written": False, "network_accessed": False,
                "source_values_decoded": False, **SCOPE, "exit_code": 0}
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (output / ".content.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Content scan already has an active writer") from None
        manifest_path = output / "manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            if not resume or manifest["fingerprint"] != fingerprint:
                raise ValueError("Content resume requires identical frozen sources, classifier and limits")
            if not (output / ".fingerprint-key").is_file():
                raise ValueError("Content fingerprint key is missing")
        else:
            if any(p.name not in {".content.lock", ".fingerprint-key"} for p in output.iterdir()):
                raise ValueError("Content output directory is not empty")
            manifest = {"fingerprint": fingerprint, "dataset": dataset, "tables": tables,
                        "source_manifest_sha256": manifest_sha, "source_import": str(source_import), **SCOPE}
            if not (output / ".fingerprint-key").exists():
                fd = os.open(output / ".fingerprint-key", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as stream: stream.write(secrets.token_bytes(32))
            manifest["fingerprint_key_sha256"] = hashlib.sha256((output / ".fingerprint-key").read_bytes()).hexdigest()
            atomic_write(manifest_path, canonical(manifest) + "\n")
        key = (output / ".fingerprint-key").read_bytes()
        if len(key) != 32:
            raise ValueError("Invalid content fingerprint key")
        if hashlib.sha256(key).hexdigest() != manifest.get("fingerprint_key_sha256"):
            raise ValueError("Content fingerprint key changed")
        db = sqlite3.connect(output / "content.sqlite")
        os.chmod(output / "content.sqlite", 0o600); db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE IF NOT EXISTS tables(path TEXT PRIMARY KEY,expected_rows INTEGER,next_row INTEGER DEFAULT 0,status TEXT DEFAULT 'pending',stats TEXT DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS cells(id TEXT PRIMARY KEY,table_path TEXT,source_row INTEGER,column_name TEXT,field_scope TEXT,characters INTEGER,scanned_characters INTEGER,text_hmac_sha256 TEXT,status TEXT);
            CREATE TABLE IF NOT EXISTS matches(id TEXT PRIMARY KEY,cell_id TEXT,category TEXT,subtype TEXT,excluded INTEGER,details TEXT);
            CREATE INDEX IF NOT EXISTS matches_cell ON matches(cell_id);
            CREATE INDEX IF NOT EXISTS matches_type ON matches(category,subtype);
            CREATE TABLE IF NOT EXISTS review_ranges(id TEXT PRIMARY KEY,table_path TEXT,column_name TEXT,field_scope TEXT,start_row INTEGER,end_row INTEGER,characters INTEGER);
            CREATE INDEX IF NOT EXISTS range_tail ON review_ranges(table_path,column_name,end_row);
        """)
        stop_reason = None
        try:
            for table in tables:
                db.execute("INSERT OR IGNORE INTO tables(path,expected_rows) VALUES(?,?)", (table["path"], table["rows"]))
            db.commit()
            for table in tables:
                progress = db.execute("SELECT * FROM tables WHERE path=?", (table["path"],)).fetchone()
                if progress["status"] == "complete": continue
                columns = [f for f in table["columns"] if f["selected"]]
                stats = Counter(json.loads(progress["stats"])); next_row = progress["next_row"]
                path = Path(table["absolute_path"])
                parquet = pq.ParquetFile(path)
                if not columns or table["rows"] == 0:
                    if not columns: stats["rows_without_text_columns"] = table["rows"]
                    with db:
                        db.execute("UPDATE tables SET next_row=expected_rows,status='complete',stats=? WHERE path=?", (canonical(stats), table["path"]))
                    continue
                open_ranges = {}
                for field in columns:
                    last = db.execute("SELECT * FROM review_ranges WHERE table_path=? AND column_name=? ORDER BY end_row DESC LIMIT 1", (table["path"], field["column"])).fetchone()
                    if last: open_ranges[field["column"]] = dict(last)
                group_start = 0; stop = False
                for group in range(parquet.metadata.num_row_groups):
                    group_rows = parquet.metadata.row_group(group).num_rows
                    if group_start + group_rows <= next_row:
                        group_start += group_rows; continue
                    row_index = group_start
                    for batch in parquet.iter_batches(batch_size=batch_size, row_groups=[group], columns=[f["column"] for f in columns]):
                        with db:
                            for raw in batch.to_pylist():
                                row_index += 1
                                if row_index <= next_row: continue
                                if (max_seconds and time.monotonic() - started >= max_seconds) or shutil.disk_usage(output).free < 2 * 1024**3:
                                    stop_reason = "time_budget" if max_seconds and time.monotonic() - started >= max_seconds else "disk_budget"
                                    stop = True; break
                                stats["rows_decoded"] += 1
                                for field in columns:
                                    value = raw[field["column"]]
                                    stats["text_cells_visited"] += 1
                                    if value is None:
                                        stats["null_cells"] += 1; continue
                                    if not value.strip():
                                        stats["empty_cells"] += 1; continue
                                    # ponytail: one bounded cell; tails need a later chunked scanner, not a silent completeness claim.
                                    text = value[:max_source_chars]
                                    detected = classify_text(text, max_matches=max_matches)
                                    limited = len(value) > len(text) or detected["truncated"]
                                    status = "truncated" if limited else "scanned_with_semantic_gaps"
                                    if not detected["matches"] and not limited:
                                        previous = open_ranges.get(field["column"])
                                        if previous and previous["end_row"] == row_index - 1:
                                            previous["end_row"] = row_index
                                            previous["characters"] += len(value)
                                        else:
                                            cid = stable_id("content-cell", manifest_sha, table["path"], row_index, field["column"])
                                            previous = {"id": cid, "table_path": table["path"], "column_name": field["column"], "field_scope": field["field_scope"], "start_row": row_index, "end_row": row_index, "characters": len(value)}
                                            open_ranges[field["column"]] = previous
                                        db.execute("INSERT OR REPLACE INTO review_ranges VALUES(?,?,?,?,?,?,?)", tuple(previous[k] for k in ("id", "table_path", "column_name", "field_scope", "start_row", "end_row", "characters")))
                                    else:
                                        cid = stable_id("content-cell", manifest_sha, table["path"], row_index, field["column"])
                                        digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
                                        db.execute("INSERT INTO cells VALUES(?,?,?,?,?,?,?,?,?)", (cid, table["path"], row_index, field["column"], field["field_scope"], len(value), len(text), digest, status))
                                    for match in detected["matches"]:
                                        if set(match) != MATCH_FIELDS:
                                            raise ValueError("Content classifier returned unapproved evidence fields")
                                        if (match["category"], match["subtype"]) not in TYPE_KEYS | {(None, None)}:
                                            raise ValueError("Content classifier returned an unknown taxonomy label")
                                        if not 0 <= match["start"] < match["end"] <= len(text):
                                            raise ValueError("Content classifier returned an invalid source span")
                                        mid = stable_id(cid, match)
                                        excluded = match["value_status"] == "placeholder_or_example"
                                        db.execute("INSERT OR IGNORE INTO matches VALUES(?,?,?,?,?,?)", (mid, cid, match.get("category"), match.get("subtype"), int(excluded), canonical(match)))
                                    stats["nonempty_cells"] += 1
                                    stats["characters_seen"] += len(value); stats["characters_scanned"] += len(text)
                                    stats["truncated_cells"] += int(limited)
                                next_row = row_index
                            db.execute("UPDATE tables SET next_row=?,status=?,stats=? WHERE path=?", (next_row, "complete" if next_row == table["rows"] else "partial", canonical(stats), table["path"]))
                        if stop: break
                    group_start += group_rows
                    if stop: break
                if _stat(path) != tuple(table["source_stat"]):
                    raise ValueError("Frozen source changed during scan; discard this run")
                if stop: break
            result = export_content(db, output, manifest)
            result.update(elapsed_seconds=round(time.monotonic() - started, 3), stop_reason=stop_reason, resumed=resume, network_accessed=False, target_code_executed=False)
            atomic_write(output / "content_coverage.json", canonical(result) + "\n")
            return result
        finally:
            db.close()
