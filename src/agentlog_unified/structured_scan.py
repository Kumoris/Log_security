"""Resumable, separate JSON evidence over frozen AIDev text cells."""
from __future__ import annotations

from collections import Counter
import fcntl
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import time

import pyarrow
import pyarrow.parquet as pq

from . import content_advance, content_scan, structured_types
from .aidev import _digest
from .storage import atomic_write, canonical, stable_id
from .taxonomy import TAXONOMY_VERSION, taxonomy_catalog

VERSION = "structured-scan-1"
SCOPE = {"observation_scope": "dataset_structured_text", "human_review_status": "pending",
         "runtime_confirmed": False, "new_type_status": "not_established",
         "application_log_evidence": False, "full_dataset_coverage_claim": False}
SOURCE_FILES = ("structured_scan.py", "structured_types.py", "content_advance.py", "content_scan.py",
                "content_types.py", "taxonomy.py", "storage.py", "aidev.py", "swechat.py")


def _sources():
    return {name: _digest(Path(__file__).with_name(name)) for name in SOURCE_FILES}


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _node_path(value):
    return isinstance(value, list) and all(_integer(n, -1) for n in value)


def _validate(result, characters, limits):
    """Only finite labels and numeric coordinates may reach SQLite or exports."""
    valid = isinstance(result, dict) and set(result) == {"matches", "documents", "gaps", "counts", "status"}
    if not valid or result["status"] not in structured_types.STATUSES:
        raise ValueError("Structured parser returned unapproved evidence")
    if not isinstance(result["counts"], dict) or not set(result["counts"]) <= structured_types.COUNT_FIELDS or not all(_integer(n) for n in result["counts"].values()):
        raise ValueError("Structured parser returned unapproved counters")
    if any(not isinstance(result[k], list) for k in ("documents", "matches", "gaps")):
        raise ValueError("Structured parser returned invalid collections")
    documents = result["documents"]
    if len(documents) > limits["max_documents"] or len(result["matches"]) > limits["max_matches"]:
        raise ValueError("Structured parser exceeded output budgets")
    for index, doc in enumerate(documents):
        if (not isinstance(doc, dict) or set(doc) != structured_types.DOCUMENT_FIELDS
                or not _integer(doc["document_index"]) or doc["document_index"] != index
                or doc["format"] not in {"whole_json", "fenced_json"}
                or doc["status"] not in structured_types.DOCUMENT_STATUSES
                or not _integer(doc["source_start"]) or not _integer(doc["source_end"])
                or not 0 <= doc["source_start"] <= doc["source_end"] <= characters):
            raise ValueError("Structured parser returned invalid document coordinates")
    for item in result["matches"]:
        if (not isinstance(item, dict) or set(item) != structured_types.MATCH_FIELDS
                or not _integer(item["document_index"]) or item["document_index"] >= len(documents)
                or not _node_path(item["node_path"])
                or (item["category"], item["subtype"]) not in content_scan.TYPE_KEYS | {(None, None)}
                or any(item[k] not in values for k, values in structured_types.MATCH_LABELS.items())):
            raise ValueError("Structured parser returned unapproved match fields")
        start, end = item["decoded_start"], item["decoded_end"]
        if not (start is None and end is None) and not (_integer(start) and _integer(end) and start <= end <= limits["max_source_chars"]):
            raise ValueError("Structured parser returned invalid decoded coordinates")
    for gap in result["gaps"]:
        if (not isinstance(gap, dict) or set(gap) != structured_types.GAP_FIELDS
                or not _node_path(gap["node_path"]) or gap["reason"] not in structured_types.GAP_REASONS
                or not (gap["document_index"] is None or _integer(gap["document_index"]) and gap["document_index"] < len(documents))):
            raise ValueError("Structured parser returned unapproved gap fields")


def _export(db, output, manifest, min_free_bytes):
    def write(stem, query, columns, transform=lambda r: dict(r)):
        return content_advance._export_rows(db, output, stem, query, columns,
            lambda row: {**transform(row), **SCOPE}, min_free_bytes=min_free_bytes)
    locations = ["id", "table_path", "source_row", "column_name"]
    document_columns = locations + ["document_index", "source_start", "source_end", "format", "status", *SCOPE]
    documents = write("structured_documents", "SELECT * FROM documents ORDER BY id", document_columns)
    match_columns = ["id", "document_id", "table_path", "source_row", "column_name", "source_start", "source_end", "format",
                     *sorted(structured_types.MATCH_FIELDS), *SCOPE]
    query = """SELECT m.id,m.document_id,m.details,d.table_path,d.source_row,d.column_name,d.source_start,d.source_end,d.format
               FROM matches m JOIN documents d ON d.id=m.document_id"""
    def match(row):
        result = dict(row); detail = json.loads(result.pop("details")); return {**result, **detail}
    candidates = write("structured_type_occurrences", query + " WHERE m.excluded=0 ORDER BY m.id", match_columns, match)
    excluded = write("structured_excluded", query + " WHERE m.excluded=1 ORDER BY m.id", match_columns, match)
    def gap(row):
        result = dict(row); result["node_path"] = json.loads(result["node_path"]); return result
    gaps = write("structured_data_gaps", "SELECT * FROM gaps ORDER BY id",
                 locations + ["document_id", "document_index", "node_path", "reason", *SCOPE], gap)
    review = write("structured_unknown_type_review_queue", "SELECT *,end_row-start_row+1 row_count FROM review_ranges ORDER BY table_path,column_name,start_row",
                   ["id", "table_path", "column_name", "start_row", "end_row", "row_count", "status", *SCOPE])
    tables = [dict(r) for r in db.execute("SELECT * FROM progress ORDER BY table_path")]
    counts = Counter()
    for table in tables:
        table["stats"] = json.loads(table["stats"]); counts.update(table["stats"])
    labels = {(r[0], r[1]): r[2] for r in db.execute("SELECT category,subtype,COUNT(*) FROM matches WHERE excluded=0 GROUP BY category,subtype")}
    summary = [{"category": category["category"], "subtype": subtype["subtype"], "label": subtype["label"],
                "candidate_occurrences": labels.get((category["category"], subtype["subtype"]), 0), **SCOPE}
               for category in taxonomy_catalog()["categories"] for subtype in category["subtypes"]]
    summary.append({"category": None, "subtype": None, "label": "Unclassified named JSON values", "candidate_occurrences": labels.get((None, None), 0), **SCOPE})
    # Reuse the gzip row writer with a tiny, in-memory result table.
    db.execute("CREATE TEMP TABLE IF NOT EXISTS type_summary(category,subtype,label,candidate_occurrences)")
    db.execute("DELETE FROM type_summary")
    db.executemany("INSERT INTO type_summary VALUES(?,?,?,?)", [(r["category"], r["subtype"], r["label"], r["candidate_occurrences"]) for r in summary])
    write("structured_type_summary", "SELECT * FROM type_summary ORDER BY category,subtype", ["category", "subtype", "label", "candidate_occurrences", *SCOPE])
    done = all(t["status"] == "complete" for t in tables)
    result = {"status": "complete_with_semantic_gaps" if done else "partial", "all_source_rows_visited": done,
        "dataset": manifest["dataset"], "source_manifest_sha256": manifest["source_manifest_sha256"],
        "source_rows": sum(t["rows"] for t in manifest["tables"]), "processed_rows": sum(t["next_row"] for t in tables),
        "row_count_semantics": "Committed source-row processing; Arrow batch materialization and skipped prefixes on resume can decode extra rows without reclassifying them.",
        "tables": tables, "counts": dict(counts), "documents": documents, "candidate_occurrences": candidates,
        "document_status_counts": dict(db.execute("SELECT status,COUNT(*) FROM documents GROUP BY status").fetchall()),
        "candidate_status_counts": dict(db.execute("SELECT json_extract(details,'$.candidate_status'),COUNT(*) FROM matches WHERE excluded=0 GROUP BY 1").fetchall()),
        "excluded_occurrences": excluded, "data_gap_records": gaps, "unknown_review_range_records": review,
        "unknown_review_source_cells": db.execute("SELECT COALESCE(SUM(end_row-start_row+1),0) FROM review_ranges").fetchone()[0],
        "observed_controlled_labels": sum(r["candidate_occurrences"] > 0 for r in summary if r["category"] is not None),
        "count_unit": "Source cell + document + ordinal node path + decoded span + complete finite match details; overlaps earlier plain-text results, not additive.",
        "coordinates": "source_start/end delimit an original-cell document envelope; decoded_start/end are leaf-local, not original-text offsets.",
        "limits": manifest["fingerprint"]["limits"], "taxonomy_version": TAXONOMY_VERSION,
        "limitations": ["Only whole JSON and explicit JSON fences plus bounded JSON-string decoding are recognized.",
            "All nonempty cells remain in the semantic review queue, including those without a supported structure.",
            "Named field hints and literal shapes do not establish ownership, sensitivity, valid credentials, or disclosure.",
            "Node, document, depth, text and match limits are explicit gaps; arbitrary encodings and general program semantics remain unresolved.",
            "No source values, dynamic JSON keys or value hashes are exported; ordinal member paths retain duplicate-key evidence."],
        "exit_code": 2, **SCOPE}
    return result


def scan_structured(import_dir, output_dir, *, resume=False, dry_run=False, batch_size=32,
                    max_seconds=None, max_rows=None, max_source_chars=1048576, max_documents=128,
                    max_depth=32, max_nodes=10000, max_decode_layers=2, max_matches=1000,
                    min_free_bytes=2 * 1024**3):
    limits = dict(max_source_chars=max_source_chars, max_documents=max_documents, max_depth=max_depth,
                  max_nodes=max_nodes, max_decode_layers=max_decode_layers, max_matches=max_matches)
    if (any(not _integer(v, 1) for k, v in limits.items() if k != "max_decode_layers")
            or not _integer(max_decode_layers) or not _integer(batch_size, 1) or batch_size > 128
            or max_source_chars > structured_types.MAX_SOURCE_CHARS
            or max_decode_layers > structured_types.MAX_DECODE_LAYERS or max_depth > structured_types.MAX_DEPTH
            or not _integer(min_free_bytes) or max_rows is not None and not _integer(max_rows)
            or max_seconds is not None and (type(max_seconds) not in (int, float) or not math.isfinite(max_seconds) or max_seconds <= 0)):
        raise ValueError("Structured scan limits must be finite and nonnegative, with positive scan budgets")
    started = time.monotonic(); imported, output = Path(import_dir).resolve(), Path(output_dir).resolve()
    dataset, manifest_sha, tables = content_scan._inventory(imported)
    if dataset != "aidev": raise ValueError("Structured scan currently requires a frozen AIDev import")
    if output == imported or output.is_relative_to(imported) or any(output == Path(t["absolute_path"]).parent or output.is_relative_to(Path(t["absolute_path"]).parent) for t in tables):
        raise ValueError("Structured output must be separate from frozen sources and imports")
    fingerprint = {"version": VERSION, "source_import": str(imported), "source_manifest_sha256": manifest_sha,
        "inputs": [{k: t[k] for k in ("path", "sha256", "bytes")} for t in tables], "source_sha256": _sources(),
        "limits": limits, "pyarrow_version": pyarrow.__version__, "taxonomy_version": TAXONOMY_VERSION}
    if dry_run:
        return {"status": "dry_run", "dataset": dataset, "source_rows": sum(t["rows"] for t in tables),
            "tables": tables, "fingerprint": fingerprint, "source_values_decoded": False, "files_written": False,
            "network_accessed": False, "target_code_executed": False, "exit_code": 0, **SCOPE}
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (output / ".structured.lock").open("a") as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError("Structured scan already has an active writer") from None
        mp, state_path = output / "manifest.json", output / "export_state.json"
        if mp.exists():
            manifest = json.loads(mp.read_text())
            if not resume or manifest["fingerprint"] != fingerprint:
                raise ValueError("Structured resume requires identical frozen inputs, implementation and limits")
        else:
            if any(p.name != ".structured.lock" for p in output.iterdir()): raise ValueError("Structured output directory is not empty")
            manifest = {"dataset": dataset, "source_manifest_sha256": manifest_sha, "tables": tables, "fingerprint": fingerprint, **SCOPE}
            atomic_write(mp, canonical(manifest) + "\n")
        atomic_write(state_path, canonical({"status": "stale_until_export_complete", "fingerprint": fingerprint}) + "\n")
        db = sqlite3.connect(output / "structured.sqlite"); os.chmod(output / "structured.sqlite", 0o600); db.row_factory = sqlite3.Row
        db.executescript("""CREATE TABLE IF NOT EXISTS progress(table_path TEXT PRIMARY KEY,expected_rows INTEGER,next_row INTEGER DEFAULT 0,status TEXT DEFAULT 'pending',stats TEXT DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY,table_path TEXT,source_row INTEGER,column_name TEXT,document_index INTEGER,source_start INTEGER,source_end INTEGER,format TEXT,status TEXT);
            CREATE TABLE IF NOT EXISTS matches(id TEXT PRIMARY KEY,document_id TEXT,category TEXT,subtype TEXT,excluded INTEGER,details TEXT);
            CREATE INDEX IF NOT EXISTS match_document ON matches(document_id);
            CREATE TABLE IF NOT EXISTS gaps(id TEXT PRIMARY KEY,table_path TEXT,source_row INTEGER,column_name TEXT,document_id TEXT,document_index INTEGER,node_path TEXT,reason TEXT);
            CREATE TABLE IF NOT EXISTS review_ranges(id TEXT PRIMARY KEY,table_path TEXT,column_name TEXT,start_row INTEGER,end_row INTEGER,status TEXT);
            CREATE INDEX IF NOT EXISTS review_tail ON review_ranges(table_path,column_name,end_row);""")
        rows_this_run = 0; stop_reason = None
        try:
            with db:
                db.executemany("INSERT OR IGNORE INTO progress(table_path,expected_rows) VALUES(?,?)", [(t["path"], t["rows"]) for t in tables])
            for table in tables:
                progress = db.execute("SELECT * FROM progress WHERE table_path=?", (table["path"],)).fetchone()
                if progress["status"] == "complete": continue
                if max_rows is not None and rows_this_run >= max_rows: stop_reason = "source_row_budget"; break
                if max_seconds is not None and time.monotonic() - started >= max_seconds: stop_reason = "time_budget"; break
                # ponytail: fixed export headroom; the writer stops safely if a larger export exhausts it.
                if shutil.disk_usage(output).free < min_free_bytes + 512 * 1024**2: stop_reason = "disk_budget"; break
                columns = [f["column"] for f in table["columns"] if f["selected"]]
                stats = Counter(json.loads(progress["stats"])); next_row = progress["next_row"]
                if not columns or not table["rows"]:
                    stats["rows_without_text_columns"] = table["rows"] if not columns else 0
                    with db: db.execute("UPDATE progress SET next_row=expected_rows,status='complete',stats=? WHERE table_path=?", (canonical(stats), table["path"]))
                    continue
                tails = {}
                for column in columns:
                    row = db.execute("SELECT * FROM review_ranges WHERE table_path=? AND column_name=? ORDER BY end_row DESC LIMIT 1", (table["path"], column)).fetchone()
                    if row: tails[column] = dict(row)
                path = Path(table["absolute_path"]); parquet = pq.ParquetFile(path); group_start = 0
                for group in range(parquet.metadata.num_row_groups):
                    group_rows = parquet.metadata.row_group(group).num_rows
                    if group_start + group_rows <= next_row: group_start += group_rows; continue
                    row_number = group_start
                    for batch in parquet.iter_batches(batch_size=batch_size, row_groups=[group], columns=columns, use_threads=False):
                        with db:
                            for raw in batch.to_pylist():
                                row_number += 1
                                if row_number <= next_row: continue
                                if max_seconds is not None and time.monotonic() - started >= max_seconds: stop_reason = "time_budget"
                                elif max_rows is not None and rows_this_run >= max_rows: stop_reason = "source_row_budget"
                                elif shutil.disk_usage(output).free < min_free_bytes + 512 * 1024**2: stop_reason = "disk_budget"
                                if stop_reason: break
                                stats["rows_decoded"] += 1
                                for column in columns:
                                    value = raw[column]; stats["text_cells_visited"] += 1
                                    if value is None: stats["null_cells"] += 1; continue
                                    if not value.strip(): stats["empty_cells"] += 1; continue
                                    stats["nonempty_cells"] += 1; stats["characters_seen"] += len(value)
                                    try: parsed = structured_types.classify_structured(value, **limits)
                                    except Exception: raise ValueError("Structured parser failed; current transaction was not committed") from None
                                    _validate(parsed, len(value), limits)
                                    stats.update({"parser_" + k: v for k, v in parsed["counts"].items() if v})
                                    stats["cells_" + parsed["status"]] += 1
                                    cell_id = stable_id(VERSION, manifest_sha, table["path"], row_number, column)
                                    documents = {}
                                    for doc in parsed["documents"]:
                                        did = stable_id(cell_id, doc["document_index"]); documents[doc["document_index"]] = did
                                        db.execute("INSERT INTO documents VALUES(?,?,?,?,?,?,?,?,?)", (did, table["path"], row_number, column, doc["document_index"], doc["source_start"], doc["source_end"], doc["format"], doc["status"]))
                                    for item in parsed["matches"]:
                                        did = documents[item["document_index"]]; mid = stable_id(did, canonical(item))
                                        db.execute("INSERT OR IGNORE INTO matches VALUES(?,?,?,?,?,?)", (mid, did, item["category"], item["subtype"], int(item["candidate_status"] == "placeholder_or_example"), canonical(item)))
                                    for gap in parsed["gaps"]:
                                        did = documents.get(gap["document_index"]); gid = stable_id(cell_id, canonical(gap))
                                        db.execute("INSERT OR IGNORE INTO gaps VALUES(?,?,?,?,?,?,?,?)", (gid, table["path"], row_number, column, did, gap["document_index"], canonical(gap["node_path"]), gap["reason"]))
                                    tail = tails.get(column)
                                    if tail and tail["end_row"] == row_number - 1 and tail["status"] == parsed["status"]: tail["end_row"] = row_number
                                    else: tail = {"id": cell_id, "table_path": table["path"], "column_name": column, "start_row": row_number, "end_row": row_number, "status": parsed["status"]}; tails[column] = tail
                                    db.execute("INSERT OR REPLACE INTO review_ranges VALUES(?,?,?,?,?,?)", tuple(tail[k] for k in ("id", "table_path", "column_name", "start_row", "end_row", "status")))
                                next_row = row_number; rows_this_run += 1
                            db.execute("UPDATE progress SET next_row=?,status=?,stats=? WHERE table_path=?", (next_row, "complete" if next_row == table["rows"] else "partial", canonical(stats), table["path"]))
                        if stop_reason: break
                    group_start += group_rows
                    if stop_reason: break
                if content_scan._stat(path) != tuple(table["source_stat"]): raise ValueError("Frozen source changed during structured scan")
                if stop_reason: break
            if _digest(imported / "manifest.json") != manifest_sha or any(content_scan._stat(Path(t["absolute_path"])) != tuple(t["source_stat"]) for t in tables):
                raise ValueError("Frozen inputs changed during structured scan")
            if _sources() != fingerprint["source_sha256"]: raise ValueError("Structured implementation changed during scan")
            result = _export(db, output, manifest, min_free_bytes)
            result.update(rows_this_invocation=rows_this_run, stop_reason=stop_reason, resumed=resume,
                          elapsed_seconds=round(time.monotonic() - started, 3), network_accessed=False, target_code_executed=False)
            atomic_write(output / "structured_coverage.json", canonical(result) + "\n")
            outputs = {p.name: {"bytes": p.stat().st_size, "sha256": _digest(p)} for p in output.glob("structured_*.gz")}
            outputs["structured_coverage.json"] = {"sha256": _digest(output / "structured_coverage.json")}
            if (_sources() != fingerprint["source_sha256"] or _digest(imported / "manifest.json") != manifest_sha
                    or any(content_scan._stat(Path(t["absolute_path"])) != tuple(t["source_stat"]) for t in tables)):
                raise ValueError("Frozen inputs or implementation changed during structured export")
            atomic_write(state_path, canonical({"status": "complete", "fingerprint": fingerprint, "outputs": outputs}) + "\n")
            return result
        finally: db.close()
