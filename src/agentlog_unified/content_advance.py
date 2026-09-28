"""Versioned gzip advance of a legacy content checkpoint, without rewriting its exports.

The scan loop and public record projection retain the frozen legacy semantics.
This module is the actual new execution engine and is fingerprinted separately.
"""
from __future__ import annotations
from collections import Counter
from contextlib import ExitStack
import csv
import fcntl
import gzip
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import time

from agentlog_unified import content_scan, content_types
from agentlog_unified.content_scan import MATCH_FIELDS, TYPE_KEYS, SCOPE, _inventory, _stat
from agentlog_unified.aidev import _digest
from agentlog_unified.storage import atomic_write, canonical, csv_cell, stable_id
from agentlog_unified.taxonomy import TAXONOMY_VERSION, taxonomy_catalog

ENGINE = "content_advance_v1"
FROZEN_FILES = ("content_scan.py", "content_types.py", "taxonomy.py", "storage.py")
SCHEMA = {
    "tables": ["path", "expected_rows", "next_row", "status", "stats"],
    "cells": ["id", "table_path", "source_row", "column_name", "field_scope", "characters", "scanned_characters", "text_hmac_sha256", "status"],
    "matches": ["id", "cell_id", "category", "subtype", "excluded", "details"],
    "review_ranges": ["id", "table_path", "column_name", "field_scope", "start_row", "end_row", "characters"],
}


def _export_reserve_ratio(output):
    previous = output / 'content_coverage.json'
    retained = sum(p.stat().st_size for p in output.glob('content_*.gz'))
    if previous.exists():
        size = json.loads(previous.read_text()).get('checkpoint_bytes_at_export', 0)
        if size > 0: return max(0.65, retained / size * 1.5), retained
    return 0.65, retained


def _scan_space_low(output, checkpoint, minimum, ratio):
    # Existing gzip/plain snapshots already consume filesystem free bytes.
    # Reserve one entire replacement export in addition; use observed sizes
    # with 50% headroom when larger than the conservative initial heuristic.
    reserve = max(512 * 1024**2, int(checkpoint.stat().st_size * ratio))
    return min(shutil.disk_usage(output).free, shutil.disk_usage(checkpoint.parent).free) < minimum + reserve


def _export_rows(db, output, stem, query, columns, transform=lambda row: dict(row), *, min_free_bytes):
    paths = [output / (stem + suffix + ".gz.tmp") for suffix in (".jsonl", ".csv")]
    count = 0
    if shutil.disk_usage(output).free < min_free_bytes:
        raise OSError("Compressed export disk reserve reached; checkpoint remains resumable")
    with ExitStack() as stack:
        streams = []
        for path in paths:
            raw = stack.enter_context(path.open("wb")); os.chmod(path, 0o600)
            compressed = stack.enter_context(gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6))
            import io
            streams.append(stack.enter_context(io.TextIOWrapper(compressed, encoding="utf-8", newline="")))
        js, cs = streams
        writer = csv.DictWriter(cs, fieldnames=columns); writer.writeheader()
        for raw in db.execute(query):
            if count % 1024 == 0 and shutil.disk_usage(output).free < min_free_bytes:
                raise OSError("Compressed export disk reserve reached; checkpoint remains resumable")
            row = transform(raw)
            js.write(canonical(row) + "\n")
            writer.writerow({key: csv_cell(row.get(key)) for key in columns})
            count += 1
    for path in paths:
        os.replace(path, path.with_suffix(""))
    return count


def export_advanced(db, output, manifest, *, min_free_bytes=1024**3):
    def write_rows(*args, **kwargs):
        return _export_rows(*args, **kwargs, min_free_bytes=min_free_bytes)
    from agentlog_unified.content_types import detector_catalog
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
    candidate_count = write_rows(db, output, "content_type_occurrences", query + " WHERE m.excluded=0 ORDER BY m.id", occurrence_columns, occurrence)
    excluded_count = write_rows(db, output, "content_excluded", query + " WHERE m.excluded=1 ORDER BY m.id", occurrence_columns, occurrence)
    cell_columns = ["id", "table_path", "source_row", "column_name", "field_scope", "characters", "scanned_characters", "text_hmac_sha256", "status", "reason", "observation_scope", "human_review_status"]
    unknown_count = sum(cell_counts.values()) + db.execute("SELECT COALESCE(SUM(end_row-start_row+1),0) FROM review_ranges").fetchone()[0]
    cell_columns += ["record_kind", "start_row", "end_row", "row_count"]
    review_query = """SELECT id,table_path,source_row,column_name,field_scope,characters,scanned_characters,text_hmac_sha256,status,'cell' record_kind,source_row start_row,source_row end_row,1 row_count FROM cells
        UNION ALL SELECT id,table_path,NULL,column_name,field_scope,characters,characters,NULL,'unclassified_text','source_row_range',start_row,end_row,end_row-start_row+1 FROM review_ranges"""
    review_records = write_rows(db, output, "content_unknown_type_review_queue", review_query, cell_columns,
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

def _advance_rows(db, tables, manifest_sha, key, output, checkpoint, *, batch_size,
                  max_seconds, max_rows, started, max_source_chars, max_matches, min_free_bytes):
    if max_rows == 0:
        return "source_row_budget"
    import pyarrow.parquet as pq
    classify_text = content_types.classify_text
    stop_reason = None
    rows_this_run = 0
    export_ratio, _ = _export_reserve_ratio(output)
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
                        if ((max_seconds and time.monotonic() - started >= max_seconds) or
                            (max_rows is not None and rows_this_run >= max_rows) or
                            _scan_space_low(output, checkpoint, min_free_bytes, export_ratio)):
                            stop_reason = ("time_budget" if max_seconds and time.monotonic() - started >= max_seconds
                                           else "source_row_budget" if max_rows is not None and rows_this_run >= max_rows else "disk_budget")
                            stop = True; break
                        stats["rows_decoded"] += 1
                        rows_this_run += 1
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
    return stop_reason


def _cursors(db):
    return {row['path']: row['next_row'] for row in db.execute('SELECT path,next_row FROM tables ORDER BY path')}


def advance_content(parent_run, output_dir, *, resume=False, dry_run=False, batch_size=64,
                    max_seconds=None, max_rows=None, min_free_bytes=1024**3):
    """Advance the existing DB; leave every legacy manifest/export byte unchanged."""
    import pyarrow
    if (type(batch_size) is not int or batch_size <= 0 or type(min_free_bytes) is not int or min_free_bytes <= 0
        or (max_seconds is not None and (type(max_seconds) not in (int, float) or not math.isfinite(max_seconds) or max_seconds <= 0))
        or (max_rows is not None and (type(max_rows) is not int or max_rows < 0))):
        raise ValueError('Time, disk and batch budgets must be positive; max_rows may be zero')
    started = time.monotonic()
    parent, output = Path(parent_run).resolve(), Path(output_dir).resolve()
    parent_manifest_path = parent / 'manifest.json'
    checkpoint = parent / 'content.sqlite'
    lock_path = parent / '.content.lock'
    if output == parent or output.is_relative_to(parent) or parent.is_relative_to(output):
        raise ValueError('Advance output must be independent of the parent')
    if not checkpoint.is_file() or checkpoint.is_symlink():
        raise ValueError('A regular existing parent checkpoint is required')
    with ExitStack() as stack:
        parent_lock = stack.enter_context(lock_path.open('rb'))
        try: fcntl.flock(parent_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('Parent content checkpoint has an active reader or writer') from None
        old = json.loads(parent_manifest_path.read_text())
        old_fp = old['fingerprint']
        dataset, manifest_sha, tables = _inventory(Path(old['source_import']))
        protected = [Path(old['source_import']).resolve()] + [Path(t['absolute_path']).parent for t in tables]
        if any(output == p or output.is_relative_to(p) or p.is_relative_to(output) for p in protected):
            raise ValueError('Advance output overlaps frozen inputs')
        frozen_hashes = {name: _digest(Path(content_scan.__file__).with_name(name)) for name in FROZEN_FILES}
        expected = {'dataset': dataset, 'source_import': old['source_import'], 'source_manifest_sha256': manifest_sha,
                    'inputs': [{k: t[k] for k in ('path', 'sha256', 'bytes')} for t in tables],
                    'source_sha256': frozen_hashes, 'pyarrow_version': pyarrow.__version__,
                    'max_source_chars': old_fp['max_source_chars'], 'max_matches': old_fp['max_matches']}
        table_keys = ('path', 'sha256', 'bytes', 'table', 'rows', 'columns', 'absolute_path')
        if [{k: t[k] for k in table_keys} for t in tables] != [{k: t[k] for k in table_keys} for t in old['tables']]:
            raise ValueError('Frozen table selection or field semantics changed')
        if expected != old_fp or old['source_manifest_sha256'] != manifest_sha:
            raise ValueError('Legacy sources, classifier, limits or runtime changed')
        if not 0 < old_fp['max_source_chars'] <= content_types.MAX_SOURCE_CHARS or old_fp['max_matches'] <= 0:
            raise ValueError('Invalid frozen classification limits')
        key = (parent / '.fingerprint-key').read_bytes()
        key_sha = hashlib.sha256(key).hexdigest()
        if len(key) != 32 or key_sha != old['fingerprint_key_sha256']:
            raise ValueError('Parent fingerprint key changed')
        stat = checkpoint.stat()
        provenance = {'parent_run': str(parent), 'parent_manifest_sha256': _digest(parent_manifest_path),
                      'checkpoint_path': str(checkpoint), 'checkpoint_lock_path': str(lock_path),
                      'checkpoint_identity': {'device': stat.st_dev, 'inode': stat.st_ino}}
        fingerprint = {'engine': ENGINE, **provenance, 'source_manifest_sha256': manifest_sha,
                       'frozen_source_sha256': frozen_hashes,
                       'inventory_dependency_sha256': {name: _digest(Path(content_scan.__file__).with_name(name)) for name in ('aidev.py', 'swechat.py')},
                       'implementation_sha256': {Path(__file__).name: _digest(Path(__file__))},
                       'fingerprint_key_sha256': key_sha, 'pyarrow_version': pyarrow.__version__,
                       'max_source_chars': old_fp['max_source_chars'], 'max_matches': old_fp['max_matches'],
                       'export_backend': 'gzip_jsonl_csv_v1', 'minimum_free_bytes': min_free_bytes}
        db = sqlite3.connect(checkpoint.as_uri() + '?mode=rw', uri=True)
        stack.callback(db.close); db.row_factory = sqlite3.Row
        for table, fields in SCHEMA.items():
            if [r['name'] for r in db.execute('PRAGMA table_info(' + table + ')')] != fields:
                raise ValueError('Parent checkpoint schema is not compatible')
        progress = {r['path']: dict(r) for r in db.execute('SELECT * FROM tables')}
        if set(progress) != {t['path'] for t in tables} or any(
            progress[t['path']]['expected_rows'] != t['rows'] or
            not 0 <= progress[t['path']]['next_row'] <= t['rows'] for t in tables):
            raise ValueError('Parent checkpoint row denominators are inconsistent')
        before = _cursors(db)
        if dry_run:
            return {'engine': ENGINE, **provenance, 'status': 'dry_run', 'before_cursors': before,
                    'source_rows': sum(t['rows'] for t in tables), 'processed_rows': sum(before.values()),
                    'free_bytes': shutil.disk_usage(parent).free, 'files_written': False,
                    'source_values_decoded': False, 'network_accessed': False, 'target_code_executed': False, 'exit_code': 0, **SCOPE}
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        output_lock = stack.enter_context((output / '.content.lock').open('a'))
        os.chmod(output / '.content.lock', 0o600)
        try: fcntl.flock(output_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('Advance output has an active reader or writer') from None
        manifest_path = output / 'manifest.json'
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            if not resume or manifest['fingerprint'] != fingerprint:
                raise ValueError('Advance resume requires the same parent checkpoint, implementation and sources')
            if hashlib.sha256((output / '.fingerprint-key').read_bytes()).hexdigest() != key_sha:
                raise ValueError('Advance fingerprint key changed')
            if any(before.get(p, -1) < n for p, n in manifest['initial_cursors'].items()):
                raise ValueError('Parent checkpoint regressed before the original advance boundary')
            previous = output / 'content_coverage.json'
            if previous.exists():
                previous = json.loads(previous.read_text())
                if any(before.get(p, -1) < n for p, n in previous.get('after_cursors', {}).items()):
                    raise ValueError('Parent checkpoint regressed after its last export')
        else:
            if any(p.name != '.content.lock' for p in output.iterdir()):
                raise ValueError('Advance output directory is not empty')
            manifest = {'engine': ENGINE, 'fingerprint': fingerprint, **provenance,
                        'parent_shared_checkpoint': provenance, 'dataset': dataset, 'tables': tables,
                        'source_import': old['source_import'], 'source_manifest_sha256': manifest_sha,
                        'fingerprint_key_sha256': key_sha, 'initial_cursors': before,
                        'legacy_exports_are_previous_snapshot': True,
                        'export_files': {stem: {'jsonl': stem + '.jsonl.gz', 'csv': stem + '.csv.gz'} for stem in
                            ('content_type_occurrences', 'content_excluded', 'content_unknown_type_review_queue')}, **SCOPE}
            fd = os.open(output / '.fingerprint-key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream: stream.write(key)
            atomic_write(manifest_path, canonical(manifest) + '\n')
        state_path = output / 'advance_state.json'
        atomic_write(state_path, canonical({'status': 'in_progress', 'engine': ENGINE, 'before_cursors': before}) + '\n')
        try:
            export_ratio_before, retained_before = _export_reserve_ratio(output)
            stop_reason = _advance_rows(db, tables, manifest_sha, key, output, checkpoint, batch_size=batch_size,
                max_seconds=max_seconds, max_rows=max_rows, started=started, max_source_chars=old_fp['max_source_chars'],
                max_matches=old_fp['max_matches'], min_free_bytes=min_free_bytes)
            after = _cursors(db)
            result = export_advanced(db, output, manifest, min_free_bytes=min_free_bytes)
            result.update(engine=ENGINE, **provenance, parent_shared_checkpoint=provenance,
                before_cursors=before, after_cursors=after, export_backend='gzip_jsonl_csv_v1',
                legacy_exports_are_previous_snapshot=True, checkpoint_bytes_at_export=checkpoint.stat().st_size,
                execution_budget={'max_seconds': max_seconds, 'max_rows': max_rows, 'batch_size': batch_size, 'max_rows_unit': 'new decoded source rows'}, elapsed_seconds=round(time.monotonic()-started,3),
                stop_reason=stop_reason, resumed=resume, network_accessed=False, target_code_executed=False,
                disk_guard={'minimum_free_bytes': min_free_bytes, 'scan_export_reserve_estimate': 'max(512 MiB, max(0.65, last gzip bytes / last checkpoint bytes * 1.5) * current checkpoint bytes); heuristic, not a bound; existing old exports remain allocated',
                            'retained_gzip_bytes_before_export': retained_before, 'export_reserve_ratio': export_ratio_before,
                            'free_bytes': shutil.disk_usage(output).free})
            atomic_write(output / 'content_coverage.json', canonical(result) + '\n')
            atomic_write(state_path, canonical({'status': 'export_complete', 'engine': ENGINE,
                'before_cursors': before, 'after_cursors': after, 'coverage_sha256': _digest(output/'content_coverage.json')}) + '\n')
            return result
        except BaseException as exc:
            atomic_write(state_path, canonical({'status': 'interrupted', 'engine': ENGINE,
                'error_type': type(exc).__name__, 'before_cursors': before, 'checkpoint_cursors': _cursors(db),
                'exports_may_be_stale': True}) + '\n')
            raise
