"""Read-only prefix preservation check; run only after both scans terminate."""
import argparse
from collections import Counter
from contextlib import ExitStack
import datetime
import fcntl
import hashlib
import json
from pathlib import Path
import sqlite3


SCOPE = {"observation_scope": "dataset_text_cells", "runtime_confirmed": False,
         "human_review_status": "pending", "new_type_status": "not_established",
         "full_dataset_coverage_claim": False, "application_log_evidence": False}
REASON = "text_semantics_and_sensitive_type_completeness_unresolved"


def canonical_line(row):
    return (json.dumps(row, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), default=str) + "\n").encode()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_dataset(root, first, baseline):
    output = Path(first["output"])
    coverage_path = Path(baseline["first_coverage_path"])
    old = json.loads(coverage_path.read_text())
    new = json.loads((output / "content_coverage.json").read_text())
    cuts = baseline["source_row_cutoffs"]
    manifest = json.loads((output / "manifest.json").read_text())
    db = sqlite3.connect("file:" + str(output / "content.sqlite") + "?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    cte = "WITH cut(path,n) AS (VALUES " + ",".join("(?,?)" for _ in cuts) + ") "
    params = [v for pair in cuts.items() for v in pair]
    checks = {
        "baseline_verified_before_resume_export": baseline["baseline_proven"],
        "first_coverage_hash_unchanged": digest(coverage_path) == baseline["first_coverage_sha256"],
        "source_manifest_unchanged": manifest["source_manifest_sha256"] == first["source_manifest_sha256"],
        "classifier_files_unchanged": all(
            digest(root / "agentlog_unified/src/agentlog_unified" / name) == value
            for name, value in first["current_classifier_sha256"].items()),
        "dataset_scope_preserved": new["observation_scope"] == "dataset_text_cells",
    }
    comparisons = {}
    query = ("SELECT m.*,c.table_path,c.source_row,c.column_name,c.field_scope FROM matches m "
             "JOIN cells c ON c.id=m.cell_id JOIN cut ON cut.path=c.table_path "
             "WHERE c.source_row<=cut.n AND m.excluded=? ORDER BY m.id")
    for stem, excluded in (("content_type_occurrences", 0), ("content_excluded", 1)):
        hashed, count = hashlib.sha256(), 0
        for raw in db.execute(cte + query, params + [excluded]):
            row = dict(raw)
            detail = json.loads(row.pop("details"))
            hashed.update(canonical_line({**row, **detail, **SCOPE}))
            count += 1
        expected = baseline["exports"][stem]
        comparisons[stem] = {"records": count, "sha256": hashed.hexdigest(),
                             "expected_records": expected["records"], "expected_sha256": expected["sha256"]}
        checks[stem + "_old_bytes_preserved"] = count == expected["records"] and hashed.hexdigest() == expected["sha256"]
    cell_query = ("SELECT c.id,c.table_path,c.source_row,c.column_name,c.field_scope,c.characters,"
                  "c.scanned_characters,c.text_hmac_sha256,c.status,'cell' record_kind,"
                  "c.source_row start_row,c.source_row end_row,1 row_count "
                  "FROM cells c JOIN cut ON cut.path=c.table_path WHERE c.source_row<=cut.n ORDER BY c.rowid")
    cell_hash, cell_count, prefix_cells = hashlib.sha256(), 0, Counter()
    for raw in db.execute(cte + cell_query, params):
        row = {**dict(raw), **SCOPE, "reason": REASON}
        cell_hash.update(canonical_line(row))
        cell_count += 1
        prefix_cells[row["table_path"]] += 1
    expected = baseline["exports"]["content_unknown_type_review_queue"]
    checks["individual_cell_fields_preserved"] = cell_count == expected["individual_cells"] and cell_hash.hexdigest() == expected["individual_cells_sha256"]
    comparisons["individual_cells"] = {"records": cell_count, "sha256": cell_hash.hexdigest(),
        "expected_records": expected["individual_cells"], "expected_sha256": expected["individual_cells_sha256"]}
    ranges_query = ("SELECT r.id,r.table_path,NULL source_row,r.column_name,r.field_scope,r.characters,"
                    "r.characters scanned_characters,NULL text_hmac_sha256,'unclassified_text' status,"
                    "'source_row_range' record_kind,r.start_row,r.end_row,r.end_row-r.start_row+1 row_count "
                    "FROM review_ranges r JOIN cut ON cut.path=r.table_path WHERE r.start_row<=cut.n ORDER BY r.rowid")
    non_tail_hash, non_tail_count, range_count = hashlib.sha256(), 0, 0
    tails = expected["legally_extendable_tail_ranges"]
    tail_checks = {}
    for raw in db.execute(cte + ranges_query, params):
        row = {**dict(raw), **SCOPE, "reason": REASON}
        cut = cuts[row["table_path"]]
        range_count += 1
        prefix_cells[row["table_path"]] += min(row["end_row"], cut) - row["start_row"] + 1
        if row["id"] not in tails:
            non_tail_hash.update(canonical_line(row))
            non_tail_count += 1
        else:
            previous = tails[row["id"]]
            changed = {"end_row", "row_count", "characters", "scanned_characters"}
            extra_rows = row["end_row"] - previous["end_row"]
            tail_checks[row["id"]] = (
                all(row[k] == v for k, v in previous.items() if k not in changed)
                and extra_rows >= 0
                and row["row_count"] == row["end_row"] - row["start_row"] + 1
                and row["scanned_characters"] == row["characters"]
                and row["characters"] >= previous["characters"] + extra_rows
                and (extra_rows > 0 or row["characters"] == previous["characters"]))
    checks["non_tail_range_fields_preserved"] = non_tail_count == expected["non_tail_ranges"] and non_tail_hash.hexdigest() == expected["non_tail_ranges_sha256"]
    checks["old_tail_ranges_present_and_only_legally_extended"] = set(tail_checks) == set(tails) and all(tail_checks.values())
    checks["prefix_range_record_count_preserved"] = range_count == expected["range_records"]
    comparisons["non_tail_ranges"] = {"records": non_tail_count, "sha256": non_tail_hash.hexdigest(),
        "expected_records": expected["non_tail_ranges"], "expected_sha256": expected["non_tail_ranges_sha256"]}
    comparisons["extendable_tails"] = {"count": len(tails), "checks_by_id": tail_checks}
    old_tables = {row["path"]: row for row in old["tables"]}
    new_tables = {row["path"]: row for row in new["tables"]}
    db_tables = {row["path"]: dict(row) for row in db.execute("SELECT * FROM tables")}
    progress = {}
    for path, before in old_tables.items():
        after = new_tables[path]
        stats_monotonic = all(after["stats"].get(k, 0) >= v for k, v in before["stats"].items())
        progress[path] = {"before_next_row": before["next_row"], "after_next_row": after["next_row"],
                         "added_source_rows": after["next_row"] - before["next_row"], "stats_monotonic": stats_monotonic}
        checks["progress_" + path] = before["next_row"] <= after["next_row"] <= before["expected_rows"] and stats_monotonic
        checks["export_checkpoint_" + path] = after["next_row"] == db_tables[path]["next_row"] and after["stats"] == json.loads(db_tables[path]["stats"])
        checks["old_nonempty_cells_" + path] = prefix_cells[path] == before["stats"].get("nonempty_cells", 0)
    db.close()
    return {"dataset": first["dataset"], "output": str(output), "checks": checks,
            "all_checks_passed": all(checks.values()), "prefix_hash_comparisons": comparisons,
            "source_row_progress": progress, "old_processed_rows": old["processed_rows"],
            "new_processed_rows": new["processed_rows"],
            "old_candidate_and_example_bytes_preserved": all(checks[k + "_old_bytes_preserved"] for k in ("content_type_occurrences", "content_excluded")),
            "individual_cell_fields_preserved": checks["individual_cell_fields_preserved"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs-confirmed-terminal", action="store_true", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    docs = root / "agentlog_unified/docs"
    first_path = docs / "v044_first_pass_content_exports_v044_verification.json"
    baseline_path = docs / "content_resume_v044_baseline_hashes.json"
    first = json.loads(first_path.read_text())
    baseline = json.loads(baseline_path.read_text())
    by_dataset = {row["dataset"]: row for row in baseline["results"]}
    result_path = docs / "content_resume_v044_preservation.json"
    if result_path.exists():
        raise RuntimeError("Refusing to overwrite prior preservation evidence")
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with ExitStack() as stack:
        for row in first["results"]:
            lock = stack.enter_context((Path(row["output"]) / ".content.lock").open("r"))
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        results = [check_dataset(root, row, by_dataset[row["dataset"]]) for row in first["results"]]
    report = {"started_at": started, "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "verifier_path": str(Path(__file__).resolve()), "verifier_sha256": digest(Path(__file__)),
              "first_verification_path": str(first_path), "first_verification_sha256": digest(first_path),
              "baseline_hash_evidence_path": str(baseline_path), "baseline_hash_evidence_sha256": digest(baseline_path),
              "confirmed_terminal_by_parent": args.runs_confirmed_terminal,
              "both_content_writer_locks_idle": True, "results": results,
              "all_checks_passed": all(row["all_checks_passed"] for row in results),
              "observation_scope": "dataset_text_cells", "source_values_read": False,
              "source_databases_modified": False, "target_code_executed": False, "network_accessed": False,
              "limitations": ["Preservation evidence concerns already observed outputs, not classifier completeness or semantic correctness."]}
    with result_path.open("x") as stream:
        stream.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"output": str(result_path), "all_checks_passed": report["all_checks_passed"],
                      "results": [{"dataset": r["dataset"], "all_checks_passed": r["all_checks_passed"],
                                   "old_processed_rows": r["old_processed_rows"], "new_processed_rows": r["new_processed_rows"]} for r in results]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
