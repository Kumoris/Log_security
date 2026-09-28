"""Independent driver checks with miniature frozen Parquet and synthetic values."""
from collections import Counter
import csv
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from agentlog_unified import structured_scan as scanner
from agentlog_unified.storage import csv_cell
from test_schema_scan import frozen


TEXT = '{"email":"unit-mailbox@researchqz.org"}'
EXAMPLE = '{"email":"unit-person@example.invalid"}'
STEMS = ("structured_documents", "structured_type_occurrences", "structured_excluded",
         "structured_data_gaps", "structured_unknown_type_review_queue", "structured_type_summary")
DB_TABLES = ("progress", "documents", "matches", "gaps", "review_ranges")


def run(imported, output, **kwargs):
    return scanner.scan_structured(imported, output, min_free_bytes=0, **kwargs)


def rows(output, stem):
    with gzip.open(output / (stem + ".jsonl.gz"), "rt") as stream:
        return [json.loads(line) for line in stream]


def snapshot(output):
    with sqlite3.connect(output / "structured.sqlite") as db:
        return {table: sorted(db.execute("SELECT * FROM " + table).fetchall()) for table in DB_TABLES}


def source_fixture(tmp_path, size=6, group=3):
    return frozen(tmp_path, {"pr_comments": pa.table({"body": [TEXT] * size, "metadata": ["ordinary prose"] * size})}, row_group_size=group)


def covered_cells(output):
    return Counter((r["table_path"], r["column_name"], n)
        for r in rows(output, "structured_unknown_type_review_queue")
        for n in range(r["start_row"], r["end_row"] + 1))


def test_dry_run_has_zero_value_decode_and_zero_writes(tmp_path, monkeypatch):
    imported, _ = source_fixture(tmp_path)
    monkeypatch.setattr(pq.ParquetFile, "iter_batches", lambda *a, **k: pytest.fail("dry-run decoded a page"))
    monkeypatch.setattr(scanner.structured_types, "classify_structured", lambda *a, **k: pytest.fail("dry-run called parser"))
    output = tmp_path / "out"
    result = run(imported, output, dry_run=True)
    assert result["source_rows"] == 6 and result["source_values_decoded"] is False
    assert result["files_written"] is False and not output.exists()


def test_real_parser_exports_exact_gzip_csv_jsonl_counts_and_no_values(tmp_path):
    imported, _ = frozen(tmp_path, {
        "pr_comments": pa.table({"body": [TEXT, EXAMPLE, None, ""], "metadata": ["UNIQUE_ORDINARY_METADATA_QZX"] * 4}),
        "repository": pa.table({"id": [1, 2]})})
    output = tmp_path / "out"; report = run(imported, output, batch_size=2)
    assert report["all_source_rows_visited"] and report["processed_rows"] == 6
    assert report["counts"]["rows_decoded"] == 4 and report["counts"]["text_cells_visited"] == 8
    assert report["counts"]["null_cells"] == report["counts"]["empty_cells"] == 1
    assert report["counts"]["nonempty_cells"] == report["unknown_review_source_cells"] == 6
    assert report["candidate_occurrences"] > 0 and report["excluded_occurrences"] > 0
    assert len(covered_cells(output)) == 6 and set(covered_cells(output).values()) == {1}
    lengths = {}
    for stem in STEMS:
        data = rows(output, stem); lengths[stem] = len(data)
        with gzip.open(output / (stem + ".csv.gz"), "rt", newline="") as stream:
            reader = csv.DictReader(stream); csv_rows = list(reader)
        assert csv_rows == [{key: csv_cell(row.get(key)) for key in reader.fieldnames} for row in data]
        assert all(row["human_review_status"] == "pending" and row["observation_scope"] == "dataset_structured_text" for row in data)
        assert all(not row["runtime_confirmed"] and not row["application_log_evidence"] for row in data)
        for row in data:
            assert not {"text", "raw_value", "value", "key", "raw_key"} & row.keys()
    assert lengths["structured_type_occurrences"] == report["candidate_occurrences"]
    assert lengths["structured_excluded"] == report["excluded_occurrences"]
    assert lengths["structured_documents"] == report["documents"]
    assert lengths["structured_data_gaps"] == report["data_gap_records"]
    assert lengths["structured_unknown_type_review_queue"] == report["unknown_review_range_records"]
    assert sum(r["candidate_occurrences"] for r in rows(output, "structured_type_summary")) == report["candidate_occurrences"]
    state = json.loads((output / "export_state.json").read_text())
    assert state["status"] == "complete"
    for name, expected in state["outputs"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == expected["sha256"]
    for path in output.iterdir():
        if not path.is_file(): continue
        data = gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes()
        for value in ("unit-mailbox@researchqz.org", "unit-person@example.invalid", "UNIQUE_ORDINARY_METADATA_QZX"):
            assert value.encode() not in data and hashlib.sha256(value.encode()).hexdigest().encode() not in data


@pytest.mark.parametrize("budget", [2, 3, 4])
def test_row_budget_and_batch_group_resume_is_exact_once(tmp_path, monkeypatch, budget):
    imported, _ = source_fixture(tmp_path)
    reference = tmp_path / "reference"; run(imported, reference, batch_size=2)
    original = scanner.structured_types.classify_structured; calls = []
    def counting(text, **limits):
        calls.append(1); return original(text, **limits)
    monkeypatch.setattr(scanner.structured_types, "classify_structured", counting)
    output = tmp_path / "out"; partial = run(imported, output, batch_size=2, max_rows=budget)
    assert partial["stop_reason"] == "source_row_budget" and partial["rows_this_invocation"] == budget
    assert partial["processed_rows"] == budget and partial["counts"]["text_cells_visited"] == budget * 2
    complete = run(imported, output, resume=True, batch_size=1)
    assert complete["all_source_rows_visited"] and len(calls) == 12
    assert snapshot(output) == snapshot(reference) and covered_cells(output) == covered_cells(reference)
    assert set(covered_cells(output).values()) == {1}
    before = snapshot(output)
    (output / "structured_documents.jsonl.gz").write_bytes(b"interrupted export")
    resumed = run(imported, output, resume=True)
    assert resumed["rows_this_invocation"] == 0 and snapshot(output) == before and len(calls) == 12
    assert all(rows(output, stem) == rows(reference, stem) for stem in STEMS)


def test_zero_row_budget_does_not_decode_values(tmp_path, monkeypatch):
    imported, _ = source_fixture(tmp_path)
    monkeypatch.setattr(pq.ParquetFile, "iter_batches", lambda *a, **k: pytest.fail("zero-row budget decoded source pages"))
    result = run(imported, tmp_path / "out", max_rows=0)
    assert result["rows_this_invocation"] == result["processed_rows"] == 0
    assert result["stop_reason"] == "source_row_budget"


def test_time_budget_stops_after_whole_source_rows(tmp_path, monkeypatch):
    imported, _ = source_fixture(tmp_path)
    original = scanner.structured_types.classify_structured; clock = [0]
    monkeypatch.setattr(scanner.time, "monotonic", lambda: clock[0])
    def timed(text, **limits):
        clock[0] += 1; return original(text, **limits)
    monkeypatch.setattr(scanner.structured_types, "classify_structured", timed)
    output = tmp_path / "out"; partial = run(imported, output, max_seconds=3)
    assert partial["stop_reason"] == "time_budget" and partial["processed_rows"] == 2
    assert partial["counts"]["text_cells_visited"] == 4
    report = run(imported, output, resume=True)
    assert report["processed_rows"] == 6 and report["counts"]["text_cells_visited"] == 12


def test_parser_failure_rolls_back_documents_matches_ranges_stats_and_cursor(tmp_path, monkeypatch):
    imported, _ = source_fixture(tmp_path, size=4, group=4)
    reference = tmp_path / "reference"; run(imported, reference, batch_size=2)
    original = scanner.structured_types.classify_structured; calls = [0]
    def fail(text, **limits):
        calls[0] += 1
        if calls[0] == 6: raise RuntimeError("PRIVATE_SYNTHETIC_ERROR_MARKER_QZX")
        return original(text, **limits)
    monkeypatch.setattr(scanner.structured_types, "classify_structured", fail)
    output = tmp_path / "out"
    with pytest.raises(ValueError, match="Structured parser failed") as error:
        run(imported, output, batch_size=2)
    assert "PRIVATE_SYNTHETIC_ERROR_MARKER_QZX" not in str(error.value)
    state = snapshot(output)
    assert state["progress"][0][2] == 2
    assert all(row[2] <= 2 for row in state["documents"])
    assert all(row[4] <= 2 for row in state["review_ranges"])
    assert json.loads(state["progress"][0][4])["text_cells_visited"] == 4
    assert json.loads((output / "export_state.json").read_text())["status"] != "complete"
    monkeypatch.setattr(scanner.structured_types, "classify_structured", original)
    run(imported, output, resume=True, batch_size=1)
    assert snapshot(output) == snapshot(reference)
    assert all(rows(output, stem) == rows(reference, stem) for stem in STEMS)


@pytest.mark.parametrize("change", ["source", "manifest", "limits", "implementation"])
def test_changed_frozen_inputs_limits_or_implementation_reject_resume(tmp_path, monkeypatch, change):
    imported, source = source_fixture(tmp_path)
    output = tmp_path / "out"; run(imported, output, max_rows=2)
    before = snapshot(output); kwargs = {}
    if change == "source":
        pq.write_table(pa.table({"body": ["changed"]}), source / "pr_comments.parquet")
    elif change == "manifest":
        mp = imported / "manifest.json"; manifest = json.loads(mp.read_text()); manifest["test_note"] = "changed"; mp.write_text(json.dumps(manifest))
    elif change == "limits": kwargs["max_nodes"] = 999
    else: monkeypatch.setattr(scanner, "_sources", lambda: {"changed": "implementation"})
    monkeypatch.setattr(scanner.structured_types, "classify_structured", lambda *a, **k: pytest.fail("changed frozen inputs reached parser"))
    with pytest.raises(ValueError, match="hash changed|identical frozen"):
        run(imported, output, resume=True, **kwargs)
    assert snapshot(output) == before


@pytest.mark.parametrize("change", ["raw_value", "category", "node_path", "decoded_end", "rule"])
def test_unapproved_match_evidence_never_reaches_database_or_exports(tmp_path, monkeypatch, change):
    imported, _ = frozen(tmp_path, {"pr_comments": pa.table({"body": [TEXT]})})
    original = scanner.structured_types.classify_structured
    def poison(text, **limits):
        result = original(text, **limits)
        assert result["matches"], "synthetic email must produce a match for validation probe"
        item = result["matches"][0]
        item[change] = (10**9 if change == "decoded_end" else ["PRIVATE_DYNAMIC_KEY_QZX"] if change == "node_path" else "PRIVATE_UNAPPROVED_VALUE_QZX")
        return result
    monkeypatch.setattr(scanner.structured_types, "classify_structured", poison)
    output = tmp_path / "out"
    with pytest.raises(ValueError, match="Structured parser returned") as error:
        run(imported, output)
    assert "PRIVATE_" not in str(error.value)
    state = snapshot(output)
    assert state["progress"][0][2] == 0 and json.loads(state["progress"][0][4]) == {}
    assert all(not state[name] for name in DB_TABLES if name != "progress")
    for path in output.iterdir():
        if path.is_file(): assert b"PRIVATE_" not in path.read_bytes()


def test_export_failure_keeps_checkpoint_stale_and_resume_rebuilds(tmp_path, monkeypatch):
    imported, _ = source_fixture(tmp_path, size=2)
    output = tmp_path / "out"; original = scanner.content_advance._export_rows; calls = [0]
    def fail(*args, **kwargs):
        calls[0] += 1
        if calls[0] == 2: raise OSError("synthetic disk reserve")
        return original(*args, **kwargs)
    monkeypatch.setattr(scanner.content_advance, "_export_rows", fail)
    with pytest.raises(OSError, match="synthetic disk reserve"):
        run(imported, output)
    before = snapshot(output)
    assert before["progress"][0][2] == 2
    assert (output / "structured_documents.jsonl.gz").exists()
    assert json.loads((output / "export_state.json").read_text())["status"] != "complete"
    monkeypatch.setattr(scanner.content_advance, "_export_rows", original)
    monkeypatch.setattr(scanner.structured_types, "classify_structured", lambda *a, **k: pytest.fail("completed checkpoint was decoded again"))
    report = run(imported, output, resume=True)
    assert report["rows_this_invocation"] == 0 and snapshot(output) == before
    assert json.loads((output / "export_state.json").read_text())["status"] == "complete"
    assert all((output / (stem + suffix)).exists() for stem in STEMS for suffix in (".jsonl.gz", ".csv.gz"))


@pytest.mark.parametrize("text,limits,reason", [
    (TEXT, {"max_source_chars": 12}, "source_size_budget"),
    ('```json\n{"user_id":1}\n```\n```json\n{"user_id":2}\n```', {"max_documents": 1}, "document_budget"),
    ('{"outer":{"inner":{"user_id":1}}}', {"max_depth": 1}, "depth_budget"),
    ('{"user_id":1,"session_id":2}', {"max_nodes": 1}, "node_budget"),
    ('{"user_id":1,"email":"unit-mailbox@researchqz.org"}', {"max_matches": 1}, "match_budget"),
    ('{"payload":"{\\"user_id\\":7}"}', {"max_decode_layers": 0}, "decode_layer_budget"),
])
def test_bounded_parser_outputs_remain_partial_and_reviewable(tmp_path, text, limits, reason):
    imported, _ = frozen(tmp_path, {"pr_comments": pa.table({"body": [text]})})
    output = tmp_path / "out"; report = run(imported, output, **limits)
    assert report["all_source_rows_visited"] and not report["full_dataset_coverage_claim"]
    assert report["unknown_review_source_cells"] == 1
    assert rows(output, "structured_unknown_type_review_queue")[0]["status"] == "partial"
    assert reason in {r["reason"] for r in rows(output, "structured_data_gaps")}


def test_source_change_during_export_prevents_complete_marker(tmp_path, monkeypatch):
    imported, source = source_fixture(tmp_path, size=1)
    original = scanner._export
    def mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        pq.write_table(pa.table({"body": ["changed"]}), source / "pr_comments.parquet")
        return result
    monkeypatch.setattr(scanner, "_export", mutate)
    output = tmp_path / "out"
    with pytest.raises(ValueError, match="changed"):
        run(imported, output)
    assert json.loads((output / "export_state.json").read_text())["status"] != "complete"


def test_actual_cli_dry_full_resume_and_online_rejection(tmp_path):
    imported, _ = source_fixture(tmp_path, size=2)
    output = tmp_path / "out"
    command = [str(Path(sys.executable).with_name("agentlog-unified")), "structured-scan",
               "--input", str(imported), "--output", str(output), "--batch-size", "2", "--offline",
               "--max-json-documents", "2", "--max-json-depth", "4", "--max-json-nodes", "100",
               "--max-json-decode-layers", "1", "--max-source-chars", "256", "--max-text-matches", "10"]
    dry = subprocess.run(command + ["--dry-run"], capture_output=True, text=True, timeout=30)
    assert dry.returncode == 0, dry.stderr
    assert json.loads(dry.stdout)["source_values_decoded"] is False and not output.exists()
    full = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert full.returncode == 2, full.stderr
    full_result = json.loads(full.stdout)
    assert full_result["all_source_rows_visited"] and full_result["processed_rows"] == 2
    assert json.loads((output / "manifest.json").read_text())["fingerprint"]["limits"] == {
        "max_documents": 2, "max_depth": 4, "max_nodes": 100, "max_decode_layers": 1,
        "max_source_chars": 256, "max_matches": 10}
    before = snapshot(output)
    resumed = subprocess.run(command + ["--resume"], capture_output=True, text=True, timeout=30)
    assert resumed.returncode == 2, resumed.stderr
    assert json.loads(resumed.stdout)["rows_this_invocation"] == 0 and snapshot(output) == before
    bad_output = tmp_path / "online-out"
    online = subprocess.run([str(Path(sys.executable).with_name("agentlog-unified")), "structured-scan",
        "--input", str(imported), "--output", str(bad_output), "--online"], capture_output=True, text=True, timeout=30)
    assert online.returncode == 1 and not bad_output.exists()
    assert "local frozen sources" in online.stderr


@pytest.mark.parametrize("kwargs", [{"batch_size": True}, {"batch_size": 129}, {"max_rows": -1},
                                    {"max_seconds": float("nan")}, {"max_nodes": 0},
                                    {"max_source_chars": scanner.structured_types.MAX_SOURCE_CHARS + 1},
                                    {"max_depth": scanner.structured_types.MAX_DEPTH + 1},
                                    {"max_decode_layers": scanner.structured_types.MAX_DECODE_LAYERS + 1}])
def test_invalid_budget_rejected_before_input_read(tmp_path, kwargs):
    with pytest.raises(ValueError, match="limits"):
        run(tmp_path / "not-read", tmp_path / "out", **kwargs)
    assert not (tmp_path / "out").exists()
