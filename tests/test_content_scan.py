"""Independent scanner checks using synthetic, genuinely frozen Parquet files."""
import hashlib
import json
import sqlite3
from collections import Counter

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from agentlog_unified import content_scan


def frozen_import(tmp_path, table, *, dataset="aidev", name="all_pull_request", row_group_size=2):
    source, imported = tmp_path / "source", tmp_path / "import"
    source.mkdir(); imported.mkdir()
    path = source / (name + ".parquet")
    pq.write_table(table, path, row_group_size=row_group_size)
    item = {"path": path.name, "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    manifest = {"status": "complete", "source_signature": {"source_dir": str(source), "inputs": [item]},
                "outputs": {"aidev.sqlite" if dataset == "aidev" else "swechat.sqlite": "fixture-reference-only"}}
    (imported / "manifest.json").write_text(json.dumps(manifest))
    return imported, path


def exported(output, name):
    return [json.loads(line) for line in (output / (name + ".jsonl")).read_text().splitlines()]


def expand_review(output):
    expanded = []
    for row in exported(output, "content_unknown_type_review_queue"):
        assert row["row_count"] == row["end_row"] - row["start_row"] + 1
        if row["record_kind"] == "cell":
            assert row["source_row"] == row["start_row"] == row["end_row"]
        else:
            assert row["source_row"] is None
        expanded.extend((row["table_path"], n, row["column_name"]) for n in range(row["start_row"], row["end_row"] + 1))
    return Counter(expanded)


def checkpoint(output):
    with sqlite3.connect(output / "content.sqlite") as db:
        return {name: sorted(db.execute("SELECT * FROM " + name).fetchall())
                for name in ("tables", "cells", "matches", "review_ranges")}


def fake_match(text):
    return {"start": 0, "end": len(text), "category": "PII", "subtype": "email", "rule": "synthetic",
            "basis": "literal_shape", "confidence": "low", "value_status": "unverified_literal",
            "candidate_status": "synthetic_shape_candidate"}


@pytest.fixture
def no_matches(monkeypatch):
    from agentlog_unified import content_types
    monkeypatch.setattr(content_types, "classify_text", lambda text, **kwargs: {"matches": [], "truncated": False})
    return content_types


@pytest.mark.parametrize("dataset,name,field", [("aidev", "all_pull_request", "body"), ("swe-chat", "conversations", "content")])
def test_dry_run_real_schemas_select_all_strings_without_writes(tmp_path, dataset, name, field):
    table = pa.table({field: pa.array(["synthetic body"], type=pa.string()),
                      "author_login": pa.array(["synthetic actor"], type=pa.large_string()),
                      "id": [1], "native_items": [["not a scalar string"]]})
    imported, source = frozen_import(tmp_path, table, dataset=dataset, name=name)
    before = source.read_bytes()
    output = tmp_path / "out"
    result = content_scan.scan_content(imported, output, dry_run=True)
    assert result["exit_code"] == 0 and result["dataset"] == dataset
    assert not output.exists() and source.read_bytes() == before
    assert not result["files_written"] and not result["source_values_decoded"]
    fields = {row["column"]: row for row in result["tables"][0]["columns"]}
    assert fields[field]["selected"] and fields[field]["field_scope"] == "content"
    assert fields["author_login"]["selected"] and fields["author_login"]["field_scope"] == "metadata"
    assert not fields["id"]["selected"] and not fields["native_items"]["selected"]


def test_unknown_ranges_exact_across_holes_matches_columns_and_row_groups(tmp_path, monkeypatch, no_matches):
    values = {"body": ["aa", "bbb", None, "", "HIT", "dddd", "e", " "],
              "author_login": ["m", None, "mm", "mmm", "", "mmmm", "mmmmm", "mmmmmm"]}
    imported, source = frozen_import(tmp_path, pa.table(values))
    monkeypatch.setattr(no_matches, "classify_text", lambda text, **kw: {"matches": [fake_match(text)] if text == "HIT" else [], "truncated": False})
    output = tmp_path / "out"
    report = content_scan.scan_content(imported, output, batch_size=1)
    expected = Counter((source.name, n, col) for col, cells in values.items()
                       for n, value in enumerate(cells, 1) if value is not None and value.strip())
    assert expand_review(output) == expected and all(n == 1 for n in expected.values())
    rows = exported(output, "content_unknown_type_review_queue")
    assert [(r["start_row"], r["end_row"]) for r in rows if r["column_name"] == "body" and r["record_kind"] == "source_row_range"] == [(1, 2), (6, 7)]
    assert report["counts"]["characters_seen"] == report["counts"]["characters_scanned"] == sum(len(v) for cells in values.values() for v in cells if v and v.strip())
    assert report["counts"]["text_cells_visited"] == 16
    assert report["counts"]["null_cells"] == 2 and report["counts"]["empty_cells"] == 3
    assert report["unknown_type_review_cells"] == len(expected)
    assert report["all_selected_text_rows_visited"] and report["all_available_text_characters_scanned"]
    assert report["application_log_evidence"] is False and report["full_dataset_coverage_claim"] is False
    assert all(row["human_review_status"] == "pending" and row["runtime_confirmed"] is False for row in rows)


def test_budget_resume_exact_once_and_completed_resume_rebuilds_exports(tmp_path, monkeypatch, no_matches):
    values = ["one", "two", "three", "four", "five", "six", "seven"]
    imported, source = frozen_import(tmp_path, pa.table({"author_login": values}), row_group_size=3)
    clock, seen = [0], []
    monkeypatch.setattr(content_scan.time, "monotonic", lambda: clock[0])
    def timed(text, **kwargs):
        seen.append(text); clock[0] += 1
        return {"matches": [fake_match(text)] if text == "four" else [], "truncated": False}
    monkeypatch.setattr(no_matches, "classify_text", timed)
    output = tmp_path / "out"
    first = content_scan.scan_content(imported, output, max_seconds=2, batch_size=2)
    assert first["processed_rows"] == 2 and first["stop_reason"] == "time_budget"
    second = content_scan.scan_content(imported, output, resume=True, max_seconds=2, batch_size=4)
    assert second["processed_rows"] == 4 and second["status"] == "partial"
    final = content_scan.scan_content(imported, output, resume=True, batch_size=1)
    assert seen == values and final["processed_rows"] == len(values)
    assert expand_review(output) == Counter((source.name, n, "author_login") for n in range(1, 8))
    assert final["counts"]["characters_seen"] == sum(map(len, values))
    before = checkpoint(output)
    public_before = {p.name: p.read_bytes() for p in output.glob("*.jsonl")}
    (output / "content_type_occurrences.jsonl").write_text("interrupted export")
    content_scan.scan_content(imported, output, resume=True)
    assert checkpoint(output) == before and seen == values
    assert {p.name: p.read_bytes() for p in output.glob("*.jsonl")} == public_before


def test_interrupted_batch_rolls_back_ranges_and_replays_uncommitted_rows(tmp_path, monkeypatch, no_matches):
    imported, source = frozen_import(tmp_path, pa.table({"author_login": ["alpha", "beta", "gamma", "delta"]}), row_group_size=4)
    def fail_on_third(text, **kwargs):
        if text == "gamma": raise RuntimeError("synthetic interruption")
        return {"matches": [], "truncated": False}
    monkeypatch.setattr(no_matches, "classify_text", fail_on_third)
    output = tmp_path / "out"
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        content_scan.scan_content(imported, output, batch_size=2)
    with sqlite3.connect(output / "content.sqlite") as db:
        assert db.execute("SELECT next_row FROM tables").fetchone()[0] == 2
        assert db.execute("SELECT start_row,end_row,characters FROM review_ranges").fetchall() == [(1, 2, 9)]
    monkeypatch.setattr(no_matches, "classify_text", lambda text, **kw: {"matches": [], "truncated": False})
    report = content_scan.scan_content(imported, output, resume=True, batch_size=3)
    assert expand_review(output) == Counter((source.name, n, "author_login") for n in range(1, 5))
    assert report["counts"]["nonempty_cells"] == 4 and report["counts"]["characters_seen"] == 19


def test_source_hash_change_is_rejected_without_advancing_checkpoint(tmp_path, no_matches):
    imported, source = frozen_import(tmp_path, pa.table({"body": ["synthetic"]}))
    output = tmp_path / "out"
    content_scan.scan_content(imported, output)
    before = checkpoint(output)
    payload = bytearray(source.read_bytes()); payload[len(payload) // 2] ^= 1
    source.write_bytes(payload)  # Same length, different bytes: the digest must catch this.
    with pytest.raises(ValueError, match="hash changed"):
        content_scan.scan_content(imported, output, resume=True)
    assert checkpoint(output) == before


def test_resume_rejects_changed_limits_manifest_or_classifier(tmp_path, monkeypatch, no_matches):
    imported, _ = frozen_import(tmp_path, pa.table({"body": ["synthetic"]}))
    output = tmp_path / "out"
    content_scan.scan_content(imported, output)
    with pytest.raises(ValueError, match="identical frozen"):
        content_scan.scan_content(imported, output, resume=True, max_source_chars=17)
    original = content_scan._digest
    monkeypatch.setattr(content_scan, "_digest", lambda p: "changed" if p.name == "content_types.py" else original(p))
    with pytest.raises(ValueError, match="identical frozen"):
        content_scan.scan_content(imported, output, resume=True)
    monkeypatch.setattr(content_scan, "_digest", original)
    with (imported / "manifest.json").open("a") as stream: stream.write("\n")
    with pytest.raises(ValueError, match="identical frozen"):
        content_scan.scan_content(imported, output, resume=True)


def test_zero_rows_and_no_text_columns_complete_without_false_text_coverage(tmp_path, no_matches):
    imported, _ = frozen_import(tmp_path, pa.table({"body": pa.array([], type=pa.string())}))
    output = tmp_path / "out"
    report = content_scan.scan_content(imported, output)
    assert report["all_selected_text_rows_visited"] and report["processed_rows"] == 0
    assert report["unknown_type_review_cells"] == 0
    other = tmp_path / "numeric"; other.mkdir()
    imported, _ = frozen_import(other, pa.table({"id": [1, 2]}))
    report = content_scan.scan_content(imported, other / "out")
    assert report["all_selected_text_rows_visited"] and report["processed_rows"] == 2
    assert report["unknown_type_review_cells"] == 0 and len(report["non_text_columns"]) == 1


@pytest.mark.parametrize("bad_kind", ["plaintext_field", "invalid_span"])
def test_bad_classifier_evidence_is_rejected_and_not_persisted(tmp_path, monkeypatch, no_matches, bad_kind):
    sentinel = "SYNTHETIC_BODY_MUST_NEVER_APPEAR_IN_ARTIFACTS"
    imported, _ = frozen_import(tmp_path, pa.table({"body": [sentinel]}))
    match = fake_match(sentinel)
    if bad_kind == "plaintext_field": match["text"] = sentinel
    else: match["end"] = len(sentinel) + 1
    monkeypatch.setattr(no_matches, "classify_text", lambda text, **kw: {"matches": [match], "truncated": False})
    output = tmp_path / "out"
    with pytest.raises(ValueError, match="unapproved evidence fields|invalid source span"):
        content_scan.scan_content(imported, output)
    with sqlite3.connect(output / "content.sqlite") as db:
        assert db.execute("SELECT next_row FROM tables").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM cells").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM matches").fetchone()[0] == 0
    assert all(sentinel.encode() not in path.read_bytes() for path in output.iterdir() if path.is_file())


def test_truncated_unmatched_cells_remain_individual_unknowns_with_precise_counts(tmp_path, no_matches):
    sentinel = "UNIQUE_SYNTHETIC_LONG_CELL_TAIL"
    imported, _ = frozen_import(tmp_path, pa.table({"author_login": ["short", "prefix_" + sentinel, "other"]}))
    output = tmp_path / "out"
    report = content_scan.scan_content(imported, output, max_source_chars=8)
    queue = exported(output, "content_unknown_type_review_queue")
    truncated = [row for row in queue if row["status"] == "truncated"]
    assert len(truncated) == 1 and truncated[0]["source_row"] == 2
    assert truncated[0]["characters"] == len("prefix_" + sentinel) and truncated[0]["scanned_characters"] == 8
    assert report["counts"]["characters_scanned"] == 18 and report["counts"]["truncated_cells"] == 1
    assert report["all_selected_text_rows_visited"] and not report["all_available_text_characters_scanned"]
    assert report["unknown_type_review_cells"] == 3
    assert all(sentinel.encode() not in path.read_bytes() for path in output.iterdir() if path.is_file())


def test_match_cap_is_explicit_even_when_no_matches_are_returned(tmp_path, monkeypatch, no_matches):
    imported, _ = frozen_import(tmp_path, pa.table({"body": ["synthetic capped content"]}))
    monkeypatch.setattr(no_matches, "classify_text", lambda text, **kw: {"matches": [], "truncated": True})
    report = content_scan.scan_content(imported, tmp_path / "out", max_matches=1)
    queue = exported(tmp_path / "out", "content_unknown_type_review_queue")
    assert report["counts"]["truncated_cells"] == 1 and not report["all_available_text_characters_scanned"]
    assert queue[0]["record_kind"] == "cell" and queue[0]["status"] == "truncated"


def test_placeholder_matches_export_separately_and_all_source_values_stay_private(tmp_path, monkeypatch, no_matches):
    values = ["UNIQUE_SYNTHETIC_CANDIDATE", "UNIQUE_SYNTHETIC_PLACEHOLDER", "UNIQUE_SYNTHETIC_METADATA"]
    imported, _ = frozen_import(tmp_path, pa.table({"body": values[:2], "author_login": [values[2], None]}), dataset="swe-chat", name="conversations")
    def classify(text, **kwargs):
        if text == values[2]: return {"matches": [], "truncated": False}
        match = fake_match(text)
        if text == values[1]: match["value_status"] = "placeholder_or_example"
        return {"matches": [match], "truncated": False}
    monkeypatch.setattr(no_matches, "classify_text", classify)
    output = tmp_path / "out"
    report = content_scan.scan_content(imported, output)
    candidates = exported(output, "content_type_occurrences")
    excluded = exported(output, "content_excluded")
    assert len(candidates) == len(excluded) == 1
    assert candidates[0]["source_row"] == 1 and excluded[0]["source_row"] == 2
    assert report["candidate_occurrences"] == report["excluded_occurrences"] == 1
    assert report["unknown_type_review_cells"] == 3
    assert all(value.encode() not in path.read_bytes() for path in output.iterdir() if path.is_file() for value in values)
    assert (output / ".fingerprint-key").stat().st_mode & 0o077 == 0
    assert (output / "content.sqlite").stat().st_mode & 0o077 == 0


def test_actual_classifier_shapes_examples_and_prose_stay_distinct(tmp_path):
    email = "review-person@unit.invalid"
    value = "UNVERIFIED" + "VALUEQZ318"
    bodies = ["Do not log password.", 'email = "' + email + '"', '密码说明 password="' + value + '"', "password=user.password"]
    imported, _ = frozen_import(tmp_path, pa.table({"body": bodies, "author_login": ["plain actor"] * 4}))
    output = tmp_path / "out"
    report = content_scan.scan_content(imported, output)
    candidates = exported(output, "content_type_occurrences")
    excluded = exported(output, "content_excluded")
    assert [(r["source_row"], r["subtype"], r["candidate_status"]) for r in excluded] == [(2, "email", "placeholder_or_example")]
    assert {(r["source_row"], r["subtype"], r["candidate_status"]) for r in candidates} == {
        (3, "password", "named_value_candidate"), (4, "password", "identifier_reference")}
    password = next(row for row in candidates if row["source_row"] == 3)
    assert bodies[2][password["start"]:password["end"]] == value
    assert report["unknown_type_review_cells"] == 8
    assert all(row["confidence"] == "low" and row["human_review_status"] == "pending" for row in candidates + excluded)
    assert all(value.encode() not in path.read_bytes() and email.encode() not in path.read_bytes()
               for path in output.iterdir() if path.is_file())


def test_actual_classifier_match_cap_remains_reviewable(tmp_path):
    body = "\n".join(f"case{n}@unit.invalid" for n in range(3))
    imported, _ = frozen_import(tmp_path, pa.table({"body": [body]}))
    output = tmp_path / "out"
    report = content_scan.scan_content(imported, output, max_matches=1)
    assert report["excluded_occurrences"] == 1 and report["candidate_occurrences"] == 0
    assert report["unknown_type_review_cells"] == 1 and report["counts"]["truncated_cells"] == 1
    queue = exported(output, "content_unknown_type_review_queue")
    assert queue[0]["status"] == "truncated" and queue[0]["characters"] == queue[0]["scanned_characters"] == len(body)


def test_resume_rejects_replaced_same_length_fingerprint_key(tmp_path, no_matches):
    imported, _ = frozen_import(tmp_path, pa.table({"body": ["synthetic"]}))
    output = tmp_path / "out"
    content_scan.scan_content(imported, output)
    before = checkpoint(output)
    key_path = output / ".fingerprint-key"
    changed = bytearray(key_path.read_bytes()); changed[0] ^= 1
    key_path.write_bytes(changed)
    with pytest.raises(ValueError, match="fingerprint key"):
        content_scan.scan_content(imported, output, resume=True)
    assert checkpoint(output) == before


@pytest.mark.parametrize("dry_run", [True, False])
def test_classifier_character_bound_is_checked_before_creating_outputs(tmp_path, dry_run):
    from agentlog_unified.content_types import MAX_SOURCE_CHARS
    imported, _ = frozen_import(tmp_path, pa.table({"body": ["short synthetic input"]}))
    output = tmp_path / "out"
    with pytest.raises(ValueError, match="bound|limit|maximum|exceed"):
        content_scan.scan_content(imported, output, max_source_chars=MAX_SOURCE_CHARS + 1, dry_run=dry_run)
    assert not output.exists()
