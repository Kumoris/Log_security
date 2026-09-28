"""Real miniature Parquet fixtures; synthetic values never leave test storage."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from agentlog_unified import schema_scan as scanner


def frozen(tmp_path, tables, dataset="aidev", row_group_size=2):
    source, imported = tmp_path / "source", tmp_path / "import"
    source.mkdir(); imported.mkdir()
    inputs = []
    for name, table in tables.items():
        path = source / (name + ".parquet")
        pq.write_table(table, path, row_group_size=row_group_size)
        inputs.append({"path": path.name, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    manifest = {"status": "complete", "source_signature": {"source_dir": str(source), "inputs": inputs},
                "outputs": {"aidev.sqlite" if dataset == "aidev" else "swechat.sqlite": "synthetic_reference"}}
    (imported / "manifest.json").write_text(json.dumps(manifest))
    return imported, source


def records(output, stem):
    return [json.loads(line) for line in (output / (stem + ".jsonl")).read_text().splitlines()]


def cells(output):
    return Counter((row["table_path"], row["column_name"], n, row["status"], row["reason"])
                   for row in records(output, "schema_context_review_queue")
                   for n in range(row["start_row"], row["end_row"] + 1))


def checkpoint(output):
    with sqlite3.connect(output / "schema.sqlite") as db:
        return {table: sorted(db.execute("SELECT * FROM " + table).fetchall()) for table in ("fields", "ranges")}


def test_explicit_registry_has_six_numeric_and_twenty_six_text_fields():
    assert len(scanner.ROLES) == 32
    assert sum(role[0] == "numeric_account_id" for role in scanner.ROLES.values()) == 6
    assert scanner.ROLES["swe-chat", "commits", "github_username"] == ("account_login", "QID", "user_identifier")
    assert not any((ds, table, col) in scanner.ROLES for ds, table, col in [
        ("aidev", "repository", "id"), ("aidev", "repository", "full_name"),
        ("swe-chat", "repositories", "name"), ("swe-chat", "repositories", "owner_id"),
        ("aidev", "pr_commits", "message")])


@pytest.mark.parametrize("dataset", ["aidev", "swe-chat"])
def test_dry_run_lists_all_fields_and_does_not_write_or_decode(tmp_path, monkeypatch, dataset):
    name = "user" if dataset == "aidev" else "sessions"
    table = pa.table({"id": [1], "login": ["opaque"], "session_id": ["opaque-session"], "enabled": [True], "count": [7], "nested": [["inside"]]})
    imported, _ = frozen(tmp_path, {name: table}, dataset)
    monkeypatch.setattr(scanner, "_quality", lambda *args: pytest.fail("dry run decoded a value"))
    output = tmp_path / "out"
    result = scanner.scan_schema_context(imported, output, dry_run=True)
    assert result["exit_code"] == 0 and not output.exists() and not result["values_decoded"]
    assert result["all_fields"] == 6 and result["scalar_fields"] == 5
    assert result["selected_fields"] == (2 if dataset == "aidev" else 1)


def test_numeric_types_precision_nulls_and_int64_exactness(tmp_path):
    values = [None, 1.0, 2.0, float("nan"), float("inf"), 2.5, float(2**53), 0.0, -1.0, 3.0]
    imported, _ = frozen(tmp_path, {"all_user": pa.table({"id": pa.array(values, type=pa.float64())}),
        "user": pa.table({"id": pa.array([2**53 + 1], type=pa.int64())}),
        "all_pull_request": pa.table({"user_id": pa.array([True, False], type=pa.bool_())})})
    output = tmp_path / "out"
    report = scanner.scan_schema_context(imported, output)
    assert report["counts"] == {"cells_decoded": 13, "null": 1, "schema_context_candidate": 4, "invalid": 8}
    rows = records(output, "schema_context_review_queue")
    assert any(r["start_row"] == 7 and r["reason"] == "floating_id_precision_unverifiable" for r in rows if r["table_path"] == "all_user.parquet")
    user = [r for r in rows if r["table_path"] == "user.parquet"]
    assert user[0]["status"] == "schema_context_candidate"
    assert all(r["status"] == "invalid" for r in rows if r["table_path"] == "all_pull_request.parquet")
    assert sum(cells(output).values()) == 13


def test_text_metadata_without_assignment_is_classified_and_values_not_exported(tmp_path):
    ids = ["00123", None, "", " ", "null", "opaque-session-key"]
    emails = ["not-an-email", "unit-person@example.invalid", None, "", "mailbox@notreservedqz.org", " "]
    names = ["build-bot", "UNIQUE_METADATA_NAME_QZ", "person", " ", None, "not-a-real"]
    imported, _ = frozen(tmp_path, {"sessions": pa.table({"session_id": ids, "owner_id": ["owner"] * 6}),
        "commits": pa.table({"author_email": emails, "author_name": names, "github_username": ["octo_bot"] * 6})}, "swe-chat")
    output = tmp_path / "out"
    report = scanner.scan_schema_context(imported, output)
    assert report["all_selected_fields_visited"] and report["selected_fields"] == 4
    rows = records(output, "schema_context_review_queue")
    assert any(r["column_name"] == "session_id" and r["start_row"] == 1 and r["status"] == "schema_context_candidate" and r["subtype"] == "session_identifier" for r in rows)
    assert any(r["column_name"] == "session_id" and r["start_row"] <= 5 <= r["end_row"] and r["status"] == "schema_context_candidate" for r in rows)  # The literal null is not Arrow null.
    assert any(r["column_name"] == "author_email" and r["start_row"] == 1 and r["status"] == "invalid" for r in rows)
    assert any(r["column_name"] == "author_email" and r["start_row"] == 2 and r["status"] == "placeholder_or_example" for r in rows)
    assert all(r["human_review_status"] == "pending" and not r["personal_ownership_confirmed"] for r in rows)
    assert all(r["candidate_status"] == "schema_context_candidate" for r in records(output, "schema_context_candidates"))
    assert all(r["category"] != "AUTH" for r in rows)
    assert report["counts"]["cells_decoded"] == 24
    for path in output.iterdir():
        if path.is_file():
            data = path.read_bytes()
            assert b"UNIQUE_METADATA_NAME_QZ" not in data and b"opaque-session-key" not in data and b"mailbox@notreservedqz.org" not in data


def test_all_scalar_unmapped_fields_remain_unread_and_explicitly_unresolved(tmp_path):
    imported, _ = frozen(tmp_path, {"repository": pa.table({"id": [1, 2], "full_name": ["name-a", "name-b"], "enabled": [True, False], "size": [None, 1.0]})})
    output = tmp_path / "out"
    report = scanner.scan_schema_context(imported, output)
    assert report["selected_fields"] == 0 and report["scalar_fields"] == 4 and report["counts"] == {}
    rows = records(output, "schema_unresolved_fields")
    assert len(rows) == 4 and all(r["status"] == "schema_semantics_unresolved" for r in rows)
    assert all(r["row_count"] == 2 and r["start_row"] == 1 and r["end_row"] == 2 and not r["values_decoded"] for r in rows)
    assert all(r["empty_count"] is None and r["invalid_count"] is None for r in rows)
    assert next(r for r in rows if r["column_name"] == "size")["footer_null_count"] == 1
    assert records(output, "schema_context_candidates") == []
    assert records(output, "schema_type_summary") == []
    assert (output / "schema_type_summary.csv").read_text().splitlines()[0].startswith("category,subtype,candidate_source_cells,")
    assert report["all_dataset_values_classified"] is False


def test_ranges_do_not_cross_quality_gaps_or_fields(tmp_path):
    imported, _ = frozen(tmp_path, {"user": pa.table({"id": [1, 2, None, 4], "login": ["one", "two", "", "four"]})})
    output = tmp_path / "out"
    scanner.scan_schema_context(imported, output, batch_size=1)
    rows = records(output, "schema_context_review_queue")
    for col in ("id", "login"):
        assert [(r["start_row"], r["end_row"]) for r in rows if r["column_name"] == col] == [(1, 2), (3, 3), (4, 4)]
    assert len(cells(output)) == 8 and all(n == 1 for n in cells(output).values())


@pytest.mark.parametrize("budget", [7, 8])
def test_field_and_row_group_resume_is_exact_once_and_idempotent(tmp_path, monkeypatch, budget):
    imported, _ = frozen(tmp_path, {"user": pa.table({"id": [1, 2, 3, 4, 5], "login": ["one", "two", "three", "four", "five"]})})
    reference = tmp_path / "reference"
    scanner.scan_schema_context(imported, reference, batch_size=4)
    original = scanner._quality; clock = [0]; seen = []
    monkeypatch.setattr(scanner.time, "monotonic", lambda: clock[0])
    def timed(value, role):
        seen.append((value, role)); clock[0] += 1
        return original(value, role)
    monkeypatch.setattr(scanner, "_quality", timed)
    output = tmp_path / "out"
    partial = scanner.scan_schema_context(imported, output, batch_size=2, max_seconds=budget)
    assert partial["stop_reason"] == "time_budget" and partial["counts"]["cells_decoded"] == budget
    login = next(f for f in partial["fields"] if f["column_name"] == "login")
    assert login["next_row"] == budget - 5 and login["next_row_group"] == 1
    result = scanner.scan_schema_context(imported, output, resume=True, batch_size=1)
    assert result["all_selected_fields_visited"] and result["counts"]["cells_decoded"] == 10 and len(seen) == 10
    assert cells(output) == cells(reference)
    before = checkpoint(output)
    (output / "schema_context_candidates.jsonl").write_text("interrupted export")
    scanner.scan_schema_context(imported, output, resume=True)
    assert checkpoint(output) == before and len(seen) == 10
    assert records(output, "schema_context_candidates") == records(reference, "schema_context_candidates")


def test_failure_in_batch_rolls_back_ranges_and_cursor(tmp_path, monkeypatch):
    imported, _ = frozen(tmp_path, {"user": pa.table({"id": [1, 2, 3, 4]})}, row_group_size=4)
    original = scanner._quality
    def fail(value, role):
        if value == 4: raise RuntimeError("synthetic failure")
        return original(value, role)
    monkeypatch.setattr(scanner, "_quality", fail)
    output = tmp_path / "out"
    with pytest.raises(RuntimeError, match="synthetic failure"):
        scanner.scan_schema_context(imported, output, batch_size=2)
    with sqlite3.connect(output / "schema.sqlite") as db:
        assert db.execute("SELECT next_row FROM fields").fetchone()[0] == 2
        assert db.execute("SELECT start_row,end_row FROM ranges").fetchall() == [(1, 2)]
    monkeypatch.setattr(scanner, "_quality", original)
    scanner.scan_schema_context(imported, output, resume=True)
    rows = records(output, "schema_context_review_queue")
    assert len(rows) == 1 and rows[0]["start_row"] == 1 and rows[0]["end_row"] == 4


def test_source_hash_and_classifier_fingerprint_freeze(tmp_path, monkeypatch):
    imported, source = frozen(tmp_path, {"user": pa.table({"id": [1]})})
    output = tmp_path / "out"
    scanner.scan_schema_context(imported, output)
    monkeypatch.setattr(scanner, "_sources", lambda: {"changed": "synthetic"})
    with pytest.raises(ValueError, match="identical frozen"):
        scanner.scan_schema_context(imported, output, resume=True)
    path = source / "user.parquet"; raw = bytearray(path.read_bytes()); raw[len(raw)//2] ^= 1; path.write_bytes(raw)
    with pytest.raises(ValueError, match="hash changed"):
        scanner.scan_schema_context(imported, output, resume=True)


def test_empty_selected_table_completes_without_fake_values(tmp_path):
    imported, _ = frozen(tmp_path, {"user": pa.table({"id": pa.array([], type=pa.int64()), "login": pa.array([], type=pa.string())})})
    report = scanner.scan_schema_context(imported, tmp_path / "out")
    assert report["all_selected_fields_visited"] and report["counts"] == {}
    assert all(f["next_row"] == 0 and not f["values_decoded"] for f in report["fields"])


@pytest.mark.parametrize("budget", [{"max_seconds": float("nan")}, {"max_seconds": float("inf")}, {"batch_size": True}, {"batch_size": 1.5}])
def test_invalid_budgets_rejected_before_writes_or_source_read(tmp_path, budget):
    output = tmp_path / "out"
    with pytest.raises(ValueError, match="budgets"):
        scanner.scan_schema_context(tmp_path / "not_read", output, **budget)
    assert not output.exists()
