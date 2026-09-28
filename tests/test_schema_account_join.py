"""Exact account joins against real, miniature frozen Parquet fixtures."""
import hashlib
import json

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from agentlog_unified import schema_scan as scanner
from test_schema_scan import cells, checkpoint, frozen, records
from test_schema_scan_v046 import LEGACY_ROLES, NEW_FIELDS


JOIN_FIELDS = [("aidev", table, column) for table in ("pr_commits", "pr_commit_details")
               for column in ("author", "committer")] + [("aidev", "pr_timeline", "assignee")]


def reference_tables():
    return {"user": pa.table({"login": ["CaseActor", "00123", "\u00e9Actor", "placeholder"]}),
            "all_user": pa.table({"login": ["CaseActor", "JOIN_MARKER_QZX", None, ""]})}


def joined_rows(output):
    return [r for r in records(output, "schema_context_review_queue") if r["schema_role"] == "account_login_join"]


def test_exactly_five_roles_added_and_old_twenty_seven_field_ids_stay_stable(tmp_path):
    old_roles = {**LEGACY_ROLES, **{k: ("account_reference", "QID", "user_identifier") for k in NEW_FIELDS}}
    assert len(old_roles) == 27 and len(scanner.ROLES) == 32
    assert sum(key[0] == "aidev" for key in scanner.ROLES) == 22
    assert {key: scanner.ROLES[key] for key in old_roles} == old_roles
    assert set(scanner.ROLES) - set(old_roles) == set(JOIN_FIELDS)
    assert all(scanner.ROLES[key] == ("account_login_join", "QID", "user_identifier") for key in JOIN_FIELDS)
    for dataset in ("aidev", "swe-chat"):
        root = tmp_path / dataset; root.mkdir()
        tables = {}
        for (ds, table, column), (role, _, _) in old_roles.items():
            if ds == dataset:
                tables.setdefault(table, {})[column] = pa.array([1] if role == "numeric_account_id" else ["opaque"])
        imported, _ = frozen(root, {name: pa.table(cols) for name, cols in tables.items()}, dataset)
        report = scanner.scan_schema_context(imported, root / "out", dry_run=True)
        manifest_sha = hashlib.sha256((imported / "manifest.json").read_bytes()).hexdigest()
        assert report["selected_fields"] == sum(k[0] == dataset for k in old_roles)
        for field in report["fields"]:
            expected = scanner.storage.stable_id("schema-context-1", manifest_sha, field["table_path"], field["column_name"])
            assert field["field_id"] == expected


def test_all_four_joins_are_exact_with_separate_quality_and_no_exported_values(tmp_path):
    values = ["CaseActor", "00123", "JOIN_MARKER_QZX", "caseactor", " CaseActor", "CaseActor ",
              "e\u0301Actor", "unknown-actor", None, "", " ", "placeholder", '{"id":1}', "bad\nvalue"]
    tables = reference_tables()
    tables.update({table: pa.table({"author": values, "committer": values, "name": values})
                   for table in ("pr_commits", "pr_commit_details")})
    imported, _ = frozen(tmp_path, tables)
    output = tmp_path / "out"
    report = scanner.scan_schema_context(imported, output, batch_size=3)
    assert report["selected_fields"] == 6 and report["unresolved_field_records"] == 2
    assert report["counts"]["cells_decoded"] == 64  # 56 joined cells + 8 independently classified reference cells.
    assert report["account_reference_coverage"]["reference_cells_decoded"] == 8
    assert report["account_reference_coverage"]["distinct_nonempty_reference_strings"] == 5
    assert report["account_reference_coverage"]["status"] == "complete"
    for table in ("pr_commits", "pr_commit_details"):
        for column in ("author", "committer"):
            field = next(f for f in report["fields"] if f["table"] == table and f["column_name"] == column)
            assert field["counts"] == {"cells_decoded": 14, "schema_context_candidate": 3,
                "unresolved": 5, "null": 1, "empty": 2, "placeholder_or_example": 1, "invalid": 2}
            subset = [r for r in joined_rows(output) if r["table_path"] == table + ".parquet" and r["column_name"] == column]
            assert sum(r["row_count"] for r in subset) == 14
            assert [(r["start_row"], r["end_row"]) for r in subset if r["status"] == "schema_context_candidate"] == [(1, 3)]
    for row in joined_rows(output):
        assert row["human_review_status"] == "pending" and row["confidence"] == "low"
        assert not row["personal_ownership_confirmed"] and not row["application_log_evidence"]
        if row["status"] == "schema_context_candidate":
            assert (row["category"], row["subtype"]) == ("QID", "user_identifier")
            assert row["reason"] == "exact_frozen_account_login_match"
        else:
            assert row["category"] is None and row["subtype"] is None and row["candidate_status"] is None
        if row["status"] == "unresolved":
            assert row["reason"] == "account_login_not_found_in_frozen_references"
    for path in output.iterdir():
        if path.is_file():
            data = path.read_bytes()
            for value in ("JOIN_MARKER_QZX", "CaseActor", "unknown-actor"):
                assert value.encode() not in data and hashlib.sha256(value.encode()).hexdigest().encode() not in data


def test_timeline_assignee_requires_exact_join_without_generic_field_expansion(tmp_path):
    tables = reference_tables()
    tables["pr_timeline"] = pa.table({"assignee": ["CaseActor", "caseactor", None, "", "placeholder", "bad\nvalue"],
                                      "actor": ["OtherActor"] * 6})
    tables["repository"] = pa.table({"assignee": ["CaseActor"]})
    imported, _ = frozen(tmp_path, tables)
    output = tmp_path / "out"; report = scanner.scan_schema_context(imported, output)
    rows = joined_rows(output)
    assert [r["status"] for r in rows] == ["schema_context_candidate", "unresolved", "null", "empty", "placeholder_or_example", "invalid"]
    assert all(r["column_name"] == "assignee" and r["table_path"] == "pr_timeline.parquet" for r in rows)
    assert rows[0]["reason"] == "exact_frozen_account_login_match"
    assert rows[1]["category"] is None and rows[1]["reason"] == "account_login_not_found_in_frozen_references"
    actor = next(f for f in report["fields"] if f["column_name"] == "actor")
    assert actor["schema_role"] == "account_reference" and actor["counts"]["schema_context_candidate"] == 6
    unresolved = records(output, "schema_unresolved_fields")
    assert len(unresolved) == 1 and unresolved[0]["table_path"] == "repository.parquet"
    assert not unresolved[0]["values_decoded"]


@pytest.mark.parametrize("other,source_status", [(None, "missing_table"),
    (pa.table({"id": [1]}), "missing_column"), (pa.table({"login": [123]}), "unsupported_type")])
def test_partial_references_keep_known_matches_and_unmatched_values_unresolved(tmp_path, other, source_status):
    tables = {"user": pa.table({"login": ["KnownActor"]}), "pr_commits": pa.table({"author": ["KnownActor", "UnknownActor"]})}
    if other is not None: tables["all_user"] = other
    imported, _ = frozen(tmp_path, tables)
    output = tmp_path / "out"; report = scanner.scan_schema_context(imported, output)
    coverage = report["account_reference_coverage"]
    assert coverage["status"] == "partial"
    assert next(s for s in coverage["sources"] if s["table"] == "all_user")["status"] == source_status
    rows = joined_rows(output)
    assert rows[0]["status"] == "schema_context_candidate"
    assert rows[1]["status"] == "unresolved"
    assert rows[1]["reason"] == "account_reference_sources_unavailable_or_incomplete"


@pytest.mark.parametrize("empty", [False, True])
def test_missing_or_empty_references_are_not_silent_negative_evidence(tmp_path, empty):
    tables = {"pr_commits": pa.table({"author": ["OpaqueActor", None, "placeholder"]})}
    if empty:
        tables.update({t: pa.table({"login": pa.array([None, ""], type=pa.string())}) for t in ("user", "all_user")})
    imported, _ = frozen(tmp_path, tables)
    output = tmp_path / "out"; report = scanner.scan_schema_context(imported, output)
    assert report["account_reference_coverage"]["status"] == ("empty" if empty else "unavailable")
    rows = joined_rows(output)
    assert [r["status"] for r in rows] == ["unresolved", "null", "placeholder_or_example"]
    assert rows[0]["reason"] == ("account_reference_contains_no_values" if empty else "account_reference_sources_unavailable_or_incomplete")
    assert records(output, "schema_context_candidates") == []


def test_join_nontext_target_is_invalid_and_nested_target_stays_unread(tmp_path):
    tables = reference_tables()
    tables["pr_commits"] = pa.table({"author": [123], "committer": [["CaseActor"]]})
    imported, _ = frozen(tmp_path, tables)
    output = tmp_path / "out"; report = scanner.scan_schema_context(imported, output)
    row = joined_rows(output)[0]
    assert row["status"] == "invalid" and row["reason"] == "expected_text_schema_field"
    assert row["category"] is None and row["subtype"] is None
    nested = records(output, "schema_unresolved_fields")[0]
    assert nested["column_name"] == "committer" and nested["status"] == "nested_schema_unresolved"
    assert not nested["values_decoded"] and report["counts"]["cells_decoded"] == 9


def test_reference_decoder_failure_is_explicit_and_sanitized(tmp_path, monkeypatch):
    tables = reference_tables(); tables["pr_commits"] = pa.table({"author": ["CaseActor"]})
    imported, _ = frozen(tmp_path, tables)
    def fail(*args, **kwargs):
        raise RuntimeError("SYNTHETIC_SOURCE_VALUE_MUST_NOT_ESCAPE")
    monkeypatch.setattr(pq.ParquetFile, "iter_batches", fail)
    output = tmp_path / "out"
    with pytest.raises(ValueError, match="Frozen account reference could not be read") as error:
        scanner.scan_schema_context(imported, output)
    assert "SYNTHETIC_SOURCE_VALUE_MUST_NOT_ESCAPE" not in str(error.value)
    assert not (output / "manifest.json").exists() and not (output / "schema.sqlite").exists()


def test_join_dry_run_does_not_decode_either_targets_or_references(tmp_path, monkeypatch):
    tables = reference_tables(); tables["pr_commits"] = pa.table({"author": ["CaseActor"]})
    imported, _ = frozen(tmp_path, tables)
    monkeypatch.setattr(pq.ParquetFile, "iter_batches", lambda *a, **kw: pytest.fail("dry-run read data pages"))
    monkeypatch.setattr(scanner, "_quality", lambda *a: pytest.fail("dry-run inspected a value"))
    output = tmp_path / "out"; report = scanner.scan_schema_context(imported, output, dry_run=True)
    assert not output.exists() and not report["values_decoded"]
    assert report["account_reference_coverage"]["status"] == "not_decoded"
    assert report["account_reference_coverage"]["reference_cells_decoded"] == 0
    assert report["account_reference_coverage"]["distinct_nonempty_reference_strings"] is None
    assert all(not s["values_decoded"] for s in report["account_reference_coverage"]["sources"])


@pytest.mark.parametrize("update_manifest", [False, True])
def test_changed_reference_rejects_resume_before_lookup_decode(tmp_path, monkeypatch, update_manifest):
    tables = reference_tables(); tables["pr_commits"] = pa.table({"author": ["CaseActor"]})
    imported, source = frozen(tmp_path, tables)
    output = tmp_path / "out"; scanner.scan_schema_context(imported, output)
    before = checkpoint(output)
    path = source / "user.parquet"; pq.write_table(pa.table({"login": ["DifferentActor"]}), path)
    if update_manifest:
        manifest_path = imported / "manifest.json"; manifest = json.loads(manifest_path.read_text())
        item = next(i for i in manifest["source_signature"]["inputs"] if i["path"] == path.name)
        item.update(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        manifest_path.write_text(json.dumps(manifest))
    monkeypatch.setattr(scanner, "_account_references", lambda *a, **kw: pytest.fail("changed frozen source was decoded"))
    with pytest.raises(ValueError, match="identical frozen|hash changed"):
        scanner.scan_schema_context(imported, output, resume=True)
    assert checkpoint(output) == before


def test_reference_mutation_after_lookup_blocks_successful_export(tmp_path, monkeypatch):
    tables = reference_tables(); tables["pr_commits"] = pa.table({"author": ["CaseActor"]})
    imported, source = frozen(tmp_path, tables)
    original = scanner._joined_account_quality
    def mutate(value, references, coverage):
        result = original(value, references, coverage)
        pq.write_table(pa.table({"login": ["DifferentActor"]}), source / "user.parquet")
        return result
    monkeypatch.setattr(scanner, "_joined_account_quality", mutate)
    output = tmp_path / "out"
    with pytest.raises(ValueError, match="account reference changed"):
        scanner.scan_schema_context(imported, output)
    assert not (output / "schema_coverage.json").exists()


def test_join_resume_preserves_each_source_cell_once_and_is_idempotent(tmp_path, monkeypatch):
    tables = {"pr_commits": pa.table({"author": ["Known", "Known", "Other", "Known", "Known"],
                                     "committer": ["Other", "Known", None, "Known", "Known"]}),
              "user": pa.table({"login": ["Known"]}), "all_user": pa.table({"login": ["Known"]})}
    imported, _ = frozen(tmp_path, tables, row_group_size=3)
    reference = tmp_path / "reference"; scanner.scan_schema_context(imported, reference, batch_size=2)
    original = scanner._quality; clock = [0]; count = [0]
    monkeypatch.setattr(scanner.time, "monotonic", lambda: clock[0])
    def timed(value, role):
        clock[0] += 1; count[0] += 1
        return original(value, role)
    monkeypatch.setattr(scanner, "_quality", timed)
    output = tmp_path / "out"
    partial = scanner.scan_schema_context(imported, output, batch_size=2, max_seconds=7)
    assert partial["stop_reason"] == "time_budget" and partial["counts"]["cells_decoded"] == 7
    report = scanner.scan_schema_context(imported, output, resume=True, batch_size=1)
    assert count[0] == 12 and report["all_selected_fields_visited"]
    assert report["counts"] == json.loads((reference / "schema_coverage.json").read_text())["counts"]
    assert cells(output) == cells(reference) and set(cells(output).values()) == {1}
    before = checkpoint(output)
    scanner.scan_schema_context(imported, output, resume=True)
    assert count[0] == 12 and checkpoint(output) == before
    assert records(output, "schema_context_review_queue") == records(reference, "schema_context_review_queue")


def test_join_failure_rolls_back_ranges_and_cursor_together(tmp_path, monkeypatch):
    tables = {"pr_commits": pa.table({"author": ["Known", "Known", "Other", "FailHere"]}),
              "user": pa.table({"login": ["Known"]}), "all_user": pa.table({"login": ["Known"]})}
    imported, _ = frozen(tmp_path, tables, row_group_size=4)
    original = scanner._joined_account_quality
    def fail(value, references, coverage):
        if value == "FailHere": raise RuntimeError("synthetic interruption")
        return original(value, references, coverage)
    monkeypatch.setattr(scanner, "_joined_account_quality", fail)
    output = tmp_path / "out"
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        scanner.scan_schema_context(imported, output, batch_size=2)
    snapshot = checkpoint(output)
    assert next(row for row in snapshot["fields"] if row[1] == 2)[1] == 2
    assert [(row[2], row[3]) for row in snapshot["ranges"]] == [(1, 2)]
    monkeypatch.setattr(scanner, "_joined_account_quality", original)
    report = scanner.scan_schema_context(imported, output, resume=True)
    assert report["counts"]["cells_decoded"] == 6
    assert sum(r["row_count"] for r in joined_rows(output)) == 4
    assert set(cells(output).values()) == {1}
