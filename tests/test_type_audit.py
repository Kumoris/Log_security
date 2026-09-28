"""Type audits over synthetic machine records; no target application execution."""
from copy import deepcopy
import csv
import json

import pytest

from agentlog_unified.config import PROJECT
from agentlog_unified.export import export_run
from agentlog_unified.storage import Store
from agentlog_unified.type_audit import build_type_audit


def entity(source="password", kind="credential", risk="supported", **extra):
    return {"path": "app.py", "symbol": "run", "identity": "log-1", "start_line": 3, "end_line": 3,
            "statement": 'logger.info("value", value)', "parser_status": "python_ast",
            "privacy_assessment": risk, "data_types": [kind] if kind else [],
            "source_to_sink": [{"source": source, "types": [kind], "basis": "explicit_sensitive_access"}] if kind else [],
            "dependencies": [], "missing_evidence": ["runtime_reachability_and_output_access_unverified"], **extra}


def event(eid, sha, parent, before, after, **extra):
    return {"id": eid, "repository_id": "r", "sha": sha, "parent_sha": parent, "before": before, "after": after,
            "relation": "direct_call_change", "change_kind": "modified", "extraction_status": "ok",
            "file_change_ids": ["diff-" + eid], **extra}


def input_data(events, shas=("c1",)):
    return {"prs": [{"id": "p", "repository": "example/repo", "pr_number": 1, "initial_commit_shas": list(shas)}],
            "repositories": [{"id": "r", "pr_ids": ["p"], "repository_id": "example/repo"}],
            "commits": [{"repository_id": "r", "sha": sha} for sha in shas],
            "snapshots": [{"repository_id": "r", "sha": sha, "whole_snapshot_unavailable": False} for sha in shas],
            "file_changes": [{"repository_id": "r", "sha": sha, "old_path": "app.py", "new_path": "app.py",
                              "extraction_status": "ok", "change_id": "diff-" + sha} for sha in shas],
            "log_events": events}


def summary(out, category, subtype=None):
    return next(row for row in out["type_summary"] if row["category"] == category and row["subtype"] == subtype)


def test_empty_audit_has_zero_counts_catalog_and_no_unknown_queue():
    out = build_type_audit()
    assert out["taxonomy_catalog"]["taxonomy_version"] == "1.2.0"
    assert out["type_occurrences"] == out["unknown_type_review_queue"] == out["pr_coverage_audit"] == []
    assert out["type_summary"] and all(row["log_version_count"] == 0 for row in out["type_summary"])
    assert out["type_summary_metadata"]["denominators"]["input_github_prs"] == 0


def test_endpoints_and_duplicate_snapshots_collapse_to_one_version_without_mutating_input():
    secret, safe = entity(), entity(kind=None, risk="not_supported")
    events = [event("e1", "c1", "c0", None, secret), event("e2", "c2", "c1", secret, safe)]
    snapshots = [{**secret, "id": "snap-1", "repository_id": "r", "snapshot_sha": "c1"}] * 3
    inputs = input_data(events, ("c1", "c2"))
    original = deepcopy(inputs)
    out = build_type_audit(**inputs, log_entities=snapshots)
    assert inputs == original
    assert len(out["type_occurrences"]) == 2
    first = next(r for r in out["type_occurrences"] if r["snapshot_sha"] == "c1")
    assert first["snapshot_entity_ids"] == ["snap-1"]
    assert {(r["event_id"], r["side"]) for r in first["event_references"]} == {("e1", "after"), ("e2", "before")}
    assert summary(out, "AUTH", "password")["log_version_count"] == 1


def test_deletion_retains_before_type_and_uses_last_observed_sha_for_gap_resumption():
    deletion = event("delete", "c2", "c1", entity(), None, change_kind="deleted")
    resumed = event("resume", "c5", "c4", entity(), None, change_kind="gap_resumed", comparison_before_sha="c1")
    out = build_type_audit(**input_data([deletion, resumed], ("c2", "c5")))
    assert len(out["type_occurrences"]) == 1
    assert out["type_occurrences"][0]["snapshot_sha"] == "c1"
    assert len(out["type_occurrences"][0]["event_references"]) == 2
    assert summary(out, "AUTH")["distinct_event_count"] == 2


def test_later_new_type_and_dependency_only_change_are_exported_without_l3():
    a, b = entity(), entity("email", "personal_identifier")
    first = event("e1", "c1", "c0", None, a)
    later = event("e2", "c2", "c1", a, b, relation="dependency_change")
    origin = {"case_id": "case1", "pr_id": "p", "log_change_id": "e1"}
    follow = {**later, "id": "follow1", "case_id": "case1", "log_change_id": "e1"}
    out = build_type_audit(**input_data([first, later]), log_changes=[origin], followups=[follow])
    pii = summary(out, "PII", "email")
    assert pii["log_version_count"] == 1 and pii["initial_github_pr_count"] == 0
    assert pii["tracked_followup_event_count"] == 1
    row = next(r for r in out["type_occurrences"] if r["snapshot_sha"] == "c2")
    assert row["observation_scopes"] == ["tracked_followup"] and row["tracked_followup_pr_ids"] == ["p"]
    assert row["event_references"][0]["relation"] == "dependency_change"


def test_multiple_commits_in_one_pr_and_shared_commit_across_prs_have_separate_denominators():
    a = entity()
    events = [event("e1", "c1", "c0", None, a), event("e2", "c2", "c1", a, a)]
    data = input_data(events, ("c1", "c2"))
    data["prs"].append({"id": "p2", "repository": "example/repo", "pr_number": 2, "initial_commit_shas": ["c1"]})
    data["repositories"][0]["pr_ids"].append("p2")
    out = build_type_audit(**data)
    row = summary(out, "AUTH")
    assert row["log_version_count"] == 2
    assert row["distinct_event_count"] == 2
    assert row["initial_github_pr_count"] == 2
    assert out["type_summary_metadata"]["denominators"]["input_github_prs"] == 2


def test_multilabel_category_summary_counts_versions_once():
    value = entity()
    value["source_to_sink"].extend([
        {"source": "api_key", "types": ["credential"], "basis": "explicit_sensitive_access"},
        {"source": "email", "types": ["personal_identifier"], "basis": "explicit_sensitive_access"}])
    out = build_type_audit(**input_data([event("e", "c1", "c0", None, value)]))
    assert summary(out, "AUTH")["log_version_count"] == summary(out, "PII")["log_version_count"] == 1
    assert summary(out, "AUTH", "password")["log_version_count"] == 1
    assert summary(out, "AUTH", "api_key")["log_version_count"] == 1
    assert out["type_summary_metadata"]["denominators"]["distinct_observed_log_versions"] == 1


def test_snapshot_only_has_no_invented_initial_pr_relation():
    out = build_type_audit(log_entities=[{**entity(), "repository_id": "r", "snapshot_sha": "c7", "id": "snapshot1"}])
    row = out["type_occurrences"][0]
    assert row["observation_scopes"] == ["snapshot_only"] and row["initial_pr_ids"] == []
    assert summary(out, "AUTH")["snapshot_only_version_count"] == 1


@pytest.mark.parametrize("value", [
    entity(kind=None, risk="unknown", missing_evidence=["unresolved_value:opaque"]),
    entity("request", "opaque_object", risk="possible"),
    entity(parser_status="lexical_only", missing_evidence=["js_ts_semantics_unparsed"]),
])
def test_unknown_carrier_and_semantic_gaps_are_pending_not_new_types(value):
    out = build_type_audit(log_events=[event("e", "c1", "c0", None, value)])
    assert len(out["unknown_type_review_queue"]) == 1
    row = out["unknown_type_review_queue"][0]
    assert row["human_review_status"] == "pending"
    assert row["runtime_confirmed"] is False and row["new_type_status"] == "not_established"


def test_safe_fixed_message_is_not_in_unknown_type_queue():
    value = entity(kind=None, risk="not_supported")
    out = build_type_audit(**input_data([event("e", "c1", "c0", None, value)]))
    assert not out["unknown_type_review_queue"]
    assert out["pr_coverage_audit"][0]["no_sensitive_evidence_observed"] is True


def test_missing_analysis_is_neither_no_log_nor_no_sensitive_evidence():
    out = build_type_audit(prs=input_data([])["prs"])
    row = out["pr_coverage_audit"][0]
    assert not row["has_git_evidence"] and not row["analyzed_in_supported_scope"]
    assert row["coverage_status"] == "not_analyzed"
    assert row["no_log_behavior_change_observed"] is None and row["no_sensitive_evidence_observed"] is None


def test_git_evidence_without_snapshot_is_not_analyzed():
    data = input_data([])
    data["snapshots"] = []
    row = build_type_audit(**data)["pr_coverage_audit"][0]
    assert row["has_git_evidence"] and not row["analyzed_in_supported_scope"]
    assert row["no_log_behavior_change_observed"] is None


def test_partial_snapshot_coverage_cannot_be_a_negative_without_gap_table():
    data = input_data([], ("c1", "c2"))
    data["snapshots"] = [data["snapshots"][0]]
    row = build_type_audit(**data)["pr_coverage_audit"][0]
    assert row["missing_analysis_shas"] == ["c2"]
    assert row["coverage_status"] == "partial" and row["no_log_behavior_change_observed"] is None
    data["snapshots"].append({"repository_id": "r", "sha": "c2", "unavailable_paths": ["app.py"]})
    row = build_type_audit(**data)["pr_coverage_audit"][0]
    assert row["unavailable_snapshot_paths"] == ["app.py"] and row["coverage_status"] == "partial"


def test_actual_no_log_analysis_and_unsupported_language_budget_are_distinct():
    data = input_data([])
    row = build_type_audit(**data)["pr_coverage_audit"][0]
    assert row["no_log_behavior_change_observed"] is True
    assert row["no_sensitive_evidence_observed"] is None
    data["file_changes"].append({"repository_id": "r", "sha": "c1", "new_path": "service.rs", "old_path": None})
    out = build_type_audit(**data, coverage_gaps=[{"repository_id": "r", "error_type": "snapshot_budget_exceeded"}])
    row = out["pr_coverage_audit"][0]
    assert row["unsupported_language_paths"] == ["service.rs"] and row["budget_limited"]
    assert row["coverage_status"] == "partial" and row["no_log_behavior_change_observed"] is None
    metrics = {r["metric"]: r["count"] for r in out["code_coverage_audit"]["metrics"]}
    assert metrics["prs_with_unsupported_language"] == metrics["prs_with_budget_gaps"] == 1


@pytest.mark.parametrize("extension", ["go", "cs"])
def test_lexical_language_selected_and_excluded_coverage_never_overlap(extension):
    data = input_data([])
    path = "service." + extension
    data["file_changes"][0].update(old_path=path, new_path=path)
    data["coverage_gaps"] = [{"repository_id": "r", "error_type": "lexical_fallback_without_ast"}]
    selected = build_type_audit(**data)["pr_coverage_audit"][0]
    assert selected["supported_changed_paths"] == [path]
    assert selected["unsupported_language_paths"] == []
    assert selected["coverage_status"] == "partial" and selected["no_log_behavior_change_observed"] is None
    excluded = build_type_audit(**data, languages=["python"])["pr_coverage_audit"][0]
    assert excluded["supported_changed_paths"] == []
    assert excluded["unsupported_language_paths"] == [path]
    assert excluded["no_sensitive_evidence_observed"] is None


def test_local_fixture_is_not_counted_as_github_pr():
    data = input_data([])
    data["prs"] = [{"id": "p", "initial_commit_shas": ["c1"]}]
    out = build_type_audit(**data)
    assert out["type_summary_metadata"]["denominators"]["input_github_prs"] == 0
    assert out["code_coverage_audit"]["metrics"][-1]["count"] == 1


def test_export_integration_creates_empty_queue_headers_and_redacts_sources(tmp_path):
    store = Store(tmp_path / "private.sqlite")
    canary = "SYNTHETIC_TYPE_AUDIT_NOT_A_CREDENTIAL"
    value = entity(statement='logger.info("value", extra={"password": "' + canary + '"})',
                   dependencies=[{"code": 'password = "' + canary + '"', "semantic_code": canary}])
    with store.db:
        store.replace("log_entities", [{**value, "id": "s", "repository_id": "r", "snapshot_sha": "c1"}])
    config = {"project_dir": str(PROJECT), "random_seed": 42, "languages": ["python"]}
    manifest = {"run_id": "synthetic-type-audit", "versions": {"PyDriller": "test", "python": "test"}, "collection_cutoff_utc": "2026-01-01"}
    export_run(tmp_path, store, manifest, config)
    store.close()
    for relative in ["data/taxonomy_catalog.json", "data/type_occurrences.jsonl", "reports/type_occurrences.csv",
                     "reports/type_summary.csv", "reports/type_summary.json", "data/unknown_type_review_queue.jsonl",
                     "reports/unknown_type_review_queue.csv", "reports/code_coverage_audit.json", "reports/code_coverage_audit.csv"]:
        path = tmp_path / relative
        assert path.is_file() and canary not in path.read_text()
    assert (tmp_path / "data/unknown_type_review_queue.jsonl").read_text() == ""
    assert "occurrence_id" in next(csv.reader((tmp_path / "reports/unknown_type_review_queue.csv").open()))
    summary_json = json.loads((tmp_path / "reports/type_summary.json").read_text())
    assert summary_json["denominators"]["distinct_observed_log_versions"] == 1


def batch_database(records):
    import sqlite3
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE records(repository TEXT,sha TEXT,kind TEXT,id TEXT,data TEXT,PRIMARY KEY(repository,sha,kind,id))")
    for record in records:
        db.execute("INSERT INTO records VALUES(?,?,?,?,?)", (record["repository"], record["sha"], "log_observations", record["id"], json.dumps(record)))
    db.commit()
    return db


def batch_observation(oid, vid, value, **extra):
    return {"id": oid, "repository": "example/repo", "sha": "c1", "parent_sha": "c0", "side": "after", "snapshot_sha": "c1", "log_version_id": vid, "entity": value, **extra}


def test_batch_type_export_deduplicates_parents_and_sides_with_multilabel_counts(tmp_path):
    from agentlog_unified.type_audit import export_batch_types
    value = entity()
    value["source_to_sink"].extend([
        {"source": "api_key", "types": ["credential"], "basis": "explicit_sensitive_access"},
        {"source": "email", "types": ["personal_identifier"], "basis": "explicit_sensitive_access"},
    ])
    unknown = entity("request", "opaque_object", risk="possible", identity="log-2")
    records = [batch_observation("a", "version-one", value),
               batch_observation("b", "version-one", value, parent_sha="other-parent"),
               batch_observation("c", "version-one", value, sha="c2", parent_sha="c1", side="before"),
               batch_observation("d", "version-two", unknown)]
    with batch_database(records) as db:
        result = export_batch_types(db, tmp_path)
        assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 4
    assert result["source_log_observations"] == 4
    assert result["distinct_observed_log_versions"] == 2
    assert result["unknown_type_review_count"] == 1
    occurrences = [json.loads(line) for line in (tmp_path / "type_occurrences.jsonl").read_text().splitlines()]
    first = next(row for row in occurrences if row["log_version_id"] == "version-one")
    assert len(first["event_references"]) == 3
    report = json.loads((tmp_path / "type_summary.json").read_text())
    observed = {(row["category"], row["subtype"]): row["log_version_count"] for row in report["summary"]}
    assert observed[("AUTH", None)] == observed[("AUTH", "password")] == observed[("AUTH", "api_key")] == 1
    assert observed[("PII", "email")] == 1
    assert report["denominators"]["distinct_observed_log_versions"] == 2
    assert report["observation_scope"] == "dataset_commit_changes"
    assert not report["full_history_tracing_completed"] and not report["full_dataset_coverage_claim"]
    queue = json.loads((tmp_path / "unknown_type_review_queue.jsonl").read_text())
    assert queue["human_review_status"] == "pending" and queue["runtime_confirmed"] is False
    assert queue["new_type_status"] == "not_established"


def test_batch_export_retains_pending_unknown_and_redacts_all_public_outputs(tmp_path):
    from agentlog_unified.type_audit import export_batch_types
    canary = "SYNTHETIC_BATCH_ONLY_NOT_A_CREDENTIAL"
    value = entity(kind=None, risk="unknown", path='=HYPERLINK("test")',
                   statement='logger.info("value", extra={"password":"' + canary + '"})',
                   dependencies=[{"code": 'password = "' + canary + '"', "semantic_code": canary}],
                   missing_evidence=["unresolved_value:opaque"], human_review_status="confirmed", runtime_confirmed=True)
    with batch_database([batch_observation("one", "version-one", value)]) as db:
        result = export_batch_types(db, tmp_path)
    for path in map(__import__("pathlib").Path, result["paths"].values()):
        assert canary not in path.read_text()
        assert path.stat().st_mode & 0o077 == 0
    with (tmp_path / "unknown_type_review_queue.csv").open() as stream:
        row = next(csv.DictReader(stream))
    assert row["path"].startswith("'=")
    assert row["human_review_status"] == "pending" and row["runtime_confirmed"] == "False"


def test_empty_batch_has_catalog_zeros_and_csv_queue_header(tmp_path):
    from agentlog_unified.type_audit import export_batch_types
    with batch_database([]) as db:
        result = export_batch_types(db, tmp_path)
    assert result["source_log_observations"] == result["distinct_observed_log_versions"] == 0
    assert result["observed_category_count"] == result["unknown_type_review_count"] == 0
    assert (tmp_path / "unknown_type_review_queue.jsonl").read_text() == ""
    assert "occurrence_id" in next(csv.reader((tmp_path / "unknown_type_review_queue.csv").open()))
    assert all(row["log_version_count"] == 0 for row in json.loads((tmp_path / "type_summary.json").read_text())["summary"])


def test_batch_export_conflicting_version_id_preserves_existing_files(tmp_path):
    from agentlog_unified.type_audit import export_batch_types
    old = tmp_path / "type_occurrences.jsonl"
    old.write_text("previous completed export\n")
    records = [batch_observation("one", "same", entity()), batch_observation("two", "same", entity(start_col=12))]
    with batch_database(records) as db:
        with pytest.raises(ValueError, match="Conflicting identity"):
            export_batch_types(db, tmp_path)
    assert old.read_text() == "previous completed export\n"
    assert not list(tmp_path.glob(".batch-types-*"))


def test_batch_export_streams_without_fetchall_and_retains_annotation_version_gap(tmp_path):
    from agentlog_unified.type_audit import export_batch_types
    value = entity(kind=None, risk="not_supported", taxonomy_version="old", taxonomy_labels=[],
                   unknown_type_review={"needs_review": False, "reasons": []}, taxonomy_status="no_sensitive_evidence")
    records = [batch_observation(str(i), f"version-{i}", value) for i in range(200)]
    db = batch_database(records)

    class Cursor:
        def __init__(self, cursor): self.cursor = cursor
        def __iter__(self): return self
        def __next__(self): return next(self.cursor)
        def fetchall(self): raise AssertionError("Batch code records must stream")

    class Reader:
        def execute(self, *args): return Cursor(db.execute(*args))

    result = export_batch_types(Reader(), tmp_path)
    db.close()
    assert result["distinct_observed_log_versions"] == result["unknown_type_review_count"] == 200
    first = json.loads((tmp_path / "unknown_type_review_queue.jsonl").read_text().splitlines()[0])
    assert "taxonomy_version_mismatch_requires_reanalysis" in first["unknown_type_review"]["reasons"]
    assert first["taxonomy_version"] == "old"
