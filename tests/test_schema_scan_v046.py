"""Exact additional actor roles over synthetic Parquet only."""
import pyarrow as pa
import pytest

from agentlog_unified import schema_scan as scanner
from test_schema_scan import cells, frozen, records

LEGACY_ROLES = {
    **{("aidev", t, "user_id"): ("numeric_account_id", "QID", "user_identifier")
       for t in ("all_pull_request", "human_pull_request", "pr_comments", "pull_request")},
    **{("aidev", t, "id"): ("numeric_account_id", "QID", "user_identifier") for t in ("user", "all_user")},
    **{("aidev", t, "login"): ("account_login", "QID", "user_identifier") for t in ("user", "all_user")},
    ("swe-chat", "commits", "author_name"): ("author_name", "PII", "person_name"),
    ("swe-chat", "commits", "author_email"): ("author_email", "PII", "email"),
    ("swe-chat", "commits", "github_username"): ("account_login", "QID", "user_identifier"),
    **{("swe-chat", t, "user_id"): ("account_reference", "QID", "user_identifier")
       for t in ("checkpoints", "commits", "conversations", "sessions")},
    **{("swe-chat", t, "session_id"): ("session_reference", "QID", "session_identifier")
       for t in ("sessions", "session_logs", "conversations")},
}
NEW_FIELDS = [("aidev", table, "user") for table in (
    "all_pull_request", "human_pull_request", "issue", "pr_comments", "pr_review_comments",
    "pr_review_comments_v2", "pr_reviews", "pull_request")] + [("aidev", "pr_timeline", "actor")]


def test_exact_legacy_roles_and_nine_account_reference_additions_preserved():
    assert {key: scanner.ROLES[key] for key in LEGACY_ROLES} == LEGACY_ROLES
    assert {key for key in scanner.ROLES if key not in LEGACY_ROLES and scanner.ROLES[key][0] != "account_login_join"} == set(NEW_FIELDS)
    assert all(scanner.ROLES[key] == ("account_reference", "QID", "user_identifier") for key in NEW_FIELDS)
    for key in [("aidev", "repository", "user"), ("aidev", "repository", "assignee"),
                ("swe-chat", "checkpoints", "session_pks"), ("swe-chat", "checkpoints", "author_user_ids"),
                ("aidev", "pr_commits", "message"), ("swe-chat", "conversations", "tool_input_json")]:
        assert key not in scanner.ROLES


@pytest.mark.parametrize("dataset,table,column", NEW_FIELDS)
def test_each_new_field_quality_ranges_and_private_exports(tmp_path, dataset, table, column):
    marker = "UNIQUE_ACCOUNT_MARKER_QZ"
    values = [marker, None, "", " ", "placeholder", '{"id":1}', '["opaque"]', "bad\nvalue", "00123", "null"]
    imported, _ = frozen(tmp_path, {table: pa.table({column: values, "owner_id": ["technical"] * 10})}, dataset)
    output = tmp_path / "out"
    report = scanner.scan_schema_context(imported, output, batch_size=3)
    assert report["counts"] == {"cells_decoded": 10, "schema_context_candidate": 3, "null": 1,
                                "empty": 2, "placeholder_or_example": 1, "invalid": 3}
    assert report["selected_fields"] == 1 and report["unresolved_field_records"] == 1
    expected = ["schema_context_candidate", "null", "empty", "empty", "placeholder_or_example",
                "invalid", "invalid", "invalid", "schema_context_candidate", "schema_context_candidate"]
    coverage = cells(output)
    assert len(coverage) == 10 and set(coverage.values()) == {1}
    assert [next(key[3] for key in coverage if key[2] == row) for row in range(1, 11)] == expected
    for row in records(output, "schema_context_review_queue"):
        assert (row["category"], row["subtype"], row["schema_role"]) == ("QID", "user_identifier", "account_reference")
        assert row["human_review_status"] == "pending" and row["confidence"] == "low"
        assert not any(row[key] for key in ("runtime_confirmed", "sensitivity_confirmed", "personal_ownership_confirmed", "application_log_evidence"))
    assert records(output, "schema_type_summary")[0]["candidate_source_cells"] == 3
    assert "32 explicit field roles" in report["limitations"][0]
    for path in output.iterdir():
        if path.is_file():
            assert marker.encode() not in path.read_bytes()


def test_new_scalar_role_rejects_numeric_value_and_keeps_nested_unread(tmp_path):
    imported, _ = frozen(tmp_path, {
        "issue": pa.table({"user": [123]}),
        "pr_timeline": pa.table({"actor": [["opaque"]]})})
    output = tmp_path / "out"
    report = scanner.scan_schema_context(imported, output)
    assert report["counts"] == {"cells_decoded": 1, "invalid": 1}
    assert records(output, "schema_context_review_queue")[0]["reason"] == "expected_text_schema_field"
    nested = records(output, "schema_unresolved_fields")[0]
    assert nested["status"] == "nested_schema_unresolved" and not nested["values_decoded"]


def test_unresolved_decreases_by_nine_without_generic_or_array_expansion(tmp_path, monkeypatch):
    fields = set(key for key in LEGACY_ROLES if key[0] == "aidev") | set(NEW_FIELDS)
    tables = {}
    for _, table, column in sorted(fields):
        tables.setdefault(table, {})[column] = pa.array([], type=pa.string())
        tables[table]["owner_id"] = pa.array([], type=pa.string())
        tables[table]["name"] = pa.array([], type=pa.string())
    imported, _ = frozen(tmp_path, {name: pa.table(columns) for name, columns in tables.items()})
    output = tmp_path / "out"
    monkeypatch.setattr(scanner, "_quality", lambda *args: pytest.fail("empty dry-run decoded a value"))
    report = scanner.scan_schema_context(imported, output, dry_run=True)
    assert not output.exists() and report["selected_fields"] == 17
    old_unmapped = sum((f["dataset"], f["table"], f["column_name"]) not in LEGACY_ROLES for f in report["fields"])
    new_unmapped = sum(not f["selected_for_value_scan"] for f in report["fields"])
    assert old_unmapped - new_unmapped == 9
    assert all(not f["selected_for_value_scan"] for f in report["fields"] if f["column_name"] in {"owner_id", "name"})
