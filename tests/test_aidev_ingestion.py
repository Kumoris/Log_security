"""Real Parquet -> SQLite joins, without API or target repository execution."""
import json
import sqlite3
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from agentlog_unified.aidev import import_aidev
from agentlog_unified.ingest import ingest_records

SHA_A = "a" * 40
SHA_B = "b" * 40


def table(source, name, rows):
    source.mkdir(exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows), source / f"{name}.parquet")


def records(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def fixture(source):
    table(source, "repository", [{"id": 50, "full_name": "Org/Repo", "url": "https://api.github.com/repos/Org/Repo"}])
    table(source, "all_user", [{"id": 11, "login": "person"}])
    table(source, "all_pull_request", [
        {"id": 100, "number": 1, "repo_id": 50, "html_url": "https://github.com/Org/Repo/pull/1", "agent": "Codex", "user_id": 11, "body": "private body sentinel"},
        {"id": 200, "number": 2, "repo_id": 50, "html_url": None, "agent": "Copilot", "user_id": 99, "body": "other private body"},
        {"id": 999, "number": None, "repo_id": None, "html_url": None, "agent": None, "user_id": None, "body": None},
    ])
    table(source, "pull_request", [{"id": 100, "number": 1, "html_url": "https://github.com/org/repo/pull/1", "agent": "Codex"}])
    table(source, "pr_commits", [
        {"pr_id": 100, "sha": SHA_A, "message": "private commit body"},
        {"pr_id": 100, "sha": SHA_A, "message": "duplicate"},
        {"pr_id": 9999, "sha": SHA_B, "message": "orphan"},
    ])
    table(source, "pr_commit_details", [
        {"pr_id": 100, "sha": SHA_A, "filename": "app.py", "patch": "@@ -1 +1 @@\n-private sentinel\n+safe"},
        {"pr_id": 100, "sha": SHA_A, "filename": "missing.py", "patch": None},
        {"pr_id": 100, "sha": SHA_A, "filename": "masked.py", "patch": "[MASKED]"},
    ])
    table(source, "pr_reviews", [{"id": 300, "pr_id": 100, "user": "person", "body": "private review"}])
    table(source, "pr_review_comments", [{"id": 400, "pull_request_review_id": 300, "body": "private inline review"}])
    table(source, "pr_comments", [{"id": 500, "pr_id": 100, "body": "private comment"}])
    table(source, "pr_timeline", [{"pr_id": 100, "commit_id": SHA_B, "event": "referenced", "message": "unrelated sha"}])
    table(source, "issue", [{"id": 600, "number": 8, "html_url": "https://github.com/org/repo/issues/8", "body": "private issue"}])
    table(source, "related_issue", [{"pr_id": 100, "issue_id": 600}, {"pr_id": 100, "issue_id": 601}])
    table(source, "pr_task_type", [{"id": 100, "type": "fix", "reason": "private model reason"}])


def test_multitable_dedup_links_missing_patch_and_provenance(tmp_path):
    source, output = tmp_path / "source", tmp_path / "out"
    fixture(source)
    result = import_aidev(source, output, batch_size=1)
    assert result["complete"] and result["exit_code"] == 2
    assert result["counts"]["source_pr_rows"] == 4
    assert result["counts"]["normalized_prs"] == 2
    assert result["counts"]["duplicate_pr_rows"] == 1
    assert result["counts"]["unresolved_pr_rows"] == 1
    assert result["counts"]["mining_prs"] == 1
    assert result["patch_coverage"] == {"null": 1, "masked": 1, "present_unverified": 1}
    row = records(result["paths"]["mining_prs.jsonl"])[0]
    assert row["commit_shas"] == [SHA_A]  # Timeline references do not establish PR membership.
    assert row["aidev_pr_ids"] == ["100"]
    assert row["provided_label"] == "Codex" and row["verified_actor_type"] == "unknown"
    assert row["related_table_rows"]["pr_review_comments"] == 1
    assert row["related_table_rows"]["related_issue"] == 2
    assert row["provenance_evidence"] == []
    assert len(ingest_records(result["paths"]["normalized_prs.jsonl"])["prs"]) == 2
    assert {"table": "related_issue", "relation": "issue", "status": "orphan", "rows": 1} in result["relationships"]
    assert {"table": "pr_commits", "relation": "pr", "status": "unresolved", "rows": 1} in result["relationships"]
    assert {"table": "pr_reviews", "relation": "user", "status": "linked", "rows": 1} in result["relationships"]
    for path in output.iterdir():
        assert "private body sentinel" not in path.read_bytes().decode("utf-8", "replace")
        assert path.stat().st_mode & 0o077 == 0
    assert output.stat().st_mode & 0o077 == 0
    assert not result["evidence_boundary"]["repository_code_mined"]


def test_column_mapping_and_conflicting_labels_are_not_verified(tmp_path):
    source = tmp_path / "source"
    table(source, "all_pull_request", [{"global_key": 100, "web": "https://github.com/O/R/pull/1", "product": "AgentA"}])
    table(source, "pull_request", [{"id": 101, "html_url": "https://github.com/o/r/pull/1", "agent": "AgentB"}])
    table(source, "pr_commits", [{"parent": 101, "revision": SHA_A}])
    mapping = {"all_pull_request": {"id": "global_key", "pr_url": "web", "agent": "product"}, "pr_commits": {"pr_id": "parent", "sha": "revision"}}
    result = import_aidev(source, tmp_path / "out", column_mapping=mapping)
    row = records(result["paths"]["mining_prs.jsonl"])[0]
    assert row["aidev_pr_ids"] == ["100", "101"]
    assert row["provided_labels"] == ["AgentA", "AgentB"]
    assert row["verified_actor_type"] == row["pr_actor_type"] == "unknown"
    assert row["collection_gaps"][0]["error_type"] == "conflicting_provided_labels"


@pytest.mark.parametrize("mapping", [{"absent": {"id": "x"}}, {"prs": {"surprise": "id"}}, {"prs": {"id": "absent"}}, {"prs": {"id": 3}}])
def test_invalid_mapping_fails_before_output(tmp_path, mapping):
    source = tmp_path / "source"
    table(source, "prs", [{"id": 1, "pr_url": "https://github.com/o/r/pull/1"}])
    with pytest.raises(ValueError):
        import_aidev(source, tmp_path / "out", column_mapping=mapping)
    assert not (tmp_path / "out").exists()


def test_lfs_and_corrupt_files_are_explicit_gaps(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    pointer = "version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 123456\n"
    (source / "all_pull_request.parquet").write_text(pointer)
    (source / "pr_commits.parquet").write_bytes(b"not parquet")
    result = import_aidev(source, tmp_path / "out")
    assert result["counts"]["readable_tables"] == result["counts"]["normalized_prs"] == 0
    assert result["status"] == "complete_with_gaps" and result["exit_code"] == 2
    assert [table["status"] for table in result["tables"]] == ["missing_lfs_object", "unreadable_parquet"]
    assert result["tables"][0]["rows"] is None
    assert result["tables"][0]["expected_bytes"] == 123456
    assert not result["evidence_boundary"]["all_local_tables_scanned"]
    assert (source / "all_pull_request.parquet").read_text() == pointer


def test_dry_run_is_read_only_and_resume_checks_inputs_outputs_and_completion(tmp_path):
    source, output = tmp_path / "source", tmp_path / "out"
    fixture(source)
    assert import_aidev(source, output, dry_run=True)["files_written"] is False
    assert not output.exists()
    original = import_aidev(source, output)
    assert import_aidev(source, output, resume=True)["resumed"] is True
    with pytest.raises(ValueError, match="already exists"):
        import_aidev(source, output)
    with pytest.raises(ValueError, match="read-only"):
        import_aidev(source, source / "out")
    manifest = output / "manifest.json"
    saved = manifest.read_text()
    payload = json.loads(saved)
    payload["status"] = "running"
    manifest.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="incomplete"):
        import_aidev(source, output, resume=True)
    manifest.write_text(saved)
    with (output / "normalized_prs.jsonl").open("a") as stream:
        stream.write("{}\n")
    with pytest.raises(ValueError, match="modified"):
        import_aidev(source, output, resume=True)
    table(source, "user", [{"id": 200}])
    with pytest.raises(ValueError, match="changed"):
        import_aidev(source, output, resume=True)
    assert original["counts"]["normalized_prs"] == 2


def test_ambiguous_global_id_never_selects_a_pr_and_invalid_sha_is_not_mineable(tmp_path):
    source = tmp_path / "source"
    table(source, "prs", [{"id": 1, "html_url": "https://github.com/o/r/pull/1"}, {"id": 1, "html_url": "https://github.com/o/r/pull/2"}])
    table(source, "pr_commits", [{"pr_id": 1, "sha": SHA_A}, {"pr_id": 100, "sha": "None", "html_url": "https://github.com/o/r/pull/1"}])
    result = import_aidev(source, tmp_path / "out")
    assert result["counts"]["ambiguous_pr_ids"] == 1
    assert result["counts"]["mining_prs"] == 0
    with sqlite3.connect(result["paths"]["aidev.sqlite"]) as db:
        assert db.execute("SELECT COUNT(*) FROM row_pr_links WHERE table_name='pr_commits' AND row_number=1").fetchone()[0] == 0


def test_api_url_only_review_comment_and_deleted_files_remain_observed(tmp_path):
    source = tmp_path / "source"
    table(source, "prs", [{"id": 1, "html_url": "https://github.com/o/r/pull/1"}])
    table(source, "pr_review_comments_v2", [{"id": 9, "pull_request_url": "https://api.github.com/repos/o/r/pulls/1", "diff_hunk": "@@ example"}])
    table(source, "files", [{"pull_request_id": 1, "commit_sha": SHA_A, "file_path": "removed.py", "status": "removed", "diff_patch": "@@ -1 +0 @@\n-logger.info(value)"}])
    result = import_aidev(source, tmp_path / "out")
    row = records(result["paths"]["mining_prs.jsonl"])[0]
    assert row["related_table_rows"]["pr_review_comments_v2"] == 1
    assert result["patch_coverage"] == {"present_unverified": 1}
    assert result["counts"]["mining_prs"] == 1


def test_file_sha_relationship_and_contradictory_pr_identity(tmp_path):
    source = tmp_path / "source"
    table(source, "prs", [{"id": 1, "html_url": "https://github.com/o/r/pull/1"}, {"id": 2, "html_url": "https://github.com/o/r/pull/2"}])
    table(source, "pr_commits", [{"pr_id": 1, "sha": SHA_A}])
    table(source, "files", [{"sha": SHA_A, "filename": "indirect.py", "patch": "@@ hunk"}])
    table(source, "pr_comments", [{"id": 9, "pr_id": 1, "pr_url": "https://github.com/o/r/pull/2"}])
    result = import_aidev(source, tmp_path / "out")
    row = records(result["paths"]["mining_prs.jsonl"])[0]
    assert row["related_table_rows"]["files"] == 1
    assert "pr_comments" not in row["related_table_rows"]
    assert {"table": "pr_comments", "relation": "pr_identity", "status": "conflict", "rows": 1} in result["relationships"]
    with sqlite3.connect(result["paths"]["aidev.sqlite"]) as db:
        assert db.execute("SELECT method FROM row_pr_links WHERE table_name='files'").fetchone()[0] == "commit_sha"


def test_input_change_during_import_leaves_explicit_incomplete_run(tmp_path, monkeypatch):
    import agentlog_unified.aidev as aidev
    source, output = tmp_path / "source", tmp_path / "out"
    table(source, "prs", [{"id": 1, "html_url": "https://github.com/o/r/pull/1"}])
    export = aidev._export

    def change_source(*args):
        result = export(*args)
        table(source, "users", [{"id": 11}])
        return result

    monkeypatch.setattr(aidev, "_export", change_source)
    with pytest.raises(ValueError, match="Source changed"):
        aidev.import_aidev(source, output)
    assert json.loads((output / "manifest.json").read_text())["status"] == "failed"
    with pytest.raises(ValueError, match="incomplete"):
        aidev.import_aidev(source, output, resume=True)


def test_user_relation_keeps_id_precedence_and_uses_both_lookup_indexes(tmp_path, monkeypatch):
    import agentlog_unified.aidev as aidev
    source = tmp_path / "source"
    table(source, "users", [{"id": 11, "login": "person"}])
    table(source, "prs", [{"id": 1, "html_url": "https://github.com/o/r/pull/1"}])
    table(source, "pr_comments", [
        {"id": 1, "pr_id": 1, "user_id": 11, "user": "old_name"},
        {"id": 2, "pr_id": 1, "user_id": None, "user": "person"},
        {"id": 3, "pr_id": 1, "user_id": 99, "user": "person"},
        {"id": 4, "pr_id": 1, "user_id": None, "user": None},
    ])
    original_connect, statements = sqlite3.connect, []

    def capture(*args, **kwargs):
        db = original_connect(*args, **kwargs)
        db.set_trace_callback(lambda sql: statements.append(sql) if "INSERT INTO relationship_audit SELECT s.table_name,'user'" in sql else None)
        return db

    monkeypatch.setattr(aidev.sqlite3, "connect", capture)
    result = aidev.import_aidev(source, tmp_path / "out")
    with original_connect(result["paths"]["aidev.sqlite"]) as db:
        observed = dict(db.execute("SELECT status,rows FROM relationship_audit WHERE table_name='pr_comments' AND relation='user'"))
        assert observed == {"linked": 2, "orphan": 1, "missing_foreign_key": 1}
        # Check the actual executed audit statement, not a parallel sample query.
        plans = [row[3] for row in db.execute("EXPLAIN QUERY PLAN " + statements[0])]
        assert any("SEARCH u USING INDEX source_entity_id" in row for row in plans)
        assert any("SEARCH u USING INDEX source_user_login" in row for row in plans)
        assert not any("SEARCH u USING INDEX source_role" in row for row in plans)


def test_interrupt_closes_database_and_preserves_explicit_manifest(tmp_path, monkeypatch):
    import agentlog_unified.aidev as aidev
    source, output = tmp_path / "source", tmp_path / "out"
    table(source, "prs", [{"id": 1, "html_url": "https://github.com/o/r/pull/1"}])

    def interrupt(db, *args):
        db.execute("CREATE TABLE interrupted_evidence(value INTEGER)")
        db.execute("INSERT INTO interrupted_evidence VALUES (1)")
        raise KeyboardInterrupt

    monkeypatch.setattr(aidev, "_load_rows", interrupt)
    with pytest.raises(KeyboardInterrupt):
        aidev.import_aidev(source, output)
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["status"] == "interrupted" and manifest["error_type"] == "KeyboardInterrupt"
    with sqlite3.connect(output / "aidev.sqlite", timeout=0) as db:
        db.execute("BEGIN EXCLUSIVE")  # The interrupted writer released its connection.
    with pytest.raises(ValueError, match="incomplete"):
        aidev.import_aidev(source, output, resume=True)
