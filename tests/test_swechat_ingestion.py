"""Real Parquet joins and source-only content references for SWE-chat."""
import json
import sqlite3
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from agentlog_unified.swechat import import_swechat

SHA_A, SHA_B, SHA_C = "a" * 40, "b" * 40, "c" * 40


def table(source, name, rows):
    source.mkdir(exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows), source / f"{name}.parquet")


def rows(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def fixture(source):
    table(source, "repositories", [{"repo_id": "Org/Repo", "settings": "private settings sentinel"}])
    table(source, "sessions", [{"session_id": "session-one", "repo_id": "Org/Repo", "checkpoint_ids": '["Org/Repo#cp-one"]', "canonical_checkpoint_pk": "Org/Repo#cp-one", "agent": "Codex"}])
    table(source, "checkpoints", [{"checkpoint_pk": "Org/Repo#cp-one", "repo_id": "Org/Repo", "session_pks": '["session-one"]', "commit_shas": json.dumps([SHA_A, SHA_B]), "checkpoint_metadata_raw": "private checkpoint sentinel"}])
    table(source, "commits", [
        {"commit_sha": SHA_A, "checkpoint_pk": "Org/Repo#cp-one", "repo_id": "Org/Repo", "patch": "private diff sentinel", "file_contents": "private source sentinel", "is_agent_author": True, "status": "ok"},
        {"commit_sha": SHA_A, "checkpoint_pk": "Org/Repo#cp-one", "repo_id": "Org/Repo", "patch": None, "file_contents": None, "is_agent_author": True, "status": "ok"},
    ])
    table(source, "session_logs", [{"session_id": "session-one", "transcript_path": "transcripts/session-one.jsonl", "context_md": "private context sentinel", "session_metadata_raw": "private session sentinel"}])
    table(source, "conversations", [{"turn_id": "session-one#0", "session_id": "session-one", "checkpoint_pk": "Org/Repo#cp-one", "repo_id": "Org/Repo", "role": "user", "turn_type": "user_prompt", "content": "private conversation sentinel", "command": "private command sentinel"}])


def test_all_table_rows_and_commit_references_without_content_or_pr_fabrication(tmp_path):
    source, output = tmp_path / "source", tmp_path / "out"
    fixture(source)
    result = import_swechat(source, output, batch_size=1)
    assert result["counts"]["source_rows_read"] == 7
    assert result["counts"]["commit_contexts"] == 2  # Includes checkpoint-only commit references.
    assert result["counts"]["contexts_without_commit_metadata"] == 1
    assert result["counts"]["duplicate_entity_rows"] == 1
    contexts = rows(result["paths"]["commit_contexts.jsonl"])
    first, second = contexts
    assert first["repository"] == "org/repo"
    assert first["commit_sha"] == SHA_A and second["commit_sha"] == SHA_B
    assert first["session_ids"] == ["session-one"]
    assert first["checkpoint_pks"] == ["org/repo#cp-one"]
    assert first["provided_agent_names"] == ["Codex"]
    assert first["verified_actor_type"] == "unknown" and first["provenance_evidence"] == []
    assert first["is_synthetic"] is False and first["source_kind"] == "commit_context"
    assert "pr_url" not in first and "pr_number" not in first
    assert second["commit_metadata_present"] is False
    commits = next(t for t in result["tables"] if t["table"] == "commits")
    assert commits["content_columns"]["patch"]["null_rows_from_footer"] == 1
    assert commits["content_columns"]["patch"]["values_read"] is False
    assert not result["evidence_boundary"]["session_content_classified"]
    assert not result["evidence_boundary"]["patches_or_full_files_loaded"]
    for path in output.iterdir():
        assert "private " not in path.read_bytes().decode("utf-8", "replace")
        assert path.stat().st_mode & 0o077 == 0
    assert output.stat().st_mode & 0o077 == 0
    with sqlite3.connect(output / "swechat.sqlite") as db:
        assert db.execute("SELECT COUNT(*) FROM source_rows").fetchone()[0] == 7
        assert db.execute("SELECT COUNT(*) FROM references_raw WHERE table_name='conversations'").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM references_all WHERE table_name='conversations'").fetchone()[0] == 3


def test_missing_foreign_keys_invalid_arrays_and_conflicting_repository_are_audited(tmp_path):
    source = tmp_path / "source"
    table(source, "repositories", [{"repo_id": "o/a"}, {"repo_id": "o/b"}])
    table(source, "sessions", [{"session_id": "s", "repo_id": "o/a", "checkpoint_ids": "invalid", "agent": "Claude Code"}])
    table(source, "checkpoints", [{"checkpoint_pk": "o/a#c", "repo_id": "o/a", "session_pks": '["missing"]', "commit_shas": json.dumps([SHA_A, "invalid"])}])
    table(source, "commits", [{"commit_sha": SHA_A, "checkpoint_pk": "o/a#c", "repo_id": "o/b"}, {"commit_sha": SHA_C, "checkpoint_pk": None, "repo_id": None}])
    table(source, "conversations", [{"turn_id": "t1", "session_id": None, "content": "not exported"}])
    result = import_swechat(source, tmp_path / "out")
    assert result["exit_code"] == 2 and result["complete"]
    assert result["counts"]["unusable_commit_references"] == 2
    assert {"table": "sessions", "field": "checkpoint_ids", "status": "invalid_json", "rows": 1} in result["array_fields"]
    assert {"table": "commits", "relation": "checkpoint", "status": "repository_conflict", "rows": 1} in result["relationships"]
    assert {"table": "conversations", "relation": "session", "status": "missing_direct_foreign_key", "rows": 1} in result["relationships"]
    conflicting = next(row for row in rows(result["paths"]["commit_contexts.jsonl"]) if row["repository"] == "o/b")
    assert conflicting["checkpoint_pks"] == [] and conflicting["session_ids"] == []
    assert conflicting["context_statuses"] == ["checkpoint_repository_conflict"]


def test_checkpoint_can_supply_missing_commit_repo_and_native_arrays_are_supported(tmp_path):
    source = tmp_path / "source"
    table(source, "repositories", [{"repo_id": "o/r"}])
    table(source, "sessions", [{"session_id": "s", "repo_id": "o/r", "checkpoint_ids": ["c", "c"]}])
    table(source, "checkpoints", [{"checkpoint_id": "c", "repo_id": "o/r", "session_ids": ["s"], "commit_shas": [SHA_A]}])
    table(source, "commits", [{"sha": SHA_A, "checkpoint_pk": "o/r#c"}])
    result = import_swechat(source, tmp_path / "out")
    row = rows(result["paths"]["commit_contexts.jsonl"])[0]
    assert row["repository"] == "o/r" and row["session_ids"] == ["s"]
    assert any(item["status"] == "duplicate_entries" for item in result["array_fields"])
    assert {"table": "checkpoints", "relation": "commit", "status": "linked", "rows": 1} in result["relationships"]


def test_lfs_corrupt_and_missing_tables_are_distinct_no_nested_target_parquet(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "commits.parquet").write_text("version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 1234\n")
    (source / "sessions.parquet").write_bytes(b"invalid")
    nested = source / "target_repo"
    table(nested, "repositories", [{"repo_id": "ignored/target"}])
    result = import_swechat(source, tmp_path / "out")
    assert result["counts"]["source_tables"] == 2
    assert result["counts"]["source_rows_read"] == result["counts"]["commit_contexts"] == 0
    assert result["tables"][0]["status"] == "missing_lfs_object"
    assert result["tables"][0]["rows"] is None and result["tables"][0]["expected_bytes"] == 1234
    assert result["tables"][1]["status"] == "unreadable_parquet"
    assert "repositories" in result["missing_expected_tables"]
    assert result["exit_code"] == 2


def test_dry_run_resume_inputs_outputs_and_interrupt_preserve_evidence(tmp_path, monkeypatch):
    import agentlog_unified.swechat as swechat
    source, output = tmp_path / "source", tmp_path / "out"
    fixture(source)
    result = import_swechat(source, output, dry_run=True)
    assert result["files_written"] is False and not output.exists()
    import_swechat(source, output)
    assert import_swechat(source, output, resume=True)["resumed"]
    with pytest.raises(ValueError, match="already exists"):
        import_swechat(source, output)
    with (output / "commit_contexts.jsonl").open("a") as stream:
        stream.write("{}\n")
    with pytest.raises(ValueError, match="modified"):
        import_swechat(source, output, resume=True)
    interrupted = tmp_path / "interrupted"

    def stop(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(swechat, "_read", stop)
    with pytest.raises(KeyboardInterrupt):
        import_swechat(source, interrupted)
    assert json.loads((interrupted / "manifest.json").read_text())["status"] == "interrupted"
    with pytest.raises(ValueError, match="incomplete"):
        import_swechat(source, interrupted, resume=True)


def test_ambiguous_session_id_cannot_link_cross_repository_context(tmp_path):
    source = tmp_path / "source"
    table(source, "repositories", [{"repo_id": "o/a"}, {"repo_id": "o/b"}])
    table(source, "sessions", [{"session_id": "same", "repo_id": "o/a", "checkpoint_ids": '["o/a#c"]'}, {"session_id": "same", "repo_id": "o/b", "checkpoint_ids": '["o/b#c"]'}])
    table(source, "checkpoints", [{"checkpoint_pk": "o/a#c", "repo_id": "o/a", "session_pks": '["same"]', "commit_shas": json.dumps([SHA_A])}])
    result = import_swechat(source, tmp_path / "out")
    row = rows(result["paths"]["commit_contexts.jsonl"])[0]
    assert row["session_ids"] == []
    assert any(relation["status"] == "ambiguous_repository" for relation in result["relationships"])


def test_checkpoint_arrays_cannot_restore_ambiguous_context_but_keep_commit_work(tmp_path):
    source = tmp_path / "source"
    checkpoint = "o/a#shared"
    table(source, "repositories", [{"repo_id": "o/a"}, {"repo_id": "o/b"}])
    table(source, "sessions", [
        {"session_id": "session-a", "repo_id": "o/a", "checkpoint_ids": [checkpoint], "agent": "agent-a"},
        {"session_id": "session-b", "repo_id": "o/b", "checkpoint_ids": [checkpoint], "agent": "agent-b"},
    ])
    table(source, "checkpoints", [
        {"checkpoint_pk": checkpoint, "repo_id": "o/a", "session_pks": ["session-a"], "commit_shas": [SHA_A]},
        {"checkpoint_pk": checkpoint, "repo_id": "o/b", "session_pks": ["session-b"], "commit_shas": [SHA_B]},
    ])
    table(source, "commits", [{"commit_sha": SHA_B, "repo_id": "o/b", "checkpoint_pk": checkpoint}])
    result = import_swechat(source, tmp_path / "out")
    contexts = rows(result["paths"]["commit_contexts.jsonl"])
    assert {(row["repository"], row["commit_sha"]) for row in contexts} == {("o/a", SHA_A), ("o/b", SHA_B)}
    assert result["counts"]["contexts_without_commit_metadata"] == 1
    for row in contexts:
        assert row["checkpoint_pks"] == row["session_ids"] == row["provided_agent_names"] == []
        assert row["context_statuses"] == ["checkpoint_ambiguous"]
        assert row["verified_actor_type"] == "unknown"
        assert any(ref["method"] == "checkpoint_commit_array" for ref in row["source_rows"])
    with sqlite3.connect(result["paths"]["swechat.sqlite"]) as db:
        assert db.execute("SELECT COUNT(*) FROM commit_references WHERE checkpoint_pk IS NOT NULL").fetchone()[0] == 0


def test_shared_fork_commit_sha_is_repository_scoped_and_missing_sha_remains_missing(tmp_path):
    source = tmp_path / "source"
    table(source, "repositories", [{"repo_id": "o/upstream"}, {"repo_id": "o/fork"}])
    table(source, "checkpoints", [
        {"checkpoint_pk": "o/upstream#c", "repo_id": "o/upstream", "commit_shas": [SHA_A, SHA_C, SHA_B]},
        {"checkpoint_pk": "o/fork#c", "repo_id": "o/fork", "commit_shas": [SHA_A, SHA_C]},
    ])
    table(source, "commits", [
        {"commit_sha": SHA_A, "repo_id": "o/upstream", "checkpoint_pk": "o/upstream#c"},
        {"commit_sha": SHA_A, "repo_id": "o/upstream", "checkpoint_pk": "o/upstream#c"},
        {"commit_sha": SHA_A, "repo_id": "o/fork", "checkpoint_pk": "o/fork#c"},
        {"commit_sha": SHA_C, "repo_id": "o/fork", "checkpoint_pk": "o/fork#c"},
        {"commit_sha": None, "repo_id": "o/upstream", "checkpoint_pk": "o/upstream#c"},
    ])
    result = import_swechat(source, tmp_path / "out")
    commit_links = [row for row in result["relationships"] if row["relation"] == "commit"]
    assert {"table": "checkpoints", "relation": "commit", "status": "linked", "rows": 3} in commit_links
    assert {"table": "checkpoints", "relation": "commit", "status": "cross_repository_reference", "rows": 1} in commit_links
    assert {"table": "checkpoints", "relation": "commit", "status": "orphan", "rows": 1} in commit_links
    assert result["counts"]["ambiguous_repository_entity_ids"] == 0
    assert result["counts"]["duplicate_entity_rows"] == 1
    assert result["counts"]["missing_primary_key_rows"] == 1
    assert {"table": "commits", "status": "missing_primary_key", "rows": 1} in result["primary_key_coverage"]
    with sqlite3.connect(result["paths"]["swechat.sqlite"]) as db:
        assert db.execute("SELECT COUNT(*) FROM entities WHERE table_name='commits'").fetchone()[0] == 3
        assert db.execute("SELECT COUNT(*) FROM entities WHERE table_name='commits' AND entity_key=?", (SHA_A,)).fetchone()[0] == 2


def test_conversation_relations_use_entity_lookup_indexes(tmp_path, monkeypatch):
    import agentlog_unified.swechat as swechat
    source = tmp_path / "source"
    fixture(source)
    table(source, "conversations", [{"turn_id": f"session-one#{i}", "session_id": "session-one", "repo_id": "Org/Repo", "checkpoint_pk": "Org/Repo#cp-one"} for i in range(2500)])
    connect, statements = sqlite3.connect, []

    def capture(*args, **kwargs):
        db = connect(*args, **kwargs)
        db.set_trace_callback(lambda sql: statements.append(sql) if sql.startswith("INSERT INTO relationship_audit SELECT r.table_name") else None)
        return db

    monkeypatch.setattr(swechat.sqlite3, "connect", capture)
    result = swechat.import_swechat(source, tmp_path / "out", batch_size=128)
    assert result["counts"]["source_rows_read"] == 2506
    assert {"table": "conversations", "relation": "session", "status": "linked", "rows": 2500} in result["relationships"]
    assert len(statements) == 4
    with connect(result["paths"]["swechat.sqlite"]) as db:
        for sql in statements:
            plan = [row[3] for row in db.execute("EXPLAIN QUERY PLAN " + sql)]
            assert any("SEARCH e USING" in line and "INDEX entity_key" in line for line in plan)
            assert not any("SCAN e" in line for line in plan)


def test_nanosecond_timestamp_keeps_precision_without_pandas(tmp_path):
    source, output = tmp_path / "source", tmp_path / "out"
    fixture(source)
    timestamp_type = pa.timestamp("ns", tz="UTC")
    nanoseconds = 1770798834310650256  # An observed precision that Python datetime cannot retain.
    timestamps = pa.array([nanoseconds], type=timestamp_type)
    pq.write_table(pa.table({"session_id": ["session-one"], "repo_id": ["Org/Repo"], "checkpoint_ids": ['["Org/Repo#cp-one"]'], "created_at": timestamps}), source / "sessions.parquet")
    result = import_swechat(source, output)
    with sqlite3.connect(result["paths"]["swechat.sqlite"]) as db:
        metadata = json.loads(db.execute("SELECT metadata FROM source_rows WHERE table_name='sessions'").fetchone()[0])
    stored = metadata["created_at"]
    assert stored == timestamps.cast(pa.string())[0].as_py()
    assert pa.array([stored]).cast(timestamp_type).cast(pa.int64())[0].as_py() == nanoseconds
    schema = next(t for t in result["tables"] if t["table"] == "sessions")["schema"]
    assert {"name": "created_at", "type": "timestamp[ns, tz=UTC]"} in schema
