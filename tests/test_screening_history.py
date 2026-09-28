"""Real Git/PyDriller history adapters; these never run target application code."""
import hashlib
import json
from pathlib import Path

import pytest

from agentlog_unified.batch_mine import ingest_commit_contexts, run_batch
from agentlog_unified.screening_history import extract_commit, iter_historical_sources, recover_population
from synthetic_histories import HEADER, commit, git, init


def text(side):
    return Path(side["source_path"]).read_text()


def version(repo, sha, path="app.py", **extra):
    return {"repository": "fixture/project", "sha": sha, "source_sha": sha,
            "side": "after", "path": path, "old_path": path, "new_path": path, **extra}


def test_real_root_add_rename_delete_and_empty_source(tmp_path):
    repo = tmp_path / "repo"
    root = init(repo)
    root_result = extract_commit(repo, "fixture/project", root, tmp_path / "run")
    assert root_result["status"] == "success"
    assert root_result["parents"] == []
    assert root_result["files"][0]["before"]["source_state"] == "absent_verified"
    source = HEADER + 'logger.info("fictional fixed output")\n'
    added = commit(repo, {"app.py": source, "empty.py": ""}, "add sources")
    result = extract_commit(repo, "fixture/project", added, tmp_path / "run")
    assert result["audit"]["metrics"]["pydriller_repository_traversals"] == 1
    assert result["audit"]["metrics"]["pydriller_diff_parsed_calls"] == 2
    assert all(row["before"]["source_state"] == "absent_verified" for row in result["files"])
    app = next(row for row in result["files"] if row["new_path"] == "app.py")
    assert text(app["after"]) == source
    assert app["after"]["source_sha"] == added
    empty = next(row for row in result["files"] if row["new_path"] == "empty.py")
    assert empty["after"]["source_state"] == "present" and text(empty["after"]) == ""
    git(repo, "mv", "app.py", "renamed.py")
    renamed = commit(repo, {}, "rename", day=3)
    result = extract_commit(repo, "fixture/project", renamed, tmp_path / "run")
    event = result["files"][0]
    assert event["change_type"] == "RENAME"
    assert event["before"]["path"] == "app.py" and event["after"]["path"] == "renamed.py"
    assert text(event["before"]) == text(event["after"]) == source
    git(repo, "rm", "renamed.py")
    deleted = commit(repo, {}, "delete", day=4)
    event = extract_commit(repo, "fixture/project", deleted, tmp_path / "run")["files"][0]
    assert event["after"]["source_state"] == "absent_verified"
    assert event["before"]["source_sha"] == renamed
    assert text(event["before"]) == source


def test_real_merge_first_parent_and_command_protections(tmp_path):
    repo = tmp_path / "repo"
    base = init(repo)
    git(repo, "checkout", "-qb", "side")
    side = commit(repo, {"side.py": HEADER + 'logger.info("side")\n'}, "side", day=2)
    git(repo, "checkout", "main")
    first = commit(repo, {"main.py": HEADER + 'logger.info("main")\n'}, "first parent", day=3)
    git(repo, "merge", "--no-ff", "-m", "merge fixture", "side", day=4)
    merged = git(repo, "rev-parse", "HEAD")
    result = extract_commit(repo, "fixture/project", merged, tmp_path / "run")
    assert result["status"] == "success", result["gaps"]
    assert result["parents"] == [first, side]
    assert result["parent_sha"] == first
    assert result["uncompared_parents"] == [side]
    assert result["audit"]["metrics"]["pydriller_git_diff_calls"] == 1
    assert {row["new_path"] for row in result["files"]} == {"side.py"}
    assert result["files"][0]["before"]["source_state"] == "absent_verified"
    assert "no_textconv" in result["audit"]["protections"]
    # A repository-configured transformation must never execute during mining.
    marker = tmp_path / "textconv-executed"
    git(repo, "config", "diff.fixture.textconv", "touch '" + str(marker) + "'")
    configured = commit(repo, {".gitattributes": "*.py diff=fixture\n", "side.py": HEADER + 'logger.info("changed")\n'},
                        "textconv trap", day=5)
    result = extract_commit(repo, "fixture/project", configured, tmp_path / "run")
    assert result["status"] == "success", result["gaps"]
    assert not marker.exists()


def test_batch_sources_exact_versions_hash_validation_and_failures(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    before = commit(repo, {"app.py": "historical = 1\n"}, "old")
    after = commit(repo, {"app.py": "historical = 2\n"}, "new", day=3)
    rows = list(iter_historical_sources(repo, [version(repo, before), version(repo, after),
        version(repo, after, "absent.py"), version(repo, "f" * 40),
        version(repo, after, source_sha256="0" * 64)], tmp_path / "run"))
    assert text(rows[0]) == "historical = 1\n" and text(rows[1]) == "historical = 2\n"
    assert rows[0]["source_sha256"] != rows[1]["source_sha256"]
    assert [row["source_state"] for row in rows] == ["present", "present", "absent_verified", "object_unavailable", "extraction_failed"]
    assert rows[-1]["reason"] == "historical_source_sha256_mismatch"
    Path(rows[0]["source_path"]).write_text("corrupted cache")
    repaired = list(iter_historical_sources(repo, [version(repo, before)], tmp_path / "run"))[0]
    assert text(repaired) == "historical = 1\n" and repaired["source_cache_hit"] is False
    limited = list(iter_historical_sources(repo, [version(repo, after)], tmp_path / "run", max_bytes=1))[0]
    assert limited["source_state"] == "extraction_failed" and limited["reason"] == "source_byte_budget_exceeded"
    assert extract_commit(repo, "fixture/project", "f" * 40, tmp_path / "run")["status"] == "blocked"
    with pytest.raises(ValueError, match="full_exact_commit_sha"):
        extract_commit(repo, "fixture/project", after[:8], tmp_path / "run")


def test_recover_frozen_population_preserves_inputs_no_logs_and_blocked(tmp_path):
    project, repo = tmp_path / "project", tmp_path / "repo"
    init(repo)
    sha = commit(repo, {"app.py": HEADER + 'logger.info("fixed")\n', "no_log.py": "answer = 42\n"}, "logs")
    old = project / "research/frozen"
    source = old / "final/input.jsonl"
    source.parent.mkdir(parents=True)
    data = [{"dataset": "SWE-chat", "repository": "fixture/project", "commit_shas": [sha],
             "source_context_id": "source-1", "local_repo_path": str(repo)},
            {"dataset": "SWE-chat", "repository": "fixture/project", "commit_shas": [sha],
             "source_context_id": "source-2", "local_repo_path": str(repo)},
            {"dataset": "SWE-chat", "repository": "fixture/project", "commit_shas": ["f" * 40],
             "source_context_id": "source-blocked", "local_repo_path": str(repo)}]
    source.write_text("".join(json.dumps(row) + "\n" for row in data))
    batch = old / "final/batch"
    ingest_commit_contexts(source, batch)
    run_batch(batch, project / "cache", offline=True)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    (old / "preparation.json").write_text(json.dumps({"fingerprint": {"input_sha256": digest},
        "repositories": [{"repository": "fixture/project", "cache": str(repo)}]}))
    db_digest = hashlib.sha256((batch / "batch.sqlite").read_bytes()).hexdigest()
    output = project / "research/new/population"
    result = recover_population(project, old, output)
    assert result["input_rows"] == 3 and result["commits"] == 2
    assert result["file_events"] == 2 and result["file_versions"] == 4
    assert result["commit_legacy_status_counts"]["blocked"] == 1
    assert result["candidate_only"] is False
    files = [json.loads(line) for line in (output / "file_versions.jsonl").read_text().splitlines()]
    assert all(row["source_state"] == "unverified_cached" for row in files)
    assert all(len(row["input_record_ids"]) == 2 for row in files)
    assert next(row for row in files if row["path"] == "no_log.py")["old_log_ids"] == []
    assert hashlib.sha256((batch / "batch.sqlite").read_bytes()).hexdigest() == db_digest
    source.write_text(source.read_text() + "{}\n")
    with pytest.raises(ValueError, match="frozen_input_sha256_mismatch"):
        recover_population(project, old, output)
