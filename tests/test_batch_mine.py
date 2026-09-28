"""Offline real-Git/PyDriller vertical slice; no target application execution."""
import ast
import json
import sqlite3
from pathlib import Path

import pytest

from agentlog_unified import batch_mine as batch
from synthetic_histories import HEADER, commit, git, init


def ingest(tmp_path, rows):
    source = tmp_path / "contexts.jsonl"
    source.write_text("".join(json.dumps(row) + "\n" for row in rows))
    output = tmp_path / "batch"
    return output, batch.ingest_commit_contexts(source, output)


def exported(output, name):
    return [json.loads(line) for line in (output / "exports" / (name + ".jsonl")).read_text().splitlines()]


def row(repo, sha, **extra):
    return {"dataset": "synthetic", "repository": "fixture/project", "sha": sha,
            "local_repo_path": str(repo), "context_ids": ["fixture-1"], **extra}


def test_exact_commit_scope_real_pydriller_before_after_and_import(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    helper = "def reveal(user):\n    return user.password\n"
    old = commit(repo, {"helpers.py": helper, "app.py": HEADER + 'logger.info("old fixed")\n'}, "old")
    source = HEADER + 'from helpers import reveal\ndef run(user, mystery):\n    logger.info(\n        "value=%s",\n        reveal(user),\n    )\n    logger.info("unknown", mystery)\n    logger.info("fixed")\n'
    wanted = commit(repo, {"app.py": source}, "change", day=3)
    later = commit(repo, {"app.py": HEADER + 'logger.info("unrequested")\n'}, "later", day=4)
    output, result = ingest(tmp_path, [row(repo, wanted)])
    assert result["unique_commits"] == 1
    result = batch.run_batch(output, tmp_path / "cache")
    audit = exported(output, "commit_audit")
    assert [record["sha"] for record in audit] == [wanted]
    assert old not in {r["sha"] for r in audit} and later not in {r["sha"] for r in audit}
    metrics = audit[0]["metrics"]
    assert metrics["pydriller_repository_traversals"] == metrics["pydriller_commits"] == 1
    assert metrics["pydriller_diff_parsed_calls"] == 1
    assert metrics["pydriller_source_reads"] == 2
    assert metrics["dependency_blobs_read"] == 1
    logs = exported(output, "log_observations")
    assert len(logs) == 4
    assert {log["side"] for log in logs} == {"before", "after"}
    credential = next(log for log in logs if "reveal(user)" in log["entity"]["statement"])
    assert credential["entity"]["end_line"] > credential["entity"]["start_line"]
    assert "credential" in credential["entity"]["data_types"]
    assert any(dep["path"] == "helpers.py" for dep in credential["entity"]["dependencies"])
    assert credential["entity"]["taxonomy_labels"]
    assert any(log["entity"]["unknown_type_review"]["needs_review"] for log in logs)
    assert any(log["entity"]["privacy_assessment"] == "not_supported" for log in logs)
    assert result["full_history_tracing_completed"] is False
    assert all(log["observation_scope"] == "dataset_commit_changes" for log in logs)
    assert result["type_audit"]["distinct_observed_log_versions"] == 4
    assert result["type_audit"]["observed_category_count"] >= 1
    assert result["type_audit"]["unknown_type_review_count"] >= 1
    assert len(exported(output, "type_occurrences")) == 4


def test_conditional_mutations_keep_distinct_evidence_without_exponential_copies(tmp_path):
    from agentlog_unified.detector import Value, _join

    first = {"source": "user.password", "basis": "explicit_sensitive_access", "types": ["credential"]}
    second = {"source": "key", "basis": "identifier_only", "types": []}
    value = Value(types={"credential"}, evidence=[first], gaps=["unresolved"], sanitization=["partial"])
    joined = _join([value, value, Value(evidence=[second], gaps=["different"])])
    # Fail immediately on the old implementation, before constructing the
    # formerly exponential synthetic history below.
    assert joined.evidence == [first, second]
    assert joined.gaps == ["unresolved", "different"]
    assert joined.sanitization == ["partial"]
    assert joined.types == {"credential"}

    repo = tmp_path / "repo"
    init(repo)
    body = 'def run(user, flag, key):\n    obj = user.password\n'
    body += '    if flag:\n        obj.append(key)\n' * 35
    body += '    logger.info("value", obj)\n'
    sha = commit(repo, {"app.py": HEADER + body}, "conditional mutations")
    output, _ = ingest(tmp_path, [row(repo, sha)])
    result = batch.run_batch(output, tmp_path / "cache")
    assert result["actual_extraction_metrics"]["pydriller_diff_parsed_calls"] == 1
    log = exported(output, "log_observations")[0]["entity"]
    assert log["privacy_assessment"] == "supported"
    assert "credential" in log["data_types"]
    assert "conditional_mutation_unresolved" in log["missing_evidence"]
    assert len(log["source_to_sink"]) == 2
    assert len({(dep["start_line"], dep["end_line"]) for dep in log["dependencies"]
                if dep["kind"] == "argument_mutation"}) == 35


def test_aidev_expansion_context_dedup_missing_inputs_and_resume(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    a = commit(repo, {"app.py": HEADER + 'logger.info("a")\n'}, "a")
    b = commit(repo, {"app.py": HEADER + 'logger.info("b")\n'}, "b", day=3)
    common = {"repository": "fixture/project", "local_repo_path": str(repo), "aidev_source_snapshot": "fixture-v1"}
    rows = [{**common, "source_pr_key": "project#1", "commit_shas": [a, b, a], "source_rows": [1]},
            {**common, "source_pr_key": "project#2", "initial_commit_shas": [b], "source_rows": [2]},
            {**common, "source_pr_key": "project#3", "commit_shas": []},
            {**common, "sha": "not-a-sha"}]
    output, result = ingest(tmp_path, rows)
    assert result["unique_commits"] == 2
    assert result["unique_contexts"] == 3
    assert result["unique_input_gaps"] == 2
    repeated = batch.ingest_commit_contexts(tmp_path / "contexts.jsonl", output)
    assert repeated["unique_contexts"] == 3
    paused = batch.run_batch(output, tmp_path / "cache", max_repositories=0)
    assert paused["commit_status_counts"] == {"pending": 2}
    assert paused["exit_code"] == 2
    assert len(exported(output, "pending_commits")) == 2
    result = batch.run_batch(output, tmp_path / "cache")
    assert result["this_run_commits_attempted"] == 2
    assert result["input_gap_count"] == 2
    assert result["exit_code"] == 2
    again = batch.run_batch(output, tmp_path / "cache")
    assert again["this_run_commits_attempted"] == 0
    assert all(record["attempts"] == 1 for record in exported(output, "commit_audit"))
    contexts = exported(output, "contexts")
    assert {context["dataset"] for context in contexts} == {"aidev"}
    assert {context["source_pr_key"] for context in contexts} == {"project#1", "project#2"}


def test_offline_never_acquires_network_and_missing_is_not_negative(tmp_path, monkeypatch):
    output, _ = ingest(tmp_path, [{"repository": "fixture/unavailable", "sha": "a" * 40, "dataset": "swe-chat"}])
    monkeypatch.setattr(batch, "_acquire_git", lambda *args: pytest.fail("offline network attempt"))
    result = batch.run_batch(output, tmp_path / "cache")
    assert result["commit_status_counts"] == {"blocked": 1}
    assert result["exit_code"] == 2
    assert not result["all_dataset_commits_analyzed_without_gaps"]
    assert not exported(output, "log_observations")
    assert exported(output, "gaps")[0]["reason"] == "repository_unavailable"


def test_interrupt_is_durable_and_resume_only_unfinished(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    init(repo)
    a = commit(repo, {"app.py": HEADER + 'logger.info("a")\n'}, "a")
    b = commit(repo, {"app.py": HEADER + 'logger.info("b")\n'}, "b", day=3)
    output, _ = ingest(tmp_path, [row(repo, a), row(repo, b)])
    original = batch._mine_commit
    calls = []

    def interrupt(path, repository, sha, **kwargs):
        calls.append(sha)
        if len(calls) == 2:
            raise KeyboardInterrupt()
        return original(path, repository, sha, **kwargs)

    monkeypatch.setattr(batch, "_mine_commit", interrupt)
    with pytest.raises(KeyboardInterrupt):
        batch.run_batch(output, tmp_path / "cache")
    with sqlite3.connect(output / "batch.sqlite") as db:
        assert dict(db.execute("SELECT sha,status FROM jobs")) == {a: "complete", b: "running"}
        assert db.execute("SELECT COUNT(*) FROM records WHERE kind='log_observations'").fetchone()[0] == 1
    monkeypatch.setattr(batch, "_mine_commit", original)
    result = batch.run_batch(output, tmp_path / "cache")
    assert result["this_run_commits_attempted"] == 1
    assert {r["sha"]: r["attempts"] for r in exported(output, "commit_audit")} == {a: 1, b: 2}
    assert len(exported(output, "log_observations")) == 3


def test_deletion_unsupported_parse_gap_and_public_redaction(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    synthetic = "ghp_" + "A" * 32
    source = HEADER + 'def run(user):\n    password = "' + synthetic + '"\n    logger.info("value", password)\n'
    old = commit(repo, {"app.py": source}, "intro")
    (repo / "app.py").unlink()
    deletion = commit(repo, {"main.go": 'package main\n', "index.mts": 'console.log("v");\n',
                           "README.md": "Unexamined documentation\n", "broken.py": 'logger.info(\n'}, "remove", day=3)
    output, _ = ingest(tmp_path, [row(repo, old), row(repo, deletion)])
    result = batch.run_batch(output, tmp_path / "cache")
    assert result["commit_status_counts"].get("partial") == 1
    assert any(log["sha"] == deletion and log["side"] == "before" for log in exported(output, "log_observations"))
    reasons = {gap["reason"] for gap in exported(output, "gaps")}
    assert "unsupported_language" in reasons
    assert "python_ast_parse_failed" in reasons
    assert result["file_analysis_status_counts"]["unsupported_language"] == 1
    assert result["file_analysis_status_counts"]["non_code_or_unrecognized_extension"] == 1
    for path in (output / "exports").iterdir():
        assert synthetic not in path.read_text()


def test_budgets_emit_gaps_and_parameter_changes_refuse_stale_resume(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    sha = commit(repo, {"a.py": HEADER + 'from helpers import value\nlogger.info("v", value)\n',
                        "b.py": HEADER + 'logger.info("b")\n'}, "two")
    output, _ = ingest(tmp_path, [row(repo, sha)])
    result = batch.run_batch(output, tmp_path / "cache", max_changed_files=1, max_dependency_files=0)
    assert result["commit_status_counts"] == {"partial": 1}
    assert {"changed_file_budget_exceeded", "direct_import_budget_exceeded"} <= {
        gap["reason"] for gap in exported(output, "gaps")}
    with pytest.raises(ValueError, match="parameters changed"):
        batch.run_batch(output, tmp_path / "cache", max_changed_files=2)


def test_real_merge_keeps_each_parent_diff_and_fallback_evidence(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    git(repo, "checkout", "-qb", "side")
    side = commit(repo, {"side.py": HEADER + 'logger.info("side")\n'}, "side")
    git(repo, "checkout", "-q", "main")
    main = commit(repo, {"main.py": HEADER + 'logger.info("main")\n'}, "main", day=3)
    git(repo, "merge", "--no-ff", "side", "-m", "merge", day=4)
    merge = git(repo, "rev-parse", "HEAD")
    output, _ = ingest(tmp_path, [row(repo, merge)])
    batch.run_batch(output, tmp_path / "cache")
    audits = exported(output, "file_audit")
    assert {a["parent_sha"] for a in audits} == {main, side}
    assert all("pydriller" in a["diff_backend"].lower() and "fallback_reason" in a for a in audits)
    commit_audit = exported(output, "commit_audit")[0]
    assert commit_audit["metrics"]["pydriller_git_diff_calls"] == 2
    assert commit_audit["metrics"]["pydriller_diff_parsed_calls"] == 2


def test_online_disk_preflight_stops_before_process(tmp_path, monkeypatch):
    from collections import namedtuple
    usage = namedtuple("usage", "total used free")(100, 99, 1)
    monkeypatch.setattr(batch.shutil, "disk_usage", lambda path: usage)
    monkeypatch.setattr(batch.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("insufficient disk must stop before clone"))
    with pytest.raises(OSError, match="disk_reserve"):
        batch._acquire_git(["clone", "https://github.com/fixture/repo.git"], 1, tmp_path)


def test_swechat_contexts_preserved_casefolded_and_body_omitted(tmp_path):
    source = {"repository": "Fixture/Project", "sha": "A" * 40, "source_context_id": "session-checkpoint-1",
        "source_kind": "swechat", "session_ids": ["session-1"], "checkpoint_pks": [42],
        "swechat_source_snapshot": "fixture-v1", "context_statuses": ["linked"],
        "commit_metadata_present": True, "body": "PRIVATE_FIXTURE_BODY_NOT_TO_EXPORT"}
    output, result = ingest(tmp_path, [source, {**source, "repository": "fixture/project"}])
    assert result["unique_commits"] == result["unique_contexts"] == 1
    batch.export_batch(output)
    context = exported(output, "contexts")[0]
    assert context["repository"] == "fixture/project"
    assert context["sha"] == "a" * 40
    assert context["dataset"] == "swe-chat"
    assert context["context_ids"] == ["session-checkpoint-1"]
    for key in ("source_kind", "source_context_id", "session_ids", "checkpoint_pks", "swechat_source_snapshot",
                "context_statuses", "commit_metadata_present"):
        assert context[key] == source[key]
    assert "body" not in context


def test_modified_classifier_code_refuses_stale_resume(tmp_path, monkeypatch):
    output, _ = ingest(tmp_path, [])
    batch.run_batch(output, tmp_path / "cache")
    original = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda path: b"changed" if path.name == "detector.py" else original(path))
    with pytest.raises(ValueError, match="Analysis code"):
        batch.run_batch(output, tmp_path / "cache")


def test_failed_real_traversal_attempt_remains_in_metrics(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    sha = init(repo)
    output, _ = ingest(tmp_path, [row(repo, sha)])
    def fail(*args, **kwargs):
        raise ValueError("synthetic extraction failure")
    monkeypatch.setattr(batch.Repository, "traverse_commits", fail)
    result = batch.run_batch(output, tmp_path / "cache")
    assert result["commit_status_counts"] == {"blocked": 1}
    assert result["actual_extraction_metrics"]["pydriller_repository_traversals"] == 1
    assert exported(output, "gaps")[0]["reason"] == "pydriller_traversal_error"


def test_same_line_repeated_calls_are_distinct_log_versions(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    sha = commit(repo, {"app.py": HEADER + 'logger.info("fixed"); logger.info("fixed")\n'}, "repeat")
    output, _ = ingest(tmp_path, [row(repo, sha)])
    result = batch.run_batch(output, tmp_path / "cache")
    logs = exported(output, "log_observations")
    assert len(logs) == 2
    assert len({log["log_version_id"] for log in logs}) == 2
    assert result["type_audit"]["distinct_observed_log_versions"] == 2


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_shared_snippets_match_ast_unicode_and_multiline(newline):
    from agentlog_unified.detector import _snippet, _source_line_bytes
    source = newline.join(['变量 = "雪🌨"; logger.info("值", 变量)',
                           'logger.info(', '    "跨行\\n值",', '    {"键": 变量},', ')',
                           'logger.info("保留\u2028字符")', '\fresult = "done"', ''])
    nodes = [node for node in ast.walk(ast.parse(source)) if hasattr(node, "end_lineno")]
    expected = [ast.get_source_segment(source, node) or "" for node in nodes]
    _source_line_bytes.cache_clear()
    for _ in range(4):
        assert [_snippet(source, node) for node in nodes] == expected
    assert _source_line_bytes.cache_info().misses == 1
    assert _source_line_bytes.cache_info().hits >= len(nodes) * 3
    assert _snippet(source, ast.Name(id="no_position")) == ""


def test_shared_snippet_cache_is_bounded():
    from agentlog_unified.detector import _snippet, _source_line_bytes
    _source_line_bytes.cache_clear()
    for index in range(20):
        source = f'logger.info("fixture {index}")\n'
        _snippet(source, ast.parse(source).body[0])
    assert _source_line_bytes.cache_info().currsize <= 4
