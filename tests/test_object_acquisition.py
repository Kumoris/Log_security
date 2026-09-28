import json
import os
import sqlite3
import subprocess

import pytest

from agentlog_unified import object_acquisition as acquire
from agentlog_unified.batch_mine import ingest_commit_contexts, run_batch, repository_cache_path
from agentlog_unified.cli import main
from synthetic_histories import HEADER, commit, git, init


def remote_transport(monkeypatch, repo):
    git(repo, "config", "uploadpack.allowFilter", "true")
    git(repo, "config", "uploadpack.allowAnySHA1InWant", "true")
    requests = []

    def fetch(args, timeout, disk_path):
        assert os.environ["GIT_NO_LAZY_FETCH"] == "1"
        args = [repo.as_uri() if arg == "https://github.com/fixture/project.git" else arg for arg in args]
        requests.append(args)
        subprocess.run(["git", *args], check=True, capture_output=True, timeout=timeout,
                       env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"})
    monkeypatch.setattr(acquire, "_acquire_git", fetch)
    return requests


def seed(tmp_path, sha):
    source = tmp_path / "input.jsonl"
    source.write_text(json.dumps({"repository": "fixture/project", "sha": sha}) + "\n")
    batch = tmp_path / "batch"
    ingest_commit_contexts(source, batch)
    return batch


def test_blobless_collection_then_offline_pydriller_and_resume(tmp_path, monkeypatch):
    repo = tmp_path / "remote"
    init(repo)
    old = commit(repo, {"helpers.py": "def reveal(user):\n    return user.password\n",
                        "src/app.py": HEADER + 'logger.info("fixed")\n'}, "before")
    sha = commit(repo, {"src/app.py": HEADER + 'from helpers import reveal\ndef run(user):\n    logger.info("v", reveal(user))\n'}, "after", day=3)
    requests = remote_transport(monkeypatch, repo)
    batch = seed(tmp_path, sha)
    result = acquire.collect_batch_objects(batch, tmp_path / "cache", offline=False)
    assert result["this_run_status_counts"] == {"objects_ready_for_offline_mining": 1}
    path = repository_cache_path(tmp_path / "cache", "fixture/project")
    assert acquire._parents(path, sha) == [old]
    assert any("--filter=blob:none" in request for request in requests)
    calls = len(requests)
    metrics = run_batch(batch, tmp_path / "cache", offline=True)["actual_extraction_metrics"]
    assert metrics["pydriller_commits"] == 1
    assert metrics["pydriller_diff_parsed_calls"] == 1
    assert metrics["pydriller_source_reads"] == 2
    assert metrics["dependency_blobs_read"] == 1
    assert len(requests) == calls
    repeat = acquire.collect_batch_objects(batch, tmp_path / "cache", offline=False)
    assert repeat["this_run_attempted"] == 0
    rows = [json.loads(r) for r in (batch / "collection/object_acquisitions.jsonl").read_text().splitlines()]
    assert rows[0]["metrics"]["direct_import_blobs_objects_missing_before"] == 1
    assert not rows[0]["classification_performed"]


def test_root_merge_rename_and_gitlink_object_planning(tmp_path, monkeypatch):
    repo = tmp_path / "remote"
    root = init(repo)
    git(repo, "checkout", "-qb", "side")
    side = commit(repo, {"old.py": HEADER + 'logger.info("side")\n'}, "side")
    git(repo, "checkout", "-q", "main")
    base = commit(repo, {"main.py": HEADER + 'logger.info("main")\n'}, "main")
    git(repo, "merge", "--no-ff", "side", "-m", "merge")
    merge = git(repo, "rev-parse", "HEAD")
    git(repo, "mv", "old.py", "new.py")
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{root},submodule")
    git(repo, "commit", "-qm", "rename plus gitlink")
    renamed = git(repo, "rev-parse", "HEAD")
    remote_transport(monkeypatch, repo)
    path = tmp_path / "cache"
    for sha in (root, merge, renamed):
        result = acquire.materialize_commit(path, "fixture/project", sha)
        assert result["status"] == "objects_ready_for_offline_mining", result
    assert set(acquire._parents(path, merge)) == {side, base}
    changes = acquire._changed_objects(path, renamed, [merge])
    assert next(c for c in changes if c["path"] == "submodule")["after"] is None
    assert {c["path"] for c in changes} >= {"old.py", "new.py", "submodule"}
    from pydriller import Repository
    mined = list(Repository(str(path), single=renamed).traverse_commits())[0]
    assert any(f.old_path == "old.py" and f.new_path == "new.py" for f in mined.modified_files)


def test_offline_dry_run_budgets_and_failed_attempt_journal(tmp_path, monkeypatch):
    batch = seed(tmp_path, "a" * 40)
    monkeypatch.setattr(acquire, "_acquire_git", lambda *a: pytest.fail("unexpected network"))
    assert main(["collect-objects", "--output", str(batch), "--cache-dir", str(tmp_path / "cache"), "--dry-run", "--online"]) == 0
    assert not (batch / "collection").exists() and not (tmp_path / "cache").exists()
    result = acquire.collect_batch_objects(batch, tmp_path / "cache", offline=True)
    assert result["this_run_status_counts"] == {"acquisition_gap": 1}
    assert not (tmp_path / "cache").exists()
    repeat = acquire.collect_batch_objects(batch, tmp_path / "cache")
    assert repeat["this_run_attempted"] == 0 and repeat["exit_code"] == 2
    assert acquire.collect_batch_objects(batch, tmp_path / "cache", retry_failed=True)["this_run_attempted"] == 1
    with sqlite3.connect(batch / "batch.sqlite") as db:
        assert db.execute("SELECT status FROM jobs").fetchone()[0] == "pending"
        assert db.execute("SELECT count(*) FROM object_acquisitions").fetchone()[0] == 2
    with pytest.raises(ValueError, match="nonnegative"):
        acquire.collect_batch_objects(batch, tmp_path / "cache", max_commits=-1)


def test_ready_collection_requeues_only_blocked_and_retains_history(tmp_path, monkeypatch):
    repo = tmp_path / "remote"
    sha = init(repo)
    remote_transport(monkeypatch, repo)
    batch = seed(tmp_path, sha)
    with sqlite3.connect(batch / "batch.sqlite") as db:
        db.execute("UPDATE jobs SET status='blocked'")
    result = acquire.collect_batch_objects(batch, tmp_path / "cache", offline=False)
    assert result["this_run_attempted"] == 1
    with sqlite3.connect(batch / "batch.sqlite") as db:
        assert db.execute("SELECT status FROM jobs").fetchone()[0] == "pending"
    run_batch(batch, tmp_path / "cache", offline=True)
    with sqlite3.connect(batch / "batch.sqlite") as db:
        assert db.execute("SELECT count(*) FROM object_acquisitions").fetchone()[0] == 1
        db.execute("UPDATE jobs SET status='partial'")
    assert acquire.collect_batch_objects(batch, tmp_path / "cache", offline=True)["this_run_attempted"] == 0
    retry = acquire.collect_batch_objects(batch, tmp_path / "cache", offline=True, retry_failed=True)
    assert retry["this_run_attempted"] == 1
    with sqlite3.connect(batch / "batch.sqlite") as db:
        assert db.execute("SELECT status FROM jobs").fetchone()[0] == "pending"


def test_failed_fetch_attempt_retains_phase_and_reason(tmp_path, monkeypatch):
    def fail(*args):
        raise TimeoutError("online_acquisition_time_budget_exceeded")
    monkeypatch.setattr(acquire, "_acquire_git", fail)
    result = acquire.materialize_commit(tmp_path / "cache", "fixture/project", "a" * 40)
    assert result["reason"] == "online_acquisition_time_budget_exceeded"
    assert result["metrics"]["explicit_fetch_attempts"] == 1
    assert result["metrics"].get("explicit_fetch_calls", 0) == 0
    assert result["stages"][0]["status"] == "failed"
