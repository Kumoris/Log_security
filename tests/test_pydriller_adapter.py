"""Real local Git histories; no target project code is executed."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from pydriller import Git

from agentlog_unified.git_support import is_ancestor, run_git
from agentlog_unified.miner import mine_repository, snapshot_files


def git(repo: Path, *args: str, date: str = "2025-01-01T12:00:00+0000",
        check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
         "-C", str(repo), *args], text=True, capture_output=True, check=check,
        env={**os.environ, "GIT_AUTHOR_NAME": "Fixture Author",
             "GIT_AUTHOR_EMAIL": "fixture-author@example.invalid",
             "GIT_COMMITTER_NAME": "Fixture Committer",
             "GIT_COMMITTER_EMAIL": "fixture-committer@example.invalid",
             "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date})
    return result.stdout.strip()


def commit(repo: Path, name: str, files: dict[str, str], **kwargs) -> str:
    for path, source in files.items():
        destination = repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source)
    git(repo, "add", "--all")
    git(repo, "commit", "-qm", name, **kwargs)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def history(tmp_path):
    repo = tmp_path / "synthetic"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    root = commit(repo, "root", {"auth.py": 'logger.info("start")\n', "empty.py": ""})
    intro = commit(repo, "intro", {"auth.py": 'logger.info(\n    "user",\n    extra={"validator": validator},\n)\n'},
                   date="2025-01-03T12:00:00+0000")
    git(repo, "mv", "auth.py", "login.py")
    git(repo, "commit", "-qm", "rename")
    rename = git(repo, "rev-parse", "HEAD")
    repair = commit(repo, "repair without PR", {"login.py": 'logger.info(\n    "user",\n)\n'},
                    date="2024-01-01T12:00:00+0000")
    git(repo, "checkout", "-qb", "side", root)
    side = commit(repo, "unmerged branch", {"side.py": 'logger.info("side")\n'})
    git(repo, "checkout", "-q", "main")
    git(repo, "branch", "-D", "side")
    return repo, root, intro, rename, repair, side


def test_real_pydriller_before_after_rename_and_date_order(history):
    repo, root, intro, rename, repair, _ = history
    result = mine_repository(str(repo), repair, [root, intro])
    assert not result["gaps"]
    assert [c["sha"] for c in result["commits"]] == [root, intro, rename, repair]
    changed = next(x for x in result["changes"] if x["sha"] == repair)
    assert changed["deleted"] == [[3, '    extra={"validator": validator},']]
    assert changed["before_source"].startswith('logger.info(\n')
    assert 'validator' not in changed["after_source"]
    assert changed["diff_backend"] == "pydriller.Commit.modified_files"
    assert changed["source_backends"]["before"] == "pydriller.ModifiedFile.source_code_before"
    renamed = next(x for x in result["changes"] if x["sha"] == rename)
    assert (renamed["old_path"], renamed["new_path"]) == ("auth.py", "login.py")
    assert renamed["change_type"] == "RENAME"
    assert result["metrics"]["pydriller_commits"] == 4
    assert result["metrics"]["pydriller_modified_files_calls"] == 4
    assert result["metrics"]["pydriller_diff_parsed_calls"] == len(result["changes"])
    empty = next(x for x in result["changes"] if x["new_path"] == "empty.py")
    assert empty["after_source"] == ""
    assert empty["source_status"]["before"] == "absent_by_change_type"
    assert is_ancestor(str(repo), intro, repair)


def test_unreachable_initial_missing_object_budget_and_snapshot(history):
    repo, root, intro, _, repair, side = history
    result = mine_repository(str(repo), repair, [intro, side, "f" * 40], max_commits=3)
    assert {intro, side, repair} == set(result["selected_shas"])
    assert {intro, side, repair} == {x["sha"] for x in result["commits"]}
    assert next(x for x in result["commits"] if x["sha"] == side)["target_reachable"] is False
    errors = {x["error_type"] for x in result["gaps"]}
    assert errors == {"missing_initial_object", "history_budget_exceeded"}
    assert result["history_scope"]["omitted_pre_initial_commits"] == 1
    snapshot = snapshot_files(str(repo), root)
    assert snapshot["files"] == {"auth.py": 'logger.info("start")\n', "empty.py": ""}
    assert snapshot["revision_backend"] == "pydriller.Git.get_commit"
    assert "empty.py" not in snapshot_files(str(repo), root, max_files=1)["files"]
    assert snapshot_files(str(repo), root, max_files=1)["gaps"]


def test_root_delete_and_invalid_source_are_explicit(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    root = commit(tmp_path, "base", {"app.py": 'logger.info("start")\n'})
    git(tmp_path, "rm", "app.py")
    (tmp_path / "invalid.py").write_bytes(b'logger.info("\xff")\n')
    deleted = commit(tmp_path, "delete", {})
    result = mine_repository(str(tmp_path), deleted, [root])
    change = next(x for x in result["changes"] if x["change_type"] == "DELETE")
    assert change["before_source"] == 'logger.info("start")\n'
    assert change["after_source"] is None
    assert change["source_status"]["after"] == "absent_by_change_type"
    invalid = next(x for x in result["changes"] if x["new_path"] == "invalid.py")
    assert invalid["after_source"] is None
    assert invalid["source_status"]["after"] == "decode_error"
    assert any(x["error_type"] == "decode_error" for x in result["gaps"])


@pytest.mark.parametrize("force_fallback", [False, True])
def test_real_merge_resolution_log_read_for_each_parent(tmp_path, monkeypatch, force_fallback):
    git(tmp_path, "init", "-q", "-b", "main")
    root = commit(tmp_path, "base", {"app.py": 'value = "base"\n'})
    git(tmp_path, "checkout", "-qb", "topic")
    left = commit(tmp_path, "left", {"app.py": 'value = "left"\n'})
    git(tmp_path, "checkout", "-q", "main")
    right = commit(tmp_path, "right", {"app.py": 'value = "right"\n'})
    git(tmp_path, "merge", "--no-ff", "topic", "-m", "merge", check=False)
    merged = commit(tmp_path, "resolution", {"app.py": 'value = "merged"\nlogger.info("payload=%s", payload)\n'})
    if force_fallback:
        monkeypatch.setattr(Git, "diff", lambda self, before, after: [])
    result = mine_repository(str(tmp_path), merged, [root, left])
    assert not result["gaps"]
    changes = [x for x in result["changes"] if x["sha"] == merged]
    assert {x["parent_sha"] for x in changes} == {left, right}
    assert all('logger.info' in x["after_source"] for x in changes)
    assert all('logger.info' not in x["before_source"] for x in changes)
    assert all([2, 'logger.info("payload=%s", payload)'] in x["added"] for x in changes)
    assert result["metrics"]["pydriller_git_diff_calls"] == 2
    if force_fallback:
        assert result["metrics"]["merge_fallbacks"] == 2
        assert all(x["fallback_reason"] for x in changes)
    else:
        assert all(x["diff_backend"] == "pydriller.Git.diff" for x in changes)
        assert all(x["fallback_reason"] is None for x in changes)
    order = {c["sha"]: c["topo_index"] for c in result["commits"]}
    assert all(order[p] < order[c["sha"]] for c in result["commits"] for p in c["parents"])


def test_readonly_git_contract_and_source_budget(history):
    repo, root, _, _, repair, _ = history
    with pytest.raises(ValueError):
        run_git(str(repo), ["checkout", root])
    with pytest.raises(ValueError):
        run_git(str(repo), ["diff", "--ext-diff"])
    result = mine_repository(str(repo), repair, [root], max_source_bytes=5)
    assert any(g["error_type"] == "source_budget_exceeded" for g in result["gaps"])
    assert all(x["after_source"] is None or len(x["after_source"].encode()) <= 5
               for x in result["changes"])


def test_shallow_and_missing_target_never_claim_complete_history(history, tmp_path):
    repo, _root, _intro, _rename, repair, side = history
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "clone", "--no-checkout",
                    "--depth", "1", repo.as_uri(), str(shallow)],
                   capture_output=True, check=True)
    result = mine_repository(str(shallow), repair, [repair])
    assert any(g["error_type"] == "shallow_history" for g in result["gaps"])
    result = mine_repository(str(repo), "f" * 40, [side])
    assert any(g["error_type"] == "missing_target_object" for g in result["gaps"])
    assert result["commits"][0]["sha"] == side
    assert result["commits"][0]["target_reachable"] is False


def test_missing_initial_object_preserves_available_history(history):
    repo, _root, intro, _rename, repair, _side = history
    # A missing initial object is real Git resolution failure, not an empty patch.
    result = mine_repository(str(repo), repair, ["f" * 40, intro])
    assert result["gaps"][0]["error_type"] == "missing_initial_object"
    assert result["metrics"]["resolved_initial_commits"] == 1
    assert result["metrics"]["pydriller_commits"] == 3


def test_promisor_missing_blob_never_triggers_implicit_fetch(tmp_path, monkeypatch):
    repo = tmp_path / "partial"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    revision = commit(repo, "root", {"app.py": 'logger.info("synthetic")\n'})
    blob = git(repo, "rev-parse", "HEAD:app.py")
    (repo / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
    git(repo, "config", "remote.origin.url", (tmp_path / "unavailable-repository").as_uri())
    git(repo, "config", "remote.origin.promisor", "true")
    git(repo, "config", "remote.origin.partialclonefilter", "blob:none")
    trace = tmp_path / "git-process-trace.txt"
    monkeypatch.setenv("GIT_TRACE", str(trace))
    monkeypatch.setenv("GIT_NO_LAZY_FETCH", "0")
    result = mine_repository(str(repo), revision, [revision])
    snapshot = snapshot_files(str(repo), revision)
    assert result["object_state"]["promisor_configured"] is True
    assert result["object_state"]["implicit_lazy_fetch_enabled"] is False
    assert any(g["error_type"] == "missing_promisor_object" for g in result["gaps"])
    assert any(g["error_type"] == "missing_promisor_object" for g in snapshot["gaps"])
    assert "fetch " not in trace.read_text()
    assert os.environ["GIT_NO_LAZY_FETCH"] == "1"
