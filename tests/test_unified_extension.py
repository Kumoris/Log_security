"""Incremental extraction checks using local Git; target code is never executed."""
import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from agentlog_unified.extension import load_previous_run, validate_extension
from agentlog_unified.miner import mine_repository
from agentlog_unified.storage import Store, canonical
from test_pydriller_adapter import commit, git


@pytest.fixture
def history(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    root = commit(repo, "initial", {"app.py": 'logger.info("start")\n'})
    intro = commit(repo, "initial PR", {"app.py": 'logger.info("request", extra={"data": user})\n'})
    previous = mine_repository(str(repo), intro, [root])
    repair = commit(repo, "later change without PR", {"app.py": 'logger.info("request")\n'})
    return repo, root, intro, repair, previous


def metadata(repo, root, tip):
    return {"id": "repository-id", "repository_id": "synthetic/repo", "local_repo_path": str(repo),
            "target_ref": "main", "initial_shas": [root], "frozen_target_tip": tip}


def test_incremental_pydriller_only_extracts_new_commit_and_rebuilds_graph(history):
    repo, root, intro, repair, previous = history
    pristine = deepcopy(previous)
    extended = mine_repository(str(repo), repair, [root], previous=previous)
    clean = mine_repository(str(repo), repair, [root])
    assert extended["selected_shas"] == clean["selected_shas"]
    assert extended["graph"] == clean["graph"]
    assert extended["first_parent_shas"] == [root, intro, repair]
    assert extended["metrics"]["pydriller_commits"] == 1
    assert extended["metrics"]["pydriller_modified_files_calls"] == 1
    assert extended["metrics"]["pydriller_diff_parsed_calls"] == 1
    assert extended["metrics"]["pydriller_source_reads"] == 2
    assert extended["metrics"]["reused_commits"] == 2
    assert extended["metrics"]["reused_files"] == 2
    assert extended["metrics"]["new_files_extracted"] == 1
    assert extended["metrics"]["total_file_records"] == 3
    assert [r["topo_index"] for r in extended["commits"]] == [0, 1, 2]
    assert [(r["sha"], r["diff"], r["before_source"], r["after_source"])
            for r in extended["changes"]] == [(r["sha"], r["diff"], r["before_source"], r["after_source"])
                                            for r in clean["changes"]]
    assert previous == pristine
    assert not extended["gaps"]


def test_unchanged_tip_reuses_all_and_current_budget_is_still_enforced(history):
    repo, root, intro, repair, previous = history
    unchanged = mine_repository(str(repo), intro, [root], previous=previous)
    assert unchanged["metrics"]["pydriller_repository_traversals"] == 0
    assert unchanged["metrics"]["pydriller_commits"] == 0
    assert unchanged["metrics"]["reused_commits"] == 2
    limited = mine_repository(str(repo), repair, [root], max_commits=2, previous=previous)
    assert limited["selected_shas"] == [root, repair]
    assert limited["metrics"]["reused_commits"] == 1
    assert limited["metrics"]["pydriller_commits"] == 1
    assert any(g["error_type"] == "history_budget_exceeded" for g in limited["gaps"])


@pytest.mark.parametrize("damage", ["missing_file", "missing_source", "source_changed", "related_gap", "marker_missing"])
def test_incomplete_cache_is_reextracted_not_treated_as_complete(history, damage):
    repo, root, intro, repair, previous = history
    if damage == "missing_file":
        previous["changes"] = [r for r in previous["changes"] if r["sha"] != intro]
    elif damage == "missing_source":
        next(r for r in previous["changes"] if r["sha"] == intro)["after_source"] = None
    elif damage == "source_changed":
        next(r for r in previous["changes"] if r["sha"] == intro)["after_source"] = "altered cache"
    elif damage == "related_gap":
        previous["gaps"].append({"sha": intro, "error_type": "source_extraction_error"})
    else:
        next(r for r in previous["commits"] if r["sha"] == intro).pop("extraction_complete")
    extended = mine_repository(str(repo), repair, [root], previous=previous)
    assert extended["metrics"]["reused_commits"] == 1
    assert extended["metrics"]["pydriller_commits"] == 2
    assert extended["metrics"]["cache_rejected_commits"] == 1
    assert not extended["gaps"]
    assert next(r for r in extended["changes"] if r["sha"] == intro)["after_source"].startswith("logger.info")


def test_rewritten_history_and_different_repo_cannot_be_spliced(history):
    repo, root, intro, repair, previous = history
    git(repo, "reset", "--hard", root)
    replacement = commit(repo, "rewritten main", {"other.py": 'logger.info("other")\n'})
    with pytest.raises(ValueError, match="first-parent"):
        mine_repository(str(repo), replacement, [root], previous=previous)
    previous["repo_path"] = str(repo.parent / "other")
    with pytest.raises(ValueError, match="repository path"):
        mine_repository(str(repo), repair, [root], previous=previous)


def test_validation_rejects_previous_tip_that_is_only_a_side_parent(history):
    repo, root, intro, repair, previous = history
    git(repo, "checkout", "-qb", "alternate", root)
    commit(repo, "other first parent", {"other.py": "x = 1\n"})
    git(repo, "merge", "--no-ff", "main", "-m", "merge former target as side parent")
    tip = git(repo, "rev-parse", "HEAD")
    previous["repository_id"] = "repository-id"
    data = {"run_id": "old", "repositories": [metadata(repo, root, intro)], "mined": [previous]}
    with pytest.raises(ValueError, match="first-parent"):
        validate_extension([metadata(repo, root, tip)], data)


def frozen_run(tmp_path, history):
    repo, root, intro, repair, previous = history
    project = tmp_path / "tool"
    run = project/"outputs/runs" / "old"
    run.mkdir(parents=True)
    config = {"storage": {"index_database": "data/index.sqlite"}}
    manifest = {"run_id": "old", "schema_version": "2.0", "code_sha256": "code",
                "config_hash": hashlib.sha256(canonical(config).encode()).hexdigest(),
                "config": config, "input_versions": {"prs_path": {"sha256": "input"}},
                "versions": {"PyDriller": "2.11", "GitPython": "3", "python": "3.11", "git": "git version"}}
    (run / "run_manifest.json").write_text(json.dumps(manifest))
    store = Store(run / "data/index.sqlite")
    previous["repository_id"] = "repository-id"
    with store.db:
        store.replace("repositories", [metadata(repo, root, intro)])
        store.replace("mined", [previous])
        store.finish("mine")
    store.close()
    return project, run, {**manifest, "run_id": "new"}


def test_load_previous_run_is_read_only_and_validates_identity(history, tmp_path):
    project, run, current = frozen_run(tmp_path, history)
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in run.rglob("*") if p.is_file()}
    data = load_previous_run(project, "old", current, current["config"])
    repo, root, intro, repair, _ = history
    previous = validate_extension([metadata(repo, root, repair)], data)["repository-id"]
    assert previous["source_run_id"] == "old"
    assert mine_repository(str(repo), repair, [root], previous=previous)["metrics"]["reused_commits"] == 2
    after = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in run.rglob("*") if p.is_file()}
    assert before == after
    bad_repo = {**metadata(repo, root, repair), "repository_id": "different/repository"}
    with pytest.raises(ValueError, match="identity"):
        validate_extension([bad_repo], data)


@pytest.mark.parametrize("key", ["code_sha256", "config_hash", "input_versions", "schema_version"])
def test_changed_rules_inputs_or_program_reject_old_run(history, tmp_path, key):
    project, run, current = frozen_run(tmp_path, history)
    current[key] = "changed"
    with pytest.raises(ValueError, match=key):
        load_previous_run(project, "old", current)
