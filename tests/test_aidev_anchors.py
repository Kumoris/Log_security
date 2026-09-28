"""Frozen metadata anchors remain separate from initial PR commit membership."""
import json
import sqlite3
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from agentlog_unified.aidev import _digest, import_aidev
from agentlog_unified.aidev_anchors import export_aidev_anchors
from agentlog_unified.batch_mine import ingest_commit_contexts


def table(source, name, rows):
    source.mkdir(exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows), source / f"{name}.parquet")


def records(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def prepare(tmp_path):
    source, imported = tmp_path / "source", tmp_path / "import"
    table(source, "prs", [{"id": 1, "html_url": "https://github.com/o/r/pull/1", "body": "PRIVATE_BODY"},
                          {"id": 2, "html_url": "https://github.com/o/r/pull/2", "body": "PRIVATE_BODY"}])
    table(source, "pr_commits", [{"pr_id": 1, "sha": "a" * 40}])
    events = [(1, "committed", "a" * 40), (1, "merged", "b" * 40), (1, "reviewed", "c" * 40),
              (2, "head_ref_force_pushed", "d" * 40), (1, "referenced", "e" * 40),
              (1, "closed", "f" * 40), (1, "PRIVATE_UNKNOWN_EVENT", "0" * 40),
              (1, "merged", "PRIVATE_INVALID_SHA"), (999, "reviewed", "1" * 40),
              (1, "merged", None)]
    table(source, "pr_timeline", [{"pr_id": p, "event": e, "commit_id": s, "message": "PRIVATE_MESSAGE"} for p, e, s in events])
    for name in ("pr_review_comments", "pr_review_comments_v2"):
        table(source, name, [{"pull_request_url": "https://api.github.com/repos/o/r/pulls/2",
                            "commit_id": "2" * 40, "original_commit_id": "3" * 40,
                            "body": "PRIVATE_REVIEW", "diff_hunk": "PRIVATE_PATCH"}])
    import_aidev(source, imported)
    return source, imported


def test_source_anchors_preserve_scope_refs_gaps_and_batch_context(tmp_path):
    source, imported = prepare(tmp_path)
    before = {p.name: _digest(p) for p in imported.iterdir()}
    output = tmp_path / "anchors"
    result = export_aidev_anchors(imported, output)
    assert result["complete"] and result["exit_code"] == 2
    assert result["counts"]["mining_contexts"] == 5
    assert result["counts"]["related_only_contexts"] == 3
    assert result["counts"]["new_unique_pr_sha_pairs"] == 8
    assert result["counts"]["newly_anchored_prs"] == 1
    assert result["counts"]["remaining_prs_without_structured_anchor"] == 0
    assert result["gap_counts"] == {"invalid_exact_sha": 1, "unresolved_or_ambiguous_pr_relation": 1}
    assert result["counts"]["source_rows_read"] == 12
    assert result["counts"]["anchor_fields_already_in_main_membership"] == 1
    assert before == {p.name: _digest(p) for p in imported.iterdir()}
    assert records(imported / "mining_prs.jsonl")[0]["initial_commit_shas"] == ["a" * 40]
    rows = records(output / "mining_commit_anchors.jsonl")
    assert {row["sha"] for row in rows} == {char * 40 for char in "bcd23"}
    original = next(row for row in rows if row["sha"] == "3" * 40)
    assert len(original["source_refs"]) == 2  # Duplicate table versions preserve both sources.
    assert {ref["column"] for ref in original["source_refs"]} == {"original_commit_id"}
    assert all(row["aidev_source_snapshot"] == result["aidev_source_snapshot"] for row in rows)
    assert all("initial_pr_membership_unverified" in row["context_statuses"] for row in rows)
    assert all("initial_commit_shas" not in row for row in rows)
    batch = tmp_path / "batch"
    ingest_commit_contexts(output / "mining_commit_anchors.jsonl", batch)
    with sqlite3.connect(batch / "batch.sqlite") as db:
        contexts = [json.loads(data) for data, in db.execute("SELECT data FROM contexts")]
    assert all("initial_pr_membership_unverified" in row["context_statuses"] for row in contexts)
    assert {row["source_kind"] for row in rows} == {row["source_kind"] for row in contexts}
    assert all(row["source_refs"] and row["source_context_id"] for row in contexts)
    for path in output.iterdir():
        assert "PRIVATE_" not in path.read_text()
        assert path.stat().st_mode & 0o077 == 0


def test_dry_run_resume_hash_checks_and_input_separation(tmp_path):
    source, imported = prepare(tmp_path)
    output = tmp_path / "anchors"
    assert not export_aidev_anchors(imported, output, dry_run=True)["files_written"]
    assert not output.exists()
    with pytest.raises(ValueError, match="separate"):
        export_aidev_anchors(imported, imported / "anchors")
    with pytest.raises(ValueError, match="separate"):
        export_aidev_anchors(imported, source)
    export_aidev_anchors(imported, output)
    assert export_aidev_anchors(imported, output, resume=True)["resumed"]
    with pytest.raises(ValueError, match="already exists"):
        export_aidev_anchors(imported, output)
    (output / "anchor_gaps.jsonl").write_text("{}\n")
    with pytest.raises(ValueError, match="modified"):
        export_aidev_anchors(imported, output, resume=True)
    table(source, "pr_timeline", [{"pr_id": 1, "event": "merged", "commit_id": "b" * 40}])
    with pytest.raises(ValueError, match="Frozen source table changed"):
        export_aidev_anchors(imported, tmp_path / "changed")
    assert not (tmp_path / "changed").exists()


def test_ambiguous_or_conflicting_pr_identity_never_becomes_anchor(tmp_path):
    source, imported = tmp_path / "source", tmp_path / "import"
    table(source, "prs", [{"id": 1, "html_url": "https://github.com/o/r/pull/1"},
                          {"id": 1, "html_url": "https://github.com/o/r/pull/2"},
                          {"id": 2, "html_url": "https://github.com/o/r/pull/3"}])
    table(source, "pr_timeline", [{"pr_id": 1, "html_url": None, "event": "merged", "commit_id": "a" * 40},
                                   {"pr_id": 2, "html_url": "https://github.com/o/r/pull/2", "event": "merged", "commit_id": "b" * 40}])
    import_aidev(source, imported)
    result = export_aidev_anchors(imported, tmp_path / "out")
    assert result["gap_counts"]["unresolved_or_ambiguous_pr_relation"] == 2
    assert result["counts"]["new_unique_pr_sha_pairs"] == 0
    assert not records(tmp_path / "out" / "mining_commit_anchors.jsonl")


def test_changed_import_and_changed_during_export_are_not_completed(tmp_path, monkeypatch):
    import agentlog_unified.aidev_anchors as anchors
    source, imported = prepare(tmp_path)
    validate = anchors._validate_inputs
    calls = 0

    def change_after_first_check(*args):
        nonlocal calls
        result = validate(*args)
        calls += 1
        if calls == 1:
            (imported / "coverage.json").write_text("{}")
        return result

    monkeypatch.setattr(anchors, "_validate_inputs", change_after_first_check)
    output = tmp_path / "out"
    with pytest.raises(ValueError, match="artifact changed"):
        export_aidev_anchors(imported, output)
    assert json.loads((output / "manifest.json").read_text())["status"] == "failed"


def test_custom_sha_mapping_reads_only_corresponding_source_field(tmp_path):
    source, imported = tmp_path / "source", tmp_path / "import"
    table(source, "prs", [{"id": 1, "html_url": "https://github.com/o/r/pull/1"}])
    table(source, "timeline", [{"pr_id": 1, "revision": "a" * 40, "event": "reviewed"}])
    import_aidev(source, imported, column_mapping={"timeline": {"sha": "revision"}})
    result = export_aidev_anchors(imported, tmp_path / "out")
    assert result["counts"]["mining_contexts"] == 1
    row = records(result["paths"]["mining_commit_anchors.jsonl"])[0]
    assert row["source_refs"][0]["column"] == "revision"


def test_invalid_main_sha_does_not_count_as_existing_commit_evidence(tmp_path):
    source, imported = tmp_path / "source", tmp_path / "import"
    table(source, "prs", [{"id": 1, "html_url": "https://github.com/o/r/pull/1"}])
    table(source, "pr_commits", [{"pr_id": 1, "sha": "invalid"}])
    table(source, "pr_timeline", [{"pr_id": 1, "commit_id": "a" * 40, "event": "reviewed"}])
    initial = import_aidev(source, imported)
    assert initial["counts"]["prs_without_commit_evidence"] == 1
    result = export_aidev_anchors(imported, tmp_path / "out")
    assert result["counts"]["newly_anchored_prs"] == 1
    assert result["counts"]["remaining_prs_without_structured_anchor"] == 0
