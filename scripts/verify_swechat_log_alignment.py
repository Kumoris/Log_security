"""Reconcile exported alignment ledgers and recheck exact evidence against source."""
import argparse
import csv
import gzip
import json
import sys
from collections import Counter
from pathlib import Path

from align_swechat_agent_logs import Guard, numstats, parse_patch, restore_parent, sha, structured_tool_patch


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def verify(workspace, output):
    import pyarrow.parquet as pq
    csv.field_size_limit(100_000_000)
    summary = json.loads((output / "summary.json").read_text())
    frozen = json.loads((output / "rule_freeze.json").read_text())
    assert any(p.is_file() and frozen["script_sha256"] == sha(p.read_bytes()) for p in [workspace / "scripts/align_swechat_agent_logs.py", output / "align_swechat_agent_logs.py"])
    scope = workspace / "outputs/swechat_agent_scope_20260919/final"
    source_scope = read_csv(scope / "main_code_files.csv")
    allowed_keys = {(r["repo_id"], r["commit_sha"], r["path"]) for r in source_scope}
    files = read_csv(output / "file_coverage.csv")
    assert len(files) == summary["input_file_units"] == len(source_scope)
    assert dict(Counter(r["status"] for r in files)) == summary["file_status_counts"]
    assert all(r["repo_id"] == r["commit_sha"] == r["path"] == "" for r in files if r["status"] == "guard_excluded")
    logs = read_csv(output / "logs.csv")
    records = [json.loads(line) for line in (output / "log_alignment_evidence.jsonl").open(encoding="utf8")]
    ids = {r["log_id"] for r in records}
    assert len(ids) == len(records) == len(logs) == summary["exported_log_candidates"]
    assert ids == {r["log_id"] for r in logs}
    assert all((r["repo_id"], r["commit_sha"], r["path"]) in allowed_keys for r in records)
    assert dict(Counter(r["attribution_grade"] for r in records)) == summary["grade_counts"]
    mixed = {r["log_id"] for r in records if "mixed" in r["file_attribution_labels"]}
    exact = {r["log_id"] for r in records if r["attribution_grade"] == "exact_tool_change_supported"}
    assert mixed == {r["log_id"] for r in read_csv(output / "mixed_logs.csv")}
    assert exact == {r["log_id"] for r in read_csv(output / "exact_supported_logs.csv")}
    observations = {}
    wanted = {}
    for log in records:
        key = log["repo_id"], log["commit_sha"], log["path"]
        assert not log["runtime_tool_success_verified"] and not log["exclusive_agent_identity_verified"]
        for obs in log["observations"]:
            ref = obs["source_row"], key
            wanted[ref] = obs
    with gzip.open(scope / "file_observations.jsonl.gz", "rt", encoding="utf8") as f:
        for line in f:
            obs = json.loads(line)
            key = obs["repo_id"], obs["commit_sha"], obs["path"]
            ref = obs["source_row"], key
            if ref in wanted:
                assert wanted[ref]["checkpoint_pk"] == obs["checkpoint_pk"]
                assert wanted[ref]["session_ids"] == obs["session_ids"]
                observations[ref] = obs
    assert set(observations) == set(wanted)
    exact_refs = {}
    for log in records:
        if log["log_id"] not in exact:
            continue
        supported = [o for o in log["observations"] if o["attribution_grade"] == "exact_tool_change_supported"]
        assert supported
        # One exact observation is sufficient; preserve all in the evidence export.
        obs = supported[0]
        assert obs["session_ids"]
        exact_refs.setdefault(obs["source_row"], []).append((log, obs))
    guard = Guard(workspace)
    checked = set()
    rownum = 0
    columns = ["repo_id", "commit_sha", "status", "patch", "numstat", "file_attribution", "agent_changes"]
    pf = pq.ParquetFile(workspace / "data/cache/swechat-frozen/commits.parquet")
    for batch in pf.iter_batches(batch_size=8, columns=columns):
        for row in batch.to_pylist():
            rownum += 1
            if rownum not in exact_refs:
                continue
            attrs, tools = json.loads(row["file_attribution"]), json.loads(row["agent_changes"])
            patches, stats = parse_patch(row["patch"]), numstats(row["numstat"])
            for log, obs in exact_refs[rownum]:
                repo, path = log["repo_id"], log["path"]
                assert row["repo_id"].lower() == repo and row["commit_sha"].lower() == log["commit_sha"] and row["status"] == "ok"
                after = attrs[path]["committed_version"].replace("\r\n", "\n")
                assert guard.check(repo, path, after) == "allowed"
                before, _ = restore_parent(after, patches[path], stats[path])
                if before:
                    assert guard.check(repo, patches[path]["old_path"] or path, before) == "allowed"
                assert sha(after) == obs["postimage_sha256"] and sha(before) == obs["parent_logical_sha256"]
                assert after[obs["start"]:obs["end"]] == obs["statement"] == log["statement"]
                strong = [e for e in obs["tool_evidence"] if e["status"] in {
                    "exact_edit_supported", "exact_write_new_file_supported", "exact_structured_patch_supported"}]
                assert strong
                for e in strong:
                    assert e["source_row"] == rownum
                    assert e["path_match"] in {"exact_relative", "repo_root_relative"}
                    assert e["session_ids"] == obs["session_ids"]
                    source_ref = observations[(rownum, (repo, log["commit_sha"], path))]
                    assert e["tool_index_0based"] in {t["tool_index_0based"] for t in source_ref["tools"] if t["recognized_modification_tool"]}
                    tool = tools[e["tool_index_0based"]]
                    if e["status"] == "exact_edit_supported":
                        old, new = tool["old_string"].replace("\r\n", "\n"), tool["new_string"].replace("\r\n", "\n")
                        assert old and before.count(old) == 1 and sha(old) == e["old_string_sha256"] and sha(new) == e["new_string_sha256"]
                        assert before.index(old) == e["preimage_offset"] and e["commit_intersection_spans"]
                        a = before[:e["preimage_offset"]].count("\n") + 1
                        b = before[:e["preimage_offset"] + len(old) - 1].count("\n") + 1
                        assert any(a <= block["old_line_end"] and b >= block["old_line_start"] for block in obs["patch_change_blocks"])
                        assert (new and after.count(new) == 1) or (not new and before.replace(old, "", 1) == after)
                    elif e["status"] == "exact_structured_patch_supported":
                        reconstructed, _ = structured_tool_patch(tool, after)
                        assert reconstructed.splitlines() == before.splitlines() and e["commit_intersection_spans"]
                        assert sha(reconstructed) == e["reconstructed_preimage_sha256"]
                    else:
                        assert not before and patches[path]["old_path"] is None
                        assert tool["content"].replace("\r\n", "\n") == after
                checked.add(log["log_id"])
    assert checked == exact
    result = {"status": "PASS", "input_file_units_accounted": len(files),
              "unique_log_candidates": len(records), "mixed_candidates": len(mixed),
              "exact_candidates_rechecked_against_original_parquet": len(checked),
              "scope_and_session_references_match": True, "csv_jsonl_subsets_match": True,
              "protected_source_identities_not_exported": True, "rule_freeze_matches": True,
              "accuracy_precision_recall": None, "independent_holdout_evaluation": False}
    (output / "verification.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf8")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--dependencies", type=Path, required=True)
    args = ap.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.dependencies))
    verify(args.workspace.resolve(), args.output.resolve())
