"""Read-only inventory and grain audit. No target source or held-out cases exported."""
from __future__ import annotations
import argparse
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from agent_log_motivation import rows, file_hash, table, write_json


def followup_files(workspace):
    """Visit result roots once, excluding caches and protected source trees."""
    w = Path(workspace)
    excluded = {"cache", ".venv", "node_modules", "sealed", "source_blobs", "sources", "repos", "library_sources", "evidence",
                "snapshots", "private", "build", "deps", "dependencies", "tmp", "inputs", "batches", "collection", "workspaces",
                "execution-code", "verification-tests", "synthetic-tests", "preexisting-tests", "tests"}
    # Legacy runs now live under outputs/runs/legacy-privacy and are scanned once.
    for base in [w / "research", w / "outputs"]:
        for directory, dirs, fs in os.walk(base):
            dirs[:] = [d for d in dirs if d not in excluded and not d.startswith("swechat_motivation_")]
            if "followups.jsonl" not in fs:continue
            p = Path(directory) / "followups.jsonl"
            yield p


def audit(workspace, output):
    w, out = Path(workspace), Path(output)
    out.mkdir(parents=True, exist_ok=False)
    research = w / "research"
    view = research / "swechat-common-flow-605-20260914"
    allowed = {r["log_version_id"] for _, r in rows(research / "swechat-independent-holdout-20260914/development_allowed_ids.jsonl")}
    guard_result = json.loads((out.parent / "development_guard.json").read_text())
    assert guard_result["allowed"] is True
    paths = [view / "current_log_coverage.jsonl", view / "current_fields.jsonl", view / "analysis_lineage.jsonl",
             research / "swechat-full-risk-20260912/final/batch/exports/type_occurrences.jsonl",
             research / "swechat-full-risk-20260912/final/batch/exports/commit_audit.jsonl",
             research / "swechat-eight-gap-targeted-closure-20260915/composite_view.json",
             w / "outputs/swechat_agent_scope_20260919/final/main_code_files.csv",
             w / "outputs/swechat_log_alignment_20260921/final/changed_logs.csv"]
    hashes = {str(p.resolve()): file_hash(p) for p in paths}
    coverage = Counter(); fields = Counter(); gaps = Counter(); unresolved = []
    lids, obs, repositories, identities = set(), set(), set(), set()
    seen_ids = Counter(); same_source = Counter(); schemas = defaultdict(set)
    development_missing = Counter(); completed_ids = set(); semantic_unknown_ids = set(); type_unknown_ids = set()
    # Reporting-only aggregate checks on the fixed frame. No held-out identity,
    # statement, prediction or gap content is used for development or exported.
    for number, r in rows(paths[0]):
        lid = r["log_version_id"]
        seen_ids[lid] += 1; lids.add(lid); repositories.add(r["repository"])
        coverage["rows"] += 1; coverage["status:" + r["status"]] += 1
        refs = r.get("observation_references", [])
        coverage["observation_reference_rows"] += len(refs)
        obs.update(x["observation_id"] for x in refs)
        identity = tuple(r.get(k) for k in ("repository", "snapshot_sha", "path", "start_line", "end_line", "target_statement_sha256"))
        identities.add(identity)
        if r.get("same_source_log_key"):same_source[r["same_source_log_key"]] += 1
        if lid not in allowed:continue
        schemas["coverage"].update(r)
        coverage["development_rows"] += 1
        if r["status"] == "completed":completed_ids.add(lid)
        for g in r.get("gaps", []):gaps[g] += 1
        missing = [k for k in ("repository", "snapshot_sha", "path", "source_sha256", "git_blob_id", "observation_ids") if not r.get(k)]
        development_missing.update(missing)
        unresolved.append({"log_version_id": lid, "repository": r["repository"], "snapshot_sha": r["snapshot_sha"],
             "file_path": r["path"], "source_path": str(paths[0].resolve()), "source_row": number,
             "extraction_status": r["status"], "missing_locator_fields": missing,
             "extraction_gaps": r.get("gaps", []), "agent_attribution": r.get("agent_attribution"),
             "session_link_status": "not_a_field_in_this_legacy_log_view",
             "later_modification_status": "not_tracked_in_this_view",
             "modification_motive_status": "not_assessed_requires_stage2_event"})
    fids = Counter(); languages = Counter(); unknowns = Counter()
    for _, r in rows(paths[1]):
        fields["rows"] += 1; fids[r["field_occurrence_id"]] += 1
        fields["countable" if r.get("count_in_field_summary") else "parent_or_noncountable"] += 1
        if r.get("count_in_field_summary"):languages[r.get("language_type") or "unknown"] += 1
        if r["log_version_id"] not in lids:fields["orphan_log_reference"] += 1
        if r["log_version_id"] not in allowed:continue
        schemas["fields"].update(r)
        if "semantic_type_undetermined" in r.get("unresolved", []):semantic_unknown_ids.add(r["log_version_id"])
        if r.get("count_in_field_summary") and (r.get("language_type") or "unknown") == "unknown":type_unknown_ids.add(r["log_version_id"])
        for g in r.get("unresolved", []):unknowns[g] += 1
        fields["development_rows"] += 1
    seen_versions = set(); refs = set(); parent_sides = Counter()
    for _, r in rows(paths[3]):
        seen_versions.add(r["log_version_id"])
        for ref in r["event_references"]:
            refs.add(ref["id"]); parent_sides[ref["side"]] += 1
    commits = Counter()
    for _, r in rows(paths[4]):commits[r["status"]] += 1
    stage2 = []
    for p in followup_files(w):
        # Inventory structure only; no event source/case content displayed.
        count = sum(1 for line in p.open(encoding="utf-8") if line.strip())
        rel = str(p.relative_to(w)).replace("\\", "/")
        stage2.append({"path": str(p.resolve()), "rows": count, "sha256": file_hash(p),
           "scope_hint": "synthetic_or_test" if "synthetic" in rel else "swechat_named_run" if "/swechat/" in rel else "other_scope_requires_manifest",
           "same_main_population_proven": False})
    count = coverage["rows"]
    summary = {"legacy_population": {"rows": count, "unique_log_version_ids": len(lids), "repositories": len(repositories),
               "unique_observation_ids": len(obs), "observation_reference_rows": coverage["observation_reference_rows"],
               "duplicate_log_id_rows": sum(v - 1 for v in seen_ids.values()), "duplicate_locator_rows": count-len(identities),
               "same_source_repeated_rows_not_deleted": sum(v - 1 for v in same_source.values()),
               "extraction_status": {k[7:]:v for k,v in coverage.items() if k.startswith("status:")},
               "extraction_complete_fraction": coverage["status:completed"]/count,
               "extraction_partial_fraction": coverage["status:partial"]/count,
               "development_rows": coverage["development_rows"], "withheld_rows": count-coverage["development_rows"],
               "source_meaning_completion_rate": None, "motivation_coverage_rate": None,
               "development_missing_locator_fields": dict(development_missing),
               "development_logs_with_undetermined_field_semantics": len(semantic_unknown_ids),
               "development_completed_logs_with_undetermined_field_semantics": len(completed_ids & semantic_unknown_ids),
               "development_logs_with_unknown_programming_types": len(type_unknown_ids)},
               "field_rows": dict(fields), "language_type_countable_occurrences": dict(languages),
               "duplicate_field_id_rows": sum(v-1 for v in fids.values()),
               "commit_status_counts": dict(commits), "observation_sides": dict(parent_sides),
               "reconciliation": {"original_log_ids_equal_current": seen_versions == lids,
                                  "original_observation_ids_equal_current": refs == obs,
                                  "latest_overlay_field_hash_matches": hashes[str(paths[1].resolve())] == json.loads(paths[5].read_text(encoding="utf-8"))["field_sha256"],
                                  "latest_overlay_coverage_hash_matches": hashes[str(paths[0].resolve())] == json.loads(paths[5].read_text(encoding="utf-8"))["coverage_sha256"]},
               "development_extraction_gap_counts": dict(gaps), "development_field_unresolved_counts": dict(unknowns),
               "stage2_status": "no_verified_swechat_main_population_subsequent_modification_artifact_found",
               "stage2_count": None, "stage2_filter_fraction": None,
               "audit_scope": "full_frame_metadata_and_reporting_aggregates; case_details_only_guard_allowed_ids"}
    table(out,"unresolved_legacy_logs",unresolved,["log_version_id","repository","snapshot_sha","file_path","extraction_gaps"])
    table(out,"stage2_inventory",stage2,["path","rows","scope_hint","same_main_population_proven"])
    write_json(out/"summary.json",summary)
    write_json(out/"observed_schema_keys.json",{k:sorted(v) for k,v in schemas.items()})
    unchanged = all(file_hash(p)==h for p,h in hashes.items())
    write_json(out/"input_integrity.json",{"input_sha256":hashes,"inputs_unchanged":unchanged})
    assert unchanged and all(summary["reconciliation"].values())
    print(json.dumps({"logs":count,"fields":fields["rows"],"status":summary["legacy_population"]["extraction_status"],
                      "stage2":summary["stage2_status"]},ensure_ascii=False))


if __name__ == "__main__":
    ap=argparse.ArgumentParser();ap.add_argument("--workspace",type=Path,default=Path(__file__).resolve().parents[1]);ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args();audit(args.workspace,args.output)
