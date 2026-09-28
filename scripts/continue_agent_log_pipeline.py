"""Non-destructive snapshot of completed original stage-two runs.

Never mines history or changes stage-one eligibility. A pending repository is
retained in the candidate ledger and makes the result explicitly incomplete.
Run with the research Python required by AGENTS.md.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from agent_log_motivation_v11 import file_hash, rows, table, write_json
from package_swechat_followups import ancestor


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def validate_repository(directory, originals):
    """Reuse the existing acceptance conditions, without selecting/writing a run."""
    directory = Path(directory)
    summary = read(directory / "summary.json")
    ledger = [r for _, r in rows(directory / "candidate_ledger.jsonl")]
    cases = [r for _, r in rows(directory / "log_changes.jsonl")]
    events = [r for _, r in rows(directory / "followups.jsonl")]
    by_id = {r["case_id"]: r for r in cases}
    frozen = ("repo_id", "commit_sha", "path", "start_line", "end_line", "attribution_grade", "file_attribution_labels")
    checks = {
        "complete_receipt": summary["status"] in {"executed", "history_unavailable"},
        "every_candidate": len(ledger) == len(originals) == len({r["log_id"] for r in ledger}) and {r["log_id"] for r in ledger} == set(originals),
        "unchanged_candidate_fields": all(r["log_id"] in originals and all(r[k] == originals[r["log_id"]][k] for k in frozen) for r in ledger),
        "event_ids_unique": len(events) == len({r["id"] for r in events}),
        "case_ids_unique": len(cases) == len(by_id),
        "events_have_cases": all(r["case_id"] in by_id for r in events),
        "declared_event_count": summary.get("events", 0) == len(events),
        "ledger_event_foreign_keys": all(set(r.get("followup_ids", [])) <= {f["id"] for f in events} for r in ledger),
    }
    if summary["status"] == "executed":
        history = read(directory / "history_scope.json")
        parents = {r["sha"]: r["parents"] for r in history["graph"]}
        fp = set(history["first_parent_shas"])
        checks.update(
            exact_first_parent=all(e["sha"] in fp and e["parent_sha"] == (parents.get(e["sha"]) or [None])[0] for e in events),
            actual_later_events=all(e["case_id"] in by_id and e["sha"] != by_id[e["case_id"]]["intro_sha"] and e["change_kind"] not in {"coverage_gap", "gap_resumed"} for e in events),
            integration_ancestry=all(e["case_id"] in by_id and by_id[e["case_id"]].get("integration_sha") and ancestor(by_id[e["case_id"]]["integration_sha"], e["sha"], parents) for e in events),
            exact_callees=all(c["after"]["callee"] == originals[i]["callee"] for c in cases for i in c["stage1_log_ids"]),
        )
    if not all(checks.values()):
        raise ValueError("repository_validation_failed:" + str(directory) + ":" + repr(checks))
    return ledger, cases, events, checks


def snapshot(workspace, source, output, attempts):
    w, source, out = Path(workspace), Path(source), Path(output)
    out.mkdir(parents=True, exist_ok=False)
    inv = read(source / "inventory.json")
    stage1 = w / "outputs/swechat_log_alignment_20260921/final/changed_logs.csv"
    if file_hash(stage1) != inv["input_sha256"]:
        raise ValueError("stage1_changed_since_frozen_inventory")
    with stage1.open(encoding="utf-8-sig", newline="") as f:
        originals = list(csv.DictReader(f))
    original_ids = {r["log_id"] for r in originals}
    if len(original_ids) != len(originals):
        raise ValueError("duplicate_stage1_id")
    hashes = {str(stage1.resolve()): file_hash(stage1), str((source / "inventory.json").resolve()): file_hash(source / "inventory.json")}
    overrides = {}
    for root in attempts:
        root = Path(root).resolve()
        if not root.is_relative_to((source / "additional-attempts").resolve()):
            raise ValueError("attempt_outside_original_run")
        status, provenance = read(root / "attempt_status.json"), read(root / "attempt_provenance.json")
        if status.get("status") != "finished" or status.get("returncode") != 0:
            raise ValueError("attempt_not_finished")
        repo = provenance["repository"]
        receipt = source / "collection" / (repo.replace("/", "--") + ".json")
        if provenance["original_input_sha256"] != inv["input_sha256"] or file_hash(receipt) != provenance["frozen_collection_receipt_sha256"] or file_hash(root / "collection" / receipt.name) != file_hash(receipt):
            raise ValueError("attempt_changed_frozen_input_or_collection")
        directory = root / "repositories" / repo.replace("/", "--")
        if read(directory / "history_scope.json")["history_scope"]["frozen_tip"] != read(receipt)["tip"]:
            raise ValueError("attempt_changed_frozen_tip")
        overrides[repo] = directory
        for p in (root / "attempt_status.json", root / "attempt_provenance.json", receipt):
            hashes[str(p.resolve())] = file_hash(p)
    tables = {n: [] for n in ("candidate_ledger", "log_changes", "followups", "repositories", "commits", "file_changes")}
    reports, mappings = [], []
    for item in inv["repositories"]:
        repo = item["repository"]
        directory = overrides.get(repo, source / "repositories" / repo.replace("/", "--"))
        selected = {r["log_id"]: r for r in originals if r["repo_id"] == repo}
        if not (directory / "summary.json").exists():
            tables["candidate_ledger"].extend({**r, "status": "pending_upstream_execution", "case_id": None, "followup_ids": []} for r in selected.values())
            reports.append({"repository": repo, "status": "pending_upstream_execution", "candidates": len(selected), "events": None, "directory": str(directory)})
            continue
        for name in ("summary", "history_scope", "candidate_ledger", "log_changes", "followups", "repositories", "commits", "file_changes"):
            p = directory / (name + (".json" if name in {"summary", "history_scope"} else ".jsonl"))
            if p.exists():
                hashes[str(p.resolve())] = file_hash(p)
        ledger, cases, events, checks = validate_repository(directory, selected)
        tables["candidate_ledger"].extend(ledger)
        tables["log_changes"].extend(cases)
        tables["followups"].extend(events)
        tables["repositories"].extend(r for _, r in rows(directory / "repositories.jsonl"))
        required_files = {i for e in events for i in e.get("file_change_ids", [])}
        required_shas = {e["sha"] for e in events}
        tables["file_changes"].extend(r for _, r in rows(directory / "file_changes.jsonl") if r["id"] in required_files)
        tables["commits"].extend(r for _, r in rows(directory / "commits.jsonl") if r["sha"] in required_shas)
        mappings.extend({"snapshot_row": len(tables["followups"]) - len(events) + i, "upstream_path": str((directory / "followups.jsonl").resolve()), "upstream_row": i, "upstream_event_id": r["id"]} for i, r in enumerate(events, 1))
        reports.append({**read(directory / "summary.json"), "directory": str(directory), "validation": checks})
        print(json.dumps({"repository": repo, "events": len(events), "validation": "PASS"}), flush=True)
    if {r["log_id"] for r in tables["candidate_ledger"]} != original_ids or len(tables["candidate_ledger"]) != len(originals):
        raise ValueError("candidate_reconciliation_failed")
    ids = [r["id"] for r in tables["followups"]]
    if len(ids) != len(set(ids)):
        raise ValueError("cross_repository_event_id_collision")
    for name, records in tables.items():
        with (out / (name + ".jsonl")).open("x", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    table(out, "upstream_event_map", mappings, ["snapshot_row", "upstream_path", "upstream_row", "upstream_event_id"])
    ledger, events = tables["candidate_ledger"], tables["followups"]
    pending = sum(r["status"] == "pending_upstream_execution" for r in ledger)
    unique_events = {(r["repository_id"], r["sha"], r["parent_sha"], r["file_path"], (r.get("before") or {}).get("start_line"), (r.get("after") or {}).get("start_line"), r["entity_fingerprint"], r["change_kind"]) for r in events}
    changed = sum(bool(r.get("followup_ids")) for r in ledger)
    summary = {"scope": "completed_repository_snapshot_with_pending_ledger", "full_stage2_complete": pending == 0,
        "stage2_input_candidates": len(originals), "processed_candidates": len(originals) - pending, "pending_candidates": pending,
        "changed_candidates_observed": changed, "stage2_event_links": len(events), "unique_modification_events": len(unique_events),
        "stage2_final_filter_fraction": changed / len(originals) if not pending else None,
        "stage2_observed_lower_bound_fraction": changed / len(originals),
        "candidate_status": dict(Counter(r["status"] for r in ledger)), "repository_status": dict(Counter(r["status"] for r in reports)),
        "event_relation": dict(Counter(r["relation"] for r in events)), "event_confidence": dict(Counter(r["behavior_confidence"] for r in events)),
        "stage1_input_hash": hashes[str(stage1.resolve())], "upstream_selection_unchanged": True}
    write_json(out / "summary.json", summary)
    write_json(out / "repository_receipts.json", reports)
    unchanged = all(file_hash(p) == h for p, h in hashes.items())
    write_json(out / "validation.json", {"status": "PASS" if unchanged else "FAIL", "inputs_unchanged": unchanged, "input_sha256": hashes, "all_existing_events_retained": True, "candidate_preservation": True, "pending_is_not_zero_changes": True})
    if not unchanged:
        raise ValueError("source_changed_during_snapshot")
    write_json(out / "manifest.json", {"created_at": datetime.now(timezone.utc).isoformat(), "artifacts": {p.name: file_hash(p) for p in out.iterdir() if p.is_file()}, "script_sha256": file_hash(__file__)})
    print(json.dumps(summary), flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--finished-attempt", type=Path, action="append", default=[])
    args = ap.parse_args()
    snapshot(args.workspace, args.source, args.output, args.finished_attempt)


if __name__ == "__main__":
    main()
