#!/usr/bin/env python3
"""Bind local Agent-session evidence to immutable GitHub PR snapshots.

Session evidence is JSONL. Strong attribution needs explicit booleans for
``known_clean_base``, ``commit_created_in_session``, and
``unaccounted_pre_session_worktree_changes`` plus immutable SHA/hash anchors.
Raw prompts and tool outputs stay outside this manifest; store only local paths
and hashes when they are needed for later audit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

if __package__:
    from .screen_github_agent_logs import _atomic_write_text
else:
    from screen_github_agent_logs import _atomic_write_text


OUTPUT_NAMES = ("provenance_bindings.jsonl", "summary.json")
GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3}


def _bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    return None


def _time(value: object) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _binding_id(session_id: str, pr_key: str) -> str:
    return hashlib.sha256(f"{session_id}|{pr_key}".encode()).hexdigest()[:20]


def evaluate_binding(session: dict, pr: dict) -> dict[str, object]:
    session_id = str(session.get("session_id") or "")
    pr_key = str(pr.get("pr_key") or "")
    session_repo, pr_repo = str(session.get("repo") or ""), str(pr.get("repo") or "")
    session_base, pr_base = str(session.get("base_sha") or ""), str(pr.get("base_sha") or "")
    session_commit = str(session.get("commit_sha") or session.get("head_sha") or "")
    pr_head = str(pr.get("head_sha") or "")
    session_tree = str(session.get("tree_sha") or "")
    pr_tree = str(pr.get("head_tree_sha") or "")
    session_patch = str(session.get("canonical_patch_sha256") or session.get("patch_sha256") or "")
    pr_patch = str(pr.get("canonical_patch_sha256") or "")
    session_content_patch = str(session.get("patch_content_sha256") or "")
    pr_content_patch = str(pr.get("patch_content_sha256") or "")

    same_repository = bool(session_repo and pr_repo and session_repo == pr_repo)
    same_base = bool(session_base and pr_base and session_base == pr_base)
    commit_match = bool(session_commit and pr_head and session_commit == pr_head)
    tree_match = bool(session_tree and pr_tree and session_tree == pr_tree)
    patch_match = bool(session_patch and pr_patch and session_patch == pr_patch)
    patch_content_match = bool(
        session_content_patch and pr_content_patch and session_content_patch == pr_content_patch
    )
    session_pr_binding = bool(
        (session.get("pr_key") and str(session["pr_key"]) == pr_key)
        or (session.get("pr_url") and str(session["pr_url"]) == str(pr.get("pr_url") or ""))
        or commit_match
    )
    artifact_time = _time(session.get("artifact_created_at") or session.get("ended_at"))
    head_time = _time(pr.get("head_committed_at"))
    temporal_order_valid = bool(artifact_time and head_time and artifact_time <= head_time)
    clean_base = _bool(session.get("known_clean_base")) is True
    preexisting_changes = _bool(session.get("unaccounted_pre_session_worktree_changes"))
    no_unaccounted_changes = preexisting_changes is False
    commit_created = _bool(session.get("commit_created_in_session")) is True
    commit_chain_complete = _bool(session.get("full_pr_commit_chain_created_in_session")) is True
    full_patch_accounted = _bool(session.get("full_patch_accounted")) is True
    try:
        changed_path_coverage = float(session.get("changed_path_coverage", 0.0))
    except (TypeError, ValueError):
        changed_path_coverage = 0.0
    full_path_coverage = changed_path_coverage == 1.0

    failures: list[str] = []
    if session_repo and pr_repo and not same_repository:
        failures.append("repository_mismatch")
    if session_base and pr_base and not same_base:
        failures.append("base_mismatch")
    if artifact_time and head_time and artifact_time > head_time:
        failures.append("session_artifact_created_after_pr_head")
    if preexisting_changes is True:
        failures.append("unaccounted_pre_session_worktree_changes")
    if _bool(session.get("claimed_added_line_already_present_in_base")) is True:
        failures.append("claimed_added_line_already_present_in_base")
    if _bool(session.get("claims_exact_binding")) is True and session_patch and pr_patch and not patch_match:
        failures.append("hash_or_patch_mismatch_for_claimed_exact_binding")
    if commit_match and commit_created and not commit_chain_complete:
        failures.append("incomplete_pr_commit_chain")
    if tree_match and session_pr_binding and not (full_patch_accounted or full_path_coverage):
        failures.append("incomplete_changed_path_coverage")

    strong_common = (
        not failures
        and same_repository
        and same_base
        and temporal_order_valid
        and clean_base
        and no_unaccounted_changes
    )
    hard_anchor = ""
    if strong_common and commit_match and commit_created and commit_chain_complete:
        grade, hard_anchor = "A", "session_commit_equals_pr_head_commit"
    elif strong_common and tree_match and session_pr_binding and (full_patch_accounted or full_path_coverage):
        grade, hard_anchor = "A", "session_tree_and_base_equal_pr_tree_and_base"
    elif strong_common and (patch_content_match or patch_match) and session_pr_binding:
        grade, hard_anchor = "B", (
            "patch_content_bidirectional_exact" if patch_content_match
            else "canonical_full_patch_bidirectional_exact"
        )
    elif pr.get("provenance") == "AGENT_SOURCE_CANDIDATE" and pr.get("source_app_slug"):
        grade = "C"
    else:
        grade = "D"

    if failures:
        status = "hard_failure"
    elif grade == "A":
        status = "high_confidence_commit_or_tree"
    elif grade == "B":
        status = "high_confidence_exact_patch"
    elif grade == "C":
        status = "github_app_candidate_only"
    else:
        status = "insufficient_evidence"

    pr_state = str(pr.get("state") or (pr.get("pr_metadata_snapshot") or {}).get("state") or "").upper()
    if grade in {"A", "B"} and pr_state == "MERGED":
        analysis_eligibility = "provenance_primary"
    elif grade in {"A", "B"}:
        analysis_eligibility = "provenance_validation_only"
    else:
        analysis_eligibility = "sensitivity_only"

    return {
        "binding_id": _binding_id(session_id, pr_key),
        "session_id": session_id,
        "pr_key": pr_key,
        "pr_url": str(pr.get("pr_url") or ""),
        "repo": pr_repo,
        "provenance_grade": grade,
        "binding_status": status,
        "hard_anchor": hard_anchor,
        "hard_failures": ";".join(failures),
        "line_authorship_proof": grade in {"A", "B"},
        "generation_stage": str(session.get("generation_stage") or "agent_session_final") if grade in {"A", "B"} else "merged_final_unresolved_actor",
        "same_repository": same_repository,
        "same_base": same_base,
        "temporal_order_valid": temporal_order_valid,
        "known_clean_base": clean_base,
        "no_unaccounted_pre_session_changes": no_unaccounted_changes,
        "session_pr_binding": session_pr_binding,
        "commit_match": commit_match,
        "tree_match": tree_match,
        "canonical_patch_match": patch_match,
        "patch_content_match": patch_content_match,
        "commit_chain_complete": commit_chain_complete,
        "changed_path_coverage": changed_path_coverage,
        "full_patch_accounted": full_patch_accounted,
        "pr_state": pr_state,
        "analysis_eligibility": analysis_eligibility,
        "session_base_sha": session_base,
        "pr_base_sha": pr_base,
        "session_commit_sha": session_commit,
        "pr_head_sha": pr_head,
        "session_tree_sha": session_tree,
        "pr_head_tree_sha": pr_tree,
        "session_patch_sha256": session_patch,
        "pr_patch_sha256": pr_patch,
        "session_patch_content_sha256": session_content_patch,
        "pr_patch_content_sha256": pr_content_patch,
        "github_evidence_chain_status": str(pr.get("evidence_chain_status") or "legacy_unhashed_snapshot"),
    }


def bind_prs(sessions: list[dict], prs: list[dict]) -> list[dict[str, object]]:
    by_pr_key: dict[str, list[dict]] = defaultdict(list)
    by_pr_url: dict[str, list[dict]] = defaultdict(list)
    by_commit: dict[str, list[dict]] = defaultdict(list)
    for session in sessions:
        if session.get("pr_key"):
            by_pr_key[str(session["pr_key"])].append(session)
        if session.get("pr_url"):
            by_pr_url[str(session["pr_url"])].append(session)
        commit = session.get("commit_sha") or session.get("head_sha")
        if commit:
            by_commit[str(commit)].append(session)

    output = []
    for pr in prs:
        candidates: dict[str, dict] = {}
        for session in (
            by_pr_key.get(str(pr.get("pr_key") or ""), [])
            + by_pr_url.get(str(pr.get("pr_url") or ""), [])
            + by_commit.get(str(pr.get("head_sha") or ""), [])
        ):
            key = str(session.get("session_id") or sha256_json(session))
            candidates[key] = session
        evaluated = [evaluate_binding(session, pr) for session in candidates.values()]
        if not evaluated:
            evaluated = [evaluate_binding({}, pr)]
        best = min(
            evaluated,
            key=lambda row: (
                GRADE_RANK[str(row["provenance_grade"])],
                bool(row["hard_failures"]),
                str(row["session_id"]),
            ),
        )
        best["session_candidate_count"] = len(candidates)
        output.append(best)
    return sorted(output, key=lambda row: str(row["pr_key"]))


def sha256_json(value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def verify_bindings(rows: list[dict]) -> list[str]:
    errors: list[str] = []
    pr_keys = [str(row.get("pr_key") or "") for row in rows]
    if len(pr_keys) != len(set(pr_keys)):
        errors.append("duplicate PR binding")
    for row in rows:
        grade = row.get("provenance_grade")
        proof = bool(row.get("line_authorship_proof"))
        if grade not in GRADE_RANK:
            errors.append("invalid provenance grade: " + str(row.get("pr_key")))
        if proof != (grade in {"A", "B"}):
            errors.append("line authorship flag disagrees with grade: " + str(row.get("pr_key")))
        if grade in {"A", "B"} and (not row.get("hard_anchor") or row.get("hard_failures")):
            errors.append("strong grade lacks a clean hard anchor: " + str(row.get("pr_key")))
        expected_eligibility = (
            "provenance_primary"
            if grade in {"A", "B"} and row.get("pr_state") == "MERGED"
            else "provenance_validation_only"
            if grade in {"A", "B"}
            else "sensitivity_only"
        )
        if row.get("analysis_eligibility") != expected_eligibility:
            errors.append("analysis eligibility disagrees with grade/state: " + str(row.get("pr_key")))
    return errors


def run(session_path: Path, pr_path: Path, output_dir: Path) -> dict[str, object]:
    sessions, prs = _read_jsonl(session_path), _read_jsonl(pr_path)
    rows = bind_prs(sessions, prs)
    errors = verify_bindings(rows)
    if errors:
        raise RuntimeError("; ".join(errors))
    output_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(
        output_dir / OUTPUT_NAMES[0],
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
    )
    grades = Counter(str(row["provenance_grade"]) for row in rows)
    statuses = Counter(str(row["binding_status"]) for row in rows)
    summary = {
        "n_prs": len(rows),
        "n_sessions": len(sessions),
        "provenance_grade_counts": dict(sorted(grades.items())),
        "binding_status_counts": dict(sorted(statuses.items())),
        "line_authorship_proven_prs": sum(bool(row["line_authorship_proof"]) for row in rows),
        "session_input_sha256": sha256_json(sessions),
        "pr_input_sha256": sha256_json(prs),
    }
    _atomic_write_text(output_dir / OUTPUT_NAMES[1], json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sessions", type=Path, required=True)
    parser.add_argument(
        "--prs", type=Path,
        default=Path("outputs/github_agent_screening/github_agent_pr_evidence.jsonl"),
    )
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/github_session_pr_binding"))
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.verify_only:
        rows = _read_jsonl(args.output_dir / OUTPUT_NAMES[0])
        errors = verify_bindings(rows)
        print(json.dumps({"ok": not errors, "errors": errors}, ensure_ascii=False, sort_keys=True))
        return 1 if errors else 0
    print(json.dumps(run(args.sessions, args.prs, args.output_dir), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
