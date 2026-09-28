"""Before/after comparison uses actual history, exact output anchors and results."""
from copy import deepcopy
from pathlib import Path

import pytest

from agentlog_unified.screening_compare import compare_cases
from agentlog_unified.screening_evidence import discover_outputs
from agentlog_unified.screening_history import extract_commit
from agentlog_unified.screening_policy import assess
from synthetic_histories import HEADER, commit, git, init


def cases_for(extracted):
    rows = []
    for event in extracted["files"]:
        for side in ("before", "after"):
            source = event[side]
            if source["source_state"] != "present" or not source["path"].endswith(".py"):
                continue
            text = Path(source["source_path"]).read_text()
            for case in discover_outputs(extracted["repository"], extracted["sha"], extracted["parent_sha"],
                    source["source_sha"], side, source["path"], text):
                case.update(old_path=event["old_path"], new_path=event["new_path"],
                            attribution={"output_unit_authorship": "unknown", "granularity": "commit_association"})
                rows.append(case)
    return rows


def assessed(cases):
    rows = []
    for case in cases:
        for variant in ("baseline", "dfg_augmented"):
            result = assess(case, case["base_evidence"])
            rows.append({"case_id": case["case_id"], "variant": variant,
                         "analysis_id": case["case_id"] + variant, "queue": result["queue"],
                         "processing_status": result["processing_status"], "assessment": result})
    return rows


def test_verified_new_and_deleted_file_risk_path(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    sha = commit(repo, {"app.py": HEADER + 'def run():\n    logger.info("secret=DUMMY_NOT_VALID")\n'}, "add")
    extracted = extract_commit(repo, "fixture/project", sha, tmp_path / "run")
    cases = cases_for(extracted)
    results = assessed(cases)
    assert results[0]["queue"] == "A"
    rows = compare_cases(cases, results, [extracted])
    assert rows[0]["pairing_status"] == "verified_absent_side"
    assert rows[0]["change_label"] == "added_risk"
    assert rows[0]["old_anchor"] is None
    assert rows[0]["attribution"]["output_unit_authorship"] == "unknown"
    git(repo, "rm", "app.py")
    deleted = commit(repo, {}, "delete", day=3)
    extracted = extract_commit(repo, "fixture/project", deleted, tmp_path / "run")
    cases = cases_for(extracted)
    rows = compare_cases(cases, assessed(cases), [extracted])
    assert rows[0]["change_label"] == "removed_path"
    assert rows[0]["new_source_state"] == "absent_verified"
    assert rows[0]["runtime_confirmed"] is False


def test_new_log_without_supported_risk_or_missing_object_does_not_imply_risk_change(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    sha = commit(repo, {"app.py": HEADER + 'logger.info("ok")\n'}, "add fixed safe")
    extracted = extract_commit(repo, "fixture/project", sha, tmp_path / "run")
    cases = cases_for(extracted)
    assert compare_cases(cases, assessed(cases), [extracted])[0]["change_label"] == "cannot_compare"
    broken = deepcopy(extracted)
    broken["files"][0]["before"]["source_state"] = "object_unavailable"
    rows = compare_cases(cases, assessed(cases), [broken])
    assert rows[0]["pairing_status"] == "unresolved"
    assert rows[0]["change_label"] == "cannot_compare"


def test_unique_exact_diff_mapping_pairs_shifted_log_and_separates_functions(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    old = HEADER + 'def first():\n    logger.info("ok")\n\ndef second():\n    logger.info("ok")\n'
    commit(repo, {"app.py": old}, "two functions")
    sha = commit(repo, {"app.py": HEADER + "configuration = 7\n" + old[len(HEADER):]}, "upstream insertion", day=3)
    extracted = extract_commit(repo, "fixture/project", sha, tmp_path / "run")
    cases = cases_for(extracted)
    assert len(cases) == 4
    rows = compare_cases(cases, assessed(cases), [extracted])
    assert all(row["pairing_status"] == "paired" for row in rows)
    assert all(row["change_label"] == "no_relevant_change" for row in rows)
    assert len({row["pair_id"] for row in rows}) == 2
    lookup = {case["case_id"]: case for case in cases}
    assert all(lookup[row["case_id"]]["scope"] == lookup[row["counterpart_case_id"]]["scope"] for row in rows)
    assert all(row["new_anchor"]["line"] == row["old_anchor"]["line"] + 1 for row in rows)
    primary_after = [case for case in cases if case["side"] == "after"]
    rows = compare_cases(primary_after, assessed(primary_after), [extracted])
    assert all(row["change_label"] == "cannot_compare" for row in rows)
    assert all(row["unselected_counterpart_analysis_inferred"] is False for row in rows)


def test_rename_pairing_exact_hash_guard_and_variant_failure_retention(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    commit(repo, {"app.py": HEADER + 'def run():\n    logger.info("ok")\n'}, "old")
    git(repo, "mv", "app.py", "renamed.py")
    sha = commit(repo, {}, "rename", day=3)
    extracted = extract_commit(repo, "fixture/project", sha, tmp_path / "run")
    cases = cases_for(extracted)
    rows = compare_cases(cases, assessed(cases), [extracted])
    assert all(row["pairing_status"] == "paired" for row in rows)
    assert all(row["old_anchor"]["path"] == "app.py" and row["new_anchor"]["path"] == "renamed.py" for row in rows)
    failed = assessed(cases)
    failed[-1]["processing_status"] = "blocked"
    failed[-1]["failure_reason"] = "test_failure"
    rows = compare_cases(cases, failed, [extracted])
    assert all(row["variant_changes"]["baseline"]["change_label"] == "no_relevant_change" for row in rows)
    assert all(row["variant_changes"]["dfg_augmented"]["change_label"] == "cannot_compare" for row in rows)
    corrupted = deepcopy(cases)
    corrupted[0]["source_sha256"] = "0" * 64
    assert compare_cases(corrupted, assessed(corrupted), [extracted])[0]["pairing_status"] == "unresolved"
    with pytest.raises(ValueError, match="duplicate_case_variant"):
        compare_cases(cases, failed + [failed[0]], [extracted])


def test_changed_statement_is_not_force_paired_from_same_name(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    commit(repo, {"app.py": HEADER + 'def run():\n    logger.info("ok")\n'}, "before")
    sha = commit(repo, {"app.py": HEADER + 'def run():\n    logger.info("done")\n'}, "after", day=3)
    extracted = extract_commit(repo, "fixture/project", sha, tmp_path / "run")
    cases = cases_for(extracted)
    rows = compare_cases(cases, assessed(cases), [extracted])
    assert all(row["pairing_status"] == "unresolved" and row["change_label"] == "cannot_compare" for row in rows)
