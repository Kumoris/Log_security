"""Classifier regression tests use parsed synthetic code, never target execution."""
from copy import deepcopy

from agentlog_unified.analysis import behavior
from agentlog_unified.detector import detect_snapshot
from agentlog_unified.lineage import assess, change_labels, same_entity, trace_logs


SECRET = "DUMMY_RESEARCH_SECRET_NOT_VALID"


def entity(statement):
    code = "import logging\nlogger = logging.getLogger(__name__)\n" + statement + "\n"
    return detect_snapshot({"app.py": code})["entities"][0]


def risky(level="info"):
    return entity(f'logger.{level}("snapshot", extra={{"password": "{SECRET}", "token_count": 3}})')


def case(value):
    return {"case_id": "synthetic_case", "before": None, "after": value,
            "introduction_relation": "unknown", "lineage_status": "tracked",
            "extraction_status": "ok", "censoring_reason": None,
            "missing_evidence": list(value["missing_evidence"]),
            "provenance_confidence": "unknown", "log_change_actor_type": "unknown",
            "parser_status": value["parser_status"], "sensitive_flow_introduced_sha": None}


def test_static_dict_field_removal_has_actual_supported_to_negative_evidence():
    before = risky()
    after = entity('logger.info("snapshot", extra={"token_count": 3})')
    assert before["privacy_assessment"] == "supported"
    assert after["privacy_assessment"] == "not_supported"
    labels, effect = change_labels(before, after, "modified", "direct_call_change")
    assert "remove_sensitive_field" in labels
    assert effect == "eliminates_observed_flow"


def test_dependency_line_offsets_alone_do_not_change_behavior():
    before = risky()
    after = deepcopy(before)
    after["start_line"] += 4
    after["end_line"] += 4
    for dep in after["dependencies"]:
        dep["start_line"] += 4
        dep["end_line"] += 4
    assert behavior(before) == behavior(after)


def test_log_deletion_is_not_automatically_a_privacy_fix():
    labels, effect = change_labels(risky(), None, "deleted", "direct_call_change")
    assert labels == ["delete_feature"]
    assert effect == "unknown"


def test_level_change_requires_configuration_evidence_before_claiming_mitigation():
    labels, effect = change_labels(risky("info"), risky("debug"), "modified", "direct_call_change")
    assert "level_or_condition_change" in labels
    assert effect == "unknown"


def test_more_enabled_level_is_not_a_mitigation():
    labels, effect = change_labels(risky("debug"), risky("info"), "modified", "direct_call_change")
    assert "level_or_condition_change" in labels
    assert effect == "unknown"


def test_unknown_after_value_does_not_establish_partial_fix():
    after = entity('logger.info("snapshot", opaque_result)')
    assert after["privacy_assessment"] == "unknown"
    _, effect = change_labels(risky(), after, "modified", "direct_call_change")
    assert effect == "unknown"


def test_format_change_with_preexisting_secret_is_not_privacy_repair():
    before = risky()
    after = entity(f'logger.info("different message", extra={{"password": "{SECRET}", "token_count": 3}})')
    labels, effect = change_labels(before, after, "modified", "direct_call_change")
    assert "message_or_format" in labels
    assert effect not in {"eliminates_observed_flow", "partial", "mitigates_under_condition"}


def test_unknown_assessment_stays_needs_context():
    unknown = entity('logger.info("snapshot", opaque_result)')
    assessed = assess([case(unknown)], [])[0]
    assert assessed["screening_bucket"] == "NEEDS_CONTEXT"
    assert assessed["human_review_status"] == "pending"
    assert assessed["new_type_status"] == "not_established"
    assert assessed["runtime_leak_claim"] is False


def test_supported_risk_without_fix_is_retained():
    assessed = assess([case(risky())], [])[0]
    assert assessed["screening_bucket"] == "NO_OBSERVED_PRIVACY_FIX"
    assert assessed["candidate_without_observed_fix"] is True


def test_duplicate_template_with_different_identity_is_not_same_entity():
    entities = detect_snapshot({"app.py": 'logger.info("same", a)\nlogger.info("same", b)\n'})["entities"]
    assert entities[0]["identity"] != entities[1]["identity"]
    assert not same_entity(entities[0], entities[1])


def trace_one(before, after):
    event = {"id": "synthetic_event", "repository_id": "synthetic_repo", "sha": "c1", "parent_sha": "c0", "topo_index": 1,
             "before": before, "after": after, "entity_fingerprint": "synthetic_entity", "behavior_match_status": "unique_template",
             "target_reachable": True, "on_target_first_parent": True, "file_path": "app.py", "symbol": after["symbol"],
             "change_kind": "modified", "relation": "direct_call_change", "parser_status": "python_ast", "extraction_status": "ok"}
    repo = {"id": "synthetic_repo", "repository_id": "fixture:classification", "pr_ids": ["synthetic_pr"],
            "target_ref": "main", "frozen_target_tip": "c1", "shallow": False}
    pr = {"id": "synthetic_pr", "repository": None, "pr_number": None, "cohort": "calibration_only", "is_synthetic": True,
          "commit_shas": ["c1"], "merged_at": None, "synthetic_author_mapping": {"agent@fixture.invalid": "agent"}}
    commits = [{"sha": sha, "parents": [] if sha == "c0" else ["c0"], "author_email": "agent@fixture.invalid",
                "committer_date": "2026-01-01T00:00:00+00:00"} for sha in ("c0", "c1")]
    mined = {"repository_id": "synthetic_repo", "commits": commits, "graph": commits, "first_parent_shas": ["c0", "c1"]}
    snapshots = [{"repository_id": "synthetic_repo", "sha": "c1", "entities": [after]}]
    return trace_logs([repo], [pr], [mined], [event], snapshots, "2026-05-01T00:00:00+00:00", 90, [])["log_changes"][0]


def test_preexisting_secret_format_edit_is_not_new_sensitive_flow():
    before = risky()
    after = entity(f'logger.info("reworded", extra={{"password": "{SECRET}", "token_count": 3}})')
    row = trace_one(before, after)
    assert row["introduction_relation"] == "preexisting_unchanged"
    assert row["sensitive_flow_introduced_sha"] is None
    assert row["risk_introducer_type"] == "unknown"


def test_adding_another_credential_field_expands_flow_even_with_same_type():
    before = risky()
    after = entity(f'logger.info("snapshot", extra={{"password": "{SECRET}", "access_token": "{SECRET}", "token_count": 3}})')
    assert before["data_types"] == after["data_types"] == ["credential"]
    row = trace_one(before, after)
    assert row["introduction_relation"] == "expanded_sensitive_flow"
    assert row["sensitive_flow_introduced_sha"] == "c1"


def test_opaque_object_without_sensitive_evidence_is_not_new_sensitive_flow():
    after = entity('logger.info("user %s", user)')
    assert after["privacy_assessment"] == "possible"
    row = trace_one(None, after)
    assert row["introduction_relation"] == "unknown"
    assert row["sensitive_flow_introduced_sha"] is None


def test_removing_one_of_two_credential_fields_is_partial_not_complete():
    before = entity(f'logger.info("snapshot", extra={{"password": "{SECRET}", "access_token": "{SECRET}"}})')
    after = entity(f'logger.info("snapshot", extra={{"access_token": "{SECRET}"}})')
    assert before["data_types"] == after["data_types"] == ["credential"]
    labels, effect = change_labels(before, after, "modified", "direct_call_change")
    assert "remove_sensitive_field" in labels
    assert effect == "partial"
