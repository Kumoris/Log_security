from copy import deepcopy

import pytest

from agentlog_unified.screening_policy import POLICY_VERSION, assess, choose_queue, load_policy, policy_hash


def evidence(**changes):
    return {"source_sensitivity": "unknown", "output_sensitivity": "unknown",
            "connection": {"status": "not_established", "reason_code": "insufficient_evidence"},
            "processing": {"kind": "unknown", "steps": []},
            "boundary": {"level": "call_argument", "status": "supported"}, "evidence_ids": ["e1"],
            "paths": [], "risk_clues": [], "critical_unknowns": [], "noncritical_unknowns": [],
            "checks_complete": False, "non_sensitive_basis": [], "processing_status": "partial", **changes}


def path(**changes):
    return {"source_sensitivity": "supported", "output_sensitivity": "supported",
            "connection_supported": True, "semantics_supported": True,
            "evidence_ids": ["e1"], "critical_unknowns": [], **changes}


@pytest.mark.parametrize("dimensions,queue", [
    (evidence(paths=[path()]), "A"),
    (evidence(paths=[path(), path(critical_unknowns=["other_external_call"])], noncritical_unknowns=["other_branch_failed"]), "A"),
    (evidence(paths=[path()], critical_unknowns=["formatter_may_remove_field"]), "B"),
    (evidence(paths=[path(semantics_supported=False)]), "B"),
    (evidence(paths=[path(connection_supported=False)]), "B"),
    (evidence(paths=[path(relation_kind="type_schema")]), "B"),
    (evidence(paths=[path(source_sensitivity="suspected")]), "B"),
    (evidence(paths=[path(output_sensitivity="unknown")]), "B"),
    (evidence(paths=[path(evidence_ids=[])]), "D"),
    (evidence(paths=[path()], boundary={"level": "log_record", "status": "unknown"}), "B"),
    (evidence(source_sensitivity="suspected", risk_clues=["credential_named_field"]), "B"),
    (evidence(risk_clues=["unlocated_name"], evidence_ids=[]), "D"),
    (evidence(output_sensitivity="not_found"), "D"),
    (evidence(output_sensitivity="not_found", checks_complete=True, processing_status="success", non_sensitive_basis=["literal_reviewed"]), "C"),
    (evidence(source_sensitivity="supported", output_sensitivity="not_found", checks_complete=True, processing_status="success",
              non_sensitive_basis=["field_projection_excludes_sensitive_key"],
              connection={"status": "not_established", "reason_code": "target_connection_excluded"}), "C"),
    (evidence(output_sensitivity="not_found", checks_complete=True, processing_status="success", non_sensitive_basis=["literal_reviewed"], critical_unknowns=["budget_exhausted"]), "D"),
    (evidence(output_sensitivity="not_found", checks_complete=True, processing_status="success", non_sensitive_basis=["literal_reviewed"], paths=[path(source_sensitivity="unknown", output_sensitivity="unknown", critical_unknowns=["necessary_transform_unknown"])]), "D"),
    (evidence(output_sensitivity="not_found", checks_complete=True, processing_status="blocked", non_sensitive_basis=["no_match"]), "D"),
    (evidence(output_sensitivity="not_found", checks_complete=True, processing_status="excluded", non_sensitive_basis=["scope_exclusion"]), "D"),
    (evidence(output_sensitivity="not_found", checks_complete=True, processing_status="failed", non_sensitive_basis=["empty_graph"]), "D"),
    (evidence(output_sensitivity="unknown", connection={"status": "not_established", "reason_code": "insufficient_evidence"}), "D"),
    (evidence(paths=[path(zero_hop=True)], processing={"kind": "fixed", "steps": []}), "A"),
])
def test_queue_table(dimensions, queue):
    assert choose_queue(dimensions)["queue"] == queue
    assert choose_queue(dimensions)["runtime_confirmed"] is False


@pytest.mark.parametrize("name", ["mask", "redact", "hash"])
def test_unverified_processing_names_never_prove_safe(name):
    finding = assess({"case_id": "unit1"}, evidence(source_sensitivity="suspected",
                     processing={"kind": "transformed", "steps": [{"function": name, "verified": False}]}))
    assert finding["queue"] == "B"
    assert finding["dimensions"]["output_sensitivity"] == "unknown"


def test_ab_same_logic_preserves_inputs_and_separate_review_layers():
    base = evidence(source_sensitivity="suspected", critical_unknowns=["connection_missing"])
    before = deepcopy(base)
    dfg = evidence(paths=[path()], critical_unknowns=[], processing_status="success")
    a, b = assess({"case_id": "same"}, base), assess({"case_id": "same"}, base, dfg)
    assert base == before
    assert a["queue"] == "B" and b["queue"] == "A"
    assert a["rule_version"] == b["rule_version"] and a["policy_version"] == b["policy_version"]
    assert a["review_status"] == {"rule": "executed", "ai": "pending", "human": "pending"}
    assert b["dimensions"]["severity"]["level"] is None


def test_parameter_is_trace_boundary_and_type_link_is_not_value_path():
    finding = assess({"case_id": "case"}, evidence(source_locations=[{"kind": "formal_parameter", "business_source_confirmed": True}],
                     paths=[path(connection_supported=False, relation_kind="type_schema")]))
    location = finding["dimensions"]["source_locations"][0]
    assert not location["business_source_confirmed"] and location["role"] == "trace_boundary"
    assert finding["queue"] == "B"


def test_policy_is_loadable_versioned_and_hashable():
    assert load_policy()["version"] == POLICY_VERSION
    assert len(policy_hash()) == 64
