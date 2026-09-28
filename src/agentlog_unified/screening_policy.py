"""Versioned, evidence-bound queues shared by baseline and DFG analyses.

This module consumes evidence summaries; it does not infer semantics from names,
import a target project, call a model, or treat a rule result as human truth.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

POLICY_VERSION = "screening-policy-v1"
RULE_VERSION = "screening-queues-v1"
POLICY_PATH = Path(__file__).resolve().parents[2] / "configs/screening_policy_v1.json"
SENSITIVITY = {"supported", "suspected", "not_found", "unknown"}
CONNECTION = {"supported", "partial", "not_established", "not_applicable"}
PROCESSING = {"raw", "partial_mask", "transformed", "fixed", "unknown"}
BOUNDARIES = {"call_argument", "log_record", "formatted_output"}
QUEUES = {
    "A": "static_risk_evidence_supported",
    "B": "suspected_risk_needs_evidence",
    "C": "no_risk_found_within_checked_scope",
    "D": "unable_to_determine",
}


def load_policy(path: str | Path | None = None) -> dict:
    policy = json.loads(Path(path or POLICY_PATH).read_text(encoding="utf-8"))
    if policy.get("version") != POLICY_VERSION:
        raise ValueError("unsupported_policy_version")
    return policy


def policy_hash(path: str | Path | None = None) -> str:
    return hashlib.sha256(Path(path or POLICY_PATH).read_bytes()).hexdigest()


def _supported_path(path: dict, dimensions: dict) -> bool:
    """Only necessary unknowns veto a supported, independently sufficient path."""
    boundary = path.get("boundary", dimensions.get("boundary", {}))
    return (
        path.get("source_sensitivity") == "supported"
        and path.get("output_sensitivity") == "supported"
        and path.get("connection_supported") is True
        and path.get("semantics_supported") is True
        and path.get("relation_kind") not in {"type", "schema", "type_schema", "type_relation", "possible"}
        and bool(path.get("evidence_ids"))
        and not path.get("critical_unknowns")
        and boundary.get("level") in BOUNDARIES
        and boundary.get("status") == "supported"
    )


def _has_clue(dimensions: dict) -> bool:
    ids = dimensions.get("evidence_ids", [])
    for clue in dimensions.get("risk_clues", []):
        if isinstance(clue, dict) and clue.get("evidence_ids"):
            return True
        if isinstance(clue, str) and clue and ids:
            return True
    if ids and any(dimensions.get(key) in {"supported", "suspected"}
                   for key in ("source_sensitivity", "output_sensitivity")):
        return True
    return any(path.get("evidence_ids") and any(path.get(key) in {"supported", "suspected"}
               for key in ("source_sensitivity", "output_sensitivity"))
               for path in dimensions.get("paths", []))


def choose_queue(dimensions: dict) -> dict:
    """Apply A/B/C/D in order. Failed/empty analysis is never evidence for C.

    ``critical_unknowns`` at top level affect all proposed conclusions. Unknowns
    local to another branch belong on that path or in ``noncritical_unknowns``.
    Every A path must carry its own sufficient evidence and processing semantics.
    """
    paths = dimensions.get("paths", [])
    connection = dimensions.get("connection", {})
    excluded = (connection.get("status") == "not_established"
                and connection.get("reason_code") == "target_connection_excluded")
    clean = (
        dimensions.get("checks_complete") is True
        and dimensions.get("processing_status") in {"success", "succeeded", "processed", "complete"}
        and not dimensions.get("critical_unknowns")
        and not any(path.get("critical_unknowns") for path in paths)
        and bool(dimensions.get("evidence_ids"))
        and bool(dimensions.get("non_sensitive_basis"))
        and dimensions.get("boundary", {}).get("status") == "supported"
        and (dimensions.get("output_sensitivity") == "not_found" or excluded)
    )
    if not dimensions.get("critical_unknowns") and any(_supported_path(p, dimensions) for p in paths):
        queue, reason = "A", "independent_static_sensitive_path_supported"
    elif _has_clue(dimensions) and not clean:
        queue, reason = "B", "concrete_risk_clue_missing_necessary_evidence"
    else:
        queue, reason = ("C", "necessary_checks_support_bounded_non_sensitive_output") if clean else (
            "D", "insufficient_evidence_without_specific_risk_clue")
    return {"queue": queue, "queue_label": QUEUES[queue], "queue_reason": reason,
            "runtime_confirmed": False}


def _normalise(evidence: dict) -> dict:
    result = {
        "source_sensitivity": "unknown", "output_sensitivity": "unknown",
        "connection": {"status": "not_established", "reason_code": "insufficient_evidence"},
        "processing": {"kind": "unknown", "steps": []},
        "boundary": {"level": "call_argument", "status": "unknown"},
        "paths": [], "risk_clues": [], "critical_unknowns": [], "noncritical_unknowns": [],
        "checks_complete": False, "non_sensitive_basis": [], "evidence_ids": [],
        "processing_status": "partial", "limitations": [], "source_locations": [],
    }
    for key in result:
        if key in evidence:
            result[key] = deepcopy(evidence[key])
    for key in ("source_sensitivity", "output_sensitivity"):
        if result[key] not in SENSITIVITY:
            raise ValueError("invalid_sensitivity_dimension")
    if result["connection"].get("status") not in CONNECTION:
        raise ValueError("invalid_connection_dimension")
    if result["processing"].get("kind") not in PROCESSING:
        raise ValueError("invalid_processing_dimension")
    if result["boundary"].get("level") not in BOUNDARIES:
        raise ValueError("invalid_log_boundary")
    # A parameter is a verified local boundary, never a proven business source.
    for location in result["source_locations"]:
        if location.get("kind") in {"parameter", "formal_parameter"}:
            location["business_source_confirmed"] = False
            location["role"] = "trace_boundary"
    return result


def assess(case: dict, base_evidence: dict, dfg_evidence: dict | None = None) -> dict:
    """Assess one unit; the presence of additional evidence is the only A/B switch.

    Callers must pass the same case and baseline evidence to both runs. Additional
    evidence can refine dimensions but cannot delete an independent baseline path.
    Neither input is mutated. Model/human reviews always start pending.
    """
    merged = deepcopy(base_evidence)
    if dfg_evidence is not None:
        additional = dfg_evidence.get("evidence", dfg_evidence)
        # Dimension refinements may legitimately clear a previously unresolved
        # baseline boundary; retain the original snapshot separately in the run.
        merged.update(deepcopy(additional))
        for key in ("paths", "risk_clues", "evidence_ids", "noncritical_unknowns", "limitations"):
            items = list(base_evidence.get(key, [])) + list(additional.get(key, []))
            unique = {json.dumps(item, sort_keys=True, ensure_ascii=False): item for item in items}
            merged[key] = list(unique.values())
    dimensions = _normalise(merged)
    # Observed categories without path evidence remain suspected. In particular,
    # a function named mask/hash/redact supplies no verifiable safety semantics.
    decision = choose_queue(dimensions)
    certainty = {"A": "supported_static", "B": "incomplete", "C": "supported_within_scope", "D": "unknown"}
    dimensions["severity"] = {"level": None, "reason": "context_and_impact_not_established"}
    dimensions["certainty"] = {"level": certainty[decision["queue"]], "reason": decision["queue_reason"]}
    result = {
        "case_id": case.get("case_id"), "policy_version": POLICY_VERSION,
        "rule_version": RULE_VERSION, "dimensions": dimensions, **decision,
        "processing_status": dimensions["processing_status"],
        "evidence_ids": dimensions["evidence_ids"],
        "scope": case.get("scope", "unknown"),
        "review_status": {"rule": "executed", "ai": "pending", "human": "pending"},
        "rule_result": {"status": "executed", **decision},
        "ai_review": {"status": "pending", "executed": False, "result": None},
        "human_review": {"status": "pending", "executed": False, "result": None},
    }
    return result
