"""Conservative same-event before/after comparison of selected output units.

Pairing requires an exact first-parent file event, exact source hashes, an
unchanged statement, a unique function/output anchor and verified diff line
mapping. An unavailable or unanalysed counterpart is never treated as safe.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy

from .screening_policy import choose_queue
from .storage import stable_id

COMPARE_VERSION = "screening-comparison-1"
VARIANTS = ("baseline", "dfg_augmented")
SUCCESS = {"success", "succeeded", "processed", "complete"}


def _span(anchor):
    first = anchor.get("line", anchor.get("start_line"))
    last = anchor.get("end_line", first)
    if not isinstance(first, int) or not isinstance(last, int) or not 0 < first <= last:
        return None
    return first, last


def _scope(case):
    return case.get("function_scope", case.get("scope"))


def _exact_mapping(before, after, event):
    old, new = _span(before.get("log_anchor", {})), _span(after.get("log_anchor", {}))
    if old is None or new is None:
        return False, "log_line_anchor_unavailable"
    if "added_line_numbers" not in event or "deleted_line_numbers" not in event:
        return False, "verified_diff_line_numbers_unavailable"
    deleted, added = set(event["deleted_line_numbers"]), set(event["added_line_numbers"])
    if any(old[0] <= line <= old[1] for line in deleted) or any(new[0] <= line <= new[1] for line in added):
        return False, "log_span_intersects_changed_lines"
    if old[1] - old[0] != new[1] - new[0]:
        return False, "log_span_length_mismatch"
    # Remove changed lines from each coordinate space. Equal unchanged-line
    # indices denote the same line; statement and function guards disambiguate.
    for left, right in zip(old, new):
        if left - sum(n < left for n in deleted) != right - sum(n < right for n in added):
            return False, "unchanged_log_diff_mapping_mismatch"
    for key in ("column", "start_col", "col", "end_column", "end_col"):
        left = before.get("log_anchor", {}).get(key)
        right = after.get("log_anchor", {}).get(key)
        if left is not None and right is not None and left != right:
            return False, "unchanged_log_column_mismatch"
    return True, "exact_unchanged_log_diff_line_mapping"


def _extract_index(records):
    if isinstance(records, dict):
        records = list(records.values())
    index = defaultdict(list)
    for record in records or []:
        record = record.get("result", record)
        if record.get("repository") and record.get("sha"):
            index[record["repository"], record["sha"]].append(record)
    return index


def _event_for_case(case, extraction):
    records = extraction.get((case.get("repository"), case.get("event_sha")), [])
    candidates = []
    for record in records:
        if record.get("comparison_strategy") != "first_parent" or record.get("parent_sha") != case.get("parent_sha"):
            continue
        for event in record.get("files", []):
            side = event.get(case.get("side"), {})
            if side.get("source_state") != "present" or side.get("source_sha") != case.get("source_sha"):
                continue
            if side.get("path") != case.get("path") or side.get("source_sha256") != case.get("source_sha256"):
                continue
            if case.get("old_path") is not None and event.get("old_path") != case["old_path"]:
                continue
            if case.get("new_path") is not None and event.get("new_path") != case["new_path"]:
                continue
            candidates.append(event)
    # Duplicate copies of the same extraction audit are harmless; inconsistent
    # events for an exact source context cannot form a reliable comparison.
    unique = {stable_id(event): event for event in candidates}
    return next(iter(unique.values())) if len(unique) == 1 else None


def _analysis_dimensions(result):
    return result.get("assessment", result).get("dimensions", {}) if result else {}


def _supported_result(result):
    if not result or result.get("processing_status") == "blocked" or result.get("failure_reason"):
        return False
    dimensions = _analysis_dimensions(result)
    return (not dimensions.get("critical_unknowns") and dimensions.get("boundary", {}).get("status") == "supported"
            and choose_queue(dimensions)["queue"] == result.get("queue"))


def _complete_negative(result):
    dimensions = _analysis_dimensions(result)
    return (result and result.get("queue") == "C" and _supported_result(result)
            and dimensions.get("checks_complete") is True
            and dimensions.get("processing_status") in SUCCESS
            and bool(dimensions.get("non_sensitive_basis")) and bool(dimensions.get("evidence_ids")))


def _source_contents(case):
    return sorted((row.get("path"), row.get("source_sha256")) for row in case.get("source_versions", []))


def _variant_change(case, counterpart, event, result, other):
    response = {"change_label": "cannot_compare", "reason": "comparison_evidence_incomplete",
                "case_analysis_id": result.get("analysis_id") if result else None,
                "counterpart_analysis_id": other.get("analysis_id") if other else None,
                "before_queue": (result if case["side"] == "before" else other or {}).get("queue") if result else None,
                "after_queue": (result if case["side"] == "after" else other or {}).get("queue") if result else None,
                "runtime_confirmed": False}
    if not result:
        response["reason"] = "selected_case_variant_not_executed"
        return response
    if not _supported_result(result):
        response["reason"] = "selected_case_boundary_or_necessary_evidence_unresolved"
        return response
    opposite = "before" if case["side"] == "after" else "after"
    if event and event.get(opposite, {}).get("source_state") == "absent_verified":
        if result.get("queue") == "A":
            response.update(change_label="added_risk" if case["side"] == "after" else "removed_path",
                reason="after_supported_static_risk_and_verified_absent_before" if case["side"] == "after"
                else "before_supported_static_risk_and_verified_absent_after")
        else:
            response["reason"] = "verified_file_side_absence_does_not_establish_risk_change"
        return response
    if counterpart is None:
        response["reason"] = "no_reliably_paired_primary_counterpart"
        return response
    if other is None:
        response["reason"] = "counterpart_variant_not_executed"
        return response
    if not _supported_result(other):
        response["reason"] = "counterpart_boundary_or_necessary_evidence_unresolved"
        return response
    before, after = (result, other) if case["side"] == "before" else (other, result)
    if _analysis_dimensions(before).get("boundary") != _analysis_dimensions(after).get("boundary"):
        response["reason"] = "declared_log_boundaries_differ"
    elif _complete_negative(before) and _complete_negative(after):
        response.update(change_label="no_relevant_change", reason="both_sides_complete_bounded_negative_at_same_boundary")
    elif before.get("queue") == after.get("queue") == "A" and _source_contents(case) and _source_contents(case) == _source_contents(counterpart):
        response.update(change_label="no_relevant_change", reason="same_supported_output_and_identical_checked_source_contents")
    else:
        # Queue migration is not itself evidence of output expansion or a risk
        # reduction. Semantic changes require a separately supported comparison.
        response["reason"] = "risk_or_processing_change_semantics_not_established"
    return response


def compare_cases(cases, results, extraction_records) -> list:
    """Compare primary cases without adding unselected cases to any denominator.

    Returns one row per supplied case with separate baseline/DFG changes. A
    duplicate result for a case/variant is an error rather than an arbitrary
    overwrite. The default change_label reflects DFG augmented results only.
    """
    cases = list(cases)
    if len({case["case_id"] for case in cases}) != len(cases):
        raise ValueError("duplicate_primary_case_id")
    analyzed = {}
    for result in results:
        key = result["case_id"], result["variant"]
        if key in analyzed:
            raise ValueError("duplicate_case_variant_result")
        analyzed[key] = result
    extraction = _extract_index(extraction_records)
    by_context = defaultdict(list)
    for case in cases:
        by_context[case.get("repository"), case.get("event_sha"), case.get("parent_sha")].append(case)
    output = []
    for case in cases:
        event = _event_for_case(case, extraction)
        opposite = "before" if case["side"] == "after" else "after"
        candidates, pair_reasons = [], []
        if event:
            target = event.get(opposite, {})
            for other in by_context[case.get("repository"), case.get("event_sha"), case.get("parent_sha")]:
                if other["side"] != opposite or other.get("path") != target.get("path"):
                    continue
                if other.get("source_sha") != target.get("source_sha") or other.get("source_sha256") != target.get("source_sha256"):
                    continue
                required = ("output_key", "output_role", "log_statement_sha256", "output_sha256", "split_version")
                if any(not case.get(key) or case.get(key) != other.get(key) for key in required):
                    continue
                if not _scope(case) or _scope(case) != _scope(other):
                    continue
                before, after = (case, other) if case["side"] == "before" else (other, case)
                valid, reason = _exact_mapping(before, after, event)
                if valid:
                    candidates.append(other)
                else:
                    pair_reasons.append(reason)
        counterpart = candidates[0] if len(candidates) == 1 else None
        absence = bool(event and event.get(opposite, {}).get("source_state") == "absent_verified")
        pairing_status = "paired" if counterpart else "verified_absent_side" if absence else "unresolved"
        if counterpart:
            basis = ["same_repository_event_and_first_parent", "verified_old_new_file_event",
                     "exact_historical_source_hashes", "same_function_and_output_key",
                     "identical_log_and_output_syntax_hashes", "unique_unchanged_diff_line_mapping"]
            uncertainty = ["comparison_applies_only_to_checked_sources_and_declared_log_boundary"]
        elif absence:
            basis = ["verified_old_new_file_event", "exact_historical_source_hash", "opposite_file_side_absent_verified"]
            uncertainty = ["removed_path_does_not_establish_removal_of_other_logs_or_repository_risk"]
        else:
            basis = []
            uncertainty = sorted(set(pair_reasons + (["multiple_exact_counterparts"] if len(candidates) > 1 else
                ["exact_extraction_context_unavailable"] if event is None else ["opposite_primary_case_not_reliably_paired"])))
        variants = {variant: _variant_change(case, counterpart, event,
            analyzed.get((case["case_id"], variant)),
            analyzed.get((counterpart["case_id"], variant)) if counterpart else None) for variant in VARIANTS}
        before = case if case["side"] == "before" else counterpart
        after = case if case["side"] == "after" else counterpart
        output.append({"case_id": case["case_id"], "comparison_version": COMPARE_VERSION,
            "pair_id": stable_id(COMPARE_VERSION, sorted([case["case_id"], counterpart["case_id"]])) if counterpart else None,
            "counterpart_case_id": counterpart["case_id"] if counterpart else None,
            "candidate_counterpart_ids": [other["case_id"] for other in candidates],
            "pairing_status": pairing_status, "pairing_basis": basis, "uncertainty": uncertainty,
            "old_anchor": deepcopy(before.get("log_anchor")) if before else None,
            "new_anchor": deepcopy(after.get("log_anchor")) if after else None,
            "old_output_anchor": deepcopy(before.get("output_anchor")) if before else None,
            "new_output_anchor": deepcopy(after.get("output_anchor")) if after else None,
            "old_source_sha": event.get("before", {}).get("source_sha") if event else None,
            "new_source_sha": event.get("after", {}).get("source_sha") if event else None,
            "old_source_state": event.get("before", {}).get("source_state") if event else None,
            "new_source_state": event.get("after", {}).get("source_state") if event else None,
            "comparison_strategy": "first_parent", "variant_changes": variants,
            "change_label": variants["dfg_augmented"]["change_label"],
            "reason": variants["dfg_augmented"]["reason"], "unselected_counterpart_analysis_inferred": False,
            "attribution": deepcopy(case.get("attribution", {"output_unit_authorship": "unknown"})),
            "attribution_inferred_from_risk_change": False, "runtime_confirmed": False})
    return output
