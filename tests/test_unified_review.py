import csv

import pytest

from agentlog_unified.review import import_reviews, review_annotations, review_history, REVIEW_FIELDS
from agentlog_unified.storage import Store

CASE = "a" * 24
OTHER = "b" * 24


def populated_store(tmp_path):
    store = Store(tmp_path / "index.sqlite")
    with store.db:
        store.replace("candidates", [
            {"case_id": case, "human_review_status": "pending", "privacy_assessment": "possible",
             "runtime_leak_claim": False, "new_type_status": "not_established"}
            for case in (CASE, OTHER)
        ])
    return store


def write_reviews(tmp_path, rows, fields=REVIEW_FIELDS):
    path = tmp_path / "reviews.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return path


def decision(case_id=CASE, **kwargs):
    return {"case_id": case_id, "human_review_status": "reviewed",
            "human_review_decision": "privacy_candidate", "reviewer": "reviewer-1",
            "evidence_notes": "Static review only.", **kwargs}


def test_reviews_persist_without_mutating_machine_findings(tmp_path):
    store = populated_store(tmp_path)
    machine = store.rows("candidates")
    result = import_reviews(store, write_reviews(tmp_path, [decision()]))
    assert result["imported"] == 1 and not result["errors"]
    assert store.rows("candidates") == machine
    store.close()
    store = Store(tmp_path / "index.sqlite")
    current = review_annotations(store)[CASE]
    assert current["human_review_status"] == "reviewed"
    assert current["review_revision"] == 1
    assert current["review_origin"] == "user_supplied_review"
    assert not current["stale_against_current_candidate"]
    assert "runtime_leak_claim" not in current
    assert len(current["source_file_sha256"]) == 64
    assert current["source_line"] == 2
    store.close()


def test_pending_template_cannot_erase_review_and_blank_extra_columns_are_ok(tmp_path):
    store = populated_store(tmp_path)
    import_reviews(store, write_reviews(tmp_path, [decision()]))
    path = write_reviews(tmp_path, [{"case_id": CASE, "human_review_status": "pending"}],
                         (*REVIEW_FIELDS, "privacy_assessment"))
    result = import_reviews(store, path, reviewer="default")
    assert result["skipped_pending"] == 1 and not result["errors"]
    assert len(review_history(store)) == 1
    store.close()


@pytest.mark.parametrize("changes,code", [
    ({"case_id": "unknown"}, "unknown_case_id"),
    ({"human_review_status": "confirmed"}, "invalid_review_status"),
    ({"human_review_decision": "runtime_leak_confirmed"}, "explicit_valid_decision_required"),
    ({"human_review_decision": ""}, "explicit_valid_decision_required"),
    ({"human_review_status": "pending"}, "pending_with_decision"),
    ({"reviewer": ""}, "reviewer_required"),
    ({"privacy_assessment": "supported"}, "non_review_field_not_allowed"),
    ({"runtime_leak_claim": "true"}, "non_review_field_not_allowed"),
])
def test_invalid_batch_is_atomic_and_never_overrides_machine_fields(tmp_path, changes, code):
    store = populated_store(tmp_path)
    machine = store.rows("candidates")
    rows = [decision(OTHER), decision(**changes)]
    fields = sorted(set(REVIEW_FIELDS) | set(changes))
    result = import_reviews(store, write_reviews(tmp_path, rows, fields))
    assert result["imported"] == 0
    assert result["errors"] == [{"line": 3, "code": code}]
    assert review_history(store) == []
    assert store.rows("candidates") == machine
    store.close()


def test_idempotent_imports_and_append_only_revisions(tmp_path):
    store = populated_store(tmp_path)
    original = write_reviews(tmp_path, [decision(), decision()])
    result = import_reviews(store, original)
    assert result["imported"] == 1 and result["duplicate_rows"] == 1
    first = review_history(store)[0]
    assert import_reviews(store, original)["unchanged"] == 1
    replacement = write_reviews(tmp_path, [decision(human_review_decision="not_privacy_candidate")])
    assert import_reviews(store, replacement)["imported"] == 1
    history = review_history(store, CASE)
    assert history[0] == first
    assert history[1]["previous_review_id"] == first["id"]
    assert history[1]["review_revision"] == 2
    assert review_annotations(store)[CASE]["human_review_decision"] == "not_privacy_candidate"
    store.close()


def test_reassessment_keeps_reviews_and_marks_changed_or_removed_evidence(tmp_path):
    store = populated_store(tmp_path)
    path = write_reviews(tmp_path, [decision()])
    import_reviews(store, path)
    rows = store.rows("candidates")
    for row in rows:
        if row["case_id"] == CASE:
            row["privacy_assessment"] = "supported"
    with store.db:
        store.replace("candidates", rows)
    assert review_annotations(store)[CASE]["stale_against_current_candidate"]
    assert import_reviews(store, path)["imported"] == 1
    assert len(review_history(store)) == 2
    assert not review_annotations(store)[CASE]["stale_against_current_candidate"]
    with store.db:
        store.replace("candidates", [])
    assert not review_annotations(store)[CASE]["candidate_present"]
    assert review_annotations(store)[CASE]["stale_against_current_candidate"]
    assert len(review_history(store)) == 2
    store.close()


def test_explicit_decision_accepts_default_reviewer_and_empty_status(tmp_path):
    store = populated_store(tmp_path)
    row = decision(human_review_status="", reviewer="", human_review_decision="needs_context")
    assert import_reviews(store, write_reviews(tmp_path, [row]), reviewer="named-auditor")["imported"] == 1
    assert review_annotations(store)[CASE]["reviewer"] == "named-auditor"
    store.close()


def test_conflicting_rows_and_malformed_headers_are_rejected(tmp_path):
    store = populated_store(tmp_path)
    rows = [decision(), decision(human_review_decision="out_of_scope")]
    result = import_reviews(store, write_reviews(tmp_path, rows))
    assert result["errors"][0]["code"] == "conflicting_duplicate_case"
    assert not review_history(store)
    path = tmp_path / "bad.csv"
    path.write_text("case_id,case_id,human_review_decision\na,b,needs_context\n")
    assert import_reviews(store, path)["errors"][0]["code"] == "duplicate_headers"
    path.write_text("case_id,human_review_decision\n" + CASE + ",needs_context,extra\n")
    assert import_reviews(store, path)["errors"][0]["code"] == "malformed_row"
    store.close()


def test_error_reporting_does_not_echo_untrusted_sensitive_values(tmp_path):
    store = populated_store(tmp_path)
    secret = "synthetic-secret-marker-only"
    path = write_reviews(tmp_path, [decision(human_review_decision=secret, evidence_notes=secret)])
    assert secret not in str(import_reviews(store, path))
    store.close()
