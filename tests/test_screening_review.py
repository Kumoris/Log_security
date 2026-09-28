from copy import deepcopy
import json

import pytest

from agentlog_unified.screening_policy import POLICY_VERSION
from agentlog_unified.screening_review import (
    PROMPT_VERSION, _digest, ai_input, blind_case, evidence_hash, export_review_packages,
    detection_metrics, import_review, review_metrics,
)


def case():
    return {"case_id": "c1", "source_sha": "a" * 40, "source_sha256": "b" * 64,
            "path": "app.py", "line": 4, "evidence_ids": ["e1"], "split": "evaluation",
            "queue": "A", "variant": "dfg_augmented", "statement": "secret-test-value-should-never-export",
            "evidence_index": [{"evidence_id": "e1", "path": "app.py", "line": 4,
                                "snippet": "secret-test-value-should-never-export"}]}


def row(c=None, reviewer="alice", slot="reviewer_1", queue="A", kind="human"):
    c = c or case()
    result = {"case_id": c["case_id"], "policy_version": POLICY_VERSION,
              "evidence_sha256": evidence_hash(c), "evidence_ids": ["e1"], "kind": kind,
              "origin": "ai" if kind == "ai" else "human", "status": "submitted", "reviewer": reviewer,
              "annotator_slot": slot, "timestamp": "2026-09-12T10:00:00+08:00",
              "result": {"queue": queue,
                         "dimensions": {"source_sensitivity": "supported", "output_sensitivity": "not_found" if queue == "C" else "supported",
                                        "connection": "supported", "connection_reason": "supported", "processing": "raw", "processing_steps": [], "boundary": "call_argument",
                                        "severity": {"level": None, "reason": "context_and_impact_not_established"},
                                        "certainty": {"level": "supported_static", "reason": "evidence_complete"}},
                         "facts": [{"text": "secret-test-value-should-never-export", "evidence_ids": ["e1"]}],
                         "inferences": [], "critical_unknowns": [], "rationale": "Historical evidence supports this output."}}
    if kind == "ai":
        result["metadata"] = {"actual_source": "test_fixture", "model_id": None,
                              "prompt_template_version": PROMPT_VERSION, "input_sha256": _digest(ai_input(c)),
                              "output_sha256": _digest(result["result"])}
    return result


def save(tmp_path, rows):
    path = tmp_path / "input.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


def test_blind_packages_pending_and_source_safe(tmp_path):
    out = tmp_path / "review"
    report = export_review_packages([case()], out)
    assert report["status"] == "pending" and not report["ai_review_executed"]
    blind_text = (out / "reviewer_1/blind_cases.jsonl").read_text()
    assert '"queue"' not in blind_text and "dfg_augmented" not in blind_text
    assert "secret-test-value-should-never-export" not in blind_text
    assert "snippet" not in blind_text
    assert blind_case(case())["evidence_ids"] == ["e1"]
    result = import_review(out / "reviewer_1/annotations.jsonl", [case()], out / "imports")
    assert result["pending"] == 1 and result["imported"] == 0
    assert review_metrics([case()], [{"case_id": "c1", "queue": "A"}], [json.loads((out / "reviewer_1/annotations.jsonl").read_text())])["risk_judgment"]["precision"] is None


@pytest.mark.parametrize("mutation,expected", [
    (lambda r: r.update(case_id="unknown"), "unknown_case_id"),
    (lambda r: r.update(policy_version="old"), "policy_version_mismatch"),
    (lambda r: r.update(evidence_sha256="0" * 64), "evidence_snapshot_mismatch"),
    (lambda r: r.update(evidence_ids=["unknown"]), "unknown_evidence_id"),
    (lambda r: r["result"].update(queue="runtime_leak_confirmed"), "invalid_review_schema"),
    (lambda r: r.update(origin="ai"), "review_origin_mismatch"),
    (lambda r: r.update(timestamp="2026-09-12T10:00:00"), "timestamp_with_timezone_required"),
    (lambda r: r.update(reviewer=None), "human_reviewer_required_without_ai_metadata"),
    (lambda r: r.update(status="pending"), "pending_record_cannot_contain_result"),
    (lambda r: r["result"].update(queue="C", critical_unknowns=["budget_exhausted"]), "critical_unknown_cannot_be_c"),
])
def test_import_validation_is_atomic_and_does_not_echo_values(tmp_path, mutation, expected):
    invalid = row(reviewer="bob", slot="reviewer_2")
    mutation(invalid)
    output = tmp_path / "results"
    result = import_review(save(tmp_path, [row(), invalid]), [case()], output)
    assert result["imported"] == 0 and result["errors"][0]["code"] == expected
    assert not (output / "review_history.json").exists()
    assert "secret-test-value" not in str(result)


def test_import_is_idempotent_keeps_separate_ledgers_and_private_prose(tmp_path):
    output = tmp_path / "results"
    source = save(tmp_path, [row()])
    assert import_review(source, [case()], output)["imported"] == 1
    assert import_review(source, [case()], output)["unchanged"] == 1
    assert (output / "ai_results.jsonl").read_text() == ""
    public = (output / "human_results.jsonl").read_text()
    assert "secret-test-value" not in public
    private = next((output / ".raw_reviews").glob("*.json"))
    assert "secret-test-value" in private.read_text()
    assert private.stat().st_mode & 0o777 == 0o600
    assert (output / ".raw_reviews").stat().st_mode & 0o777 == 0o700


def test_ai_requires_real_metadata_and_hashes_and_never_enters_human_gold(tmp_path):
    output = tmp_path / "results"
    sample = row(kind="ai")
    assert import_review(save(tmp_path, [sample]), [case()], output, kind="ai")["imported"] == 1
    history = json.loads((output / "review_history.json").read_text())
    assert review_metrics([case()], [{"case_id": "c1", "queue": "A"}], history)["human_gold_count"] == 0
    sample["metadata"]["input_sha256"] = "0" * 64
    assert import_review(save(tmp_path, [sample]), [case()], output, kind="ai")["errors"][0]["code"] == "ai_input_hash_mismatch"


def test_double_human_consensus_and_disagreement_adjudication(tmp_path):
    output = tmp_path / "results"
    assert import_review(save(tmp_path, [row(), row(reviewer="bob", slot="reviewer_2")]), [case()], output)["imported"] == 2
    history = json.loads((output / "review_history.json").read_text())
    metrics = review_metrics([case()], [{"case_id": "c1", "queue": "A"}], history)
    assert metrics["risk_judgment"]["precision"] == 1.0
    assert metrics["log_detection"]["recall"] is None
    assert import_review(save(tmp_path, [row(reviewer="bob", slot="reviewer_2", queue="C")]), [case()], output)["unresolved_disagreements"] == 1
    history = json.loads((output / "review_history.json").read_text())
    assert review_metrics([case()], [{"case_id": "c1", "queue": "A"}], history)["risk_judgment"]["precision"] is None
    annotation_ids = [history[0]["id"], history[-1]["id"]]
    adjudication = row(reviewer="carol", slot=None, kind="adjudication")
    adjudication["annotation_ids"] = annotation_ids
    assert import_review(save(tmp_path, [adjudication]), [case()], output, kind="adjudication")["imported"] == 1
    history = json.loads((output / "review_history.json").read_text())
    assert review_metrics([case()], [{"case_id": "c1", "queue": "A"}], history)["risk_judgment"]["precision"] == 1.0


def test_same_person_two_slots_is_not_independent_truth(tmp_path):
    output = tmp_path / "results"
    import_review(save(tmp_path, [row(), row(slot="reviewer_2")]), [case()], output)
    history = json.loads((output / "review_history.json").read_text())
    assert review_metrics([case()], [{"case_id": "c1", "queue": "A"}], history)["human_gold_count"] == 0


def test_changed_source_refuses_existing_review_history(tmp_path):
    output = tmp_path / "results"
    source = save(tmp_path, [row()])
    import_review(source, [case()], output)
    changed = deepcopy(case())
    changed["source_sha256"] = "c" * 64
    with pytest.raises(ValueError, match="existing_review_history_incompatible"):
        import_review(source, [changed], output)


def test_blind_anchor_coordinates_and_dependency_hash_are_bound():
    c = case()
    c["log_anchor"] = {"line": 4, "column": 0, "end_line": 4, "end_column": 28, "expression": "secret-test-value"}
    c["output_anchor"] = {"line": 4, "column": 12, "end_line": 4, "end_column": 27}
    c["source_versions"] = [{"path": "helper.py", "sha": "a" * 40, "source_sha256": "c" * 64}]
    before = evidence_hash(c)
    assert blind_case(c)["identity"]["output_anchor"]["column"] == 12
    assert "expression" not in blind_case(c)["identity"]["log_anchor"]
    c["source_versions"][0]["source_sha256"] = "d" * 64
    assert evidence_hash(c) != before


def test_file_detection_metrics_uses_original_files_and_log_anchors():
    anchor1 = {"line": 1, "column": 0, "end_line": 1, "end_column": 10}
    anchor2 = {"line": 2, "column": 0, "end_line": 2, "end_column": 10}
    files = [{"file_version_id": "f1", "source_sha256": "a" * 64}]
    predictions = [{"file_version_id": "f1", "source_sha256": "a" * 64, "status": "success", "log_anchors": [anchor1]}]
    base = {"file_version_id": "f1", "source_sha256": "a" * 64, "origin": "human", "status": "submitted",
            "timestamp": "2026-09-12T10:00:00+08:00", "inspection_complete": True, "critical_unknowns": [],
            "review_scope": "original_modified_file", "log_anchors": [anchor1, anchor2]}
    annotations = [{**base, "reviewer": "alice", "annotator_slot": "reviewer_1"}, {**base, "reviewer": "bob", "annotator_slot": "reviewer_2"}]
    result = detection_metrics(files, predictions, annotations)
    assert result["precision"] == 1.0 and result["recall"] == .5 and result["fn"] == 1
    assert detection_metrics(files, predictions, annotations[:1])["recall"] is None
    assert detection_metrics(files, predictions, [{"status": "pending"}])["recall"] is None
    annotations[1] = {**annotations[1], "source_sha256": "b" * 64}
    with pytest.raises(ValueError, match="file_annotation_source_hash_mismatch"):
        detection_metrics(files, predictions, annotations)
