"""Synthetic tests of the independent metadata export, outside frozen src/config."""
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("screening_share", Path(__file__).resolve().parents[1] / "scripts/export_screening_share.py")
share = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(share)
MARKER = "ghp_" + "a" * 36
CID, AID, EID = "c" * 24, "a" * 24, "e" * 24


def write(path, value, lines=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in value) if lines else json.dumps(value))


def prepared_run(tmp_path):
    run = tmp_path / "run"
    case = {"case_id": CID, "repository": "private/" + MARKER, "path": "app/" + MARKER + ".py",
            "field": MARKER, "output_key": "arg:0/field:" + MARKER, "source_sha": "a" * 40,
            "source_sha256": "b" * 64, "log_anchor": {"path": MARKER + ".py", "line": 2, "column": 0, "end_line": 2, "end_column": 48},
            "output_anchor": {"path": MARKER + ".py", "line": 2, "column": 10, "end_line": 2, "end_column": 47},
            "base_evidence": {"evidence_ids": [EID], "source_sensitivity": "suspected", "code_view": MARKER},
            "source_path": str(run / "private" / (MARKER + ".py")), "source": MARKER}
    write(run / "selection/engineering.jsonl", [case], True)
    write(run / "selection/manifest.json", {"primary_selected": 1, "evaluation_selected": 1, "policy_version": "screening-policy-v1"})
    graph = run / ("analyses/main/graphs/" + AID + "/attempt.json")
    write(graph, {"field": MARKER, "code_view": MARKER})
    write(run / "analyses/main/results.jsonl", [{"case_id": CID, "analysis_id": AID, "variant": "baseline", "queue": "B",
          "assessment": {"dimensions": {"source_sensitivity": "suspected", "critical_unknowns": [MARKER]}},
          "artifact_hashes": {str(graph.relative_to(run / "analyses/main")): share.hash_file(graph)}}], True)
    write(run / "analyses/main/coverage.json", {"primary_cases": 1, "actual_analyses": 1, "human_labels": 0, "precision": None, "recall": None,
          "variants": {"baseline": {"queue_counts": {"B": 1}, "critical_unknown_ratio": 1.0}}})
    write(run / "review/metrics.json", {"risk_judgment": {"precision": None, "recall": None}, "human_gold_count": 0, "ai_used_as_gold": False})
    for slot in ("reviewer_1", "reviewer_2"):
        write(run / "review" / slot / "blind_cases.jsonl", [{"case_id": CID, "identity": case, "field": MARKER, "output_anchor": case["output_anchor"],
              "queue": "A", "variant": "dfg_augmented", "evidence_ids": [EID], "machine_answers_included": False}], True)
        write(run / "review" / slot / "annotations.jsonl", [{"case_id": CID, "evidence_sha256": "d" * 64, "status": "pending", "result": None}], True)
    return run


def test_synthetic_source_derived_secrets_never_enter_share_copy(tmp_path):
    run = prepared_run(tmp_path)
    original = {p: share.hash_file(p) for p in run.rglob("*") if p.is_file()}
    out = tmp_path / "share"
    assert share.export_share(run, out)["status"] == "verified"
    assert all(share.hash_file(path) == expected for path, expected in original.items())
    for path in out.rglob("*"):
        if path.is_file():
            assert MARKER not in path.read_text()
            assert path.suffix not in {"svg", ".svg"}
    cases = json.loads((out / "cases.jsonl").read_text())
    assert cases["field"].startswith("field_sha256:") and cases["output_key"].startswith("field_sha256:")
    assert cases["output_anchor"]["line"] == 2 and cases["output_anchor"]["column"] == 10
    assert cases["source_sha256"] == "b" * 64
    assert "source" not in cases and "source_path" not in cases
    mapping = next((run / "private/share-maps").glob("*.json"))
    assert MARKER in mapping.read_text() and mapping.stat().st_mode & 0o777 == 0o600
    assert (run / "review").stat().st_mode & 0o777 == 0o700
    assert share.verify_package(out)["raw_graphs_included"] is False


def test_dry_run_validates_without_any_writes_or_permissions(tmp_path):
    run = prepared_run(tmp_path)
    before = {p: (share.hash_file(p), p.stat().st_mode) for p in run.rglob("*") if p.is_file()}
    out = tmp_path / "share"
    assert share.export_share(run, out, dry_run=True)["status"] == "dry_run_validated"
    assert not out.exists() and not (run / "private/share-maps").exists()
    assert {p: (share.hash_file(p), p.stat().st_mode) for p in run.rglob("*") if p.is_file()} == before


def test_blind_export_strips_accidental_prediction_keys(tmp_path):
    run = prepared_run(tmp_path)
    out = tmp_path / "share"
    share.export_share(run, out)
    for slot in ("reviewer_1", "reviewer_2"):
        text = (out / "review" / slot / "blind_cases.jsonl").read_text()
        assert '"queue"' not in text and '"variant"' not in text and '"base_evidence"' not in text
        assert json.loads(text)["identity"]["output_anchor"]["line"] == 2
    metrics = json.loads((out / "review/metrics.json").read_text())
    assert metrics["risk_judgment"]["precision"] is None and metrics["human_gold_count"] == 0


def test_changed_original_graph_refuses_export(tmp_path):
    run = prepared_run(tmp_path)
    graph = next((run / "analyses/main/graphs").rglob("*.json"))
    graph.write_text("changed")
    with pytest.raises(ValueError, match="original_artifact_hash_mismatch"):
        share.export_share(run, tmp_path / "share")


def test_even_rehashed_secret_injection_fails_metadata_validation(tmp_path):
    run = prepared_run(tmp_path)
    out = tmp_path / "share"
    share.export_share(run, out)
    path = out / "cases.jsonl"
    value = json.loads(path.read_text())
    value["field"] = MARKER
    path.write_text(json.dumps(value) + "\n")
    manifest_path = out / "share_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"]["cases.jsonl"] = {"sha256": share.hash_file(path), "bytes": path.stat().st_size}
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="share_contains_unapproved_text"):
        share.verify_package(out)


def test_manifest_cannot_carry_unchecked_secret_text(tmp_path):
    run = prepared_run(tmp_path)
    out = tmp_path / "share"
    share.export_share(run, out)
    path = out / "share_manifest.json"
    manifest = json.loads(path.read_text())
    manifest["notes"] = MARKER
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="invalid_share_manifest_fields"):
        share.verify_package(out)


def test_missing_review_is_not_reported_as_finished_share_package(tmp_path):
    run = prepared_run(tmp_path)
    (run / "review/reviewer_1/blind_cases.jsonl").unlink()
    with pytest.raises(ValueError, match="analysis_or_review_export_not_ready"):
        share.export_share(run, tmp_path / "share")


def test_existing_share_is_not_silently_overwritten(tmp_path):
    run = prepared_run(tmp_path)
    out = tmp_path / "share"
    share.export_share(run, out)
    with pytest.raises(ValueError, match="share_output_exists_choose_new_directory"):
        share.export_share(run, out)
    assert share.main(["--verify", "--output", str(out)]) == 0
