"""Raw CRLF repair is exercised through actual Git/PyDriller source blobs."""
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from agentlog_unified.screening import near_key
from agentlog_unified.screening_evidence import discover_outputs
from agentlog_unified.screening_history import extract_commit
from agentlog_unified.screening_repair import repair_source_hashes
from agentlog_unified.storage import canonical, stable_id
from synthetic_histories import HEADER, commit, git, init


def write_gzip(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wb") as stream:
        for row in rows:
            stream.write((canonical(row) + "\n").encode())


def read_gzip(path):
    with gzip.open(path, "rt") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def fixture(tmp_path):
    repo, out = tmp_path / "repo", tmp_path / "run"
    init(repo)
    git(repo, "config", "core.autocrlf", "false")
    crlf = (HEADER + 'def run():\n    logger.info("ok")\n').replace("\n", "\r\n")
    lf = HEADER + 'def other():\n    logger.info("done")\n'
    sha = commit(repo, {"crlf.py": crlf, "lf.py": lf}, "literal CRLF source")
    extracted = extract_commit(repo, "fixture/project", sha, tmp_path / "sources")
    versions, old_cases = [], []
    for original in extracted["file_versions"]:
        if original["source_state"] != "present":
            continue
        fv = {**original, "commit_id": stable_id("fixture/project", sha), "repo_path": str(repo),
              "scope": "application_or_unknown", "input_record_ids": ["input-fixture"],
              "old_stratum": "legacy_no_log_observation", "old_log_ids": []}
        versions.append(fv)
        # Deliberately reproduce the original discovery bug, including literals
        # and scopes from the real historical blob rather than mocked cases.
        source = Path(fv["source_path"]).read_text()
        for case in discover_outputs("fixture/project", sha, extracted["parent_sha"], sha,
                "after", fv["path"], source):
            case["function_scope"] = case["scope"]
            case.update(file_version_id=fv["file_version_id"], input_record_ids=fv["input_record_ids"],
                commit_id=fv["commit_id"], repo_path=str(repo), source_path=fv["source_path"],
                old_path=fv["old_path"], new_path=fv["new_path"], legacy_stratum=fv["old_stratum"],
                legacy_log_ids=[], near_duplicate_key=near_key(case, source), scope=fv["scope"],
                attribution={"output_unit_authorship": "unknown", "granularity": "commit"})
            old_cases.append(case)
    write_gzip(out / "discovery/file_coverage.jsonl.gz", versions)
    write_gzip(out / "discovery/output_units.jsonl.gz", old_cases)
    return out, versions, old_cases


def test_repair_real_crlf_hashes_and_preserve_unaffected_original_records(tmp_path):
    out, versions, old_cases = fixture(tmp_path)
    original = out / "discovery/output_units.jsonl.gz"
    initial_hash = hashlib.sha256(original.read_bytes()).hexdigest()
    crlf_file = next(row for row in versions if row["path"] == "crlf.py")
    assert b"\r\n" in Path(crlf_file["source_path"]).read_bytes()
    assert next(row for row in old_cases if row["path"] == "crlf.py")["source_sha256"] != crlf_file["source_sha256"]
    report = repair_source_hashes(out)
    assert report["affected_file_versions"] == report["mismatched_cases_before"] == 1
    assert report["mismatched_cases_after"] == 0
    assert report["input_cases"] == report["output_cases"] == 2
    assert report["unaffected_records_byte_identical"] is True
    assert report["performed_before_sample_freeze"] is True and report["sample_replacement"] is False
    assert hashlib.sha256(original.read_bytes()).hexdigest() == initial_hash
    repaired = read_gzip(report["output_path"])
    assert next(row for row in repaired if row["path"] == "lf.py") == next(row for row in old_cases if row["path"] == "lf.py")
    raw = next(row for row in repaired if row["path"] == "crlf.py")
    assert raw["source_sha256"] == crlf_file["source_sha256"]
    assert raw["source_versions"][0]["source_sha256"] == crlf_file["source_sha256"]
    assert raw["scope"] == crlf_file["scope"] and raw["function_scope"] == "run"
    assert raw["input_record_ids"] == ["input-fixture"]
    assert report["mapping_status_counts"] == {"unique_function_and_output_coordinates": 1}
    source_audit = json.loads(Path(report["source_audit_path"]).read_text().splitlines()[0])
    assert source_audit["crlf_pairs"] > 0 and source_audit["source_verified_this_repair"]


def test_repair_refuses_changed_source_cache_and_keeps_old_frame(tmp_path):
    out, versions, _ = fixture(tmp_path)
    crlf_file = next(row for row in versions if row["path"] == "crlf.py")
    Path(crlf_file["source_path"]).write_bytes(b"unrelated corrupted source\n")
    with pytest.raises(ValueError, match="verified_source_cache_content_hash_mismatch"):
        repair_source_hashes(out)
    assert (out / "discovery/output_units.jsonl.gz").exists()
    assert not (out / "discovery/output_units.repaired.jsonl.gz").exists()


def test_repair_cannot_change_already_frozen_sample(tmp_path):
    out, _, _ = fixture(tmp_path)
    selection = out / "selection"
    selection.mkdir()
    (selection / "manifest.json").write_text("{}\n")
    with pytest.raises(ValueError, match="repair_must_precede_sample_freeze"):
        repair_source_hashes(out)
    assert not (out / "discovery/source-hash-repair.json").exists()


def test_repair_rejects_non_newline_case_hash_corruption(tmp_path):
    out, versions, old = fixture(tmp_path)
    for case in old:
        if case["path"] == "lf.py":
            case["source_sha256"] = "0" * 64
    write_gzip(out / "discovery/output_units.jsonl.gz", old)
    with pytest.raises(ValueError, match="not_universal_newline_conversion"):
        repair_source_hashes(out)
    assert not (out / "discovery/output_units.repaired.jsonl.gz").exists()
