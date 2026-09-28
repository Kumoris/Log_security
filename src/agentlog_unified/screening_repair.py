"""Repair universal-newline discovery inputs before freezing the pilot sample.

The original compressed frame remains untouched. Only file versions whose case
source hash disagrees with their verified raw blob hash are rediscovered, using
read_bytes().decode('utf-8'). Unaffected records retain their exact input bytes.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

from .storage import atomic_write, canonical

REPAIR_VERSION = "screening-raw-source-repair-1"


def _hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _lines(path):
    with gzip.open(path, "rb") as stream:
        for line in stream:
            if line.strip():
                yield line, json.loads(line)


def _coordinate(anchor):
    # Byte offsets change when CRLF bytes are retained; semantic row/column
    # coordinates, output roles and function context remain separately checked.
    return tuple(anchor.get(key) for key in ("line", "end_line", "column", "end_column", "node_kind"))


def _case_key(case):
    return (case.get("function_scope", case.get("scope")), case.get("output_key"), case.get("output_role"),
            _coordinate(case.get("log_anchor", {})), _coordinate(case.get("output_anchor", {})))


def _mapping(file_version, old, new):
    old_keys, new_keys = defaultdict(list), defaultdict(list)
    for case in old:
        old_keys[_case_key(case)].append(case)
    for case in new:
        new_keys[_case_key(case)].append(case)
    records = []
    for key in sorted(set(old_keys) | set(new_keys), key=repr):
        before, after = old_keys.get(key, []), new_keys.get(key, [])
        if len(before) == len(after) == 1:
            records.append({"file_version_id": file_version, "old_case_id": before[0]["case_id"],
                "new_case_id": after[0]["case_id"], "mapping_status": "unique_function_and_output_coordinates",
                "old_source_sha256": before[0]["source_sha256"], "new_source_sha256": after[0]["source_sha256"],
                "reason": "raw_historical_bytes_preserved_in_place_of_universal_newline_input"})
        else:
            records.append({"file_version_id": file_version, "old_case_ids": [c["case_id"] for c in before],
                "new_case_ids": [c["case_id"] for c in after], "mapping_status": "unmatched_or_ambiguous",
                "old_source_sha256": sorted({c["source_sha256"] for c in before}),
                "new_source_sha256": sorted({c["source_sha256"] for c in after}),
                "reason": "no_forced_case_identity_after_rediscovery"})
    return records


def repair_source_hashes(out) -> dict:
    """Stream the old frame, repair verified newline mismatches, write a new one.

    Reads the full ledger twice but retains only hash indexes and cases from
    affected files in memory. This must happen before selection/manifest.json
    exists. A manifest is written only after source/frame integrity verification.
    """
    from .screening import DEFAULT_CONFIG, discover_version

    started = time.monotonic()
    out = Path(out).resolve()
    if (out / "selection/manifest.json").exists():
        raise ValueError("source_frame_repair_must_precede_sample_freeze")
    directory = out / "discovery"
    original = directory / "output_units.jsonl.gz"
    file_coverage = directory / "file_coverage.jsonl.gz"
    repaired = directory / "output_units.repaired.jsonl.gz"
    manifest_path = directory / "source-hash-repair.json"
    if manifest_path.exists() or repaired.exists():
        raise ValueError("source_repair_output_already_exists")
    cfg = json.loads(Path(DEFAULT_CONFIG).read_text())
    original_physical_hash, coverage_hash = _hash(original), _hash(file_coverage)
    files = {}
    for _, row in _lines(file_coverage):
        fid = row["file_version_id"]
        if fid in files:
            raise ValueError("duplicate_file_coverage_identity")
        files[fid] = (row.get("source_sha256"), row.get("source_state"))
    affected, input_count, mismatch_count, original_logical = set(), 0, 0, hashlib.sha256()
    for line, case in _lines(original):
        input_count += 1
        original_logical.update(line)
        fid = case["file_version_id"]
        if fid not in files:
            raise ValueError("case_has_no_file_version_record")
        expected, state = files[fid]
        if state != "present" or not expected:
            raise ValueError("case_has_no_verified_source_blob")
        if case.get("source_sha256") != expected:
            affected.add(fid)
            mismatch_count += 1
    selected_files = {row["file_version_id"]: row for _, row in _lines(file_coverage)
                      if row["file_version_id"] in affected}
    replacements, source_audits, raw_normalized_hashes = {}, [], {}
    for fid, row in sorted(selected_files.items()):
        source_path = Path(row["source_path"])
        raw = source_path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != row["source_sha256"]:
            raise ValueError("verified_source_cache_content_hash_mismatch")
        source = raw.decode("utf-8")
        normalized = source.replace("\r\n", "\n").replace("\r", "\n")
        normalized_hash = hashlib.sha256(normalized.encode()).hexdigest()
        if normalized_hash == digest:
            raise ValueError("source_mismatch_is_not_universal_newline_conversion")
        raw_normalized_hashes[fid] = normalized_hash
        updated, cases = discover_version((deepcopy(row), cfg))
        if updated.get("processing_status") == "blocked":
            raise ValueError("raw_source_rediscovery_blocked")
        if any(case.get("source_sha256") != digest for case in cases):
            raise ValueError("raw_source_rediscovery_still_normalizes_source")
        replacements[fid] = sorted(cases, key=lambda case: case["case_id"])
        source_audits.append({"file_version_id": fid, "source_path": str(source_path),
            "source_sha": row["source_sha"], "source_sha256": digest,
            "blob_oid": row.get("blob_oid"), "normalized_input_sha256": normalized_hash,
            "crlf_pairs": raw.count(b"\r\n"), "standalone_cr": raw.count(b"\r") - raw.count(b"\r\n"),
            "replacement_case_count": len(cases), "source_bytes": len(raw),
            "source_verified_this_repair": True, "source_backend": row.get("source_backend")})
    old_affected, emitted_files, emitted_ids = defaultdict(list), set(), set()
    output_count, replaced_old_count, unaffected_count, unmatched_hashes = 0, 0, 0, 0
    old_unaffected_hash, new_unaffected_hash, output_logical = hashlib.sha256(), hashlib.sha256(), hashlib.sha256()
    fd, temporary = tempfile.mkstemp(dir=directory, prefix=repaired.name + ".")
    try:
        with os.fdopen(fd, "wb") as raw_output, gzip.GzipFile(fileobj=raw_output, mode="wb", filename="", mtime=0) as stream:
            def emit(line, row):
                nonlocal output_count, unmatched_hashes
                if row["case_id"] in emitted_ids:
                    raise ValueError("repair_produced_duplicate_case_identity")
                emitted_ids.add(row["case_id"])
                if row.get("source_sha256") != files[row["file_version_id"]][0]:
                    unmatched_hashes += 1
                stream.write(line)
                output_logical.update(line)
                output_count += 1
            for line, case in _lines(original):
                fid = case["file_version_id"]
                if fid not in affected:
                    old_unaffected_hash.update(line)
                    emit(line, case)
                    new_unaffected_hash.update(line)
                    unaffected_count += 1
                    continue
                if case.get("source_sha256") not in {raw_normalized_hashes[fid], files[fid][0]}:
                    raise ValueError("old_case_hash_not_explained_by_verified_newline_conversion")
                old_affected[fid].append(case)
                replaced_old_count += 1
                if fid not in emitted_files:
                    for replacement in replacements[fid]:
                        emit((canonical(replacement) + "\n").encode(), replacement)
                    emitted_files.add(fid)
        if emitted_files != affected or unmatched_hashes:
            raise ValueError("source_repair_coverage_or_hash_mismatch")
        if _hash(original) != original_physical_hash or _hash(file_coverage) != coverage_hash:
            raise ValueError("source_frame_or_file_ledger_changed_during_repair")
        if (out / "selection/manifest.json").exists():
            raise ValueError("sample_was_frozen_during_source_repair")
        os.replace(temporary, repaired)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    mappings = [mapping for fid in sorted(affected) for mapping in _mapping(fid, old_affected[fid], replacements[fid])]
    mapping_path = directory / "source-hash-repair-mapping.jsonl"
    atomic_write(mapping_path, "".join(canonical(row) + "\n" for row in mappings))
    source_audit_path = directory / "source-hash-repair-files.jsonl"
    atomic_write(source_audit_path, "".join(canonical(row) + "\n" for row in source_audits))
    code_paths = [Path(__file__), Path(__file__).with_name("screening.py"),
                  Path(__file__).with_name("screening_evidence.py"), Path(__file__).with_name("detector.py")]
    summary = {"version": REPAIR_VERSION, "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "success", "performed_before_sample_freeze": True,
        "sample_replacement": False, "original_frame_preserved": True,
        "input_path": str(original), "input_physical_sha256": original_physical_hash,
        "input_logical_sha256": original_logical.hexdigest(),
        "file_coverage_path": str(file_coverage), "file_coverage_physical_sha256": coverage_hash,
        "output_path": str(repaired), "output_physical_sha256": _hash(repaired),
        "output_logical_sha256": output_logical.hexdigest(),
        "input_cases": input_count, "output_cases": output_count, "affected_file_versions": len(affected),
        "mismatched_cases_before": mismatch_count, "mismatched_cases_after": unmatched_hashes,
        "old_cases_replaced": replaced_old_count, "new_cases_generated": sum(map(len, replacements.values())),
        "unaffected_case_count": unaffected_count,
        "unaffected_original_bytes_sha256": old_unaffected_hash.hexdigest(),
        "unaffected_output_bytes_sha256": new_unaffected_hash.hexdigest(),
        "unaffected_records_byte_identical": old_unaffected_hash.hexdigest() == new_unaffected_hash.hexdigest(),
        "mapping_path": str(mapping_path), "mapping_sha256": _hash(mapping_path),
        "mapping_status_counts": dict(Counter(row["mapping_status"] for row in mappings)),
        "source_audit_path": str(source_audit_path), "source_audit_sha256": _hash(source_audit_path),
        "actual_code_sha256": {str(path): _hash(path) for path in code_paths},
        "config_sha256": _hash(DEFAULT_CONFIG),
        "ordering_rule": "Original frame order; affected file replacements sorted by case_id emitted at its first original occurrence.",
        "target_code_executed": False, "pydriller_remining_performed": False,
        "source_basis": "Current-run verified exact Git blob bytes; per-file source SHA256 rechecked before rediscovery.",
        "elapsed_seconds": round(time.monotonic() - started, 6)}
    atomic_write(manifest_path, canonical(summary) + "\n")
    return summary
