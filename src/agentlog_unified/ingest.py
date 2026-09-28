"""Stream heterogeneous PR exports into provenance-neutral, deduplicated records."""
from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse
from .paths import resolve_path

ALIASES = {
    "repository": ["repository", "repository.full_name", "repo", "repo_name", "repository_name", "repo_full_name", "full_name", "base.repo.full_name"],
    "pr_number": ["pr_number", "number", "pull_number", "pull_request_number", "pr_id"],
    "pr_url": ["pr_url", "html_url", "pull_request_url", "url"],
    "pr_actor_type": ["pr_actor_type", "provided_label", "agent", "agent_name", "provenance", "actor_type"],
    "agent_name": ["agent_name", "agent"],
    "base_ref": ["base_ref", "base.ref", "pr_metadata_snapshot.base_ref"],
    "base_sha": ["base_sha", "base.sha", "pr_metadata_snapshot.base_sha"],
    "head_sha": ["head_sha", "head.sha", "pr_metadata_snapshot.head_sha"],
    "commit_shas": ["commit_shas", "pr_commits", "commits", "pr_metadata_snapshot.commit_shas"],
    "fixture_repository_id": ["fixture_repository_id", "fixture_id"],
    "provenance_evidence": ["provenance_evidence", "provenance_bindings", "evidence"],
}
FIELDS = ("repository pr_number pr_url cohort pr_actor_type agent_name provenance_evidence created_at merged_at closed_at state base_ref base_sha head_sha merge_commit_sha commit_shas metadata_source metadata_collected_at local_repo_path target_ref initial_commit_shas fixture_repository_id is_synthetic synthetic_author_mapping author_mapping collection_gaps github_pr_author github_commit_metadata github_reported_commit_count commit_list_status review_collection_status sampling_reason source_snapshot_cutoff_utc metadata_accessed_at").split()
FIELDS += ['source_pr_key', 'aidev_pr_ids', 'aidev_source_snapshot', 'aidev_import_coverage', 'related_table_rows']
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _get(row, key):
    if key in row:
        return row[key]
    obj = row
    for part in key.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return None
        obj = obj[part]
    return obj


def _present(value):
    return value is not None and value != "" and value != []


def _shas(value):
    if not value:
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            value = re.split(r"[;,\s]+", value.strip())
    if not isinstance(value, list):
        value = [value] if isinstance(value, str) else []
    return list(dict.fromkeys(str(v.get("sha") or v.get("commit_sha") or "") if isinstance(v, dict) else str(v) for v in value if v))


def _json_array(stream):
    """Incremental JSON array reader; wrappers may expose rows/data/records/PRs."""
    decoder, buffer, eof = json.JSONDecoder(), "", False
    while not eof:
        chunk = stream.read(65536)
        if not chunk and buffer.strip():
            raise ValueError("Truncated JSON input or unsupported wrapper")
        buffer += chunk
        stripped = buffer.lstrip()
        if stripped.startswith("["):
            buffer = stripped[1:]
            break
        match = re.search(r'"(?:rows|data|records|pull_requests|Sources)"\s*:\s*\[', buffer)
        if match:
            buffer = buffer[match.end():]
            break
        if len(buffer) > 1048576:
            raise ValueError("JSON wrapper has no supported row array within 1 MiB")
        if not stripped:
            return
        try:
            value = decoder.decode(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            yield value
            return
        raise ValueError("JSON input must contain PR objects")
    while True:
        buffer = buffer.lstrip()
        if buffer.startswith(","):
            buffer = buffer[1:].lstrip()
        if buffer.startswith("]"):
            return
        try:
            item, consumed = decoder.raw_decode(buffer)
        except json.JSONDecodeError as exc:
            more = stream.read(65536)
            if not more:
                raise ValueError("Truncated or invalid JSON array") from exc
            buffer += more
            continue
        yield item
        buffer = buffer[consumed:]


def _rows(path, fmt):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        if fmt == "txt":
            for number, line in enumerate(stream, 1):
                if line.strip() and not line.lstrip().startswith('#'):
                    yield number, {"url": line.strip()}
        elif fmt == "csv":
            yield from enumerate(csv.DictReader(stream), 2)
        elif fmt == "jsonl":
            for number, line in enumerate(stream, 1):
                if line.strip():
                    try:
                        yield number, json.loads(line)
                    except json.JSONDecodeError:
                        yield number, {"__ingest_error__": "invalid_jsonl"}
        else:
            yield from enumerate(_json_array(stream), 1)


def ingest_records(input_path, column_mapping=None, format=None, limit=None):
    path = Path(input_path).resolve()
    fmt = format or path.suffix.lstrip(".").lower()
    if fmt == "aidev":
        fmt = "csv" if path.suffix.lower() == ".csv" else "jsonl" if path.suffix.lower() in {".jsonl", ".ndjson"} else "json"
    if fmt == "ndjson":
        fmt = "jsonl"
    if fmt not in {"csv", "jsonl", "json", "txt"}:
        raise ValueError("Supported formats: csv, jsonl, json, txt, aidev (JSON/CSV export)")
    if limit is not None and limit < 0:
        raise ValueError("limit must be nonnegative")
    mapping = column_mapping or {}
    if not isinstance(mapping, dict) or any(k not in FIELDS for k in mapping):
        raise ValueError("column_mapping must map canonical field names to input dotted paths")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            digest.update(block)
    records, gaps, columns, rows_read = {}, [], set(), 0
    if limit != 0:
        for row_num, raw in _rows(path, fmt):
            rows_read += 1
            if isinstance(raw, dict) and isinstance(raw.get("row"), dict):
                raw = raw["row"]
            if not isinstance(raw, dict) or "__ingest_error__" in raw:
                gaps.append({"stage": "ingest", "row": row_num, "error_type": "invalid_row", "reason": "Expected valid JSON object", "retryable": False})
                continue
            columns.update(raw)
            row = {}
            for field in FIELDS:
                paths = mapping.get(field, ALIASES.get(field, [field]))
                if isinstance(paths, str):
                    paths = [paths]
                row[field] = next((v for name in paths if _present(v := _get(raw, name))), None)
            if isinstance(row["repository"], dict):
                row["repository"] = row["repository"].get("full_name")
            parsed = urlparse(str(row["pr_url"] or ""))
            match = re.fullmatch(r"/([^/]+/[^/]+)/pull/(\d+)/?", parsed.path)
            if match and parsed.hostname == "github.com" and parsed.scheme == "https":
                row["repository"] = row["repository"] or match[1]
                # AIDev pr_id may be a global ID; the real URL's number wins.
                row["pr_number"] = int(match[2])
            if row["repository"] and str(row["repository"]).startswith("https://github.com/"):
                row["repository"] = str(row["repository"])[19:].removesuffix(".git").rstrip("/")
            if row["repository"] and not REPO_RE.fullmatch(str(row["repository"])):
                gaps.append({"stage": "ingest", "row": row_num, "error_type": "invalid_repository", "reason": "Expected owner/repo", "retryable": False})
                continue
            try:
                row["pr_number"] = int(row["pr_number"]) if row["pr_number"] is not None else None
            except (ValueError, TypeError):
                row["pr_number"] = None
            if row["pr_number"] is not None and row["pr_number"] <= 0:
                row["pr_number"] = None
            row["is_synthetic"] = row["is_synthetic"] is True or str(row["is_synthetic"]).lower() == "true"
            row["commit_shas"] = _shas(row["commit_shas"])
            row["initial_commit_shas"] = _shas(row["initial_commit_shas"])
            row["cohort"] = row["cohort"] or ("calibration_only" if row["is_synthetic"] else "primary_cohort")
            if row["cohort"] not in {"primary_cohort", "repair_enriched", "calibration_only"}:
                row["provided_cohort"] = row["cohort"]
                row["cohort"] = "primary_cohort"
            if row["is_synthetic"]:
                row["cohort"] = "calibration_only"
                row["repository"] = row["pr_number"] = row["pr_url"] = None
                row["fixture_repository_id"] = row["fixture_repository_id"] or "fixture-" + hashlib.sha256(str(row["local_repo_path"]).encode()).hexdigest()[:12]
            elif row["repository"] and row["pr_number"]:
                canonical_url = f"https://github.com/{row['repository']}/pull/{row['pr_number']}"
                if match and match[1].lower() != row["repository"].lower():
                    gaps.append({"stage": "ingest", "row": row_num, "error_type": "repository_url_mismatch", "reason": "Repository and PR URL disagree", "retryable": False})
                    continue
                row["pr_url"] = canonical_url
            elif not row["local_repo_path"]:
                gaps.append({"stage": "ingest", "row": row_num, "error_type": "missing_pr_identity", "reason": "No repository+PR or local repository", "retryable": False})
                continue
            if row["local_repo_path"]:
                row["local_repo_path"] = str(resolve_path(row["local_repo_path"], base=path.parent))
            row["pr_metadata_status"] = "provided" if row["repository"] and row["pr_number"] else "missing"
            row["provided_label"] = row["pr_actor_type"]
            row["verified_actor_type"] = "unknown"
            row["metadata_source"] = row["metadata_source"] or str(path)
            row["raw_records"] = [raw]
            row["source_rows"] = [{"path": str(path), "row": row_num}]
            key = (row["repository"], row["pr_number"]) if row["repository"] and row["pr_number"] else (row["fixture_repository_id"] or row["local_repo_path"], tuple(row["initial_commit_shas"] or row["commit_shas"]))
            if key in records:
                prev = records[key]
                for field in ("raw_records", "source_rows", "commit_shas", "initial_commit_shas"):
                    for item in row[field]:
                        if item not in prev[field]:
                            prev[field].append(item)
                for field, value in row.items():
                    if not _present(prev.get(field)) and _present(value):
                        prev[field] = value
            else:
                records[key] = row
            if limit is not None and len(records) >= limit:
                break
    schema = {"input_path": str(path), "input_sha256": digest.hexdigest(), "format": fmt, "column_mapping": mapping, "columns_observed": sorted(columns), "rows_read": rows_read, "unique_records": len(records), "limit": limit, "sample_selection": "input_order_before_log_detection", "streaming": True}
    return {"prs": list(records.values()), "gaps": gaps, "source_schema": schema}
