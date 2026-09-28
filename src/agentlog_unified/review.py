"""Explicit user-supplied reviews, separate from machine findings and append-only.

CSV columns match reports/human_review_template.csv. Decisions are static review
labels, never runtime evidence. Reviewer names are supplied by the importer;
this local workflow does not authenticate their identity.
"""
from __future__ import annotations

import csv
import hashlib
import io
from datetime import datetime, timezone
from pathlib import Path

from .storage import canonical, stable_id

REVIEW_DECISIONS = frozenset({
    "privacy_candidate", "not_privacy_candidate", "needs_context", "out_of_scope",
})
REVIEW_FIELDS = (
    "case_id", "human_review_status", "human_review_decision", "reviewer", "evidence_notes",
)


def _ensure_schema(store) -> None:
    # Separate from replaceable machine records: re-assessment cannot erase reviews.
    store.db.execute("""CREATE TABLE IF NOT EXISTS review_history (
        case_id TEXT NOT NULL, revision INTEGER NOT NULL, data TEXT NOT NULL,
        PRIMARY KEY(case_id, revision)
    )""")


def _digest(candidate: dict) -> str:
    return hashlib.sha256(canonical(candidate).encode("utf-8")).hexdigest()


def review_history(store, case_id: str | None = None) -> list[dict]:
    """Return every accepted revision, ordered by case and revision, for export."""
    import json

    _ensure_schema(store)
    query = "SELECT data FROM review_history"
    params = ()
    if case_id is not None:
        query += " WHERE case_id=?"
        params = (case_id,)
    return [json.loads(row[0]) for row in store.db.execute(query + " ORDER BY case_id,revision", params)]


def review_annotations(store) -> dict[str, dict]:
    """Latest labels for a nested ``human_review`` export; never merge into machines.

    A changed or removed machine candidate keeps its review history. The stale flag
    prevents that persistence from implying the changed evidence was re-reviewed.
    """
    candidates = {row["case_id"]: row for row in store.rows("candidates")}
    latest = {row["case_id"]: row for row in review_history(store)}
    for case_id, row in latest.items():
        row["candidate_present"] = case_id in candidates
        row["stale_against_current_candidate"] = (
            case_id not in candidates or row["candidate_digest"] != _digest(candidates[case_id])
        )
    return latest


def import_reviews(store, path: str | Path, reviewer: str | None = None) -> dict:
    """Validate a CSV batch before appending reviews. Any invalid row rejects it all.

    An untouched pending row is a no-op, including on a previously reviewed case.
    Repeat imports with identical current content and candidate evidence are no-ops.
    Unknown nonempty columns are rejected so no uploaded machine field is applied.
    Error messages intentionally omit cell values and source excerpts.
    """
    path = Path(path)
    result = {"imported": 0, "unchanged": 0, "skipped_pending": 0,
              "duplicate_rows": 0, "errors": [], "atomic": True}
    errors = result["errors"]
    try:
        raw = path.read_bytes()
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""), strict=True)
        headers = reader.fieldnames or []
        if len(headers) != len(set(headers)):
            errors.append({"line": 1, "code": "duplicate_headers"})
            return result
        if not {"case_id", "human_review_decision"}.issubset(headers):
            errors.append({"line": 1, "code": "missing_required_headers"})
            return result
        rows = [(reader.line_num, row) for row in reader]
    except (OSError, UnicodeError, csv.Error):
        errors.append({"line": None, "code": "unreadable_review_csv"})
        return result

    candidates = {row["case_id"]: row for row in store.rows("candidates")}
    prepared = {}
    for line, row in rows:
        if None in row or any(value is None for value in row.values()):
            errors.append({"line": line, "code": "malformed_row"})
            continue
        row = {key: value.strip() for key, value in row.items()}
        if any(row[key] for key in row.keys() - set(REVIEW_FIELDS)):
            errors.append({"line": line, "code": "non_review_field_not_allowed"})
            continue
        case_id = row.get("case_id", "")
        status = row.get("human_review_status", "")
        decision = row.get("human_review_decision", "")
        notes = row.get("evidence_notes", "")
        identity = row.get("reviewer", "") or (reviewer or "").strip()
        if case_id not in candidates:
            errors.append({"line": line, "code": "unknown_case_id"})
        elif status not in {"", "pending", "reviewed"}:
            errors.append({"line": line, "code": "invalid_review_status"})
        elif status in {"", "pending"} and not decision and not notes:
            result["skipped_pending"] += 1
        elif decision not in REVIEW_DECISIONS:
            errors.append({"line": line, "code": "explicit_valid_decision_required"})
        elif status == "pending":
            errors.append({"line": line, "code": "pending_with_decision"})
        elif not identity:
            errors.append({"line": line, "code": "reviewer_required"})
        else:
            payload = {"case_id": case_id, "human_review_status": "reviewed",
                       "human_review_decision": decision, "reviewer": identity,
                       "evidence_notes": notes, "candidate_digest": _digest(candidates[case_id])}
            if case_id in prepared:
                if prepared[case_id][0] == payload:
                    result["duplicate_rows"] += 1
                else:
                    errors.append({"line": line, "code": "conflicting_duplicate_case"})
            else:
                prepared[case_id] = (payload, line)
    if errors:
        return result

    _ensure_schema(store)
    source_hash = hashlib.sha256(raw).hexdigest()
    with store.db:
        latest = {row["case_id"]: row for row in review_history(store)}
        for case_id, (payload, line) in prepared.items():
            previous = latest.get(case_id)
            if previous and all(previous[key] == value for key, value in payload.items()):
                result["unchanged"] += 1
                continue
            revision = previous["review_revision"] + 1 if previous else 1
            annotation = {
                **payload, "id": stable_id("human_review", case_id, revision, payload),
                "review_revision": revision,
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "previous_review_id": previous["id"] if previous else None,
                "review_origin": "user_supplied_review",
                "source_file_sha256": source_hash, "source_line": line,
            }
            store.db.execute("INSERT INTO review_history VALUES(?,?,?)",
                             (case_id, revision, canonical(annotation)))
            result["imported"] += 1
    return result
