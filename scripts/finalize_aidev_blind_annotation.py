#!/usr/bin/env python3
"""Validate and freeze the provenance-blind 200-row semantic annotation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


LABEL_FIELDS = (
    "manual_is_executable_log",
    "manual_is_application_observability",
    "manual_sensitive_decision",
    "manual_sensitive_type",
    "manual_false_positive_reason",
    "reviewer_notes",
)
FORBIDDEN_FIELDS = {"provenance", "repo", "pr_key", "pair_id", "cohort", "risk_features"}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    queue = read_csv(args.queue)
    labels = read_csv(args.labels)
    if len(queue) != 200 or len(labels) != 200:
        raise ValueError(f"expected 200 queue and label rows; got {len(queue)} and {len(labels)}")
    if FORBIDDEN_FIELDS & (set(queue[0]) | set(labels[0])):
        raise ValueError("provenance-bearing fields are forbidden in blind annotation inputs")

    by_id = {row["audit_id"]: row for row in labels}
    queue_ids = [row["audit_id"] for row in queue]
    if len(by_id) != 200 or set(queue_ids) != set(by_id):
        raise ValueError("audit IDs are duplicated or labels do not cover the queue exactly")

    output_rows = []
    for row in queue:
        label = by_id[row["audit_id"]]
        if label["manual_is_executable_log"] not in {"YES", "NO"}:
            raise ValueError(f"invalid executable label for {row['audit_id']}")
        if label["manual_is_application_observability"] not in {"YES", "NO"}:
            raise ValueError(f"invalid observability label for {row['audit_id']}")
        decision = label["manual_sensitive_decision"]
        if decision not in {"YES", "CARRIER", "NO", "UNCLEAR"}:
            raise ValueError(f"invalid sensitive decision for {row['audit_id']}")
        if decision in {"YES", "CARRIER"} and not label["manual_sensitive_type"]:
            raise ValueError(f"missing sensitive type for {row['audit_id']}")
        if decision == "NO" and label["manual_sensitive_type"]:
            raise ValueError(f"NO row has a sensitive type for {row['audit_id']}")
        if label["manual_is_executable_log"] == "NO" and label["manual_is_application_observability"] != "NO":
            raise ValueError(f"non-log row marked as application observability for {row['audit_id']}")
        merged = dict(row)
        merged.update({field: label[field] for field in LABEL_FIELDS})
        output_rows.append(merged)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fields = list(queue[0])
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(output_rows)

    decisions = Counter(row["manual_sensitive_decision"] for row in output_rows)
    types = Counter()
    for row in output_rows:
        for item in filter(None, row["manual_sensitive_type"].split("+")):
            types[item] += 1
    manifest = {
        "version": "aidev_blind_semantic_annotation_v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "reviewer": "single Codex semantic reviewer",
        "independence_protocol": "source provenance hidden during all row-level decisions",
        "provenance_unblinded": False,
        "inter_rater_reliability": "NOT_AVAILABLE_SINGLE_REVIEWER",
        "n_rows": len(output_rows),
        "n_executable_logs": sum(row["manual_is_executable_log"] == "YES" for row in output_rows),
        "n_application_observability": sum(row["manual_is_application_observability"] == "YES" for row in output_rows),
        "sensitive_decision_counts": dict(sorted(decisions.items())),
        "sensitive_type_mentions": dict(sorted(types.items())),
        "queue_sha256": sha256(args.queue),
        "labels_sha256": sha256(args.labels),
        "frozen_output_sha256": sha256(args.output),
        "contains_provenance_fields": False,
        "claim_boundary": "YES means a static sensitive-value candidate; CARRIER is a possible opaque carrier; neither proves runtime leakage",
    }
    args.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
