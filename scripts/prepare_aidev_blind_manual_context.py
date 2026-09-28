#!/usr/bin/env python3
"""Build redacted source windows for the blinded AIDev manual-audit queue."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

if __package__:
    from .analyze_aidev_primary_queue import file_sha256
    from .screen_github_agent_logs import _raw_diff_files, redact_excerpt
else:
    from analyze_aidev_primary_queue import file_sha256
    from screen_github_agent_logs import _raw_diff_files, redact_excerpt


BASE = Path("outputs/aidev_combined_482_preanalysis_audit_v1")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def new_file_lines(section: str) -> list[tuple[int, str, str]]:
    output, line_number = [], 0
    for raw in section.splitlines():
        match = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
        if match:
            line_number = int(match.group(1))
        elif raw.startswith("+") and not raw.startswith("+++"):
            output.append((line_number, "+", raw[1:]))
            line_number += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        elif raw.startswith(" "):
            output.append((line_number, " ", raw[1:]))
            line_number += 1
    return output


def source_window(diff: str, filename: str, target: int, radius: int) -> tuple[str, str]:
    for path, section in _raw_diff_files(diff):
        if path != filename:
            continue
        lines = new_file_lines(section)
        matches = [index for index, (line, marker, _) in enumerate(lines) if line == target and marker == "+"]
        if not matches:
            return "TARGET_LINE_NOT_FOUND", ""
        index = matches[0]
        chosen = lines[max(0, index - radius): min(len(lines), index + radius + 1)]
        text = "\n".join(f"{line:>6} {marker} {redact_excerpt(value)}" for line, marker, value in chosen)
        return "FOUND_REDACTED_WINDOW", text
    return "FILE_NOT_FOUND", ""


def run(args: argparse.Namespace) -> dict:
    queue, key = read_csv(args.queue), read_csv(args.key)
    if len(queue) != 200 or {row["audit_id"] for row in queue} != {row["audit_id"] for row in key}:
        raise ValueError("queue/key mismatch")
    key_by_id = {row["audit_id"]: row for row in key}
    paths = {}
    for row in read_csv(args.original_pairs):
        for side in ("agent", "human"):
            paths[("original_300", row["pair_id"], side)] = row[f"{side}_diff_path"]
    for row in read_csv(args.expansion_pairs):
        for side in ("agent", "human"):
            paths[("expansion_182", row["candidate_id"], side)] = row[f"{side}_diff_path"]

    output, counts = [], {}
    for row in queue:
        hidden = key_by_id[row["audit_id"]]
        path = Path(paths[(hidden["cohort"], hidden["pair_id"], hidden["provenance"])])
        status, context = source_window(path.read_text(encoding="utf-8", errors="replace"), row["file"], int(row["line"]), args.radius)
        counts[status] = counts.get(status, 0) + 1
        output.append({**row, "context_status": status, "redacted_context": context or row["log_text_redacted"]})

    with args.output.open("w", encoding="utf-8", newline="") as handle:
        fields = tuple(output[0])
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(output)
    manifest = {
        "status": "BLINDED_CONTEXT_READY", "rows": len(output), "context_status": counts,
        "contains_provenance_fields": False, "radius": args.radius,
        "script_sha256": file_sha256(Path(__file__)),
        "input_sha256": {str(path): file_sha256(path) for path in (args.queue, args.key, args.original_pairs, args.expansion_pairs)},
        "output_sha256": file_sha256(args.output),
    }
    args.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--queue", type=Path, default=BASE / "manual_audit_queue.csv")
    result.add_argument("--key", type=Path, default=BASE / "manual_audit_key.csv")
    result.add_argument("--original-pairs", type=Path, default=Path("outputs/aidev_observational_primary_300/matched_pairs.csv"))
    result.add_argument("--expansion-pairs", type=Path, default=Path("outputs/aidev_expansion_structured_evidence_v1/matched_pairs.csv"))
    result.add_argument("--output", type=Path, default=BASE / "manual_audit_context_queue.csv")
    result.add_argument("--manifest", type=Path, default=BASE / "manual_audit_context_manifest.json")
    result.add_argument("--radius", type=int, default=6)
    return result


if __name__ == "__main__":
    print(json.dumps(run(parser().parse_args()), ensure_ascii=False, sort_keys=True))
