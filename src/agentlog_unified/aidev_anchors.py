"""Supplementary AIDev commit anchors; never extend initial PR commit membership."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path

from .aidev import SHA_RE, _digest, _json, _write

OUTPUTS = {"mining_commit_anchors.jsonl", "related_unverified_anchors.jsonl", "anchor_gaps.jsonl", "coverage.json"}
ELIGIBLE_EVENTS = {"merged", "reviewed", "head_ref_force_pushed", "committed"}
KNOWN_EVENTS = ELIGIBLE_EVENTS | {"referenced", "closed"}


def _validate_inputs(import_dir, source_dir):
    manifest_path = import_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("status") != "complete":
        raise ValueError("AIDev import must be complete")
    # Only the two consumed import artifacts need re-reading; normalized PR exports are untouched.
    hashes = {}
    for name in ("aidev.sqlite", "coverage.json"):
        hashes[name] = _digest(import_dir / name)
        if hashes[name] != manifest.get("outputs", {}).get(name):
            raise ValueError("AIDev import artifact changed")
    coverage = json.loads((import_dir / "coverage.json").read_text())
    snapshot = hashlib.sha256(_json(manifest["source_signature"]).encode()).hexdigest()
    if coverage.get("aidev_source_snapshot") != snapshot:
        raise ValueError("AIDev source snapshot mismatch")
    source = Path(source_dir or manifest["source_signature"]["source_dir"]).resolve()
    expected = {item["path"]: item for item in manifest["source_signature"]["inputs"]}
    tables = [item for item in coverage["tables"] if item["role"] in {"timeline", "review_comment"}]
    for item in tables:
        path = (source / item["path"]).resolve()
        if source not in path.parents or item["path"] not in expected:
            raise ValueError("Invalid source table path")
        if item["status"] != "complete" or item["sha256"] != expected[item["path"]]["sha256"]:
            raise ValueError("Supplement requires complete frozen anchor tables")
        if _digest(path) != item["sha256"]:
            raise ValueError("Frozen source table changed")
    signature = {"import_dir": str(import_dir), "import_hashes": hashes,
                 "source_dir": str(source), "aidev_source_snapshot": snapshot,
                 "source_tables": [{k: item[k] for k in ("table", "path", "sha256")} for item in tables],
                 "implementation_sha256": _digest(Path(__file__))}
    return source, coverage, tables, signature


def export_aidev_anchors(import_dir, output_dir, source_dir=None, *, dry_run=False, resume=False):
    """Export ignored structured SHA anchors into separate, provenance-neutral queues.

    Hash-verified existing PR relations are reused. No bodies, target repositories,
    network or main-import mutations are involved. Related-only anchors remain
    outside the mining input and every anchor remains outside initial membership.
    """
    import pyarrow.parquet as pq

    imported, output = Path(import_dir).resolve(), Path(output_dir).resolve()
    source, coverage, tables, signature = _validate_inputs(imported, source_dir)
    for protected in (imported, source):
        if output == protected or output in protected.parents or protected in output.parents:
            raise ValueError("Output must be separate from read-only input directories")
    if dry_run:
        return {"status": "dry_run", "exit_code": 0, "files_written": False,
                "source_signature": signature, "planned_outputs": sorted(OUTPUTS | {"manifest.json"})}
    if output.exists():
        manifest_path = output / "manifest.json"
        if not resume or not manifest_path.is_file():
            raise ValueError("Output already exists; use --resume or a new directory")
        previous = json.loads(manifest_path.read_text())
        if previous.get("status") != "complete" or previous.get("source_signature") != signature:
            raise ValueError("Cannot resume incomplete or changed supplement")
        if set(previous.get("outputs", {})) != OUTPUTS or any(
            not (output / name).is_file() or _digest(output / name) != digest
            for name, digest in previous["outputs"].items()
        ):
            raise ValueError("Cannot resume modified supplement outputs")
        return dict(json.loads((output / "coverage.json").read_text()), resumed=True)
    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)
    _write(output / "manifest.json", {"status": "running", "source_signature": signature})
    counts, kinds, gap_counts = Counter(), Counter(), Counter()
    grouped = {}
    try:
        # ponytail: aggregate only ignored anchors in memory; use SQLite grouping if future snapshots outgrow RAM.
        with sqlite3.connect((imported / "aidev.sqlite").as_uri() + "?mode=ro", uri=True) as db:
            db.execute("PRAGMA query_only=ON")
            existing = {(key, sha.lower()) for key, sha in db.execute("SELECT pr_key,sha FROM pr_commit_evidence")
                        if isinstance(sha, str) and SHA_RE.fullmatch(sha)}
            existing_prs = {key for key, _ in existing}
            with (output / "anchor_gaps.jsonl").open("w", encoding="utf-8") as gaps:
                for item in tables:
                    table, mapping = item["table"], item["column_mapping"]
                    parquet = pq.ParquetFile(source / item["path"])
                    names = parquet.schema_arrow.names
                    fields = {"commit_id": mapping.get("sha")}
                    if item["role"] == "review_comment":
                        fields["original_commit_id"] = "original_commit_id" if "original_commit_id" in names else None
                    event_column = "event" if "event" in names else None
                    columns = list(dict.fromkeys(value for value in [*fields.values(), event_column] if value))
                    links = dict(db.execute("SELECT row_number,pr_key FROM row_pr_links WHERE table_name=?", (table,)))
                    rownum = 0
                    for batch in parquet.iter_batches(batch_size=8192, columns=columns):
                        for raw in batch.to_pylist():
                            rownum += 1
                            counts["source_rows_read"] += 1
                            event = raw.get(event_column) if event_column else None
                            event = event if event in KNOWN_EVENTS else "unknown"
                            for canonical, field in fields.items():
                                if not field:
                                    continue
                                value = raw.get(field)
                                if value in (None, ""):
                                    counts["null_anchor_fields"] += 1
                                    continue
                                counts["nonnull_anchor_fields"] += 1
                                ref = {"table": table, "path": item["path"], "row": rownum,
                                       "column": field, "source_sha256": item["sha256"]}
                                key = links.get(rownum)
                                reason = "invalid_exact_sha" if not isinstance(value, str) or not SHA_RE.fullmatch(value) else "unresolved_or_ambiguous_pr_relation" if key is None else None
                                if reason:
                                    gap_counts[reason] += 1
                                    gaps.write(_json({"reason": reason, "source_refs": [ref],
                                        "aidev_source_snapshot": signature["aidev_source_snapshot"],
                                        "value_fingerprint": hashlib.sha256(_json(value).encode()).hexdigest()}) + "\n")
                                    continue
                                sha = value.lower()
                                if (key, sha) in existing:
                                    counts["anchor_fields_already_in_main_membership"] += 1
                                    continue
                                kind = f"aidev_timeline_{event}_anchor" if item["role"] == "timeline" else f"aidev_review_comment_{canonical}_anchor"
                                eligible = item["role"] == "review_comment" or event in ELIGIBLE_EVENTS
                                identity = (key, sha, kind)
                                grouped.setdefault(identity, {"eligible": eligible, "refs": []})["refs"].append(ref)
                                counts["new_anchor_source_references"] += 1
                    if rownum != item["rows_read"]:
                        raise ValueError("Frozen anchor table row count mismatch")
        pairs, eligible_pairs = set(), set()
        with (output / "mining_commit_anchors.jsonl").open("w", encoding="utf-8") as mining, (output / "related_unverified_anchors.jsonl").open("w", encoding="utf-8") as related:
            for (key, sha, kind), value in sorted(grouped.items()):
                repository, number = key.rsplit("#", 1)
                eligible = value["eligible"]
                statuses = ["related_commit_anchor", "initial_pr_membership_unverified", "actor_unknown",
                            "eligible_for_exact_commit_mining" if eligible else "related_reference_only"]
                row = {"dataset": "aidev", "repository": repository, "sha": sha,
                       "source_pr_key": key, "pr_number": int(number),
                       "pr_url": f"https://github.com/{repository}/pull/{number}",
                       "aidev_source_snapshot": signature["aidev_source_snapshot"],
                       "source_kind": kind, "source_refs": value["refs"], "context_statuses": statuses,
                       "source_context_id": hashlib.sha256(_json([signature["aidev_source_snapshot"], key, sha, kind]).encode()).hexdigest()}
                (mining if eligible else related).write(_json(row) + "\n")
                counts["mining_contexts" if eligible else "related_only_contexts"] += 1
                kinds[kind] += 1
                pairs.add((key, sha))
                if eligible:
                    eligible_pairs.add((key, sha))
        # Recheck consumed sources and import artifacts before sealing the completed manifest.
        if _validate_inputs(imported, source)[3] != signature:
            raise ValueError("Inputs changed during anchor export")
        newly_anchored = {key for key, _ in pairs} - existing_prs
        counts.update(new_unique_pr_sha_pairs=len(pairs),
                      new_unique_repository_sha=len({(key.rsplit("#", 1)[0], sha) for key, sha in pairs}),
                      mining_unique_pr_sha_pairs=len(eligible_pairs),
                      mining_unique_repository_sha=len({(key.rsplit("#", 1)[0], sha) for key, sha in eligible_pairs}),
                      newly_anchored_prs=len(newly_anchored),
                      remaining_prs_without_structured_anchor=coverage["counts"]["normalized_prs"] - len(existing_prs) - len(newly_anchored))
        report = {"status": "complete_with_gaps" if gap_counts else "complete", "exit_code": 2 if gap_counts else 0,
                  "complete": True, "resumed": False, "counts": dict(counts), "source_kind_counts": dict(kinds),
                  "gap_counts": dict(gap_counts), "aidev_source_snapshot": signature["aidev_source_snapshot"],
                  "main_import_counts": coverage["counts"],
                  "evidence_boundary": {"supplementary_related_commit_scope": True,
                      "initial_commit_membership_extended": False, "main_corpus_denominator_extended": False,
                      "repository_code_mined": False, "runtime_confirmed": False,
                      "agent_authorship_verified": False, "bodies_or_patches_read": False,
                      "network_accessed": False, "related_only_anchors_in_mining_input": False},
                  "paths": {name: str(output / name) for name in sorted(OUTPUTS)}}
        _write(output / "coverage.json", report)
        for name in OUTPUTS:
            (output / name).chmod(0o600)
        _write(output / "manifest.json", {"status": "complete", "source_signature": signature,
               "outputs": {name: _digest(output / name) for name in sorted(OUTPUTS)}})
        return report
    except (Exception, KeyboardInterrupt) as exc:
        _write(output / "manifest.json", {"status": "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed",
               "source_signature": signature, "error_type": type(exc).__name__,
               "recovery": "Preserve this directory; export into a new directory"})
        raise
