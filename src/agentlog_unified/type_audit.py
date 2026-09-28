"""Version-level type observations and evidence-bounded coverage denominators.

An occurrence is one observed log version, not one label and not one PR. Before,
after and snapshot references collapse per version. No output proves runtime safety.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath

from .detector import LANGUAGES
from .storage import canonical, stable_id
from .taxonomy import annotate_entity, taxonomy_catalog

OTHER_SOURCE_EXTENSIONS = {
    ".pyi", ".mts", ".cts", ".java", ".kt", ".kts", ".scala", ".go", ".rs",
    ".rb", ".php", ".cs", ".c", ".h", ".cc", ".cpp", ".hpp", ".cxx",
    ".swift", ".m", ".dart", ".ex", ".exs", ".sh", ".bash", ".zsh", ".ps1", ".lua", ".pl",
}


def _initial_shas(pr):
    shas = set(pr.get("commit_shas") or pr.get("initial_commit_shas") or
               ([pr["head_sha"]] if pr.get("head_sha") else []))
    if pr.get("merged_at") and pr.get("merge_commit_sha"):
        shas.add(pr["merge_commit_sha"])
    return shas


def _version_key(rid, sha, entity):
    return stable_id("type_log_version", rid, sha, entity.get("path"), entity.get("symbol"),
                     entity.get("identity"), entity.get("start_line"), entity.get("start_col", 0))


def _event_key(event):
    return (event.get("repository_id"), event.get("sha"), event.get("relation"), event.get("change_kind"),
            (event.get("before") or {}).get("identity"), (event.get("after") or {}).get("identity"),
            (event.get("before") or {}).get("path"), (event.get("after") or {}).get("path"))


def _unknown_review(value):
    unknown = value.get("unknown_type_review") or {}
    reasons = set(unknown.get("reasons", []))
    if any(label.get("evidence_status") == "carrier_candidate" for label in value.get("taxonomy_labels", [])):
        reasons.add("broad_carrier_requires_value_context")
    return {**unknown, "needs_review": bool(unknown.get("needs_review") or reasons or value.get("taxonomy_status") == "needs_review"), "reasons": sorted(reasons)}


def build_type_audit(*, prs=(), repositories=(), commits=(), file_changes=(), log_events=(),
                     log_entities=(), log_changes=(), followups=(), snapshots=(), coverage_gaps=(),
                     retrieval_audit=(), languages=None):
    """Derive tables from private machine records. Use redacted exporters on all outputs."""
    catalog = taxonomy_catalog()
    version = catalog["taxonomy_version"]
    prs_by = {p["id"]: p for p in prs}
    repos_by = {r["id"]: r for r in repositories}
    github_keys = {pid: (p.get("repository"), p.get("pr_number")) for pid, p in prs_by.items()
                   if p.get("repository") and p.get("pr_number")}
    initial_shas = {pid: _initial_shas(p) for pid, p in prs_by.items()}
    initial_by_event, cases_by_event = defaultdict(set), defaultdict(set)
    case_to_pr = {}
    for row in log_changes:
        eid = row.get("log_change_id")
        if eid and row.get("pr_id"):
            initial_by_event[eid].add(row["pr_id"])
            if row.get("case_id"):
                cases_by_event[eid].add(row["case_id"])
                case_to_pr[row["case_id"]] = row["pr_id"]
    follow_by_event = defaultdict(list)
    for row in followups:
        follow_by_event[_event_key(row)].append(row)
    observations = {}

    def observe(rid, sha, entity):
        oid = _version_key(rid, sha, entity)
        if oid not in observations:
            value = annotate_entity(entity)
            labels = value.get("taxonomy_labels", [])
            unknown = _unknown_review(value)
            observations[oid] = {
                "id": oid, "occurrence_id": oid, "unit": "distinct_observed_log_version",
                "taxonomy_version": version, "repository_id": rid, "snapshot_sha": sha,
                "path": entity.get("path"), "symbol": entity.get("symbol"), "identity": entity.get("identity"),
                "start_line": entity.get("start_line"), "end_line": entity.get("end_line"),
                "statement": entity.get("statement"), "parser_status": entity.get("parser_status"),
                "privacy_assessment": entity.get("privacy_assessment", "unknown"),
                "source_to_sink": entity.get("source_to_sink", []), "dependencies": entity.get("dependencies", []),
                "missing_evidence": entity.get("missing_evidence", []), "taxonomy_labels": labels,
                "taxonomy_status": value.get("taxonomy_status", "needs_review"),
                "unknown_type_review": unknown,
                "event_references": [], "snapshot_entity_ids": [], "initial_pr_ids": [],
                "tracked_followup_pr_ids": [], "initial_case_ids": [], "observation_scopes": [],
                "human_review_status": "pending", "runtime_confirmed": False, "new_type_status": "not_established",
            }
        return observations[oid]

    for event in log_events:
        eid, rid = event["id"], event["repository_id"]
        initial = set(initial_by_event[eid])
        initial.update(pid for pid in repos_by.get(rid, {}).get("pr_ids", [])
                       if event.get("sha") in initial_shas.get(pid, set()))
        follow = follow_by_event[_event_key(event)]
        follow_prs = {case_to_pr[f["case_id"]] for f in follow if f.get("case_id") in case_to_pr}
        for side in ("before", "after"):
            entity = event.get(side)
            if entity is None:
                continue
            sha = (event.get("comparison_before_sha") or event.get("parent_sha")) if side == "before" else event.get("sha")
            row = observe(rid, sha, entity)
            reference = {"event_id": eid, "side": side, "event_sha": event.get("sha"),
                         "change_kind": event.get("change_kind"), "relation": event.get("relation"),
                         "extraction_status": event.get("extraction_status", "unknown"),
                         "file_change_ids": event.get("file_change_ids", []), "initial_pr_ids": sorted(initial),
                         "tracked_followup_pr_ids": sorted(follow_prs), "followup_ids": sorted({f["id"] for f in follow})}
            if reference not in row["event_references"]:
                row["event_references"].append(reference)
            row["initial_pr_ids"] = sorted(set(row["initial_pr_ids"]) | initial)
            row["tracked_followup_pr_ids"] = sorted(set(row["tracked_followup_pr_ids"]) | follow_prs)
            row["initial_case_ids"] = sorted(set(row["initial_case_ids"]) | cases_by_event[eid])
            scopes = set(row["observation_scopes"])
            if initial:
                scopes.add("initial_pr_change")
            if follow:
                scopes.add("tracked_followup")
            if not initial and not follow:
                scopes.add("other_history_event")
            row["observation_scopes"] = sorted(scopes)
    for entity in log_entities:
        row = observe(entity["repository_id"], entity.get("snapshot_sha"), entity)
        if entity.get("id") and entity["id"] not in row["snapshot_entity_ids"]:
            row["snapshot_entity_ids"].append(entity["id"])
    for row in observations.values():
        if not row["event_references"]:
            row["observation_scopes"] = ["snapshot_only"]
        row["event_references"].sort(key=canonical)
        row["snapshot_entity_ids"].sort()
    occurrences = sorted(observations.values(), key=lambda r: r["id"])
    queue = [{**row, "queue_reason": "unresolved_type_or_value_context_not_a_new_type",
              "unclassified_sources": row["unknown_type_review"].get("unclassified_sources", [])}
             for row in occurrences if row["unknown_type_review"]["needs_review"]]

    types = {(c["category"], s["subtype"]): (c.get("label", c["category"]), s.get("label", s["subtype"]))
             for c in catalog["categories"] for s in c["subtypes"]}
    types.update({(c["category"], "__all__"): (c.get("label", c["category"]), None) for c in catalog["categories"]})
    groups = defaultdict(list)
    for row in occurrences:
        for category in {label["category"] for label in row["taxonomy_labels"]}:
            groups[(category, "__all__")].append(row)
        for key in {(label["category"], label["subtype"]) for label in row["taxonomy_labels"]}:
            groups[key].append(row)
            types.setdefault(key, key)
    summaries = []
    for (category, subtype), (category_label, subtype_label) in sorted(types.items()):
        rows = groups[(category, subtype)]
        refs = [ref for row in rows for ref in row["event_references"]]
        pids = {pid for row in rows for pid in row["initial_pr_ids"]}
        summaries.append({"taxonomy_version": version, "category": category, "category_label": category_label,
            "summary_level": "category" if subtype == "__all__" else "subtype",
            "subtype": None if subtype == "__all__" else subtype, "subtype_label": subtype_label, "log_version_count": len(rows),
            "log_version_denominator": len(occurrences), "distinct_event_count": len({r["event_id"] for r in refs}),
            "initial_event_count": len({r["event_id"] for r in refs if r["initial_pr_ids"]}),
            "tracked_followup_event_count": len({r["event_id"] for r in refs if r["followup_ids"]}),
            "initial_input_count": len(pids), "initial_github_pr_count": len({github_keys[p] for p in pids if p in github_keys}),
            "snapshot_only_version_count": sum(row["observation_scopes"] == ["snapshot_only"] for row in rows),
            "repository_count": len({r["repository_id"] for r in rows}), "human_review_status": "pending",
            "runtime_confirmed": False})
    coverage = _coverage(prs_by, repos_by, initial_shas, github_keys, commits, file_changes,
                         log_events, occurrences, snapshots, coverage_gaps, retrieval_audit, languages)
    denominators = {"distinct_observed_log_versions": len(occurrences), "distinct_log_events": len({e["id"] for e in log_events}),
                    "input_github_prs": len(set(github_keys.values())), "input_records": len(prs_by),
                    "initial_inputs_with_log_event_evidence": len({p for o in occurrences for p in o["initial_pr_ids"]})}
    return {"taxonomy_catalog": catalog, "type_occurrences": occurrences, "type_summary": summaries,
            "unknown_type_review_queue": queue, "pr_coverage_audit": coverage["inputs"],
            "code_coverage_audit": coverage,
            "type_summary_metadata": {"taxonomy_version": version, "denominators": denominators,
                "occurrence_unit": "repository + snapshot_sha + path + symbol + identity + source_position",
                "multi_label_policy": "One log version can have several types; category totals must not be added as a denominator.",
                "context_policy": "Before/after and snapshot references collapse per version. Initial PR, tracked followup, and other history contexts may overlap.",
                "scope": "All detected log event endpoints and stored snapshot entities, including deleted and dependency-only changes; no L3 filter.",
                "evidence_boundary": "Static observations, not verified leaks, prevalence, human confirmation, or new privacy types.",
                "summary": summaries}}


def _coverage(prs, repos, expected, github_keys, commits, changes, events, occurrences, snapshots, gaps, audits, languages):
    selected = {language.lower() for language in (languages or ["python", "javascript", "typescript", "go", "csharp"])}
    observed = {(c["repository_id"], c["sha"]) for c in commits}
    snapshot_map = {(s["repository_id"], s["sha"]): s for s in snapshots}
    inputs = []
    for pid, pr in sorted(prs.items()):
        repo_ids = {rid for rid, r in repos.items() if pid in r.get("pr_ids", [])}
        obtained = {sha for rid, sha in observed if rid in repo_ids and sha in expected[pid]}
        files = [c for c in changes if c.get("repository_id") in repo_ids and c.get("sha") in expected[pid]]
        paths = {c.get(k) for c in files for k in ("old_path", "new_path") if c.get(k)}
        supported = {p for p in paths if LANGUAGES.get(PurePosixPath(p).suffix.lower()) in selected}
        unsupported = sorted(p for p in paths - supported
                             if PurePosixPath(p).suffix.lower() in OTHER_SOURCE_EXTENSIONS | LANGUAGES.keys())
        initial_events = [e for e in events if e.get("repository_id") in repo_ids and e.get("sha") in expected[pid]]
        versions = [o for o in occurrences if pid in o["initial_pr_ids"]]
        available = {sha for (rid, sha), s in snapshot_map.items() if rid in repo_ids and sha in expected[pid]
                     and not s.get("whole_snapshot_unavailable")}
        unavailable_paths = sorted({path for (rid, sha), snapshot in snapshot_map.items()
                                    if rid in repo_ids and sha in expected[pid]
                                    for path in snapshot.get("unavailable_paths", [])})
        analyzed = bool(obtained and available and (supported or initial_events or not files))
        related_gaps = [g for g in gaps if g.get("repository_id") in repo_ids or
                        (pr.get("repository") and g.get("repository") == pr["repository"]) or g.get("pr_id") == pid]
        gap_kinds = sorted({g.get("error_type") or g.get("reason") or "unknown_gap" for g in related_gaps})
        lexical = [o for o in occurrences if o.get("parser_status") == "lexical_only" and
                   (pid in o["initial_pr_ids"] or (o["repository_id"] in repo_ids and o["snapshot_sha"] in expected[pid] and o["path"] in paths))]
        partial = bool(unsupported or lexical or related_gaps or unavailable_paths or
                       expected[pid] - obtained or expected[pid] - available or
                       any(c.get("extraction_status") not in {None, "ok"} for c in files))
        typed = any(o["taxonomy_labels"] for o in versions)
        unknown = any(o["unknown_type_review"]["needs_review"] for o in versions)
        inputs.append({"id": stable_id("type_input_coverage", pid), "pr_id": pid,
            "unit": "GitHub_PR" if pid in github_keys else "local_input", "repository": pr.get("repository"),
            "pr_number": pr.get("pr_number"), "repository_ids": sorted(repo_ids),
            "expected_initial_shas": sorted(expected[pid]), "git_evidence_shas": sorted(obtained),
            "missing_initial_shas": sorted(expected[pid] - obtained), "has_git_evidence": bool(obtained),
            "analyzed_in_supported_scope": analyzed, "analysis_snapshot_shas": sorted(available),
            "missing_analysis_shas": sorted(expected[pid] - available), "unavailable_snapshot_paths": unavailable_paths,
            "coverage_status": "not_analyzed" if not analyzed else "partial" if partial else "bounded_complete",
            "supported_changed_paths": sorted(supported), "unsupported_language_paths": unsupported,
            "lexical_fallback_version_count": len(lexical), "gap_types": gap_kinds,
            "budget_limited": any("budget" in k.lower() or "limit" in k.lower() for k in gap_kinds),
            "initial_log_event_ids": sorted({e["id"] for e in initial_events}),
            "initial_log_version_count": len(versions), "has_observed_type_labels": typed,
            "has_unknown_type_review": unknown,
            "no_log_behavior_change_observed": not initial_events if analyzed and not partial else None,
            "no_sensitive_evidence_observed": (not typed and not unknown) if analyzed and not partial and versions else None,
            "retrieval_audit_ids": sorted({a["id"] for a in audits if a.get("id") and a.get("repository_id") in repo_ids
                                            and (a.get("sha") in expected[pid] or a.get("file_change_id") in {f.get("change_id") for f in files})}),
            "interpretation": "Bounded static coverage only; missing/unexamined evidence is never a safety finding.",
            "human_review_status": "pending", "runtime_confirmed": False})
    github_inputs = [row for row in inputs if row["unit"] == "GitHub_PR"]
    checks = {
        "input_prs": lambda r: True,
        "prs_with_git_evidence": lambda r: r["has_git_evidence"],
        "prs_analyzed_in_supported_scope": lambda r: r["analyzed_in_supported_scope"],
        "prs_not_analyzed": lambda r: not r["analyzed_in_supported_scope"],
        "prs_with_unsupported_language": lambda r: bool(r["unsupported_language_paths"]),
        "prs_with_lexical_fallback": lambda r: bool(r["lexical_fallback_version_count"]),
        "prs_with_budget_gaps": lambda r: r["budget_limited"],
        "prs_with_no_observed_log_behavior_change": lambda r: r["no_log_behavior_change_observed"] is True,
        "prs_with_no_sensitive_evidence": lambda r: r["no_sensitive_evidence_observed"] is True,
        "prs_with_unknown_types": lambda r: r["has_unknown_type_review"],
    }
    metrics = [{"metric": name, "unit": "distinct_GitHub_PR", "count": len({(r["repository"], r["pr_number"]) for r in github_inputs if check(r)}),
                "denominator": len(set(github_keys.values())), "denominator_definition": "distinct ingested GitHub PRs; local inputs excluded"}
               for name, check in checks.items()]
    metrics.append({"metric": "local_inputs", "unit": "local_input", "count": len(inputs)-len(github_inputs),
                    "denominator": len(inputs), "denominator_definition": "all ingested input records"})
    return {"inputs": inputs, "metrics": metrics, "coverage_gap_count": len(gaps),
            "limitations": ["Coverage starts at successfully ingested input records; rejected input rows remain in coverage_gaps.",
                "Unsupported languages are identified from known source extensions; this is not a complete source-code census.",
                "PR metrics overlap and are not additive. Snapshot-only observations do not imply the PR changed those logs.",
                "No-log and no-sensitive-evidence flags require actual bounded analysis and no recorded coverage loss; null means unestablished.",
                "Known data gaps conservatively prevent repository-level negative claims; static completeness is not runtime safety."]}


def export_batch_types(db, output_dir):
    """Stream distinct changed-log versions from a batch checkpoint into public tables.

    SQLite orders the records; Python retains only one log version and small
    per-type counters/repository sets. Supplied commits do not imply whole-history
    or full-dataset analysis. Caller owns the database connection and batch lock.
    """
    import csv
    import json
    import os
    import tempfile
    from collections import Counter
    from contextlib import ExitStack
    from itertools import groupby
    from pathlib import Path

    from .storage import csv_cell, redact

    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    catalog = taxonomy_catalog()
    version = catalog["taxonomy_version"]
    types = {(c["category"], s["subtype"]): (c.get("label", c["category"]), s.get("label", s["subtype"]))
             for c in catalog["categories"] for s in c["subtypes"]}
    types.update({(c["category"], "__all__"): (c.get("label", c["category"]), None) for c in catalog["categories"]})
    counts, type_counts, queued_counts = Counter(), Counter(), Counter()
    repositories, observed_versions = defaultdict(set), set()
    scope = {"observation_scope": "dataset_commit_changes", "full_history_tracing_completed": False,
             "full_dataset_coverage_claim": False, "human_review_status": "pending", "runtime_confirmed": False,
             "new_type_status": "not_established"}
    fields = ["occurrence_id", "log_version_id", "repository", "snapshot_sha", "path", "symbol", "start_line", "end_line",
              "statement", "taxonomy_version", "taxonomy_labels", "taxonomy_status", "unknown_type_review", "unclassified_sources",
              "source_to_sink", "dependencies", "missing_evidence", "event_references", "observation_scope", "queue_reason",
              "human_review_status", "runtime_confirmed", "new_type_status"]
    filenames = ["type_occurrences.jsonl", "type_occurrences.csv", "type_summary.json", "type_summary.csv", "unknown_type_review_queue.jsonl", "unknown_type_review_queue.csv"]
    cursor = db.execute("""SELECT json_extract(data,'$.log_version_id') AS version_key,data FROM records
      WHERE kind='log_observations' ORDER BY version_key,repository,sha,id""")
    with tempfile.TemporaryDirectory(prefix=".batch-types-", dir=output) as temporary:
        temp = Path(temporary)
        with ExitStack() as stack:
            handles = {name: stack.enter_context(os.fdopen(os.open(temp / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8", newline="")) for name in filenames}
            queue_csv = csv.DictWriter(handles["unknown_type_review_queue.csv"], fieldnames=fields, extrasaction="ignore")
            queue_csv.writeheader()
            occurrence_fields = [field for field in fields if field not in {"queue_reason", "unclassified_sources"}]
            occurrence_csv = csv.DictWriter(handles["type_occurrences.csv"], fieldnames=occurrence_fields, extrasaction="ignore")
            occurrence_csv.writeheader()
            for oid, group in groupby(cursor, key=lambda row: row["version_key"]):
                if not isinstance(oid, str) or not oid:
                    raise ValueError("Batch log observation lacks log_version_id")
                occurrence, signature = None, None
                labels, refs, reasons, unknown_sources, metadata_seen = {}, {}, set(), set(), defaultdict(set)
                needs_review = False
                for stored in group:
                    record = json.loads(stored["data"])
                    entity = record.get("entity")
                    if not isinstance(entity, dict):
                        raise ValueError("Batch log observation lacks an entity object")
                    signature_now = (record.get("repository"), record.get("snapshot_sha"), *(entity.get(key) for key in ("path", "symbol", "identity", "start_line", "start_col", "end_line", "end_col")))
                    if signature is not None and signature_now != signature:
                        raise ValueError("Conflicting identity for batch log_version_id")
                    signature = signature_now
                    value = dict(entity) if "taxonomy_labels" in entity and "unknown_type_review" in entity else annotate_entity(entity)
                    observed_version = value.get("taxonomy_version") or version
                    observed_versions.add(observed_version)
                    unknown = _unknown_review(value)
                    reasons.update(unknown.get("reasons", []))
                    unknown_sources.update(unknown.get("unclassified_sources", []))
                    needs_review |= unknown["needs_review"]
                    if observed_version != version:
                        reasons.add("taxonomy_version_mismatch_requires_reanalysis")
                    if occurrence is None:
                        occurrence = {**value, **scope, "id": oid, "occurrence_id": oid, "log_version_id": oid,
                                      "unit": "distinct_observed_log_version", "repository": record.get("repository"),
                                      "snapshot_sha": record.get("snapshot_sha"), "taxonomy_version": observed_version}
                        for key in ("source_to_sink", "dependencies", "missing_evidence"):
                            occurrence[key] = []
                    for label in value.get("taxonomy_labels", []):
                        labels[canonical(label)] = label
                    reference = {key: record.get(key) for key in ("id", "sha", "parent_sha", "side", "snapshot_sha", "change_basis")}
                    refs[canonical(reference)] = reference
                    for key in ("source_to_sink", "dependencies", "missing_evidence"):
                        for value_item in value.get(key, []):
                            encoded = canonical(value_item)
                            if encoded not in metadata_seen[key]:
                                metadata_seen[key].add(encoded)
                                occurrence[key].append(value_item)
                    counts["source_log_observations"] += 1
                occurrence["taxonomy_labels"] = [labels[key] for key in sorted(labels)]
                occurrence["event_references"] = [refs[key] for key in sorted(refs)]
                occurrence["unknown_type_review"] = {"needs_review": bool(needs_review or reasons), "reasons": sorted(reasons), "unclassified_sources": sorted(unknown_sources)}
                occurrence["taxonomy_status"] = "needs_review" if occurrence["unknown_type_review"]["needs_review"] else "typed_candidate" if labels else "no_sensitive_evidence"
                counts["distinct_observed_log_versions"] += 1
                counts["distinct_observation_references"] += len(refs)
                public_occurrence = redact(occurrence)
                handles["type_occurrences.jsonl"].write(canonical(public_occurrence) + "\n")
                occurrence_csv.writerow({key: csv_cell(value) for key, value in public_occurrence.items() if key in occurrence_fields})
                queued = occurrence["unknown_type_review"]["needs_review"]
                if queued:
                    counts["unknown_type_review_count"] += 1
                    queued_row = {**occurrence, "queue_reason": "unresolved_type_or_value_context_not_a_new_type", "unclassified_sources": sorted(unknown_sources)}
                    public = redact(queued_row)
                    handles["unknown_type_review_queue.jsonl"].write(canonical(public) + "\n")
                    queue_csv.writerow({key: csv_cell(value) for key, value in public.items() if key in fields})
                keys = {(label["category"], label["subtype"]) for label in occurrence["taxonomy_labels"]}
                keys |= {(category, "__all__") for category, subtype in keys}
                for key in keys:
                    types.setdefault(key, (key[0], None if key[1] == "__all__" else key[1]))
                    type_counts[key] += 1
                    queued_counts[key] += int(queued)
                    repositories[key].add(occurrence["repository"])
            summary = [{**scope, "taxonomy_version": version, "category": category, "category_label": names[0],
                        "summary_level": "category" if subtype == "__all__" else "subtype", "subtype": None if subtype == "__all__" else subtype,
                        "subtype_label": names[1], "log_version_count": type_counts[(category, subtype)],
                        "log_version_denominator": counts["distinct_observed_log_versions"], "repository_count": len(repositories[(category, subtype)]),
                        "unknown_review_version_count": queued_counts[(category, subtype)]}
                       for (category, subtype), names in sorted(types.items())]
            metadata = {**scope, "taxonomy_version": version, "observed_taxonomy_versions": sorted(observed_versions),
                        "denominators": {key: counts[key] for key in ("source_log_observations", "distinct_observed_log_versions", "distinct_observation_references", "unknown_type_review_count")},
                        "occurrence_unit": "log_version_id; repeated parent/side observations collapse while references are retained",
                        "multi_label_policy": "One version may have several subtypes; category versions count once and category totals are not additive.",
                        "evidence_boundary": "Static versions observed in supplied commit changes, including deleted-side and one-hop dependency changes; no full-history, full-dataset, runtime, human confirmation or new-type claim.",
                        "summary": summary}
            handles["type_summary.json"].write(canonical(redact(metadata)) + "\n")
            writer = csv.DictWriter(handles["type_summary.csv"], fieldnames=list(summary[0]) if summary else ["category", "subtype", "log_version_count"])
            writer.writeheader()
            for row in summary:
                writer.writerow({key: csv_cell(value) for key, value in redact(row).items()})
        for name in filenames:
            os.replace(temp / name, output / name)
    return {**scope, **{key: counts[key] for key in ("source_log_observations", "distinct_observed_log_versions", "distinct_observation_references", "unknown_type_review_count")},
            "observed_category_count": sum(count > 0 for (category, subtype), count in type_counts.items() if subtype == "__all__"),
            "observed_subtype_count": sum(count > 0 for (category, subtype), count in type_counts.items() if subtype != "__all__"),
            "taxonomy_version": version, "paths": {name: str(output / name) for name in filenames}}
