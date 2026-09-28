"""Additive stage-three evidence collection. Never selects or retraces logs.

Inputs are the existing trace_logs exports. All input events survive, including
ambiguous, malformed and guard-blocked events. Remote access uses GET only.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "agent-log-motivation-1.1"
TYPES = ("prompt", "commit_message", "pr_description", "review_comment", "issue")
STATUSES = ("explicit", "inferred", "unknown", "conflicting")
LABELS = {"noise_control", "log_level", "diagnostics", "message_accuracy", "performance",
          "sensitive_information", "format_consistency", "requirements_change", "other", "unknown"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


def canonical(x):
    return json.dumps(x, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def digest(x):
    return hashlib.sha256((x if isinstance(x, str) else canonical(x)).encode()).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def rows(path):
    if not Path(path).exists():
        return
    with Path(path).open(encoding="utf-8-sig") as f:
        for number, line in enumerate(f, 1):
            if line.strip():
                yield number, json.loads(line)


def write_json(path, obj):
    Path(path).write_text(json.dumps(obj, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def table(out, name, records, fields):
    with (out / (name + ".jsonl")).open("w", encoding="utf-8") as f:
        for r in records:
            f.write(canonical(r) + "\n")
    keys = list(dict.fromkeys(fields + [k for r in records for k in r]))
    with (out / (name + ".csv")).open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in records:
            w.writerow({k: canonical(v) if isinstance(v, (list, dict)) else v for k, v in r.items()})


class EvidenceStore:
    def __init__(self):
        self.evidence = {}
        self.links = {}
        self.missing = []
        self.duplicate_attempts = 0

    def gap(self, event, source_type, reason, **details):
        self.missing.append({"event_id": event["event_id"], "source_type": source_type,
                             "reason": reason, **details})

    def add(self, event, source_type, source_id, text, *, local_path=None, url=None,
            timestamp=None, method, basis, relation="modification_context", **ids):
        if source_type not in TYPES:
            raise ValueError("invalid_source_type")
        if not isinstance(text, str) or not text.strip():
            self.gap(event, source_type, "empty_source_body", source_id=source_id)
            return None
        if not source_id or str(source_id) == "None" or not (local_path or url) or not basis:
            self.gap(event, source_type, "source_locator_or_identifier_or_basis_missing", source_id=source_id)
            return None
        # Different versions of one comment remain separate evidence rows.
        eid = digest([source_type, event["repository"].lower(), ids.get("source_subtype"), str(source_id), digest(text)])[:24]
        evidence = {"evidence_id": eid, "source_type": source_type, "source_id": str(source_id),
                    "repository": event["repository"], "source_url": url, "source_local_path": local_path,
                    "source_locators": [{"url": url, "local_path": local_path, "time": timestamp}],
                    "source_time": timestamp, "source_time_status": "available" if timestamp else "missing_in_source",
                    "content_sha256": digest(text), "text": text, "excerpt": text[:2000],
                    "excerpt_truncated": len(text) > 2000, **ids}
        if eid not in self.evidence:
            self.evidence[eid] = evidence
        else:
            locator = {"url": url, "local_path": local_path, "time": timestamp}
            if locator not in self.evidence[eid]["source_locators"]:
                self.evidence[eid]["source_locators"].append(locator)
            if url and not self.evidence[eid]["source_url"]:
                self.evidence[eid]["source_url"] = url
            if timestamp and not self.evidence[eid]["source_time"]:
                self.evidence[eid]["source_time"] = timestamp
                self.evidence[eid]["source_time_status"] = "available"
        linkid = digest([event["event_id"], eid, method, basis, relation])[:24]
        if linkid in self.links:
            self.duplicate_attempts += 1
        self.links[linkid] = {"link_id": linkid, "event_id": event["event_id"], "evidence_id": eid,
                             "source_type": source_type, "repository": event["repository"],
                             "modification_sha": event["modification_sha"], "file_path": event["file_path"],
                             "association_method": method, "association_basis": basis,
                             "relation": relation, **ids}
        return eid


def trace_rows(path):
    with Path(path).open(encoding="utf-8-sig") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("event_not_object")
                yield number, value
            except (ValueError, TypeError):
                yield number, {"_parse_error": "invalid_json_or_nonobject", "_raw_sha256": digest(line)}


def normalize_trace(run, guard):
    """Preserve original trace selection and identity, adding only an adapter view."""
    run = Path(run)
    data = run / "data" if (run / "data" / "followups.jsonl").exists() else run
    repos = {r["id"]: r for _, r in rows(data / "repositories.jsonl")}
    origins = {r.get("case_id", r.get("id")): r for _, r in rows(data / "log_changes.jsonl")}
    files = {r["id"]: r for _, r in rows(data / "file_changes.jsonl")}
    commits = {(r.get("repository_id"), r.get("sha")): r for _, r in rows(data / "commits.jsonl")}
    anchors = {(r.get("repository_id"), r.get("sha"), r.get("path")): r
               for _, r in rows(data / "log_source_anchors.jsonl")}
    events, details, gaps = [], {}, []
    for number, f in trace_rows(data / "followups.jsonl"):
        origin = origins.get(f.get("case_id"), {})
        repository = (repos.get(f.get("repository_id"), {}).get("repository") or f.get("repository")
                      or origin.get("repository") or "")
        before, after = f.get("before") or {}, f.get("after") or {}
        path = f.get("file_path") or after.get("path") or before.get("path") or ""
        # Each upstream row is retained, even if an upstream ID is duplicated.
        event_id = digest([str(data.resolve()), number, f.get("id")])[:24]
        e = {"event_id": event_id, "upstream_event_id": f.get("id"), "upstream_case_id": f.get("case_id"),
             "input_path": str((data / "followups.jsonl").resolve()), "input_row": number,
             "input_record_sha256": digest(f), "repository": repository,
             "modification_sha": f.get("followup_sha") or f.get("sha"), "parent_sha": f.get("parent_sha"),
             "introduction_sha": origin.get("intro_sha") or origin.get("sha"), "file_path": path,
             "old_path": before.get("path"), "new_path": after.get("path"),
             "upstream_confidence": f.get("behavior_confidence"), "phase": f.get("phase"),
             "stage1_log_ids": origin.get("stage1_log_ids", []), "stage1_attribution": origin.get("stage1_attribution", []),
             "upstream_attribution": {k: origin.get(k) for k in ("cohort", "log_change_actor_type", "provenance_confidence")},
             "change_kind": f.get("change_kind"), "change_relation": f.get("relation"), "guard_status": "unverified",
             "observed_change": None, "motive_status": "unknown", "motive_labels": ["unknown"]}
        reasons = [f["_parse_error"]] if f.get("_parse_error") else []
        if not REPO.fullmatch(repository) or not SHA.fullmatch(e["modification_sha"] or "") or not path:
            reasons.append("invalid_event_locator")
        if not origin:
            reasons.append("origin_record_missing")
        if e["introduction_sha"] == e["modification_sha"]:
            reasons.append("not_a_later_commit")
        relevant = [files[i] for i in f.get("file_change_ids", []) if i in files]
        if not relevant:
            reasons.append("historical_file_source_missing")
        for fc in relevant:
            if fc.get("sha") != e["modification_sha"] or fc.get("repository_id") != f.get("repository_id"):
                reasons.append("file_event_join_mismatch")
                continue
            for side, pkey in (("before", "old_path"), ("after", "new_path")):
                source = fc.get(side + "_source")
                if source is None:
                    log_entity = before if side == "before" else after
                    if log_entity and fc.get(pkey) == log_entity.get("path"):
                        reasons.append("historical_" + side + "_source_missing")
                    continue
                checked = guard.check(repository, fc.get(pkey) or path, source)
                if checked != "allowed":
                    reasons.append(checked)
        if not reasons:
            for entity, side, pkey in ((before, "before", "old_path"), (after, "after", "new_path")):
                if not entity:
                    continue
                matches = [fc for fc in relevant if fc.get(pkey) == entity.get("path")]
                valid = False
                for fc in matches:
                    lines = (fc.get(side + "_source") or "").splitlines()
                    start, end = entity.get("start_line"), entity.get("end_line")
                    if isinstance(start, int) and isinstance(end, int) and 1 <= start <= end <= len(lines):
                        valid |= bool(entity.get("statement") and entity["statement"].strip() in "\n".join(lines[start-1:end]))
                if not valid:
                    revision = e["parent_sha"] if side == "before" else e["modification_sha"]
                    anchor = anchors.get((f.get("repository_id"), revision, entity.get("path")))
                    if anchor:
                        source = anchor.get("source") or ""
                        raw = source.encode("utf-8")
                        integrity = (digest(source) == anchor.get("source_sha256") and
                                     hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == anchor.get("git_blob_id"))
                        checked = guard.check(repository, entity["path"], source)
                        if checked != "allowed": reasons.append(checked)
                        lines = source.splitlines()
                        start, end = entity.get("start_line"), entity.get("end_line")
                        valid = bool(integrity and checked == "allowed" and isinstance(start,int) and isinstance(end,int)
                                     and 1 <= start <= end <= len(lines) and entity.get("statement")
                                     and entity["statement"].strip() in "\n".join(lines[start-1:end]))
                        if valid:
                            e.setdefault("source_anchors", []).append({k: anchor[k] for k in
                                ("repository_id", "sha", "path", "source_sha256", "git_blob_id", "source_locator")})
                if not valid:
                    reasons.append("log_statement_anchor_mismatch")
            for fc in relevant:
                if fc.get("diff_target_sha") != e["modification_sha"] or fc.get("diff_basis_sha") != e["parent_sha"]:
                    reasons.append("diff_revision_mismatch")
        if not reasons:
            e["guard_status"] = "allowed"
            e["observed_change"] = {"kind": e["change_kind"], "before_statement": before.get("statement"),
                                    "after_statement": after.get("statement"), "before_level": before.get("level"),
                                    "after_level": after.get("level"), "before_lines": [before.get("start_line"), before.get("end_line")],
                                    "after_lines": [after.get("start_line"), after.get("end_line")],
                                    "description_basis": "unchanged_upstream_trace_event_not_motive"}
            e["diffs"] = [{"file_change_id": fc["id"], "old_path": fc.get("old_path"), "new_path": fc.get("new_path"),
                           "diff": fc.get("diff"), "diff_basis_sha": fc.get("diff_basis_sha"),
                           "diff_target_sha": fc.get("diff_target_sha")} for fc in relevant]
            details[event_id] = {"commit": commits.get((f.get("repository_id"), e["modification_sha"]), {}), "origin": origin}
        else:
            e["guard_status"] = "blocked_or_unverifiable"
            # Protected case identity is not exposed in the new development delivery.
            if any(r.startswith("guard_") for r in reasons):
                for key in ("repository", "modification_sha", "parent_sha", "introduction_sha", "file_path", "old_path", "new_path", "upstream_event_id", "upstream_case_id"):
                    e[key] = None
            gaps.extend({"event_id": event_id, "source_type": "event", "reason": r} for r in sorted(set(reasons)))
        events.append(e)
    ledger_path = data / "candidate_ledger.jsonl"
    initial_count = sum(1 for _ in rows(ledger_path)) if ledger_path.exists() else len(origins)
    changed_initials = len({i for e in events for i in e.get("stage1_log_ids", [])}) if ledger_path.exists() else len({r["upstream_case_id"] for r in events})
    return events, details, gaps, {"stage1_rows": initial_count, "trace_origin_rows": len(origins), "stage2_event_rows": len(events),
        "stage2_unique_upstream_ids": len({r["upstream_event_id"] for r in events}),
        "stage2_initial_logs_with_changes": changed_initials,
        "selection_unchanged": True, "data_directory": str(data.resolve())}


def inline_relation(event, comment):
    """Same PR/path is context; exact revision plus intersecting lines is direct."""
    obs = event.get("observed_change") or {}
    cpath = comment.get("path")
    if cpath not in {event.get("file_path"), event.get("old_path"), event.get("new_path")}:
        return "pr_context"
    for original in (False, True):
        prefix = "original_" if original else ""
        revision = comment.get(prefix + "commit_id")
        line = comment.get(prefix + "line")
        side = comment.get("side")
        # LEFT lines belong to the PR comparison baseline, which is not proven
        # to be this event's parent. Keep those comments as file context.
        if side != "RIGHT":
            continue
        start = (comment.get(prefix + "start_line") or line) if comment.get("start_side") == side else line
        if not isinstance(line, int) or not isinstance(start, int) or start > line:
            continue
        if revision == event.get("parent_sha") and cpath == (event.get("old_path") or event.get("file_path")):
            a, b = obs.get("before_lines", [None, None])
            if isinstance(a, int) and isinstance(b, int) and max(a, start) <= min(b, line):
                return "direct_parent_log_location"
        if revision != event["modification_sha"] or cpath != (event.get("new_path") or event.get("file_path")):
            continue
        a, b = obs.get("after_lines", [None, None])
        if isinstance(a, int) and isinstance(b, int) and max(a, start) <= min(b, line):
            return "direct_log_location"
    return "same_file_context"


def issue_refs(text, default_repo):
    """References in a verified source are edges, not a keyword search."""
    found = set()
    pattern = r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/issues/(\d+)"
    found.update((m[1], int(m[2])) for m in re.finditer(pattern, text or ""))
    found.update((m[1], int(m[2])) for m in re.finditer(r"(?<![\w/])([\w.-]+/[\w.-]+)#(\d+)", text or ""))
    # Skip code spans, full URLs and cross-repository fragments for bare references.
    cleaned = re.sub(r"https?://\S+|[\w.-]+/[\w.-]+#\d+|`[^`]*`", " ", text or "")
    found.update((default_repo, int(m[1])) for m in re.finditer(r"(?<![\w/#])#(\d+)\b", cleaned))
    return sorted(found)


class Collector:
    def __init__(self, client, store):
        self.client, self.store = client, store
        self.cache = {}
        self._indexed_cache_files = set()
        self._page_locators = {}

    def request(self, event, kind, endpoint, paginated=False):
        key = endpoint, paginated
        if key not in self.cache:
            start = len(self.client.failures)
            value = self.client.paginate(endpoint) if paginated else self.client.get(endpoint)
            self.cache[key] = value, self.client.failures[start:]
        value, failures = self.cache[key]
        for failure in failures:
            self.store.gap(event, kind, failure.get("error_type", "fetch_failed"), endpoint=endpoint,
                           detail=failure.get("reason"), failure_receipt=failure.get("failure_receipt"))
        return value

    def collect(self, e, detail):
        s, repo, sha = self.store, e["repository"], e["modification_sha"]
        base = f"repos/{repo}"
        local = detail.get("commit") or {}
        message = local.get("message")
        if message:
            s.add(e, "commit_message", sha, message, local_path=str(Path(e["input_path"]).parent / "commits.jsonl"),
                  timestamp=local.get("committer_date"), method="local_exact_repository_sha",
                  basis={"repository_id": local.get("repository_id"), "sha": sha})
        remote = self.request(e, "commit_message", base + f"/commits/{sha}")
        if isinstance(remote, dict) and remote.get("sha") == sha:
            c = remote.get("commit") or {}
            if c.get("message"):
                s.add(e, "commit_message", sha, c["message"], url=remote.get("html_url"),
                      local_path=self.cache_path(base + f"/commits/{sha}"), timestamp=(c.get("committer") or {}).get("date"),
                      method="github_exact_repository_sha", basis={"response_sha": sha})
                message = c["message"]
        elif remote is not None:
            s.gap(e, "commit_message", "response_sha_mismatch")
        prs = self.request(e, "pr_description", base + f"/commits/{sha}/pulls", True) or []
        if not prs:
            s.gap(e, "pr_description", "no_pr_returned_for_exact_commit", endpoint=base + f"/commits/{sha}/pulls")
            s.gap(e, "review_comment", "pr_association_unavailable")
        references = [(r, n, {"from": "commit_message", "sha": sha}) for r, n in issue_refs(message, repo)]
        for pr in prs:
            number = pr.get("number")
            if not isinstance(number, int) or (pr.get("base", {}).get("repo") or {}).get("full_name", "").lower() != repo.lower():
                s.gap(e, "pr_description", "invalid_or_cross_repository_pr_association")
                continue
            endpoint = base + f"/pulls/{number}"
            full = self.request(e, "pr_description", endpoint)
            if not isinstance(full, dict) or full.get("number") != number:
                continue
            basis = {"chain": [e["event_id"], sha, f"{repo}#{number}"],
                     "association_endpoint": base + f"/commits/{sha}/pulls", "pr_number": number}
            text = (full.get("title") or "") + "\n\n" + (full.get("body") or "")
            s.add(e, "pr_description", f"{repo}#{number}", text, url=full.get("html_url"),
                  local_path=self.cache_path(endpoint), timestamp=full.get("updated_at") or full.get("created_at"),
                  method="exact_commit_pr_association", basis=basis, pr_number=number)
            references.extend((r, n, {**basis, "from": "pr_description"}) for r, n in issue_refs(full.get("body"), repo))
            for suffix, subtype in (("comments", "inline"), ("reviews", "review_summary")):
                comments = self.request(e, "review_comment", endpoint + "/" + suffix, True) or []
                for comment in comments:
                    relation = inline_relation(e, comment) if subtype == "inline" else "pr_context"
                    s.add(e, "review_comment", str(comment.get("id")), comment.get("body"),
                          url=comment.get("html_url"), local_path=self.cache_path(endpoint + "/" + suffix, True, comment.get("id")),
                          timestamp=comment.get("updated_at") or comment.get("submitted_at") or comment.get("created_at"),
                          method="commit_pr_review" , relation=relation,
                          basis={**basis, "review_path": comment.get("path"), "review_commit_id": comment.get("commit_id"),
                                 "original_commit_id": comment.get("original_commit_id"), "line": comment.get("line"),
                                 "original_line": comment.get("original_line"), "side": comment.get("side"),
                                 "start_line": comment.get("start_line"), "original_start_line": comment.get("original_start_line"),
                                 "start_side": comment.get("start_side"),
                                 "direct_location_policy": "explicit_RIGHT_side_matching_blob_revision_path_and_lines;LEFT_baseline_unverified_context_only",
                                 "in_reply_to_id": comment.get("in_reply_to_id"),
                                 "diff_hunk": comment.get("diff_hunk")},
                          pr_number=number, comment_id=comment.get("id"), reply_to_comment_id=comment.get("in_reply_to_id"), source_subtype=subtype)
                    references.extend((r, n, {**basis, "from": subtype, "comment_id": comment.get("id")})
                                      for r, n in issue_refs(comment.get("body"), repo))
            conversation = self.request(e, "review_comment", base + f"/issues/{number}/comments", True) or []
            for comment in conversation:
                s.add(e, "review_comment", str(comment.get("id")), comment.get("body"), url=comment.get("html_url"),
                      local_path=self.cache_path(base + f"/issues/{number}/comments", True, comment.get("id")), timestamp=comment.get("created_at"),
                      method="commit_pr_conversation", basis=basis, relation="pr_context", pr_number=number,
                      comment_id=comment.get("id"), source_subtype="pr_conversation")
                references.extend((r, n, {**basis, "from": "pr_conversation", "comment_id": comment.get("id")})
                                  for r, n in issue_refs(comment.get("body"), repo))
        if not references:
            s.gap(e, "issue", "no_explicit_issue_reference_in_available_modification_sources")
        for issue_repo, number, origin in references:
            endpoint = f"repos/{issue_repo}/issues/{number}"
            issue = self.request(e, "issue", endpoint)
            if not isinstance(issue, dict) or issue.get("number") != number:
                continue
            if issue.get("pull_request"):
                s.gap(e, "issue", "reference_is_pull_request_not_issue", referenced_repository=issue_repo, number=number)
                continue
            basis = {"chain": [e["event_id"], sha, origin, f"{issue_repo}#{number}"],
                     "reference_semantics": "explicit_reference_not_automatically_a_causal_or_closing_link"}
            s.add(e, "issue", f"{issue_repo}#{number}", (issue.get("title") or "") + "\n\n" + (issue.get("body") or ""),
                  url=issue.get("html_url"), local_path=self.cache_path(endpoint), timestamp=issue.get("updated_at"),
                  method="explicit_reference_from_modification_source", basis=basis, relation="linked_issue_context",
                  issue_number=number, issue_repository=issue_repo, source_subtype="body")
            for comment in self.request(e, "issue", endpoint + "/comments", True) or []:
                s.add(e, "issue", f"{issue_repo}#{number}/comment/{comment.get('id')}", comment.get("body"),
                      url=comment.get("html_url"), local_path=self.cache_path(endpoint + "/comments", True, comment.get("id")),
                      timestamp=comment.get("updated_at") or comment.get("created_at"),
                      method="linked_issue_discussion", basis=basis, relation="linked_issue_context",
                      issue_number=number, issue_repository=issue_repo, comment_id=comment.get("id"), source_subtype="discussion")

    def cache_path(self, endpoint, paginated=False, source_id=None):
        url = self.client._url(endpoint + ("?per_page=100" if paginated else ""))
        p = self.client.cache_dir / (digest(url) + ".json")
        if not paginated:
            return str(p.resolve()) if p.exists() else None
        # A comment from page 2 must not point at a page-1 cache. Verify ID in
        # the actual response page; canonical remote URLs remain independent.
        prefix = self.client._url(endpoint)
        key = prefix, source_id
        if key in self._page_locators:
            return self._page_locators[key]
        for candidate in self.client.cache_dir.glob("*.json"):
            if candidate in self._indexed_cache_files:
                continue
            saved = json.loads(candidate.read_text(encoding="utf-8"))
            data = saved.get("data")
            if isinstance(data, list):
                page_endpoint = saved.get("url", "").split("?", 1)[0]
                for row in data:
                    if isinstance(row, dict) and row.get("id") is not None:
                        self._page_locators.setdefault((page_endpoint, row["id"]), str(candidate.resolve()))
            self._indexed_cache_files.add(candidate)
        return self._page_locators.get(key)


def collect_prompts(events, frozen, store):
    """Only user conversational turns tied by repo+commit+checkpoint+session.

    Such prompts are context. Checkpoint membership alone does not assert that
    the user requested this particular log edit, nor a particular execution order.
    """
    if not events:
        return
    if not frozen or not all((Path(frozen) / (n + ".parquet")).exists() for n in ("commits", "checkpoints", "conversations")):
        for e in events:
            store.gap(e, "prompt", "local_swechat_tables_unavailable")
        return
    import pyarrow.parquet as pq
    frozen = Path(frozen)
    lookup = defaultdict(list)
    for e in events:
        lookup[(e["repository"].lower(), e["modification_sha"])].append(e)
    cps = {}
    for b in pq.ParquetFile(frozen / "checkpoints.parquet").iter_batches(columns=["repo_id", "checkpoint_pk", "session_pks", "commit_shas"]):
        for r in b.to_pylist():
            try:
                sessions = json.loads(r.get("session_pks") or "[]")
                shas = json.loads(r.get("commit_shas") or "[]")
                if not isinstance(sessions, list) or not isinstance(shas, list):
                    continue
                cps[(r["repo_id"].lower(), r["checkpoint_pk"])] = (set(sessions), set(shas))
            except (TypeError, ValueError, AttributeError):
                continue
    links = defaultdict(list)
    row_number = 0
    for b in pq.ParquetFile(frozen / "commits.parquet").iter_batches(columns=["repo_id", "commit_sha", "checkpoint_pk", "commit_message", "commit_date"]):
        for r in b.to_pylist():
            row_number += 1
            for e in lookup.get(((r.get("repo_id") or "").lower(), r.get("commit_sha")), []):
                cp = r.get("checkpoint_pk")
                membership = cps.get((e["repository"].lower(), cp))
                message_basis = {"commits_source_row": row_number, "commit_sha": e["modification_sha"],
                                 "repository": e["repository"], "checkpoint_required_for_this_commit_message": False}
                store.add(e, "commit_message", e["modification_sha"], r.get("commit_message"),
                          local_path=str((frozen / "commits.parquet").resolve()), timestamp=r.get("commit_date"),
                          method="parquet_exact_repository_sha", basis=message_basis)
                if not membership or e["modification_sha"] not in membership[1]:
                    store.gap(e, "prompt", "checkpoint_membership_missing_or_conflicting", source_row=row_number)
                    continue
                basis = {"commits_source_row": row_number, "checkpoint_pk": cp,
                         "commit_sha": e["modification_sha"], "repository": e["repository"]}
                for session in membership[0]:
                    links[(e["repository"].lower(), cp, session)].append((e, basis))
    seen = set()
    if links:
        columns = ["repo_id", "session_id", "checkpoint_pk", "turn_id", "role", "is_conversational", "content", "timestamp", "tool_name", "turn_number"]
        source_row = 0
        for b in pq.ParquetFile(frozen / "conversations.parquet").iter_batches(batch_size=4096, columns=columns):
            for r in b.to_pylist():
                source_row += 1
                candidates = links.get(((r.get("repo_id") or "").lower(), r.get("checkpoint_pk"), r.get("session_id")), [])
                if not candidates or r.get("role") != "user" or r.get("is_conversational") is not True or r.get("tool_name"):
                    continue
                for e, basis in candidates:
                    eid = store.add(e, "prompt", r.get("turn_id") or f"conversations:{source_row}", r.get("content"),
                              local_path=str((frozen / "conversations.parquet").resolve()), timestamp=r.get("timestamp"),
                              method="commit_checkpoint_session_user_turn", basis={**basis, "conversation_source_row": source_row,
                              "role": r["role"], "turn_number": r.get("turn_number"), "execution_order_verified": False},
                              relation="modification_session_context", session_id=r.get("session_id"), checkpoint_pk=r.get("checkpoint_pk"),
                              turn_id=r.get("turn_id"))
                    if eid:
                        seen.add(e["event_id"])
    for e in events:
        if e["event_id"] not in seen:
            store.gap(e, "prompt", "no_verified_modification_checkpoint_user_prompt")


def judge(event, store, annotations):
    """Motive claims are evidence-reviewed annotations, never code-change labels.

    Explicit requires an exact source quotation and a stated correspondence to
    this edit. Inferred retains a separate inference. Opposing claims share an
    explicit claim_key; different compatible labels do not imply a conflict.
    """
    associated = {r["evidence_id"]: r for r in store.links.values() if r["event_id"] == event["event_id"]}
    accepted = []
    for a in annotations:
        if a.get("event_id") != event["event_id"]:
            continue
        try:
            if a.get("status") not in {"explicit", "inferred"} or not a.get("annotator") or not a.get("rationale"):
                raise ValueError("claim_metadata_missing")
            labels = a.get("labels", [])
            if not labels or not set(labels) <= LABELS or "unknown" in labels:
                raise ValueError("invalid_claim_labels")
            refs = a.get("citations") or []
            if not refs:
                raise ValueError("claim_requires_citations")
            for ref in refs:
                ev = store.evidence.get(ref.get("evidence_id"))
                link = associated.get(ref.get("evidence_id"))
                quote = ref.get("quote")
                if not ev or not link or not isinstance(quote, str) or not quote or quote not in ev["text"]:
                    raise ValueError("invalid_or_unassociated_quote")
                if link["relation"] == "introduction_background":
                    raise ValueError("introduction_prompt_not_modification_purpose")
            if a["status"] == "explicit":
                if not a.get("stated_purpose") or not a.get("direct_correspondence"):
                    raise ValueError("explicit_requires_stated_purpose_and_edit_correspondence")
                anchor = a.get("target_anchor") or {}
                obs = event.get("observed_change") or {}
                side = anchor.get("side")
                span = obs.get("before_lines" if side == "before" else "after_lines", [None, None])
                if (side not in {"before", "after"} or anchor.get("modification_sha") != event.get("modification_sha")
                    or anchor.get("file_path") != event.get("old_path" if side == "before" else "new_path")
                    or not isinstance(anchor.get("line"), int) or not all(isinstance(v, int) for v in span)
                    or not span[0] <= anchor["line"] <= span[1]):
                    raise ValueError("explicit_requires_exact_target_anchor")
                if event.get("upstream_confidence") != "supported":
                    raise ValueError("ambiguous_lineage_cannot_support_explicit_motive")
            elif not a.get("inference"):
                raise ValueError("inferred_requires_separate_inference")
            if not a.get("claim_key") or a.get("position") not in {"supports", "opposes"}:
                raise ValueError("claim_key_and_position_required")
            accepted.append(a)
        except ValueError as ex:
            store.gap(event, "annotation", str(ex), annotation_sha256=digest(a))
    opposites = defaultdict(lambda: defaultdict(set))
    for a in accepted:
        opposites[a["claim_key"]][a["position"]].update(r["evidence_id"] for r in a["citations"])
    conflict = any(v.get("supports") and v.get("opposes") and v["supports"] != v["opposes"] for v in opposites.values())
    annotation_disagreement = any(v.get("supports") and v.get("opposes") and v["supports"] == v["opposes"] for v in opposites.values())
    if annotation_disagreement:
        store.gap(event, "annotation", "opposed_interpretations_of_same_evidence_require_adjudication")
    status = "conflicting" if conflict else "unknown" if annotation_disagreement else "explicit" if any(a["status"] == "explicit" for a in accepted) else "inferred" if accepted else "unknown"
    return {"event_id": event["event_id"], "motive_status": status,
            "motive_labels": sorted({v for a in accepted for v in a["labels"]}) or ["unknown"],
            "stated_purposes": [a["stated_purpose"] for a in accepted if a["status"] == "explicit"],
            "inferences": [a["inference"] for a in accepted if a["status"] == "inferred"],
            "claims": accepted, "unknown_reason": ("opposed_interpretations_of_same_evidence" if annotation_disagreement else
                "available_context_not_yet_validated_for_this_log" if not accepted and associated else
                "no_available_modification_evidence" if not accepted else None),
            "purpose_review_status": "accepted_evidence_review" if accepted and not annotation_disagreement else "not_established",
            "human_validated": False, "annotation_disagreement": annotation_disagreement}


def export(out, events, store, annotations, upstream, provenance):
    out = Path(out)
    conclusions = [judge(e, store, annotations) for e in events]
    by_id = {r["event_id"]: r for r in conclusions}
    for e in events:
        e.update({k: v for k, v in by_id[e["event_id"]].items() if k in {"motive_status", "motive_labels"}})
    joined = []
    event_map = {e['event_id']: e for e in events}
    join_fields = ('parent_sha', 'introduction_sha', 'old_path', 'new_path', 'observed_change', 'change_kind', 'change_relation',
                   'upstream_confidence', 'stage1_log_ids', 'stage1_attribution', 'input_path', 'input_row', 'guard_status')
    for link in store.links.values():
        evidence = store.evidence[link["evidence_id"]]
        event_values = {k: event_map[link['event_id']].get(k) for k in join_fields}
        joined.append({**evidence, **event_values, **link, "motive_status": by_id[link["event_id"]]["motive_status"]})
    linked_ids = {r["event_id"] for r in joined}
    for e in events:
        if e["event_id"] not in linked_ids:
            joined.append({**{k: e.get(k) for k in join_fields}, "event_id": e["event_id"], "evidence_id": None, "repository": e.get("repository"),
                           "modification_sha": e.get("modification_sha"), "file_path": e.get("file_path"), "motive_status": "unknown"})
    tables = {"log_modifications": (events, ["event_id", "repository", "modification_sha", "file_path", "observed_change", "motive_status"]),
              "motive_evidence": (list(store.evidence.values()), ["evidence_id", "source_type", "source_id", "source_url", "source_local_path", "source_time", "excerpt"]),
              "evidence_links": (list(store.links.values()), ["event_id", "evidence_id", "modification_sha", "file_path", "association_method", "association_basis"]),
              "motives": (conclusions, ["event_id", "motive_status", "motive_labels", "stated_purposes", "inferences", "claims"]),
              "modifications_with_evidence": (joined, ["event_id", "evidence_id", "source_type", "motive_status"]),
              "unresolved_records": (store.missing, ["event_id", "source_type", "reason"])}
    for name, (records, fields) in tables.items():
        table(out, name, records, fields)
    coverage = {}
    for kind in TYPES:
        n = len({r["event_id"] for r in store.links.values() if r["source_type"] == kind})
        coverage[kind] = {"events": n, "denominator": None if upstream.get("status") == "missing_stage2_artifact" else len(events), "fraction": n / len(events) if events else None}
    summary = {"version": VERSION, "upstream": upstream, "events": len(events), "evidence_rows": len(store.evidence),
               "links": len(store.links), "source_coverage": coverage,
               "motive_distribution": {s: sum(r["motive_status"] == s for r in conclusions) if upstream.get("status") != "missing_stage2_artifact" else None for s in STATUSES},
               "population_event_count": None if upstream.get("status") == "missing_stage2_artifact" else len(events),
               "delivery_status": "awaiting_upstream_stage2" if upstream.get("status") == "missing_stage2_artifact" else "processed_with_recorded_gaps",
               "duplicate_evidence_link_attempts_collapsed": store.duplicate_attempts,
               "missing_reason_counts": dict(Counter(r["reason"] for r in store.missing)),
               "purpose_classification": "evidence_review_annotations_only_no_keyword_or_code_only_motive_inference",
               "zero_denominator_policy": "null_not_zero_percent", "provenance": provenance}
    write_json(out / "summary.json", summary)
    validation = {"status": "PASS", "all_upstream_events_preserved": len(events) == upstream["stage2_event_rows"] if upstream.get("stage2_event_rows") is not None else None,
                  "event_ids_unique": len({r["event_id"] for r in events}) == len(events),
                  "conclusions_cover_all_events": set(by_id) == {e["event_id"] for e in events},
                  "join_preserves_events_without_evidence": {r["event_id"] for r in joined} == set(by_id),
                  "evidence_foreign_keys_resolve": all(r["evidence_id"] in store.evidence for r in store.links.values()),
                  "original_stages_modified": False, "scope": "schema_only_missing_upstream" if upstream.get("stage2_event_rows") is None else "executed_input_reconciliation"}
    if not all(v for k, v in validation.items() if isinstance(v, bool) and k != "original_stages_modified"):
        validation["status"] = "FAIL"
    write_json(out / "validation.json", validation)
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--trace-run", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--online", action="store_true")
    ap.add_argument("--annotations", type=Path)
    ap.add_argument("--swechat-frozen", type=Path)
    ap.add_argument("--external-cache", type=Path, help="Reuse existing success cache; new downloads still go to the new output directory.")
    ap.add_argument("--external-failures", type=Path, help="Read actual connector failure receipts alongside successful evidence caches.")
    ap.add_argument("--missing-stage2", action="store_true")
    args = ap.parse_args()
    if bool(args.trace_run) == bool(args.missing_stage2):
        ap.error("provide exactly one of --trace-run or --missing-stage2")
    # Never overwrite a run, even an interrupted new one.
    args.output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(args.workspace / "src"))
    from agentlog_unified.github_client import GitHubClient
    from align_swechat_agent_logs import Guard
    s = EvidenceStore()
    provenance = {"executed_at": datetime.now(timezone.utc).isoformat(), "script_sha256": file_hash(__file__),
                  "remote_operations": "GET_only", "online_requested": args.online}
    if args.missing_stage2:
        events, details = [], {}
        upstream = {"status": "missing_stage2_artifact", "stage1_rows": None, "stage2_event_rows": None,
                    "stage2_initial_logs_with_changes": None, "selection_unchanged": True}
        s.missing.append({"event_id": None, "source_type": "upstream", "reason": "swechat_subsequent_modification_artifact_not_found",
                          "detail": "Empty output is a schema-only delivery, not evidence of no later log changes."})
    else:
        guard = Guard(args.workspace)
        events, details, gaps, upstream = normalize_trace(args.trace_run, guard)
        s.missing.extend(gaps)
        provenance["guard_calls"] = dict(guard.calls)
        data = Path(upstream["data_directory"])
        hashes = {str(p.resolve()): file_hash(p) for n in ("followups", "log_changes", "file_changes", "commits", "repositories", "log_source_anchors", "candidate_ledger")
                  for p in [data / (n + ".jsonl")] if p.exists()}
        provenance["input_sha256"] = hashes
        provenance["implementation_dependencies"] = {str(p.resolve()): file_hash(p) for p in (
            args.workspace / "scripts/align_swechat_agent_logs.py",
            args.workspace / "src/agentlog_unified/github_client.py",
            args.workspace / "research/swechat-independent-holdout-20260914/guard.py")}
        if args.swechat_frozen:
            dependencies = args.workspace / "outputs/swechat_log_alignment_20260921/dependencies"
            if dependencies.exists():
                sys.path.insert(0, str(dependencies))
        if args.external_cache:
            import shutil
            if not args.external_cache.is_dir():
                raise ValueError("external_cache_not_found")
            shutil.copytree(args.external_cache, args.output / "external_cache")
        client = GitHubClient(args.output / "external_cache", offline=not args.online, timeout=20, max_retries=0)
        if args.external_cache or args.external_failures:
            from swechat_connector_cache import install as install_connector_cache
            failure_dir = None
            if args.external_failures:
                import shutil
                failure_dir = args.output / "external_failures"
                shutil.copytree(args.external_failures, failure_dir)
                provenance["external_failure_receipts"] = {p.name: file_hash(p) for p in failure_dir.glob("*.json")}
            install_connector_cache(client, failure_dir)
            provenance["connector_adapter_sha256"] = file_hash(Path(__file__).with_name("swechat_connector_cache.py"))
        collector = Collector(client, s)
        for index, e in enumerate(events, 1):
            if e["guard_status"] == "allowed":
                collector.collect(e, details[e["event_id"]])
            if index % 100 == 0 or index == len(events):
                write_json(args.output / "progress.json", {"stage": "remote_evidence", "processed_events": index,
                    "total_events": len(events), "evidence_rows": len(s.evidence), "requests": client.requests})
        write_json(args.output / "progress.json", {"stage": "modification_prompts", "total_events": len(events)})
        collect_prompts([e for e in events if e["guard_status"] == "allowed"], args.swechat_frozen, s)
        if any(file_hash(p) != h for p, h in hashes.items()):
            raise ValueError("upstream_input_changed_during_run")
        provenance["inputs_unchanged"] = True
        provenance["github_requests"] = client.requests
        provenance["external_cache_artifacts"] = {p.name: file_hash(p) for p in client.cache_dir.glob("*.json")}
    if args.annotations:
        provenance["annotation_input"] = {"path": str(args.annotations.resolve()), "sha256": file_hash(args.annotations)}
    annotations = [r for _, r in rows(args.annotations)] if args.annotations else []
    summary = export(args.output, events, s, annotations, upstream, provenance)
    write_json(args.output / "progress.json", {"stage": "complete", "events": len(events)})
    write_json(args.output / "manifest.json", {"version": VERSION, "artifacts": {p.name: file_hash(p) for p in args.output.iterdir() if p.is_file()}})
    print(canonical({k: summary[k] for k in ("events", "evidence_rows", "links", "motive_distribution")}))


if __name__ == "__main__":
    main()
