"""Guarded, offline alignment of SWE-chat commit log changes and agent edits.

No business code is executed. Exact content correspondence is evidence, not
proof that a tool succeeded or that one named session is the exclusive author.
"""
from __future__ import annotations

import argparse
import ast
import csv
import difflib
import gzip
import hashlib
import importlib.util
import io
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "swechat-log-alignment-v1.1"


def sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def json_write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def git_path(value):
    if value.startswith('"'):
        try:
            value = ast.literal_eval(value)
            try:
                value = value.encode("latin1").decode("utf8")
            except UnicodeError:
                pass
        except (ValueError, SyntaxError):
            return None
    else:
        value = value.split("\t", 1)[0]
    if value == "/dev/null":
        return None
    return value[2:] if value.startswith(("a/", "b/")) else value


def parse_patch(raw):
    """Parse ordinary git unified diffs; reject malformed/combined hunks."""
    files = {}
    file = hunk = None
    for line in (raw or "").splitlines():
        if line.startswith("diff --git "):
            file = {"old_path": None, "path": None, "hunks": [], "errors": []}
            hunk = None
        elif file is None:
            continue
        elif line.startswith("@@"):
            m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not m:
                file["errors"].append("unsupported_hunk_header")
                hunk = None
                continue
            a, b, c, d = m.groups()
            hunk = {"old_start": int(a), "old_count": int(b or 1),
                    "new_start": int(c), "new_count": int(d or 1), "lines": []}
            file["hunks"].append(hunk)
        elif hunk is not None and line[:1] in {" ", "+", "-"}:
            hunk["lines"].append((line[0], line[1:]))
        elif hunk is not None and line.startswith("\\ No newline"):
            continue
        elif line.startswith("--- "):
            file["old_path"] = git_path(line[4:])
        elif line.startswith("+++ "):
            file["path"] = git_path(line[4:])
            if file["path"] in files:
                file["errors"].append("duplicate_file_patch")
            files[file["path"]] = file
    for f in files.values():
        for h in f["hunks"]:
            if sum(op != "+" for op, _ in h["lines"]) != h["old_count"] or sum(op != "-" for op, _ in h["lines"]) != h["new_count"]:
                f["errors"].append("hunk_count_mismatch")
    return files


def changed_spans(before, after, offset=0):
    """Character-level spans in postimage; deletions retain zero-width anchors."""
    if len(before) + len(after) > 200_000:
        raise ValueError("alignment_budget_exceeded")
    return [(offset + c, offset + d) for tag, a, b, c, d in
            difflib.SequenceMatcher(None, before, after, autojunk=False).get_opcodes() if tag != "equal"]


def overlaps(span, start, end):
    a, b = span
    return start < a < end if a == b else a < end and b > start


def spans_intersect(a, b):
    if a[0] == a[1] and b[0] == b[1]:
        return a[0] == b[0]
    if a[0] == a[1]:
        return b[0] <= a[0] < b[1]
    if b[0] == b[1]:
        return a[0] <= b[0] < a[1]
    return max(a[0], b[0]) < min(a[1], b[1])


def restore_parent(after, patch, expected_counts=None):
    """Validate every hunk against postimage and reconstruct its parent image.

    We operate on logical lines: original CRLF and final-newline differences
    are not a claim of byte-identical Git blob reconstruction.
    """
    if patch["errors"] or not patch["hunks"]:
        raise ValueError("invalid_or_empty_patch")
    source = after.splitlines()
    old = []
    cursor = 0
    added = removed = 0
    edits = []
    offsets = [0]
    for line in after.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    for index, h in enumerate(patch["hunks"]):
        pos = h["new_start"] - (1 if h["new_count"] else 0)
        oldpos = h["old_start"] - (1 if h["old_count"] else 0)
        if pos < cursor or pos > len(source):
            raise ValueError("invalid_hunk_order")
        old.extend(source[cursor:pos])
        if len(old) != oldpos:
            raise ValueError("old_new_coordinates_disagree")
        pre = [text for op, text in h["lines"] if op != "+"]
        post = [text for op, text in h["lines"] if op != "-"]
        if source[pos:pos + len(post)] != post:
            raise ValueError("patch_postimage_mismatch")
        added += sum(op == "+" for op, _ in h["lines"])
        removed += sum(op == "-" for op, _ in h["lines"])
        # Each contiguous change block is bounded by actual context lines.
        newpos, oldline = pos, oldpos
        block_old, block_new = [], []
        block_pos, block_oldpos = newpos, oldline
        def flush():
            if not block_old and not block_new:
                return
            newtext = "\n".join(block_new) + ("\n" if block_new else "")
            oldtext = "\n".join(block_old) + ("\n" if block_old else "")
            offset = offsets[min(block_pos, len(offsets) - 1)]
            # after is normalized to LF by the caller.
            spans = changed_spans(oldtext, newtext, offset)
            edits.append({"hunk": index, "old_line_start": block_oldpos + 1,
                          "old_line_end": block_oldpos + len(block_old),
                          "new_line_start": block_pos + 1,
                          "new_line_end": block_pos + len(block_new), "spans": spans})
        for op, text in h["lines"]:
            if op == " ":
                flush()
                block_old, block_new = [], []
                newpos += 1
                oldline += 1
                block_pos, block_oldpos = newpos, oldline
            elif op == "-":
                block_old.append(text)
                oldline += 1
            else:
                block_new.append(text)
                newpos += 1
        flush()
        old.extend(pre)
        cursor = pos + len(post)
    old.extend(source[cursor:])
    if expected_counts is None:
        raise ValueError("missing_numstat_completeness_check")
    if (added, removed) != tuple(expected_counts):
        raise ValueError("patch_numstat_mismatch")
    if patch["old_path"] is None and old:
        raise ValueError("new_file_has_nonempty_parent")
    return "\n".join(old) + ("\n" if old else ""), edits


def occurrences(source, needle):
    if not needle:
        return []
    out, pos = [], 0
    while len(out) < 3:
        pos = source.find(needle, pos)
        if pos < 0:
            break
        out.append(pos)
        pos += 1
    return out


def structured_tool_patch(tool, after):
    raw = tool.get("structured_patch")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            parts = [f for f in parse_patch(raw).values() if f["path"]]
            if len(parts) != 1:
                return None
            part = parts[0]
            counts = tuple(sum(op == sign for h in part["hunks"] for op, _ in h["lines"]) for sign in ("+", "-"))
            return restore_parent(after, part, counts)
    if isinstance(raw, dict):
        raw = raw.get("hunks")
    if not isinstance(raw, list) or not raw:
        return None
    hunks = []
    for h in raw:
        if not isinstance(h, dict) or not all(k in h for k in ("oldStart", "oldLines", "newStart", "newLines", "lines")):
            return None
        lines = h["lines"]
        if not isinstance(lines, list) or any(not isinstance(x, str) or x[:1] not in {" ", "+", "-"} for x in lines):
            return None
        old_count, new_count = int(h["oldLines"]), int(h["newLines"])
        payload = [(x[0], x[1:]) for x in lines]
        if sum(op != "+" for op, _ in payload) != old_count or sum(op != "-" for op, _ in payload) != new_count:
            raise ValueError("structured_tool_hunk_count_mismatch")
        hunks.append({"old_start": int(h["oldStart"]), "new_start": int(h["newStart"]),
                      "old_count": old_count, "new_count": new_count, "lines": payload})
    part = {"old_path": "tool-preimage", "path": "tool-postimage", "hunks": hunks, "errors": []}
    counts = tuple(sum(op == sign for h in hunks for op, _ in h["lines"]) for sign in ("+", "-"))
    return restore_parent(after, part, counts)


def tool_alignment(tool, before, after, start, end, new_file=False):
    """Only changed tool characters overlapping the log can support an edit."""
    prepared = tool.get("_structured_alignment")
    if "_structured_alignment" not in tool and not tool.get("_structured_preimage_disallowed"):
        try:
            reconstructed = structured_tool_patch(tool, after)
        except (ValueError, TypeError):
            reconstructed = None
        if reconstructed:
            preimage, blocks = reconstructed
            prepared = {"exact_preimage": preimage.splitlines() == before.splitlines(),
                        "spans": [span for b in blocks for span in b["spans"]],
                        "structured_patch_sha256": sha(json.dumps(tool["structured_patch"], sort_keys=True)),
                        "reconstructed_preimage_sha256": sha(preimage)}
    if prepared:
        touched = [span for span in prepared["spans"] if overlaps(span, start, end)]
        if touched:
            return {"status": "exact_structured_patch_supported" if prepared["exact_preimage"] else "structured_patch_postimage_supported",
                    "changed_log_spans": touched,
                    "structured_patch_sha256": prepared["structured_patch_sha256"],
                    "reconstructed_preimage_sha256": prepared["reconstructed_preimage_sha256"]}
    if tool.get("_unverified_preimage"):
        return {"status": "tool_preimage_not_in_guarded_source_versions"}
    old, new = tool.get("old_string"), tool.get("new_string")
    if isinstance(old, str) and isinstance(new, str) and old != new:
        old, new = old.replace("\r\n", "\n"), new.replace("\r\n", "\n")
        if not new and old and len(occurrences(before, old)) == 1 and before.replace(old, "", 1) == after:
            p = before.index(old)
            if overlaps((p, p), start, end):
                return {"status": "exact_edit_supported", "postimage_offset": p,
                        "preimage_offset": p, "changed_log_spans": [(p, p)],
                        "old_string_sha256": sha(old), "new_string_sha256": sha(new)}
        positions = occurrences(after, new)
        if len(positions) != 1:
            return {"status": "ambiguous_or_missing_postimage"}
        p = positions[0]
        spans = changed_spans(old, new, p)
        touched = [x for x in spans if overlaps(x, start, end)]
        if not touched:
            return {"status": "log_only_in_unchanged_tool_context"}
        oldpositions = occurrences(before, old)
        status = "exact_edit_supported" if old and len(oldpositions) == 1 else "edit_postimage_supported"
        return {"status": status, "postimage_offset": p,
                "preimage_offset": oldpositions[0] if len(oldpositions) == 1 else None,
                "changed_log_spans": touched, "old_string_sha256": sha(old), "new_string_sha256": sha(new)}
    content = tool.get("content")
    if isinstance(content, str) and content.replace("\r\n", "\n") == after:
        return {"status": "exact_write_new_file_supported" if new_file else "write_snapshot_supported",
                "content_sha256": sha(content)}
    return {"status": "no_supported_content_alignment"}


def locate_entities(source, entities):
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    used = set()
    result = []
    for e in entities:
        lo = offsets[min(e["start_line"] - 1, len(lines))]
        hi = offsets[min(e["end_line"], len(lines))]
        text = e["statement"]
        positions = occurrences(source[lo:hi], text)
        positions = [lo + p for p in positions if (lo + p, text) not in used]
        if not positions:
            continue
        pos = positions[0]
        used.add((pos, text))
        result.append({"callee": e["callee"], "start_line": e["start_line"],
                       "end_line": e["end_line"], "statement": text, "start": pos,
                       "end": pos + len(text), "log_detection_status": e["log_detection_status"],
                       "parser_status": e.get("parser_status")})
    return result


def align_file(before, after, edits, before_logs, after_logs, tools, agent_version=None, new_file=False):
    out = []
    for log in after_logs:
        relevant = [b for b in edits if any(overlaps(s, log["start"], log["end"]) for s in b["spans"])]
        if not relevant:
            continue
        prior = [e for e in before_logs if any(e["start_line"] <= b["old_line_end"] and e["end_line"] >= b["old_line_start"] for b in relevant)]
        exact_prior = [e for e in prior if e["statement"] == log["statement"]]
        if exact_prior:
            kind = "unchanged_statement_relocated"
        elif len(prior) == 1 and prior[0]["callee"] == log["callee"]:
            kind = "modified"
        elif prior:
            kind = "added_or_modified_unresolved"
        else:
            kind = "added"
        evidence = []
        for tool in tools:
            try:
                match = tool_alignment(tool["payload"], before, after, log["start"], log["end"], new_file)
            except ValueError as exc:
                match = {"status": str(exc)}
            if "changed_log_spans" in match:
                committed = [span for block in relevant for span in block["spans"]
                             if overlaps(span, log["start"], log["end"])]
                matched = [span for span in match["changed_log_spans"]
                           if any(spans_intersect(span, actual) for actual in committed)]
                if not matched:
                    match["status"] = "tool_change_does_not_overlap_commit_log_change"
                match["commit_intersection_spans"] = matched
            if match["status"] == "exact_edit_supported":
                # Reject a coincidental preimage at an unrelated parent location.
                p = match["preimage_offset"]
                n = len(tool["payload"]["old_string"].replace("\r\n", "\n"))
                line_a = before[:p].count("\n") + 1
                line_b = before[:p + max(n - 1, 0)].count("\n") + 1
                if not any(line_a <= b["old_line_end"] and line_b >= b["old_line_start"] for b in relevant):
                    match["status"] = "edit_postimage_supported"
                    match["downgrade_reason"] = "preimage_not_in_same_commit_change_block"
            evidence.append({**tool["reference"], **match})
        statuses = {m["status"] for m in evidence}
        if kind == "unchanged_statement_relocated":
            grade = "not_new_log_content"
        elif statuses & {"exact_edit_supported", "exact_write_new_file_supported", "exact_structured_patch_supported"}:
            grade = "exact_tool_change_supported"
        elif statuses & {"edit_postimage_supported", "write_snapshot_supported", "structured_patch_postimage_supported"}:
            grade = "tool_postimage_supported"
        elif isinstance(agent_version, str) and len(occurrences(agent_version, log["statement"])) == 1:
            grade = "agent_snapshot_only"
        else:
            grade = "file_attribution_only"
        out.append({**log, "change_kind": kind, "attribution_grade": grade,
                    "before_candidates": [{k: e[k] for k in ("callee", "start_line", "end_line", "statement")} for e in prior],
                    "patch_change_blocks": relevant, "tool_evidence": evidence})
    return out


class Guard:
    """Use the sealed protocol's existing guard, without exposing its registry."""
    def __init__(self, project):
        sys.path.insert(0, str(project / "research/swechat-independent-holdout-20260914"))
        import guard
        self.api = guard
        self.ids, self.keys = guard.protected()
        self.cache = {}
        self.calls = Counter()

    def check_path(self, repo, path):
        return self.api.assess([{"repository": repo, "path": path}], self.ids, self.keys)["allowed"]

    def check(self, repo, path, text):
        key = repo, path, sha(text)
        if key in self.cache:
            return self.cache[key]
        if not self.check_path(repo, path):
            result = "guard_protected"
        else:
            parsed = self.api.parse_source(text.encode(), path)
            if parsed["status"] != "parsed":
                result = "guard_unverifiable"
            else:
                records = [{"repository": repo, "path": path, "source_sha256": sha(text),
                            "function_exact": parsed.get("module_fingerprint")}]
                records.extend({"function_exact": f["exact"], "function_abstract": f["abstract"] if f["nodes"] >= 20 else None} for f in parsed["functions"])
                result = "allowed" if self.api.assess(records, self.ids, self.keys)["allowed"] else "guard_protected"
        self.calls[result] += 1
        self.cache[key] = result
        return result


def numstats(raw):
    result = {}
    raw = raw or ""
    if raw.startswith("insertions,deletions,path"):
        records = ([r["insertions"], r["deletions"], r["path"]] for r in csv.DictReader(io.StringIO(raw)))
    else:
        records = (line.split("\t", 2) for line in raw.splitlines())
    for parts in records:
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            path = parts[2]
            if path.startswith('"'):
                try:
                    path = ast.literal_eval(path)
                except (SyntaxError, ValueError):
                    continue
            if " => " in path:
                path = re.sub(r"\{[^{}]* => ([^{}]*)\}", r"\1", path) if "{" in path else path.split(" => ", 1)[1]
            result[path] = (int(parts[0]), int(parts[1]))
    return result


def emit_csv(path, rows, fields):
    with Path(path).open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v for k, v in row.items() if k in fields})


def run(workspace, output, limit=None):
    import pyarrow.parquet as pq
    project = workspace
    sys.path.insert(0, str(project / "src"))
    from agentlog_unified.detector import detect_snapshot
    scope = workspace / "outputs/swechat_agent_scope_20260919/final"
    with (scope / "main_code_files.csv").open(encoding="utf-8-sig", newline="") as f:
        files = list(csv.DictReader(f))
    if limit:
        files = files[:limit]
    bykey = {(r["repo_id"], r["commit_sha"], r["path"]): r for r in files}
    observations = defaultdict(list)
    with gzip.open(scope / "file_observations.jsonl.gz", "rt", encoding="utf8") as f:
        for line in f:
            r = json.loads(line)
            key = r["repo_id"], r["commit_sha"], r["path"]
            if key in bykey:
                observations[r["source_row"]].append(r)
    output.mkdir(parents=True, exist_ok=True)
    guard = Guard(project)
    # Freeze implementation and detector before processing historical source.
    json_write(output / "rule_freeze.json", {"version": VERSION, "created_at": datetime.now(timezone.utc).isoformat(),
               "script_sha256": sha(Path(__file__).read_bytes()), "detector_sha256": sha((project / "src/agentlog_unified/detector.py").read_bytes()),
               "guard_sha256": sha((project / "research/swechat-independent-holdout-20260914/guard.py").read_bytes()),
               "scope_sha256": sha((scope / "main_code_files.csv").read_bytes()),
               "evidence_policy": "Exact old/new content and actual patch character intersection; all source versions must pass existing guard. No runtime success, exclusive session authorship or independent accuracy claim."})
    ledger = defaultdict(list)
    candidates = defaultdict(list)
    row_number = 0
    selected_rows_done = 0
    start = time.monotonic()
    cache_logs = {}
    prepared_tools = {}
    def logs(path, source):
        key = path, sha(source)
        if key not in cache_logs:
            detected = detect_snapshot({path: source}, languages=["python", "javascript", "typescript", "jsx", "tsx", "go"])
            cache_logs[key] = locate_entities(source, detected["entities"])
        return cache_logs[key]
    parquet = pq.ParquetFile(project/"data/cache/swechat-frozen/commits.parquet")
    cols = ["repo_id", "commit_sha", "status", "patch", "numstat", "file_attribution", "agent_changes"]
    for batch in parquet.iter_batches(batch_size=8, columns=cols):
        for row in batch.to_pylist():
            row_number += 1
            if row_number not in observations:
                continue
            todo = observations[row_number]
            attrs = json.loads(row["file_attribution"] or "{}")
            patch = None
            changes = None
            stats = numstats(row["numstat"])
            for obs in todo:
                repo, commit, path = obs["repo_id"], obs["commit_sha"], obs["path"]
                key = repo, commit, path
                status = {"source_row": row_number, "status": "pending"}
                ledger[key].append(status)
                if not guard.check_path(repo, path):
                    status["status"] = "guard_protected"
                    continue
                item = attrs.get(path)
                if not isinstance(item, dict) or not isinstance(item.get("committed_version"), str):
                    status["status"] = "missing_postimage"
                    continue
                after = item["committed_version"].replace("\r\n", "\n")
                permitted = guard.check(repo, path, after)
                if permitted != "allowed":
                    status["status"] = permitted
                    continue
                agent_version = item.get("agent_version")
                if isinstance(agent_version, str):
                    agent_version = agent_version.replace("\r\n", "\n")
                    permitted = guard.check(repo, path, agent_version)
                    if permitted != "allowed":
                        status["status"] = permitted
                        continue
                if patch is None:
                    patch = parse_patch(row["patch"])
                part = patch.get(path)
                if not part:
                    status["status"] = "missing_file_patch"
                    continue
                try:
                    before, blocks = restore_parent(after, part, stats.get(path))
                except ValueError as exc:
                    status["status"] = str(exc)
                    continue
                if before:
                    permitted = guard.check(repo, part["old_path"] or path, before)
                    if permitted != "allowed":
                        status["status"] = permitted
                        continue
                if changes is None:
                    changes = json.loads(row["agent_changes"] or "[]")
                tools = []
                for ref in obs["tools"]:
                    if not ref["recognized_modification_tool"] or ref["path_match"] not in {"exact_relative", "repo_root_relative"}:
                        continue
                    payload = changes[ref["tool_index_0based"]]
                    cache_key = (repo, path, sha(before), sha(after), sha(agent_version or ""), sha(json.dumps(payload, sort_keys=True)))
                    if cache_key not in prepared_tools:
                        permitted_payload = dict(payload)
                        content = payload.get("content")
                        # Only inspect content retained in an already-guarded full image.
                        if isinstance(content, str) and content.replace("\r\n", "\n") not in {after, agent_version}:
                            permitted_payload.pop("content", None)
                        try:
                            tool_preimage = structured_tool_patch(payload, after)
                        except (ValueError, TypeError):
                            tool_preimage = None
                        prepared = None
                        if tool_preimage and tool_preimage[0].splitlines() == before.splitlines():
                            prepared = {"exact_preimage": True,
                                        "spans": [span for b in tool_preimage[1] for span in b["spans"]],
                                        "structured_patch_sha256": sha(json.dumps(payload["structured_patch"], sort_keys=True)),
                                        "reconstructed_preimage_sha256": sha(tool_preimage[0])}
                        old = payload.get("old_string")
                        unverified = isinstance(old, str) and bool(old) and not any(old.replace("\r\n", "\n") in image for image in (before, after, agent_version or ""))
                        permitted_payload.update(_structured_alignment=prepared, _unverified_preimage=unverified)
                        prepared_tools[cache_key] = permitted_payload
                    payload = prepared_tools[cache_key]
                    tools.append({"payload": payload, "reference": {**ref, "checkpoint_pk": obs["checkpoint_pk"], "session_ids": obs["session_ids"], "agents": obs["agents"]}})
                try:
                    before_logs, after_logs = logs(path, before) if before else [], logs(path, after)
                    if not guard.api.assess([{"callee": e["callee"]} for e in before_logs + after_logs], guard.ids, guard.keys)["allowed"]:
                        status["status"] = "guard_protected"
                        continue
                    result = align_file(before, after, blocks, before_logs, after_logs, tools,
                                        agent_version, part["old_path"] is None)
                except (ValueError, RecursionError, SyntaxError) as exc:
                    status["status"] = "analysis_" + type(exc).__name__
                    continue
                status.update(status="aligned", postimage_sha256=sha(after), parent_logical_sha256=sha(before), log_observations=len(result))
                # Evidence without a same-repository session never lifts a grade.
                for result_row in result:
                    if not obs["session_ids"]:
                        result_row["attribution_grade"] = "file_attribution_only"
                    result_row.update(source_row=row_number, checkpoint_pk=obs["checkpoint_pk"],
                                      session_ids=obs["session_ids"], agents=obs["agents"], file_attribution=item.get("attribution"),
                                      postimage_sha256=sha(after), parent_logical_sha256=sha(before))
                    candidates[key].append(result_row)
            selected_rows_done += 1
            if selected_rows_done % 10 == 0:
                print(json.dumps({"processed_source_row": row_number, "file_units_visited": len(ledger), "elapsed_seconds": round(time.monotonic()-start)}), flush=True)
    exported = []
    file_rows = []
    ranks = {"exact_tool_change_supported": 4, "tool_postimage_supported": 3, "agent_snapshot_only": 2, "file_attribution_only": 1, "not_new_log_content": 0}
    evidence_file = output / "log_alignment_evidence.jsonl"
    with evidence_file.open("w", encoding="utf8") as ef:
        for key, scope_row in bykey.items():
            states = ledger[key]
            statuses = {r["status"] for r in states}
            blocked = bool(statuses & {"guard_protected", "guard_unverifiable"})
            hashes = {r["postimage_sha256"] for r in states if "postimage_sha256" in r}
            parent_hashes = {r["parent_logical_sha256"] for r in states if "parent_logical_sha256" in r}
            conflict = len(hashes) > 1 or len(parent_hashes) > 1
            file_status = "guard_excluded" if blocked else "source_version_conflict" if conflict else "aligned" if "aligned" in statuses else "unresolved"
            file_row = {"file_id": scope_row["file_id"], "status": file_status, "observation_statuses": dict(Counter(r["status"] for r in states))}
            # Protected identities and contents are never copied to this output.
            if not blocked:
                file_row.update(repo_id=key[0], commit_sha=key[1], path=key[2], attribution_labels=json.loads(scope_row["attribution_labels"]))
            else:
                file_row["file_id"] = "withheld"
            file_rows.append(file_row)
            if blocked or conflict:
                continue
            groups = defaultdict(list)
            for record in candidates[key]:
                groups[(record["start"], record["end"], sha(record["statement"]))].append(record)
            for logkey, records in groups.items():
                best = max(records, key=lambda r: ranks[r["attribution_grade"]])
                logid = sha(json.dumps([*key, *logkey]))[:24]
                record = {"log_id": logid, "repo_id": key[0], "commit_sha": key[1], "path": key[2],
                          "file_attribution_labels": json.loads(scope_row["attribution_labels"]),
                          **{k: best[k] for k in ["start_line", "end_line", "callee", "statement", "change_kind", "attribution_grade", "log_detection_status", "parser_status"]},
                          "source_rows": sorted({r["source_row"] for r in records}), "observations": records,
                          "runtime_tool_success_verified": False, "exclusive_agent_identity_verified": False}
                ef.write(json.dumps(record, ensure_ascii=False) + "\n")
                exported.append({k: v for k, v in record.items() if k != "observations"})
    fields = ["log_id", "repo_id", "commit_sha", "path", "start_line", "end_line", "callee", "change_kind", "file_attribution_labels", "attribution_grade", "log_detection_status", "parser_status", "source_rows", "statement"]
    emit_csv(output / "logs.csv", exported, fields)
    emit_csv(output / "mixed_logs.csv", [r for r in exported if "mixed" in r["file_attribution_labels"]], fields)
    emit_csv(output / "exact_supported_logs.csv", [r for r in exported if r["attribution_grade"] == "exact_tool_change_supported"], fields)
    emit_csv(output / "file_coverage.csv", file_rows, ["file_id", "repo_id", "commit_sha", "path", "status", "attribution_labels", "observation_statuses"])
    counts = Counter(r["attribution_grade"] for r in exported)
    summary = {"version": VERSION, "input_file_units": len(files), "file_status_counts": dict(Counter(r["status"] for r in file_rows)),
               "exported_log_candidates": len(exported), "grade_counts": dict(counts),
               "mixed_grade_counts": dict(Counter(r["attribution_grade"] for r in exported if "mixed" in r["file_attribution_labels"])),
               "change_kind_counts": dict(Counter(r["change_kind"] for r in exported)),
               "log_detection_counts": dict(Counter(r["log_detection_status"] for r in exported)),
               "runtime_seconds": round(time.monotonic()-start), "holdout_evaluation_performed": False}
    json_write(output / "summary.json", summary)
    print(json.dumps(summary), flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dependencies", type=Path)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    if args.dependencies:
        sys.path.insert(0, str(args.dependencies))
    run(args.workspace.resolve(), args.output.resolve(), args.limit)


if __name__ == "__main__":
    main()
