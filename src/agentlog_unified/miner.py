"""PyDriller-backed commit mining with explicit topology and coverage evidence."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

from pydriller import Git, Repository

from .git_support import (commit_graph, diff_paths, disable_implicit_fetch, is_ancestor, merge_diff_fallback,
                          read_blob, repository_object_state, resolve_ref, run_git)


def _gap(sha: str | None, error_type: str, reason: str, **extra) -> dict:
    return {"stage": "mine", "sha": sha, "error_type": error_type,
            "reason": reason, "retryable": error_type not in {
                "history_budget_exceeded", "source_budget_exceeded", "binary"}, **extra}


def _failure(sha: str | None, default_type: str, exc: Exception, object_state: dict,
             **extra) -> dict:
    # Inspect errors only in memory; Git stderr may contain URLs or source data.
    message = str(exc).lower()
    missing = any(word in message for word in ("missing", "bad object", "bad tree", "unable to read",
                  "could not read", "could not get object", "could not be resolved", "promisor", "not a valid object"))
    kind = ("missing_promisor_object" if object_state.get("promisor_configured") else "missing_git_object") if missing else default_type
    return _gap(sha, kind, "Required Git object is unavailable; implicit network fetch disabled"
                if missing else type(exc).__name__, exception_type=type(exc).__name__,
                object_state=object_state, **extra)


def _record_file(repo_path: str, sha: str, parent: str | None, modified,
                 backend: str, fallback_reason: str | None, max_bytes: int,
                 gaps: list, metrics: dict, object_state: dict) -> dict:
    old_path, new_path = modified.old_path, modified.new_path
    basis = {"sha": sha, "parent_sha": parent, "old_path": old_path,
             "new_path": new_path, "change_type": modified.change_type.name,
             "diff_backend": backend, "diff_basis_sha": parent,
             "diff_target_sha": sha, "fallback_reason": fallback_reason,
             "source_backends": {}, "source_status": {}}
    identity = json.dumps(["2.0", str(Path(repo_path).resolve()), parent, sha,
                           old_path, new_path], ensure_ascii=False)
    basis["change_id"] = hashlib.sha256(identity.encode()).hexdigest()[:24]
    statuses = []
    for side, path, source_sha, attribute in (
        ("before", old_path, parent, "source_code_before"),
        ("after", new_path, sha, "source_code"),
    ):
        status, text, source_backend = "ok", None, f"pydriller.ModifiedFile.{attribute}"
        if path is None or source_sha is None:
            status, source_backend = "absent_by_change_type", "not_applicable"
        else:
            try:
                text = getattr(modified, attribute)
                metrics["pydriller_source_reads"] += 1
                # PyDriller returns None for empty blobs. Resolve that ambiguity.
                if text is None:
                    text, status = read_blob(repo_path, source_sha, path, max_bytes)
                    source_backend = "gitpython.blob_auxiliary"
                    basis.setdefault("source_fallback_reasons", {})[side] = (
                        "pydriller_source_none_resolve_empty_binary_or_missing")
                    metrics["auxiliary_blob_reads"] += 1
                elif len(text.encode("utf-8")) > max_bytes:
                    text, status = None, "source_budget_exceeded"
                elif "\x00" in text:
                    text, status = None, "binary"
                else:
                    # PyDriller's decoder can silently ignore invalid UTF-8.
                    raw = modified.content_before if side == "before" else modified.content
                    if raw is not None:
                        try:
                            raw.decode("utf-8")
                        except UnicodeDecodeError:
                            text, status = None, "decode_error"
            except Exception as exc:
                status = "source_extraction_error"
                gaps.append(_failure(sha, status, exc, object_state, path=path, side=side))
        basis[f"{side}_source"] = text
        basis["source_backends"][side], basis["source_status"][side] = source_backend, status
        if status not in {"ok", "absent_by_change_type"}:
            statuses.append(status)
            gaps.append(_gap(sha, status, "Historical source unavailable", path=path, side=side))
    try:
        parsed = modified.diff_parsed
        metrics["pydriller_diff_parsed_calls"] += 1
        basis["added"] = [[int(n), line] for n, line in parsed.get("added", [])]
        basis["deleted"] = [[int(n), line] for n, line in parsed.get("deleted", [])]
        basis["diff"] = modified.diff
        if len(basis["diff"].encode("utf-8")) > max_bytes:
            basis.update(diff=None, added=[], deleted=[])
            statuses.append("diff_budget_exceeded")
            gaps.append(_gap(sha, "diff_budget_exceeded", "Diff exceeds source byte budget",
                             path=new_path or old_path))
    except Exception as exc:
        basis.update(added=[], deleted=[], diff=None)
        statuses.append("diff_extraction_error")
        gaps.append(_failure(sha, "diff_extraction_error", exc, object_state, path=new_path or old_path))
    basis["extraction_status"] = "ok" if not statuses else "partial"
    basis["retrieval_mode"] = "new_pydriller_extraction"
    return basis


def _file_fingerprint(files: list[dict]) -> str:
    fields = ("sha", "parent_sha", "old_path", "new_path", "change_type", "diff_backend",
              "fallback_reason", "source_backends", "source_status", "before_source",
              "after_source", "diff", "added", "deleted", "extraction_status")
    payload = sorted(json.dumps({key: row.get(key) for key in fields}, sort_keys=True,
                               ensure_ascii=False) for row in files)
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False).encode()).hexdigest()


def _reusable_commit(commit: dict, files: list[dict], previous: dict, max_bytes: int) -> bool:
    if not commit.get("extraction_complete") or commit.get("extracted_file_count") != len(files):
        return False
    if commit.get("extraction_fingerprint") != _file_fingerprint(files):
        return False
    for gap in previous.get("gaps", []):
        if not gap.get("sha") or gap["sha"] == commit["sha"] or gap.get("error_type") in {
            "shallow_history", "commit_graph_error", "pydriller_traversal_error",
        }:
            return False
    for row in files:
        if (row.get("extraction_status") != "ok" or not isinstance(row.get("diff"), str)
                or len(row["diff"].encode()) > max_bytes):
            return False
        for side in ("before", "after"):
            status = row.get("source_status", {}).get(side)
            value = row.get(side + "_source")
            if status == "ok":
                if not isinstance(value, str) or len(value.encode()) > max_bytes:
                    return False
            elif status != "absent_by_change_type":
                return False
    return True


def mine_repository(repo_path: str, tip_sha: str, initial_shas: list[str],
                    max_commits: int = 50000, max_source_bytes: int = 2097152,
                    since_initial: bool = True, previous: dict | None = None) -> dict:
    """Mine all selected authors using PyDriller; graph helpers only choose scope.

    The default begins at the earliest initial commit reachable from the frozen
    target. Every target commit from that topological point onward is eligible,
    including side-branch ancestors and merges. Explicit unreachable PR objects
    are also read; their target_reachable flag remains false. Budget cuts always
    emit a coverage gap and preserve initial objects before recent history.

    A compatible ``previous`` result reuses complete immutable extractions only;
    current graph, selection and topology are recomputed. PyDriller counters and
    files_extracted count new work; reused_commits/reused_files count cached work.
    """
    if max_commits < 1 or max_source_bytes < 1:
        raise ValueError("mining budgets must be positive")
    disable_implicit_fetch()
    repo_path = str(Path(repo_path).resolve())
    result = {"repo_path": repo_path, "commits": [], "changes": [], "gaps": [], "selected_shas": [],
              "first_parent_shas": [], "graph": [], "metrics": {
                  "pydriller_repository_traversals": 0, "pydriller_commits": 0,
                  "pydriller_modified_files_calls": 0, "pydriller_git_diff_calls": 0,
                  "pydriller_diff_parsed_calls": 0, "pydriller_source_reads": 0,
                  "auxiliary_blob_reads": 0, "merge_fallbacks": 0,
                  "files_extracted": 0, "target_graph_commits": 0,
                  "reused_commits": 0, "reused_files": 0, "cache_rejected_commits": 0,
              }}
    gaps, metrics = result["gaps"], result["metrics"]
    try:
        object_state = repository_object_state(repo_path)
    except Exception as exc:
        object_state = {"implicit_lazy_fetch_enabled": False, "state_read_error": type(exc).__name__}
    result["object_state"] = object_state
    tip = resolve_ref(repo_path, tip_sha)
    initials = []
    for ref in dict.fromkeys(initial_shas):
        sha = resolve_ref(repo_path, ref)
        if sha:
            initials.append(sha)
        else:
            gaps.append(_gap(ref, "missing_initial_object", "Initial commit cannot be resolved"))
    if not tip:
        gaps.append(_gap(tip_sha, "missing_target_object", "Frozen target tip cannot be resolved"))
    if not tip and not initials:
        return result
    try:
        target_graph = commit_graph(repo_path, [tip]) if tip else []
        graph = commit_graph(repo_path, ([tip] if tip else []) + initials)
        result["graph"] = graph
        first_parent = (run_git(repo_path, ["rev-list", "--first-parent", "--reverse", tip])
                        .stdout.splitlines()) if tip else []
        result["first_parent_shas"] = first_parent
        shallow = run_git(repo_path, ["rev-parse", "--is-shallow-repository"]).stdout.strip()
        if shallow == "true":
            gaps.append(_gap(tip, "shallow_history", "Repository has shallow boundaries"))
    except Exception as exc:
        gaps.append(_failure(tip, "commit_graph_error", exc, object_state))
        return result
    target_order = [x["sha"] for x in target_graph]
    target_set, first_parent_set = set(target_order), set(first_parent)
    target_positions = {sha: i for i, sha in enumerate(target_order)}
    metrics["target_graph_commits"] = len(target_order)
    starts = [target_positions[sha] for sha in initials if sha in target_set]
    start = min(starts) if since_initial and starts else 0
    eligible = target_order[start:]
    result["history_scope"] = {"policy": "target_topology_since_earliest_reachable_initial"
                              if start else "all_target_reachable",
                              "omitted_pre_initial_commits": start,
                              "scope_start_sha": eligible[0] if eligible else None,
                              "frozen_tip": tip, "target_graph_backend": "git.rev-list",
                              "author_filter": None}
    required = list(dict.fromkeys(initials))
    selected = set(required[:max_commits])
    for sha in reversed(eligible):
        if len(selected) >= max_commits:
            break
        selected.add(sha)
    requested = set(required) | set(eligible)
    if requested - selected:
        gaps.append(_gap(tip, "history_budget_exceeded", "Commit extraction budget reached",
                         eligible_count=len(requested), selected_count=len(selected),
                         omitted_count=len(requested - selected)))
    selected_order = [row["sha"] for row in graph if row["sha"] in selected]
    result["selected_shas"] = selected_order
    positions = {row["sha"]: i for i, row in enumerate(graph)}
    metrics["requested_initial_commits"] = len(initial_shas)
    metrics["resolved_initial_commits"] = len(required)
    metrics["eligible_commits"] = len(requested)
    extracted = set()
    if previous is not None:
        if previous.get("repo_path") != repo_path:
            raise ValueError("Extension repository path does not match previous mining result")
        old_tip = previous.get("history_scope", {}).get("frozen_tip")
        if not old_tip or old_tip not in first_parent_set or not is_ancestor(repo_path, old_tip, tip):
            raise ValueError("Extension requires the previous tip on the current first-parent chain")
        old_files = {}
        for change in previous.get("changes", []):
            old_files.setdefault(change["sha"], []).append(change)
        graph_parents = {row["sha"]: row["parents"] for row in graph}
        for commit in previous.get("commits", []):
            sha = commit["sha"]
            if sha not in selected:
                continue
            files = old_files.get(sha, [])
            if commit.get("parents") != graph_parents[sha] or not _reusable_commit(commit, files, previous, max_source_bytes):
                metrics["cache_rejected_commits"] += 1
                continue
            copied = deepcopy(commit)
            for key in ("id", "repository_id", "github_author", "evidence_ref"):
                copied.pop(key, None)
            copied.update(topo_index=positions[sha], target_reachable=sha in target_set,
                          on_target_first_parent=sha in first_parent_set,
                          extraction_mode="reused_immutable_commit",
                          cache_origin_run_id=previous.get("source_run_id"))
            result["commits"].append(copied)
            for change in deepcopy(files):
                change.update(retrieval_mode="reused_immutable_commit",
                              cache_origin_run_id=previous.get("source_run_id"))
                result["changes"].append(change)
            for comparison in previous.get("empty_merge_comparisons", []):
                if comparison["sha"] == sha:
                    result.setdefault("empty_merge_comparisons", []).append(deepcopy(comparison))
            extracted.add(sha)
            metrics["reused_commits"] += 1
            metrics["reused_files"] += len(files)
    git = Git(repo_path)

    def extract(commit) -> None:
        sha = commit.hash
        if sha in extracted:
            return
        extracted.add(sha)
        metrics["pydriller_commits"] += 1
        metadata = {"sha": sha, "parents": list(commit.parents),
            "author": {"name": commit.author.name, "email": commit.author.email},
            "committer": {"name": commit.committer.name, "email": commit.committer.email},
            "author_date": commit.author_date.isoformat(),
            "committer_date": commit.committer_date.isoformat(), "merge": commit.merge,
            "message": commit.msg, "topo_index": positions[sha],
            "target_reachable": sha in target_set,
            "on_target_first_parent": sha in first_parent_set,
            "extraction_mode": "new_pydriller_extraction"}
        result["commits"].append(metadata)
        file_start, gap_start = len(result["changes"]), len(gaps)
        comparisons = list(commit.parents) if commit.merge else [commit.parents[0] if commit.parents else None]
        for parent in comparisons:
            backend, reason = "pydriller.Commit.modified_files", None
            try:
                if commit.merge:
                    metrics["pydriller_git_diff_calls"] += 1
                    backend = "pydriller.Git.diff"
                    expected = diff_paths(repo_path, parent, sha)
                    try:
                        modified_files = git.diff(parent, sha)
                        actual = {(item.old_path, item.new_path) for item in modified_files}
                        if actual != expected:
                            raise ValueError("merge_diff_path_set_mismatch")
                    except Exception as exc:
                        metrics["merge_fallbacks"] += 1
                        backend = "gitpython.explicit_parent_diff+pydriller.ModifiedFile"
                        reason = "pydriller_Git.diff_failed_or_path_set_mismatch:" + type(exc).__name__
                        modified_files = merge_diff_fallback(repo_path, parent, sha)
                        if {(item.old_path, item.new_path) for item in modified_files} != expected:
                            raise ValueError("fallback_merge_diff_path_set_mismatch")
                    if not modified_files:
                        result.setdefault("empty_merge_comparisons", []).append({
                            "sha": sha, "parent_sha": parent, "diff_backend": backend,
                            "fallback_reason": reason, "verified_equal_trees": True})
                else:
                    metrics["pydriller_modified_files_calls"] += 1
                    modified_files = commit.modified_files
                for modified in modified_files:
                    result["changes"].append(_record_file(repo_path, sha, parent, modified,
                        backend, reason, max_source_bytes, gaps, metrics, object_state))
            except Exception as exc:
                gaps.append(_failure(sha, "commit_diff_error", exc, object_state,
                                 parent_sha=parent, diff_backend=backend, fallback_reason=reason))
        files = result["changes"][file_start:]
        metadata.update(extraction_complete=len(gaps) == gap_start,
                        extracted_file_count=len(files), extraction_fingerprint=_file_fingerprint(files))

    try:
        uncached = selected - extracted
        if tip and uncached & target_set:
            metrics["pydriller_repository_traversals"] += 1
            # only_commits is a graph/budget selection, never an author/PR filter.
            for commit in Repository(repo_path, to_commit=tip,
                    only_commits=list(uncached & target_set), order="topo-order",
                    num_workers=1).traverse_commits():
                extract(commit)
    except Exception as exc:
        gaps.append(_failure(tip, "pydriller_traversal_error", exc, object_state))
    # Explicit objects can be dangling or outside the default branch walk.
    for sha in selected_order:
        if sha in extracted:
            continue
        try:
            metrics["pydriller_repository_traversals"] += 1
            for commit in Repository(repo_path, single=sha, num_workers=1).traverse_commits():
                extract(commit)
            if sha not in extracted:
                extract(git.get_commit(sha))
                metrics["pydriller_get_commit_fallbacks"] = metrics.get("pydriller_get_commit_fallbacks", 0) + 1
        except Exception as exc:
            gaps.append(_failure(sha, "selected_commit_not_extracted", exc, object_state))
    result["commits"].sort(key=lambda item: item["topo_index"])
    result["changes"].sort(key=lambda item: (positions[item["sha"]], item["parent_sha"] or "",
                                             item["new_path"] or item["old_path"] or ""))
    metrics["files_extracted"] = len(result["changes"]) - metrics["reused_files"]
    metrics["new_files_extracted"] = metrics["files_extracted"]
    metrics["total_file_records"] = len(result["changes"])
    metrics["selected_commits_missing"] = len(selected - extracted)
    git.clear()
    return result


def snapshot_files(repo_path: str, sha: str, max_files: int = 2000,
                   max_source_bytes: int = 2097152,
                   extensions: list[str] | tuple[str, ...] | None = None) -> dict:
    """Read a bounded historical source snapshot without checkout or execution.

    PyDriller 2.11 has no historical whole-tree content API. Its get_commit
    anchors the revision; GitPython tree/blob reads supply unmodified dependency
    files. Mining itself still uses ModifiedFile history APIs and diff parsing.
    """
    supported = set(extensions) if extensions is not None else {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".go", ".cs", ".java", ".json", ".yaml",
        ".yml", ".toml", ".ini", ".cfg", ".conf", ".xml", ".mod"}
    result = {"files": {}, "gaps": [], "backend": "gitpython.tree_blob_auxiliary",
              "revision_backend": "pydriller.Git.get_commit",
              "fallback_reason": "pydriller_2_11_has_no_whole_tree_source_API",
              "extensions": sorted(supported), "excluded_by_extension": 0}
    if max_files < 1 or max_source_bytes < 1:
        raise ValueError("snapshot budgets must be positive")
    disable_implicit_fetch()
    object_state = {}
    git = None
    try:
        object_state = repository_object_state(repo_path)
        result["object_state"] = object_state
        git = Git(repo_path)
        revision = git.get_commit(sha).hash
        result["sha"] = revision
        attempted = 0
        for blob in git.repo.commit(revision).tree.traverse():
            if blob.type != "blob":
                if blob.type == "submodule":
                    result["gaps"].append(_gap(sha, "submodule_source_unavailable", "Submodule not traversed", path=blob.path))
                continue
            if supported and Path(blob.path).suffix.lower() not in supported:
                result["excluded_by_extension"] += 1
                continue
            if attempted >= max_files:
                result["gaps"].append(_gap(sha, "snapshot_file_budget_exceeded",
                                         "Reverse dependency snapshot is partial", max_files=max_files))
                break
            attempted += 1
            try:
                if blob.size > max_source_bytes:
                    result["gaps"].append(_gap(sha, "source_budget_exceeded", "Snapshot blob too large", path=blob.path))
                    continue
                raw = blob.data_stream.read()
            except Exception as exc:
                # Partial clones often have the changed source but lack unrelated
                # blobs. One absent file must not discard the rest of this SHA.
                result["gaps"].append({**_failure(sha, "snapshot_blob_error", exc, object_state), "path": blob.path})
                continue
            try:
                if b"\x00" in raw:
                    result["gaps"].append(_gap(sha, "binary", "Binary snapshot blob", path=blob.path))
                    continue
                result["files"][blob.path] = raw.decode("utf-8")
            except UnicodeDecodeError:
                result["gaps"].append(_gap(sha, "decode_error", "Non UTF-8 snapshot blob", path=blob.path))
    except Exception as exc:
        result["gaps"].append(_failure(sha, "snapshot_error", exc, object_state))
    finally:
        if git is not None:
            git.clear()
    return result
