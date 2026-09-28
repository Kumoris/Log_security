"""Explicit, bounded Git object collection before offline PyDriller mining.

The shallow graph and changed blobs are acquisition inputs, not code analysis.
Completed attempts stay in SQLite when mining replaces its commit records.
An interrupted, uncommitted acquisition is retried and never counted complete.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from .batch_mine import _acquire_git, _database, _import_paths, _stream_jsonl, repository_cache_path
from .git_support import disable_implicit_fetch
from .storage import atomic_write, canonical, stable_id


def _git(path, *args, check=True, input=None):
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(path), *args],
        input=input, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=check, timeout=120,
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"})


def _parents(path, sha):
    # Raw headers retain the real parents even when rev-list hides a shallow edge.
    header = _git(path, "cat-file", "commit", sha).stdout.split(b"\n\n", 1)[0]
    return [line[7:].decode("ascii") for line in header.splitlines() if line.startswith(b"parent ")]


def _present(path, ids):
    if not ids:
        return set()
    result = _git(path, "cat-file", "--batch-check=%(objectname) %(objecttype)",
                  input=("\n".join(ids) + "\n").encode()).stdout
    return {line.split()[0].decode() for line in result.splitlines() if not line.endswith(b" missing")}


def _changed_objects(path, sha, parents):
    result = []
    for parent in parents or [None]:
        args = ["diff-tree", "-r", "--raw", "--no-abbrev", "--no-renames", "--no-commit-id",
                "--no-ext-diff", "--no-textconv", "-z"]
        args += [parent, sha] if parent else ["--root", sha]
        parts = _git(path, *args).stdout.split(b"\0")
        for i in range(0, len(parts) - 1, 2):
            oldmode, newmode, old, new, status = parts[i].decode("ascii").split()
            result.append({"parent": parent, "path": parts[i + 1].decode("utf-8", "replace"),
                           "before": old if oldmode[1:] not in {"000000", "160000"} else None,
                           "after": new if newmode not in {"000000", "160000"} else None,
                           "submodule": "160000" in (oldmode[1:], newmode)})
    return result


def materialize_commit(path, repository, sha, *, offline=False, git_timeout=120,
                       max_changed_files=2000, max_dependency_files=40, max_source_bytes=2097152):
    """Collect exact parents, changed blobs and bounded direct Python imports.

    No checkout or target execution; Git reads below only plan object acquisition.
    The caller must use PyDriller separately for the actual code observations.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or any(
            p in {".", ".."} for p in repository.split("/")):
        raise ValueError("invalid_repository")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
        raise ValueError("invalid_exact_sha")
    disable_implicit_fetch()
    path = Path(path)
    metrics = Counter()
    stages = []
    report = {"repository": repository, "sha": sha, "cache_path": str(path.resolve()),
              "method": "explicit_depth2_graph_then_changed_blobs_and_direct_imports",
              "implicit_fetch_enabled": False, "offline": offline,
              "full_history_collected": False, "classification_performed": False,
              "stages": stages, "metrics": metrics}
    started = time.monotonic()

    def fetch(stage, ids, graph=False):
        if offline:
            raise FileNotFoundError("required_git_objects_unavailable_offline")
        before = time.monotonic()
        evidence = {"stage": stage, "object_count": len(ids), "object_ids": ids,
                    "status": "attempted"}
        stages.append(evidence)
        metrics["explicit_fetch_attempts"] += 1
        # The remote URL is constructed here, never taken from repository config.
        try:
            _acquire_git(["-C", str(path), "fetch", "--no-tags", "--no-write-fetch-head", "--no-auto-gc",
                          *(["--depth=2", "--filter=blob:none"] if graph else []),
                          "--", f"https://github.com/{repository}.git", *ids],
                         git_timeout, path)
        except Exception:
            evidence["status"] = "failed"
            raise
        finally:
            evidence["elapsed_seconds"] = round(time.monotonic() - before, 4)
        evidence["status"] = "fetched"
        metrics["explicit_fetch_calls"] += 1
        metrics[stage + "_requested_objects"] += len(ids)

    def blobs(ids, stage):
        ids = sorted(set(ids))
        missing = sorted(set(ids) - _present(path, ids))
        metrics[stage + "_objects_missing_before"] += len(missing)
        for start in range(0, len(missing), 50):
            fetch(stage, missing[start:start + 50])
        if set(ids) - _present(path, ids):
            raise FileNotFoundError("required_git_blobs_still_missing")

    def imports(revision, sources):
        # Match _snapshot: count attempted paths, stop at the first readable
        # candidate for each import, and do not recursively inspect helpers.
        seen, available, attempts = set(sources), set(sources), 0
        for file, source in sources.items():
            for module, candidates in _import_paths(file, source):
                for candidate in candidates:
                    if candidate in available:
                        break
                    if candidate in seen:
                        continue
                    if attempts >= max_dependency_files:
                        metrics["direct_import_candidate_budget_truncations"] += 1
                        return
                    seen.add(candidate)
                    attempts += 1
                    metrics["direct_import_candidate_attempts"] += 1
                    entries = _git(path, "ls-tree", "-r", "-z", revision, "--", candidate).stdout.split(b"\0")
                    oid = next((entry.split(b"\t", 1)[0].split()[2].decode() for entry in entries
                        if entry and entry.split(b"\t", 1)[1].decode("utf-8", "replace") == candidate
                        and entry.split(b"\t", 1)[0].split()[1] == b"blob"), None)
                    if not oid:
                        continue
                    blobs([oid], "direct_import_blobs")
                    if int(_git(path, "cat-file", "-s", oid).stdout) > max_source_bytes:
                        continue
                    raw = _git(path, "cat-file", "blob", oid).stdout
                    metrics["auxiliary_dependency_validation_reads"] += 1
                    try:
                        raw.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                    if b"\0" not in raw:
                        available.add(candidate)
                        break

    try:
        if not (path / ".git").is_dir():
            if offline:
                raise FileNotFoundError("repository_unavailable_offline")
            if path.exists() and any(path.iterdir()):
                raise ValueError("nonempty_destination_is_not_owned_git_cache")
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            _git(path, "init", "--quiet")
            _git(path, "config", "remote.agentlog.url", f"https://github.com/{repository}.git")
            _git(path, "config", "remote.agentlog.promisor", "true")
            _git(path, "config", "remote.agentlog.partialclonefilter", "blob:none")
        if sha not in _present(path, [sha]):
            fetch("commit_graph", [sha], graph=True)
        parents = _parents(path, sha)
        missing_parents = sorted(set(parents) - _present(path, parents))
        if missing_parents:
            fetch("parent_graph", missing_parents, graph=True)
        if set(parents) - _present(path, parents):
            raise FileNotFoundError("parent_commit_objects_unavailable")
        report["parents"] = parents
        changes = _changed_objects(path, sha, parents)
        metrics["raw_changed_entries"] = len(changes)
        metrics["submodule_entries"] = sum(c["submodule"] for c in changes)
        if len(changes) > max_changed_files:
            raise ValueError("changed_file_acquisition_budget_exceeded")
        blobs([c[side] for c in changes for side in ("before", "after") if c[side]], "changed_blobs")
        # One hop only, sharing the mining module's static import resolution.
        for revision, side in [(p, "before") for p in parents] + [(sha, "after")]:
            sources = {}
            for c in changes:
                if side == "before" and c["parent"] != revision:
                    continue
                if c[side] and c["path"].endswith(".py") and c["path"] not in sources:
                    size = int(_git(path, "cat-file", "-s", c[side]).stdout)
                    if size <= max_source_bytes:
                        raw = _git(path, "cat-file", "blob", c[side]).stdout
                        metrics["auxiliary_source_reads_for_import_planning"] += 1
                        try:
                            sources[c["path"]] = raw.decode("utf-8")
                        except UnicodeDecodeError:
                            metrics["import_planning_decode_gaps"] += 1
            imports(revision, sources)
        report["status"] = "objects_ready_for_offline_mining"
    except Exception as exc:
        allowed = {"required_git_objects_unavailable_offline", "required_git_blobs_still_missing",
                   "repository_unavailable_offline", "nonempty_destination_is_not_owned_git_cache",
                   "parent_commit_objects_unavailable", "changed_file_acquisition_budget_exceeded",
                   "online_acquisition_disk_reserve_unavailable", "online_acquisition_disk_budget_exceeded",
                   "online_acquisition_time_budget_exceeded", "online_acquisition_failed"}
        report.update(status="acquisition_gap", reason=str(exc) if str(exc) in allowed else type(exc).__name__,
                      exception_type=type(exc).__name__)
    report["elapsed_seconds"] = round(time.monotonic() - started, 4)
    return report


def collect_batch_objects(batch_dir, cache_dir, *, offline=True, max_commits=None,
                          max_seconds=None, max_repositories=None, retry_failed=False):
    """Resume attempts without replaying unavailable repositories every run.

    Ready blocked jobs (also partial jobs on explicit retry) become pending.
    Collection does not replace classification evidence; PyDriller mines next.
    """
    if any(x is not None and x < 0 for x in (max_commits, max_seconds, max_repositories)):
        raise ValueError("Collection budgets must be nonnegative")
    batch_dir, cache_dir = Path(batch_dir), Path(cache_dir).resolve()
    if not (batch_dir / "batch.sqlite").is_file():
        raise ValueError("collect-objects requires an existing batch")
    started, attempted, repositories = time.monotonic(), 0, set()
    counts = Counter()
    with _database(batch_dir) as db:
        db.execute("CREATE TABLE IF NOT EXISTS object_acquisitions(repository TEXT,sha TEXT,id TEXT PRIMARY KEY,data TEXT)")
        db.execute("CREATE INDEX IF NOT EXISTS acquisitions_commit ON object_acquisitions(repository,sha)")
        condition = "" if retry_failed else "AND NOT EXISTS(SELECT 1 FROM object_acquisitions a WHERE a.repository=j.repository AND a.sha=j.sha)"
        states = "('blocked','pending','partial')" if retry_failed else "('blocked','pending')"
        jobs = db.execute("SELECT j.repository,j.sha FROM jobs j WHERE j.status IN " + states + " " + condition + " ORDER BY j.repository,j.rowid")
        for repository, sha in jobs:
            if (max_commits is not None and attempted >= max_commits) or (max_seconds is not None and time.monotonic() - started >= max_seconds):
                break
            if repository not in repositories and max_repositories is not None and len(repositories) >= max_repositories:
                break
            repositories.add(repository)
            local = {json.loads(r[0]).get("local_repo_path") for r in db.execute(
                "SELECT data FROM contexts WHERE repository=?", (repository,))} - {None, ""}
            path = repository_cache_path(cache_dir, repository)
            if local or path.is_symlink() or (path / ".git").is_symlink() or (path.exists() and not path.resolve().is_relative_to(cache_dir)):
                result = {"repository": repository, "sha": sha, "status": "acquisition_gap",
                          "reason": "external_local_repository_not_modified", "classification_performed": False}
            else:
                result = materialize_commit(path, repository, sha, offline=offline)
            result.update(recorded_at_epoch=time.time(),
                          collector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
            identifier = stable_id(repository, sha, result)
            result["id"] = identifier
            with db:
                db.execute("INSERT INTO object_acquisitions VALUES(?,?,?,?)", (repository, sha, identifier, canonical(result)))
                if result["status"] == "objects_ready_for_offline_mining":
                    db.execute("UPDATE jobs SET status='pending' WHERE repository=? AND sha=? AND status IN ('blocked','partial')", (repository, sha))
            attempted += 1
            counts[result["status"]] += 1
        output = batch_dir / "collection"
        output.mkdir(exist_ok=True)
        _stream_jsonl(output / "object_acquisitions.jsonl", (json.loads(r[0]) for r in db.execute("SELECT data FROM object_acquisitions ORDER BY rowid")))
        latest_statuses = dict(db.execute("SELECT json_extract(data,'$.status'),count(*) FROM object_acquisitions WHERE rowid IN (SELECT max(rowid) FROM object_acquisitions GROUP BY repository,sha) GROUP BY 1"))
        summary = {"this_run_attempted": attempted, "this_run_repositories": len(repositories),
                   "this_run_status_counts": dict(counts), "offline": offline,
                   "latest_collection_status_counts": latest_statuses,
                   "total_recorded_attempts": db.execute("SELECT count(*) FROM object_acquisitions").fetchone()[0],
                   "elapsed_seconds": round(time.monotonic() - started, 4),
                   "classification_performed": False, "full_history_collected": False,
                   "remaining_without_collection_attempt": db.execute("SELECT count(*) FROM jobs j WHERE j.status IN ('pending','blocked') AND NOT EXISTS(SELECT 1 FROM object_acquisitions a WHERE a.repository=j.repository AND a.sha=j.sha)").fetchone()[0],
                   "output": str(output.resolve())}
        summary["exit_code"] = 2 if latest_statuses.get("acquisition_gap") or summary["remaining_without_collection_attempt"] else 0
        atomic_write(output / "summary.json", canonical(summary) + "\n")
    return summary
