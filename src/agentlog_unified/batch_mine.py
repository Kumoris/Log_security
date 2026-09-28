"""Durable exact-dataset-commit census, using real PyDriller extraction.

This is not whole-history tracing. Every result is an observation of a supplied
commit versus each parent. SQLite is the private checkpoint; public JSONL is a
redacted, rebuildable projection. No dataset-provided patch is used as Git data.
"""
from __future__ import annotations

import ast
from collections import Counter, defaultdict
from contextlib import contextmanager
import fcntl
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

from pydriller import Git, Repository

from .detector import LANGUAGES, detect_snapshot
from .git_support import (diff_paths, disable_implicit_fetch, merge_diff_fallback,
                          read_blob, repository_object_state, resolve_ref)
from .miner import _record_file
from .storage import atomic_write, canonical, redact, stable_id
from .taxonomy import TAXONOMY_VERSION, taxonomy_catalog
from .type_audit import OTHER_SOURCE_EXTENSIONS, export_batch_types

SCOPE = {"observation_scope": "dataset_commit_changes",
         "full_history_tracing_completed": False,
         "reverse_dependency_coverage": "changed_files_and_direct_imports_only",
         "runtime_confirmed": False, "human_review_status": "pending"}
CODE_EXTENSIONS = set(LANGUAGES) | OTHER_SOURCE_EXTENSIONS | {".vue", ".svelte"}


@contextmanager
def _database(batch_dir):
    directory = Path(batch_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # ponytail: one worker owns one SQLite queue; shard batch directories if needed.
    with (directory / ".batch.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("This batch already has an active writer") from None
        db = sqlite3.connect(directory / "batch.sqlite")
        os.chmod(directory / "batch.sqlite", 0o600)
        db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE IF NOT EXISTS jobs(repository TEXT,sha TEXT,status TEXT DEFAULT 'pending',
              attempts INTEGER DEFAULT 0,data TEXT DEFAULT '{}',PRIMARY KEY(repository,sha));
            CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status,repository);
            CREATE TABLE IF NOT EXISTS contexts(id TEXT PRIMARY KEY,repository TEXT,sha TEXT,data TEXT);
            CREATE INDEX IF NOT EXISTS context_commit ON contexts(repository,sha);
            CREATE TABLE IF NOT EXISTS input_gaps(id TEXT PRIMARY KEY,data TEXT);
            CREATE TABLE IF NOT EXISTS records(repository TEXT,sha TEXT,kind TEXT,id TEXT,data TEXT,
              PRIMARY KEY(repository,sha,kind,id));
            CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,data TEXT);
        """)
        try:
            yield db
        finally:
            db.close()


def _list(value):
    return [] if value is None else value if isinstance(value, list) else [value]


def ingest_commit_contexts(input_jsonl, batch_dir) -> dict:
    """Stream canonical commit rows or normalized AIDev PR rows into the queue.

    Re-ingestion is idempotent. Shared commits are extracted once while every PR,
    dataset and source-row association remains in contexts. Invalid/empty commit
    evidence stays in input_gaps, outside the analyzable commit denominator.
    """
    counts = Counter()
    with _database(batch_dir) as db, Path(input_jsonl).open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            counts["input_rows_seen"] += 1
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("not_an_object")
            except (ValueError, TypeError):
                gap = {"reason": "invalid_json_object", "line_number": line_number,
                       "input_path": str(Path(input_jsonl).resolve()), "raw_sha256": hashlib.sha256(line.encode()).hexdigest()}
                db.execute("INSERT OR IGNORE INTO input_gaps VALUES(?,?)", (stable_id(gap), canonical(gap)))
                counts["input_gap_rows"] += 1
                continue
            repository = row.get("repository", "")
            valid_repo = isinstance(repository, str) and re.fullmatch(
                r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) and not any(
                part in {".", ".."} for part in repository.split("/"))
            if valid_repo:
                repository = repository.lower()
            dataset = row.get("dataset") or ("aidev" if row.get("aidev_source_snapshot")
                or row.get("source_pr_key") else "swe-chat" if row.get("swechat_source_snapshot") else "unknown_dataset")
            context = {key: row[key] for key in ("source_pr_key", "pr_number", "pr_url",
                "source_rows", "aidev_source_snapshot", "source_refs", "context_ids", "local_repo_path",
                "source_kind", "source_context_id", "session_ids", "checkpoint_pks", "swechat_source_snapshot",
                "context_statuses", "commit_metadata_present") if key in row}
            context.update(dataset=dataset, repository=repository)
            context.setdefault("context_ids", _list(row.get("source_pr_key") or (
                f"{repository}#{row['pr_number']}" if row.get("pr_number") else None)))
            context["context_ids"] = _list(context["context_ids"])
            if row.get("source_context_id"):
                context["context_ids"] = list(dict.fromkeys(context["context_ids"] + _list(row["source_context_id"])))
            context.setdefault("source_refs", _list(row.get("pr_url")))
            shas = _list(row.get("sha")) if row.get("sha") else _list(
                row.get("commit_shas") or row.get("initial_commit_shas"))
            for sha in shas or [None]:
                if not valid_repo or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", sha):
                    reason = "invalid_repository" if not valid_repo else "no_commit_evidence" if sha is None else "invalid_exact_sha"
                    gap = {**context, "reason": reason, "input_path": str(Path(input_jsonl).resolve()),
                           "line_number": line_number, "invalid_sha_fingerprint": stable_id(sha) if sha else None}
                    db.execute("INSERT OR IGNORE INTO input_gaps VALUES(?,?)", (stable_id(gap), canonical(gap)))
                    counts["input_gap_rows"] += 1
                    continue
                sha = sha.lower()
                item = {**context, "sha": sha, "observation_scope": SCOPE["observation_scope"]}
                identifier = stable_id(item)
                db.execute("INSERT OR IGNORE INTO jobs(repository,sha) VALUES(?,?)", (repository, sha))
                db.execute("INSERT OR IGNORE INTO contexts VALUES(?,?,?,?)", (identifier, repository, sha,
                            canonical({"id": identifier, **item})))
            if counts["input_rows_seen"] % 1000 == 0:
                db.commit()
        db.commit()
        counts.update(unique_commits=db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0],
                      unique_contexts=db.execute("SELECT COUNT(*) FROM contexts").fetchone()[0],
                      unique_input_gaps=db.execute("SELECT COUNT(*) FROM input_gaps").fetchone()[0])
    return dict(counts)


def repository_cache_path(cache_dir, repository) -> Path:
    """Deterministic owned cache location; callers may seed it with a local clone."""
    return Path(cache_dir).resolve() / (repository.replace("/", "--") + "-" + stable_id(repository)[:8])


def _acquire_git(args, timeout, disk_path):
    # Explicit online acquisition only; never use repository-configured remote URLs.
    minimum_free, acquisition_limit = 2 * 1024**3, 1024**3
    initial_free = shutil.disk_usage(disk_path).free
    if initial_free < minimum_free + acquisition_limit:
        raise OSError("online_acquisition_disk_reserve_unavailable")
    started = time.monotonic()
    process = subprocess.Popen(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                    *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                    env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"})
    try:
        while process.poll() is None:
            free = shutil.disk_usage(disk_path).free
            if free < minimum_free or initial_free - free > acquisition_limit:
                raise OSError("online_acquisition_disk_budget_exceeded")
            if time.monotonic() - started >= timeout:
                raise TimeoutError("online_acquisition_time_budget_exceeded")
            time.sleep(0.2)
        if process.returncode:
            raise RuntimeError("online_acquisition_failed")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def _prepare_repository(db, repository, cache_dir, offline, timeout):
    local_paths = {json.loads(row[0]).get("local_repo_path") for row in db.execute(
        "SELECT data FROM contexts WHERE repository=?", (repository,))} - {None, ""}
    if len(local_paths) > 1:
        raise ValueError("conflicting_local_repository_paths")
    if local_paths:
        return Path(next(iter(local_paths))).resolve(), False
    destination = repository_cache_path(cache_dir, repository)
    if destination.exists():
        return destination, True
    if offline:
        raise FileNotFoundError("repository_unavailable_offline")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=destination.name + ".clone-", dir=destination.parent))
    # A failed staging clone is retained as a clearly separate incomplete artifact.
    _acquire_git(["clone", "--no-checkout", "--", f"https://github.com/{repository}.git", str(staging)], timeout, staging)
    staging.rename(destination)
    return destination, True


def _import_paths(path, source):
    """Only statically named direct imports; no tree scan and no recursive imports."""
    if not path.endswith(".py"):
        return []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    result = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        names = [name.name for name in node.names] if isinstance(node, ast.Import) else [node.module or ""]
        for name in names:
            if not getattr(node, "level", 0) and name.split(".")[0] in sys.stdlib_module_names:
                continue
            parent = PurePosixPath(path).parent
            level = getattr(node, "level", 0)
            if level:
                for _ in range(level - 1):
                    parent = parent.parent
                bases = [parent / name.replace(".", "/")]
            else:
                bases = [PurePosixPath(name.replace(".", "/")), parent / name.replace(".", "/"),
                         PurePosixPath("src") / name.replace(".", "/")]
            candidates = []
            for base in bases:
                candidates.extend([str(base) + ".py", str(base / "__init__.py")])
            result.append((name, list(dict.fromkeys(candidates))))
    return result


def _snapshot(repo_path, revision, files, limit, max_bytes, gaps, metrics, side):
    sources = dict(files)
    attempts, seen = 0, set(files)
    for path, source in files.items():
        for module, candidates in _import_paths(path, source):
            found = False
            for candidate in candidates:
                if candidate in sources:
                    found = True
                    break
                if candidate in seen:
                    continue
                if attempts >= limit:
                    gaps.append({"reason": "direct_import_budget_exceeded", "side": side,
                                 "path": path, "max_dependency_blob_reads": limit})
                    return sources
                seen.add(candidate)
                attempts += 1
                metrics["dependency_blob_read_attempts"] += 1
                try:
                    text, status = read_blob(repo_path, revision, candidate, max_bytes)
                except Exception as exc:
                    text, status = None, type(exc).__name__
                if status == "ok":
                    sources[candidate] = text
                    metrics["dependency_blobs_read"] += 1
                    found = True
                    break
                if status != "path_absent":
                    gaps.append({"reason": "dependency_source_unavailable", "status": status,
                                 "side": side, "path": candidate})
            if not found:
                gaps.append({"reason": "direct_import_unresolved_or_external", "path": path,
                             "module": module, "side": side})
    return sources


def _intersects(entity, changed):
    def overlap(row):
        return any(row.get("start_line", 0) <= line <= row.get("end_line", 0)
                   for line in changed.get(row.get("path"), set()))
    return overlap(entity), any(overlap(dep) for dep in entity.get("dependencies", []))


def _mine_commit(repo_path, repository, sha, *, max_source_bytes, max_changed_files, max_dependency_files):
    metrics, gaps, records = defaultdict(int), [], []
    object_state = repository_object_state(str(repo_path))
    metrics["pydriller_repository_traversals"] += 1
    try:
        traversal = Repository(str(repo_path), single=sha, num_workers=1).traverse_commits()
        commits = list(traversal)
        if len(commits) != 1 or commits[0].hash != sha:
            raise ValueError("exact_commit_traversal_mismatch")
    except Exception as exc:
        return ({"status": "blocked", "metrics": dict(metrics), "object_state": object_state,
                 "taxonomy_version": TAXONOMY_VERSION}, [("gaps", {"reason": "pydriller_traversal_error",
                 "exception_type": type(exc).__name__, "retryable": True})])
    commit = commits[0]
    metrics["pydriller_commits"] += 1
    if object_state.get("shallow") and not commit.parents:
        gaps.append({"reason": "possible_shallow_boundary_parent_missing"})
    comparisons = commit.parents if commit.merge else [commit.parents[0] if commit.parents else None]
    pydriller_git = Git(str(repo_path))
    for parent in comparisons:
        backend, fallback = "pydriller.Commit.modified_files", None
        changes = []
        try:
            if commit.merge:
                backend = "pydriller.Git.diff"
                metrics["pydriller_git_diff_calls"] += 1
                expected = diff_paths(str(repo_path), parent, sha)
                try:
                    modified_files = pydriller_git.diff(parent, sha)
                    if {(m.old_path, m.new_path) for m in modified_files} != expected:
                        raise ValueError("merge_path_set_mismatch")
                except Exception as exc:
                    backend = "gitpython.explicit_parent_diff+pydriller.ModifiedFile"
                    fallback = "pydriller_Git.diff_failed_or_path_set_mismatch:" + type(exc).__name__
                    metrics["merge_fallbacks"] += 1
                    modified_files = merge_diff_fallback(str(repo_path), parent, sha)
                    if {(m.old_path, m.new_path) for m in modified_files} != expected:
                        raise ValueError("merge_fallback_path_set_mismatch")
            else:
                metrics["pydriller_modified_files_calls"] += 1
                modified_files = commit.modified_files
            for index, modified in enumerate(modified_files):
                path = modified.new_path or modified.old_path
                if index >= max_changed_files:
                    gaps.append({"reason": "changed_file_budget_exceeded", "path": path, "parent_sha": parent})
                    continue
                change = _record_file(str(repo_path), sha, parent, modified, backend, fallback,
                                      max_source_bytes, gaps, metrics, object_state)
                metrics["files_extracted"] += 1
                extension = PurePosixPath(path or "").suffix.lower()
                change["language"] = LANGUAGES.get(extension)
                change["analysis_status"] = "supported_language" if extension in LANGUAGES else (
                    "unsupported_language" if extension in CODE_EXTENSIONS else "non_code_or_unrecognized_extension")
                if change["analysis_status"] == "unsupported_language":
                    gaps.append({"reason": "unsupported_language", "path": path, "parent_sha": parent})
                changes.append(change)
            records.append(("comparisons", {"parent_sha": parent, "diff_backend": backend,
                            "fallback_reason": fallback, "modified_files": len(modified_files)}))
        except Exception as exc:
            gaps.append({"reason": "commit_diff_error", "exception_type": type(exc).__name__,
                         "parent_sha": parent, "diff_backend": backend, "fallback_reason": fallback})
        for side, revision, path_key, lines_key in (("before", parent, "old_path", "deleted"),
                                                    ("after", sha, "new_path", "added")):
            sources, changed = {}, {}
            for change in changes:
                path, source = change[path_key], change[side + "_source"]
                if path and isinstance(source, str) and change["language"]:
                    sources[path] = source
                    changed[path] = {int(line[0]) for line in change[lines_key]}
            if not revision or not sources:
                continue
            snapshot = _snapshot(str(repo_path), revision, sources, max_dependency_files,
                                 max_source_bytes, gaps, metrics, side)
            try:
                detection = detect_snapshot(snapshot, list(set(LANGUAGES.values())))
            except Exception as exc:
                gaps.append({"reason": "snapshot_detection_error", "exception_type": type(exc).__name__, "side": side})
                continue
            gaps.extend({"reason": "parse_or_semantic_gap", "side": side, **gap} for gap in detection["gaps"])
            for entity in detection["entities"]:
                direct, indirect = _intersects(entity, changed)
                if not direct and not indirect:
                    continue
                metrics["log_observations"] += 1
                records.append(("log_observations", {"parent_sha": parent, "side": side,
                    "snapshot_sha": revision, "entity": entity,
                    "change_basis": "statement_lines" if direct else "one_hop_dependency_lines",
                    "log_version_id": stable_id(repository, revision, entity["path"], entity["identity"],
                        entity["start_line"], entity.get("start_col"), entity["end_line"], entity.get("end_col")),
                    "diff_backend": backend, "fallback_reason": fallback,
                    "dependency_source_backend": "gitpython.blob_auxiliary_at_pydriller_commit",
                    "context_join_fields": ["repository", "sha"]}))
        for change in changes:
            # Whole historical source stays transient; complete log evidence is retained.
            audit = {key: value for key, value in change.items() if key not in {"before_source", "after_source"}}
            for side in ("before", "after"):
                source = change[side + "_source"]
                audit[side + "_source_fingerprint"] = stable_id(source) if source is not None else None
            records.append(("file_audit", audit))
    for gap in gaps:
        records.append(("gaps", gap))
    metadata = {"parents": commit.parents, "merge": commit.merge, "metrics": dict(metrics),
                "object_state": object_state, "taxonomy_version": TAXONOMY_VERSION,
                "analysis_limits": {"max_source_bytes": max_source_bytes,
                    "max_changed_files": max_changed_files, "max_dependency_blob_reads": max_dependency_files},
                "status": "partial" if gaps else "complete", "gap_count": len(gaps),
                "no_changed_logs_detected": not metrics["log_observations"],
                "no_changed_logs_is_safety_claim": False}
    return metadata, records


def _summary(db):
    statuses = {row[0]: row[1] for row in db.execute("SELECT status,COUNT(*) FROM jobs GROUP BY status")}
    metrics = Counter()
    for row in db.execute("SELECT data FROM jobs WHERE status IN ('complete','partial','blocked')"):
        metrics.update(json.loads(row[0]).get("metrics", {}))
    count = lambda table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    complete = not any(value for key, value in statuses.items() if key != "complete") and not count("input_gaps")
    return {**SCOPE, "taxonomy_version": TAXONOMY_VERSION, "commit_status_counts": statuses,
        "actual_extraction_metrics": dict(metrics),
        "file_analysis_status_counts": {row[0]: row[1] for row in db.execute(
            "SELECT json_extract(data,'$.analysis_status'),COUNT(*) FROM records WHERE kind='file_audit' GROUP BY 1")},
        "status": "complete_within_declared_scope" if complete else "incomplete_or_gaps",
        "exit_code": 0 if complete else 2,
        "unique_dataset_commits": count("jobs"), "context_associations": count("contexts"),
        "input_gap_count": count("input_gaps"),
        "record_counts": {row[0]: row[1] for row in db.execute("SELECT kind,COUNT(*) FROM records GROUP BY kind")},
        "queue_exhausted": not statuses.get("pending", 0) and not statuses.get("running", 0),
        "all_dataset_commits_analyzed_without_gaps": bool(statuses.get("complete")) and not any(
            value for key, value in statuses.items() if key != "complete"),
        "denominator_note": "Unique supplied repository+SHA jobs only; contexts are associations, not independent observations. PRs without commit evidence are separate input gaps. This is not the full AIDev population denominator.",
        "evidence_boundary": "Static changed-code candidates only. Unchanged reverse dependents outside directly imported files and full follow-up histories are not examined."}


def run_batch(batch_dir, cache_dir, *, offline=True, max_repositories=None,
              max_seconds=None, workers=1, retry_failed=False, max_source_bytes=2097152,
              max_changed_files=2000, max_dependency_files=40, git_timeout=120) -> dict:
    """Run a single bounded worker, resume atomically at commit boundaries.

    max_seconds is a soft budget checked between commits/acquisitions, not a
    promise to interrupt an individual PyDriller extraction. Exceptions persist
    a blocked job; process interruption leaves the current job pending on resume.
    """
    if workers != 1:
        raise ValueError("This minimal worker supports workers=1; use separate batch directories for independent shards")
    if any(value < 1 for value in (max_source_bytes, max_changed_files, git_timeout)) or max_dependency_files < 0:
        raise ValueError("Invalid extraction budget")
    if (max_repositories is not None and max_repositories < 0) or (max_seconds is not None and max_seconds < 0):
        raise ValueError("Run budgets must be nonnegative")
    disable_implicit_fetch()
    started, processed, repositories = time.monotonic(), 0, 0
    out_of_time = lambda: max_seconds is not None and time.monotonic() - started >= max_seconds
    with _database(batch_dir) as db:
        fingerprint = {"source_sha256": {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
            for name in ("batch_mine.py", "detector.py", "taxonomy.py", "miner.py", "git_support.py", "storage.py", "type_audit.py")},
            "pydriller_version": version("pydriller"), "max_source_bytes": max_source_bytes,
            "max_changed_files": max_changed_files, "max_dependency_files": max_dependency_files}
        prior = db.execute("SELECT data FROM metadata WHERE key='analysis_fingerprint'").fetchone()
        if prior and json.loads(prior[0]) != fingerprint:
            raise ValueError("Analysis code or extraction parameters changed; use a new batch directory to avoid mixing classifications")
        db.execute("INSERT OR IGNORE INTO metadata VALUES('analysis_fingerprint',?)", (canonical(fingerprint),))
        db.execute("UPDATE jobs SET status='pending' WHERE status='running'")
        if retry_failed:
            db.execute("UPDATE jobs SET status='pending' WHERE status IN ('blocked','partial')")
        db.commit()
        repo_cursor = db.execute("SELECT DISTINCT repository FROM jobs WHERE status='pending' ORDER BY repository")
        for repo_row in repo_cursor:
            if out_of_time() or (max_repositories is not None and repositories >= max_repositories):
                break
            repository = repo_row[0]
            repositories += 1
            try:
                repo_path, owned = _prepare_repository(db, repository, cache_dir, offline, git_timeout)
                prepare_error = None
            except Exception as exc:
                repo_path, owned, prepare_error = None, False, type(exc).__name__
            jobs = db.execute("SELECT sha FROM jobs WHERE repository=? AND status='pending' ORDER BY rowid", (repository,))
            for job in jobs:
                if out_of_time():
                    break
                sha = job[0]
                db.execute("UPDATE jobs SET status='running',attempts=attempts+1 WHERE repository=? AND sha=?", (repository, sha))
                db.commit()
                try:
                    if prepare_error:
                        raise FileNotFoundError(prepare_error)
                    if not resolve_ref(str(repo_path), sha) and not offline and owned:
                        _acquire_git(["-C", str(repo_path), "fetch", "--no-tags", "--",
                                     f"https://github.com/{repository}.git", sha], git_timeout, repo_path)
                    if resolve_ref(str(repo_path), sha) != sha:
                        raise ValueError("exact_commit_object_unavailable")
                    metadata, records = _mine_commit(repo_path, repository, sha,
                        max_source_bytes=max_source_bytes, max_changed_files=max_changed_files,
                        max_dependency_files=max_dependency_files)
                except Exception as exc:
                    metadata = {"status": "blocked", "exception_type": type(exc).__name__,
                        "reason": "repository_unavailable" if prepare_error else "commit_extraction_unavailable",
                        "offline": offline, "metrics": {}, "taxonomy_version": TAXONOMY_VERSION}
                    records = [("gaps", {"reason": metadata["reason"], "exception_type": type(exc).__name__,
                                          "retryable": True})]
                metadata = {**SCOPE, "repository": repository, "sha": sha, **metadata}
                metadata["analysis_fingerprint"] = stable_id(fingerprint)
                with db:
                    db.execute("DELETE FROM records WHERE repository=? AND sha=?", (repository, sha))
                    for kind, record in records:
                        item = {**SCOPE, "repository": repository, "sha": sha, **record}
                        identifier = stable_id(kind, item)
                        db.execute("INSERT OR REPLACE INTO records VALUES(?,?,?,?,?)", (repository, sha, kind,
                            identifier, canonical({"id": identifier, **item})))
                    db.execute("UPDATE jobs SET status=?,data=? WHERE repository=? AND sha=?",
                               (metadata["status"], canonical(metadata), repository, sha))
                processed += 1
        summary = {**_summary(db), "this_run_commits_attempted": processed,
                   "this_run_repositories_attempted": repositories, "offline": offline,
                   "budget_stopped": out_of_time() or (max_repositories is not None and repositories >= max_repositories
                                                         and bool(_summary(db)["commit_status_counts"].get("pending")))}
        db.execute("INSERT OR REPLACE INTO metadata VALUES('last_run',?)", (canonical(summary),))
        db.commit()
    summary.update(export_batch(batch_dir))
    return summary


def _stream_jsonl(path, rows):
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            for row in rows:
                stream.write(canonical(redact(row)) + "\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def export_batch(batch_dir) -> dict:
    """Stream redacted JSONL from the committed checkpoint, including pending work."""
    directory = Path(batch_dir) / "exports"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _database(batch_dir) as db:
        for kind in ("log_observations", "file_audit", "comparisons", "gaps"):
            _stream_jsonl(directory / (kind + ".jsonl"), (json.loads(row[0]) for row in db.execute(
                "SELECT data FROM records WHERE kind=? ORDER BY repository,sha,id", (kind,))))
        for table in ("contexts", "input_gaps"):
            _stream_jsonl(directory / (table + ".jsonl"), (json.loads(row[0]) for row in db.execute(
                f"SELECT data FROM {table} ORDER BY id")))
        def jobs(pending_only=False):
            for row in db.execute("SELECT * FROM jobs" + (" WHERE status IN ('pending','running')" if pending_only else "")
                                  + " ORDER BY repository,sha"):
                yield {**SCOPE, **json.loads(row["data"]), "repository": row["repository"], "sha": row["sha"],
                       "status": row["status"], "attempts": row["attempts"]}
        _stream_jsonl(directory / "commit_audit.jsonl", jobs())
        _stream_jsonl(directory / "pending_commits.jsonl", jobs(True))
        summary = {**_summary(db), "type_audit": export_batch_types(db, directory)}
        atomic_write(directory / "summary.json", canonical(redact(summary)) + "\n")
        atomic_write(directory / "taxonomy_catalog.json", canonical(taxonomy_catalog()) + "\n")
    return summary
