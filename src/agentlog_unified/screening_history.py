"""Read-only population recovery and exact historical-source adapters.

Legacy results are provenance/stratification evidence, never current source or
final verdict caches. Raw blobs are written only beneath a new run's private
directory. No target checkout, hook, textconv, external diff or fetch is used.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
from .paths import resolve_path, PurePosixPath
import re
import sqlite3
import subprocess
import tempfile
import time

from git.cmd import Git as GitCommand
from pydriller import Git, Repository

from .batch_mine import repository_cache_path
from .git_support import diff_paths, disable_implicit_fetch, merge_diff_fallback
from .miner import _record_file
from .storage import atomic_write, canonical, stable_id

HISTORY_VERSION = "screening-history-1"
COMPARISON_STRATEGY = "first_parent"
MAX_SOURCE_BYTES = 2097152
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def _digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_rows(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            for row in rows:
                stream.write(canonical(row) + "\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _json_rows(path):
    with Path(path).open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def _read_database(path):
    # mode=ro does not create journals or alter checkpoints. Do not use the old
    # batch._database helper here: that helper creates schema/locks/exports.
    db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


def classify_file_scope(path):
    parts = [part.lower() for part in PurePosixPath(path or "").parts]
    name = parts[-1] if parts else ""
    if any(p in {"tests", "test", "__tests__", "fixtures", "__fixtures__", "testdata"}
           for p in parts) or name.startswith("test_") or ".test." in name or ".spec." in name:
        return "test"
    if any(p in {"examples", "example", "samples", "sample", "demo", "demos"} for p in parts):
        return "example"
    if any(p in {"vendor", "node_modules", "dist", "build", "generated", "__generated__"}
           for p in parts) or name.endswith((".min.js", ".generated.py", ".g.go")):
        return "generated_or_vendor"
    if any(p in {"scripts", "tools", ".github", ".claude", ".codex"} for p in parts):
        return "development_tool"
    return "application_or_unknown"


def _stratum(observations):
    if any(row.get("privacy_assessment") in {"supported", "conditional"} for row in observations):
        return "legacy_candidate"
    if any(row.get("privacy_assessment") in {"unknown", "insufficient_evidence"}
           or row.get("unknown_needs_review") for row in observations):
        return "legacy_unknown"
    return "legacy_no_hit" if observations else "legacy_no_log_observation"


def recover_population(project, old_root, output) -> dict:
    """Recover all frozen commit inputs and all legacy first-parent file events.

    Returns paths/counts, including all blocked/pending/excluded jobs. Missing
    file events remain commit-level gaps: no fictional file or output is added.
    The two source versions of each event remain distinct, including normally
    absent sides. Old source status is explicitly unverified until blob reading.
    """
    project, old_root, output = (Path(p).resolve() for p in (project, old_root, output))
    if output == old_root or old_root in output.parents:
        raise ValueError("output_must_not_mutate_frozen_experiment")
    input_path = old_root / "final/input.jsonl"
    database = old_root / "final/batch/batch.sqlite"
    prep_path = old_root / "preparation.json"
    if not all(p.is_file() for p in (input_path, database, prep_path)):
        raise FileNotFoundError("frozen_full_population_inputs_unavailable")
    prep = json.loads(prep_path.read_text())
    input_hash = _digest(input_path)
    expected_hash = prep.get("fingerprint", {}).get("input_sha256")
    if not expected_hash or input_hash != expected_hash:
        raise ValueError("frozen_input_sha256_mismatch")
    canonical_input = project/"data/inputs/swechat-full-v3/commit_contexts.jsonl"
    canonical_match = canonical_input.is_file() and _digest(canonical_input) == input_hash
    database_hash = _digest(database)
    cache_paths = {row["repository"].lower(): str(resolve_path(row["cache"], project=project)) for row in prep.get("repositories", [])}
    inputs, input_map, expected_jobs = [], defaultdict(list), set()
    for line_number, row in enumerate(_json_rows(input_path), 1):
        repository = str(row.get("repository", "")).lower()
        shas = row.get("commit_shas") or ([row["sha"]] if row.get("sha") else [])
        identifier = stable_id(HISTORY_VERSION, input_hash, line_number, row)
        valid = bool(re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", repository))
        exact = [sha.lower() for sha in shas if isinstance(sha, str) and _SHA.fullmatch(sha.lower())]
        if len(exact) != len(shas):
            valid = False
        record = {"input_record_id": identifier, "dataset": row.get("dataset", "unknown"),
            "dataset_snapshot": row.get("swechat_source_snapshot"), "input_sha256": input_hash,
            "input_line": line_number, "original_record_id": row.get("source_context_id"),
            "repository": repository, "commit_shas": exact, "source_rows": row.get("source_rows", []),
            "session_ids": row.get("session_ids", []), "checkpoint_pks": row.get("checkpoint_pks", []),
            "provided_agent_names": row.get("provided_agent_names", []),
            "attribution_granularity": "commit_association", "verified_actor_type": "unknown",
            "processing_status": "pending" if valid and exact else "blocked",
            "reason": None if valid and exact else "invalid_or_missing_exact_commit_evidence"}
        inputs.append(record)
        if valid:
            for sha in exact:
                input_map[repository, sha].append(identifier)
                expected_jobs.add((repository, sha))
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    commits, job_map, gaps, observations, file_versions = [], {}, [], [], []
    by_file = defaultdict(list)
    with _read_database(database) as db:
        for row in db.execute("SELECT repository,sha,status,attempts,data FROM jobs ORDER BY repository,sha"):
            metadata = json.loads(row["data"])
            repository, sha = row["repository"], row["sha"]
            parents = metadata.get("parents")
            parent = parents[0] if parents else None
            commit_id = stable_id(HISTORY_VERSION, repository, sha, COMPARISON_STRATEGY, parent)
            item = {"commit_id": commit_id, "repository": repository, "sha": sha,
                "parents": parents, "parent_sha": parent, "parents_state": "legacy_recorded" if parents is not None else "unknown",
                "comparison_strategy": COMPARISON_STRATEGY, "uncompared_parents": parents[1:] if parents else [],
                "input_record_ids": input_map.get((repository, sha), []),
                "repo_path": cache_paths.get(repository, str(repository_cache_path(project/"data/cache/swechat-full-20260912", repository))),
                "legacy_status": row["status"], "legacy_attempts": row["attempts"],
                "legacy_metrics": metadata.get("metrics", {}), "legacy_gap_count": metadata.get("gap_count"),
                "processing_status": "pending", "reason": "requires_full_changed_file_source_scan",
                "legacy_no_changed_logs_detected": metadata.get("no_changed_logs_detected"),
                "legacy_analysis_fingerprint": metadata.get("analysis_fingerprint"),
                "legacy_record_source": str(database), "file_event_count": 0,
                "runtime_confirmed": False}
            if row["status"] in {"blocked", "pending", "running"}:
                item.update(processing_status="blocked" if row["status"] == "blocked" else "pending",
                            reason=metadata.get("reason", "legacy_commit_not_completed"))
            commits.append(item)
            job_map[repository, sha] = item
        actual_jobs = set(job_map)
        if actual_jobs != expected_jobs:
            raise ValueError("frozen_input_and_commit_population_mismatch")
        for record in db.execute("SELECT data FROM records WHERE kind='log_observations' ORDER BY repository,sha,id"):
            row = json.loads(record[0])
            commit = job_map[row["repository"], row["sha"]]
            if row.get("parent_sha") != commit["parent_sha"]:
                continue
            entity = row.get("entity", {})
            item = {"legacy_log_id": row["id"], "legacy_log_version_id": row.get("log_version_id"),
                "repository": row["repository"], "sha": row["sha"], "parent_sha": row.get("parent_sha"),
                "side": row.get("side"), "source_sha": row.get("snapshot_sha"), "path": entity.get("path"),
                "start_line": entity.get("start_line"), "end_line": entity.get("end_line"),
                "privacy_assessment": entity.get("privacy_assessment"),
                "unknown_needs_review": entity.get("unknown_type_review", {}).get("needs_review", False),
                "legacy_change_basis": row.get("change_basis"), "final_label_inherited": False}
            observations.append(item)
            by_file[row["repository"], row["sha"], row.get("parent_sha"), row.get("side"), entity.get("path")].append(item)
        for record in db.execute("SELECT data FROM records WHERE kind='file_audit' ORDER BY repository,sha,id"):
            row = json.loads(record[0])
            commit = job_map[row["repository"], row["sha"]]
            if row.get("parent_sha") != commit["parent_sha"]:
                continue
            commit["file_event_count"] += 1
            for side, source_sha, path in (("before", commit["parent_sha"], row.get("old_path")),
                                          ("after", row["sha"], row.get("new_path"))):
                old_logs = by_file.get((row["repository"], row["sha"], row.get("parent_sha"), side, path), [])
                legacy_status = row.get("source_status", {}).get(side, "unknown")
                event_path = path or row.get("new_path") or row.get("old_path")
                item = {"file_version_id": stable_id(HISTORY_VERSION, commit["commit_id"], side,
                                                     source_sha, row.get("old_path"), row.get("new_path")),
                    "commit_id": commit["commit_id"], "repository": row["repository"], "sha": row["sha"],
                    "parents": commit["parents"], "parent_sha": commit["parent_sha"],
                    "comparison_strategy": COMPARISON_STRATEGY, "side": side, "source_sha": source_sha,
                    "path": path, "old_path": row.get("old_path"), "new_path": row.get("new_path"),
                    "change_type": row.get("change_type"), "repo_path": commit["repo_path"],
                    "language": row.get("language"), "scope": classify_file_scope(event_path),
                    "legacy_analysis_status": row.get("analysis_status"),
                    "legacy_source_status": legacy_status, "source_state": "unverified_cached",
                    "legacy_source_fingerprint": row.get(side + "_source_fingerprint"),
                    "source_sha256": None, "blob_oid": None, "source_path": None,
                    "processing_status": "pending", "reason": "exact_blob_not_read_this_run",
                    "old_log_ids": [log["legacy_log_id"] for log in old_logs],
                    "old_stratum": _stratum(old_logs), "input_record_ids": commit["input_record_ids"],
                    "legacy_record_id": row["id"], "legacy_diff_backend": row.get("diff_backend")}
                file_versions.append(item)
        for record in db.execute("SELECT data FROM records WHERE kind='gaps' ORDER BY repository,sha,id"):
            row = json.loads(record[0])
            # Deliberately avoid raw diff, exception text, URLs or source snippets.
            gaps.append({key: row.get(key) for key in ("id", "repository", "sha", "parent_sha", "path",
                "side", "reason", "error_type", "exception_type", "retryable", "status")})
        for record in db.execute("SELECT id,data FROM input_gaps ORDER BY id"):
            raw = json.loads(record["data"])
            gaps.append({"id": record["id"], "level": "input", "reason": raw.get("reason"),
                         "input_line": raw.get("line_number")})
    for row in inputs:
        matches = [job_map.get((row["repository"], sha)) for sha in row["commit_shas"]]
        row["commit_ids"] = [item["commit_id"] for item in matches if item]
        if row["commit_ids"]:
            row.update(processing_status="success", reason="mapped_to_commit_ledger")
    names = {"input_records": inputs, "commits": commits, "file_versions": file_versions,
             "old_log_observations": observations, "legacy_gaps": gaps}
    paths = {}
    for name, rows in names.items():
        path = output / (name + ".jsonl")
        _write_rows(path, rows)
        paths[name] = str(path)
    summary = {"history_version": HISTORY_VERSION, "population_scope": "full_frozen_commit_input",
        "candidate_only": False, "input_rows": len(inputs), "commits": len(commits),
        "repositories": len({row["repository"] for row in commits}),
        "file_events": sum(row["file_event_count"] for row in commits), "file_versions": len(file_versions),
        "legacy_first_parent_log_observations": len(observations), "legacy_gaps": len(gaps),
        "commit_legacy_status_counts": dict(Counter(row["legacy_status"] for row in commits)),
        "file_language_counts": dict(Counter(row["language"] or "unrecognized" for row in file_versions)),
        "legacy_source_status_counts": dict(Counter(row["legacy_source_status"] for row in file_versions)),
        "commits_without_file_events": sum(not row["file_event_count"] for row in commits),
        "input_sha256": input_hash, "database_sha256": database_hash,
        "canonical_input_hash_matches": canonical_match, "comparison_strategy": COMPARISON_STRATEGY,
        "paths": paths, "output_sha256": {name: _digest(path) for name, path in paths.items()},
        "limitations": ["Legacy log observations used diff or direct-dependency intersections; full-source discovery must run anew.",
            "Legacy file events retain known gaps and may omit files when extraction or changed-file budgets failed.",
            "No historical source is marked present merely from old cached status.",
            "First-parent comparison excludes other merge-parent changes.",
            "No reverse impact analysis of unchanged log files is implied."]}
    if _digest(database) != database_hash or _digest(input_path) != input_hash:
        raise ValueError("frozen_source_changed_during_recovery")
    atomic_write(output / "population_summary.json", canonical(summary) + "\n")
    return summary


def _git_prefix(repo_path):
    return ["git", "--no-pager", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "protocol.allow=never", "-C", str(Path(repo_path).resolve())]


def _git(repo_path, *args):
    return subprocess.run(_git_prefix(repo_path) + list(args), capture_output=True, timeout=120,
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"})


def _valid_source_spec(sha, path):
    return bool(isinstance(sha, str) and _SHA.fullmatch(sha) and isinstance(path, str)
                and path and "\x00" not in path and "\n" not in path and "\r" not in path
                and not path.startswith("/") and ".." not in PurePosixPath(path).parts)


def _missing_state(repo_path, sha, path):
    if _git(repo_path, "cat-file", "-e", sha + "^{tree}").returncode:
        return "object_unavailable", "historical_commit_or_tree_unavailable"
    found = _git(repo_path, "ls-tree", "-z", sha, "--", path)
    if found.returncode:
        return "object_unavailable", "historical_path_tree_unavailable"
    if not found.stdout:
        return "absent_verified", "path_absent_in_exact_historical_tree"
    return "object_unavailable", "historical_blob_unavailable"


def _store_source(out, raw):
    digest = hashlib.sha256(raw).hexdigest()
    target = Path(out).resolve() / "private/sources" / digest[:2] / (digest + ".txt")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # A hash-named cache hit is accepted only after content verification.
    hit = target.is_file() and _digest(target) == digest
    if not hit:
        atomic_write(target, raw.decode("utf-8"))
    os.chmod(target, 0o600)
    return str(target), digest, hit


def iter_historical_sources(repo_path, file_versions, out, max_bytes=MAX_SOURCE_BYTES):
    """Yield verified file versions using one safe Git cat-file batch process.

    This is explicitly Git auxiliary source reading, not PyDriller mining. Exact
    SHA:path resolution yields a blob OID and content hash. Returned source_path
    contains private UTF-8 text; consumers should not print or publish the text.
    Normal absence, missing objects, binary/decode failures remain distinguishable.
    """
    if max_bytes < 1:
        raise ValueError("invalid_source_byte_budget")
    disable_implicit_fetch()
    with subprocess.Popen(_git_prefix(repo_path) + ["cat-file", "--batch"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}) as process:
        try:
            for original in file_versions:
                tick = time.monotonic()
                row = {**original, "source_backend": "git.cat-file.batch_exact_sha_path_auxiliary",
                       "source_sha256": None, "source_path": None, "blob_oid": None,
                       "source_cache_hit": False}
                sha, path = row.get("source_sha"), row.get("path")
                intended_absent = path is None
                if intended_absent:
                    path = row.get("new_path") if row.get("side") == "before" else row.get("old_path")
                if sha is None and row.get("side") == "before" and row.get("parents") == []:
                    # The event's root designation is checked against the actual
                    # commit object, not inferred from PyDriller's null source.
                    header = _git(repo_path, "cat-file", "commit", row.get("sha", ""))
                    if header.returncode:
                        state, reason = "object_unavailable", "root_commit_object_unavailable"
                    elif any(line.startswith(b"parent ") for line in header.stdout.split(b"\n\n", 1)[0].splitlines()):
                        state, reason = "extraction_failed", "root_parent_context_mismatch"
                    else:
                        state, reason = "absent_verified", "verified_root_empty_before_tree"
                    row.update(source_state=state, reason=reason)
                elif not _valid_source_spec(sha, path):
                    row.update(source_state="extraction_failed", reason="invalid_or_missing_exact_source_spec")
                else:
                    spec = (sha + ":" + path).encode("utf-8")
                    try:
                        process.stdin.write(spec + b"\n")
                        process.stdin.flush()
                        header = process.stdout.readline()
                        fields = header.rstrip(b"\n").rsplit(b" ", 2)
                        if header.endswith(b" missing\n"):
                            state, reason = _missing_state(repo_path, sha, path)
                            row.update(source_state=state, reason=reason)
                        elif len(fields) == 3 and fields[1] in {b"blob", b"tree", b"commit", b"tag"}:
                            oid, kind, size = fields[0].decode("ascii"), fields[1], int(fields[2])
                            # Drain the entire object to preserve protocol sync;
                            # retain at most the configured source byte budget.
                            remain, chunks = size, []
                            while remain:
                                chunk = process.stdout.read(min(remain, 1024 * 1024))
                                if not chunk:
                                    raise EOFError("cat_file_body_truncated")
                                if size <= max_bytes:
                                    chunks.append(chunk)
                                remain -= len(chunk)
                            if process.stdout.read(1) != b"\n":
                                raise ValueError("cat_file_protocol_terminator")
                            row["blob_oid"] = oid
                            if intended_absent:
                                row.update(source_state="extraction_failed", reason="expected_absent_path_is_present")
                            elif kind != b"blob":
                                row.update(source_state="extraction_failed", reason="non_blob_source")
                            elif size > max_bytes:
                                row.update(source_state="extraction_failed", reason="source_byte_budget_exceeded")
                            else:
                                raw = b"".join(chunks)
                                try:
                                    raw.decode("utf-8")
                                    if b"\x00" in raw:
                                        raise ValueError("binary")
                                    source_path, digest, hit = _store_source(out, raw)
                                    # Git identity is independently recomputed,
                                    # so exact SHA/path lookup is not the sole check.
                                    algorithm = hashlib.sha1 if len(oid) == 40 else hashlib.sha256
                                    actual_oid = algorithm(b"blob " + str(size).encode() + b"\0" + raw).hexdigest()
                                    if actual_oid != oid:
                                        raise ValueError("blob_oid_mismatch")
                                    expected = original.get("source_sha256")
                                    if expected and expected != digest:
                                        row.update(source_state="extraction_failed", reason="historical_source_sha256_mismatch")
                                    else:
                                        row.update(source_state="present", reason=None, source_path=source_path,
                                                   source_sha256=digest, source_cache_hit=hit, source_bytes=size)
                                except UnicodeDecodeError:
                                    row.update(source_state="extraction_failed", reason="source_utf8_decode_error")
                                except ValueError as exc:
                                    row.update(source_state="extraction_failed", reason=str(exc))
                        else:
                            row.update(source_state="object_unavailable", reason="cat_file_no_object_response")
                    except (OSError, ValueError, EOFError) as exc:
                        row.update(source_state="extraction_failed", reason="cat_file_protocol_error",
                                   exception_type=type(exc).__name__)
                row["processing_status"] = ("success" if row["source_state"] in {"present", "absent_verified"} else "blocked")
                row["source_read_seconds"] = round(time.monotonic() - tick, 6)
                yield row
        finally:
            if process.stdin:
                process.stdin.close()
            if process.poll() is None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


@contextmanager
def _safe_pydriller_commands():
    """Add missing textconv protection to real PyDriller/GitPython diff calls.

    GitPython already sets --no-ext-diff for patch extraction, but PyDriller's
    stock calls do not set --no-textconv. This scoped command adapter supplies
    both protections and never modifies target Git configuration on disk.
    """
    execute = GitCommand.execute
    def safe_execute(self, command, *args, **kwargs):
        if isinstance(command, (list, tuple)):
            command = list(command)
            for index, word in enumerate(command):
                if word in {"diff", "diff-tree"}:
                    command[index + 1:index + 1] = ["--no-ext-diff", "--no-textconv"]
                    break
            command[1:1] = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                            "-c", "protocol.allow=never"]
        return execute(self, command, *args, **kwargs)
    GitCommand.execute = safe_execute
    try:
        yield
    finally:
        GitCommand.execute = execute


def extract_commit(repo_path, repository, sha, out) -> dict:
    """Actually call PyDriller, then verify complete before/after source blobs.

    Only the explicitly supplied exact commit and its first parent are mined.
    Result files contain private source paths; full text/diffs are not copied
    into shareable audit JSON. All parents and auxiliary/fallback calls are kept.
    """
    started = time.monotonic()
    out, repo_path = Path(out).resolve(), Path(repo_path).resolve()
    repository = repository.lower()
    if not _SHA.fullmatch(sha):
        raise ValueError("full_exact_commit_sha_required")
    if out == repo_path or repo_path in out.parents:
        raise ValueError("output_must_not_mutate_target_repository")
    disable_implicit_fetch()
    audit = {"history_version": HISTORY_VERSION, "repository": repository, "sha": sha,
        "pydriller_version": version("PyDriller"), "gitpython_version": version("GitPython"),
        "entry": "pydriller.Repository(...).traverse_commits",
        "parameters": {"path_to_repo": str(repo_path), "single": sha, "num_workers": 1},
        "started_at": datetime.now(timezone.utc).isoformat(), "metrics": {},
        "comparison_strategy": COMPARISON_STRATEGY,
        "protections": ["no_lazy_fetch", "protocol_allow_never", "hooks_disabled", "fsmonitor_disabled",
                        "no_ext_diff", "no_textconv", "no_checkout", "no_target_execution"]}
    metrics, gaps = defaultdict(int), []
    result = {"repository": repository, "sha": sha, "parents": None, "parent_sha": None,
              "comparison_strategy": COMPARISON_STRATEGY, "files": [], "file_versions": [],
              "status": "blocked", "gaps": gaps, "audit": audit}
    try:
        header = _git(repo_path, "cat-file", "commit", sha)
        if header.returncode:
            raise ValueError("exact_commit_object_unavailable")
        parents = [line[7:].decode("ascii") for line in header.stdout.split(b"\n\n", 1)[0].splitlines()
                   if line.startswith(b"parent ")]
        parent = parents[0] if parents else None
        result.update(parents=parents, parent_sha=parent, uncompared_parents=parents[1:])
        with _safe_pydriller_commands():
            metrics["pydriller_repository_traversals"] += 1
            commits = list(Repository(str(repo_path), single=sha, num_workers=1).traverse_commits())
            if len(commits) != 1 or commits[0].hash != sha:
                raise ValueError("exact_commit_traversal_mismatch")
            commit = commits[0]
            metrics["pydriller_commits"] += 1
            if list(commit.parents) != parents:
                raise ValueError("pydriller_parent_context_mismatch")
            backend, fallback = "pydriller.Commit.modified_files", None
            if len(parents) > 1:
                metrics["pydriller_git_diff_calls"] += 1
                expected = diff_paths(str(repo_path), parent, sha)
                try:
                    modified = Git(str(repo_path)).diff(parent, sha)
                    if {(m.old_path, m.new_path) for m in modified} != expected:
                        raise ValueError("merge_path_set_mismatch")
                    backend = "pydriller.Git.diff"
                except Exception as exc:
                    modified = merge_diff_fallback(str(repo_path), parent, sha)
                    backend, fallback = "gitpython.explicit_parent_diff+pydriller.ModifiedFile", type(exc).__name__
                    metrics["merge_fallbacks"] += 1
                    if {(m.old_path, m.new_path) for m in modified} != expected:
                        raise ValueError("merge_fallback_path_set_mismatch")
            else:
                metrics["pydriller_modified_files_calls"] += 1
                modified = commit.modified_files
            audit.update(diff_backend=backend, fallback_reason=fallback, modified_file_count=len(modified))
            raw_changes = [_record_file(str(repo_path), sha, parent, m, backend, fallback,
                           MAX_SOURCE_BYTES, gaps, metrics, {}) for m in modified]
        flat = []
        for change in raw_changes:
            event_id = stable_id(HISTORY_VERSION, repository, sha, parent, change["old_path"], change["new_path"])
            public = {key: change.get(key) for key in ("old_path", "new_path", "change_type", "diff_backend",
                "fallback_reason", "source_backends", "source_status", "extraction_status")}
            public.update(file_event_id=event_id, diff_sha256=hashlib.sha256((change.get("diff") or "").encode()).hexdigest(),
                          added_line_numbers=[row[0] for row in change["added"]],
                          deleted_line_numbers=[row[0] for row in change["deleted"]])
            for side, source_sha, path in (("before", parent, change["old_path"]), ("after", sha, change["new_path"])):
                item = {"file_version_id": stable_id(HISTORY_VERSION,
                        stable_id(HISTORY_VERSION, repository, sha, COMPARISON_STRATEGY, parent), side,
                        source_sha, change["old_path"], change["new_path"]),
                    "file_event_id": event_id, "repository": repository, "sha": sha, "parents": parents,
                    "parent_sha": parent, "side": side, "source_sha": source_sha, "path": path,
                    "old_path": change["old_path"], "new_path": change["new_path"],
                    "change_type": change["change_type"], "comparison_strategy": COMPARISON_STRATEGY,
                    "pydriller_source_status": change["source_status"][side],
                    "pydriller_source_backend": change["source_backends"][side],
                    "_pydriller_text": change.get(side + "_source")}
                flat.append(item)
            result["files"].append(public)
        for row in iter_historical_sources(repo_path, flat, out):
            source = row.pop("_pydriller_text", None)
            if row["source_state"] == "present" and isinstance(source, str):
                agrees = hashlib.sha256(source.encode()).hexdigest() == row["source_sha256"]
                row["pydriller_exact_blob_agrees"] = agrees
                if not agrees:
                    row.update(source_state="extraction_failed", processing_status="blocked", reason="pydriller_historical_source_mismatch")
            elif row["source_state"] == "present":
                row["pydriller_exact_blob_agrees"] = None
                row["source_fallback_reason"] = "pydriller_source_unavailable_exact_git_blob_verified"
            result["file_versions"].append(row)
        indexed = {(row["file_event_id"], row["side"]): row for row in result["file_versions"]}
        for item in result["files"]:
            item["before"] = indexed[item["file_event_id"], "before"]
            item["after"] = indexed[item["file_event_id"], "after"]
        if any(row["source_state"] not in {"present", "absent_verified"} for row in result["file_versions"]) or gaps:
            result["status"] = "partial"
        else:
            result["status"] = "success"
    except Exception as exc:
        gaps.append({"reason": str(exc) if isinstance(exc, ValueError) and re.fullmatch(r"[a-z0-9_]+", str(exc))
                     else "historical_extraction_failed", "exception_type": type(exc).__name__})
    audit.update(metrics=dict(metrics), elapsed_seconds=round(time.monotonic() - started, 6),
                 status=result["status"], file_versions=len(result["file_versions"]))
    path = out / "extraction" / (stable_id(repository, sha, COMPARISON_STRATEGY) + ".json")
    atomic_write(path, canonical(result) + "\n")
    result["audit_path"] = str(path)
    return result
