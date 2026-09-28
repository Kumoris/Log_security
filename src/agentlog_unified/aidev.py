"""Offline AIDev metadata census. Parquet patches never replace PyDriller evidence."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

VERSION = 1
ALIASES = {
    "id": ("id", "node_id"),
    "pr_id": ("pr_id", "pull_request_id", "pull_id"),
    "pr_number": ("number", "pr_number", "pull_number", "pull_request_number"),
    "pr_url": ("html_url", "pr_url", "pull_request_url", "url"),
    "repository": ("full_name", "repository", "repo", "repo_name", "repo_full_name"),
    "repo_id": ("repo_id", "repository_id"),
    "repo_url": ("repo_url", "repository_url"),
    "user_id": ("user_id", "author_id"),
    "user": ("user", "login", "author_login", "actor"),
    "author": ("author", "author_name"),
    "committer": ("committer", "committer_name"),
    "review_id": ("pull_request_review_id", "review_id"),
    "issue_id": ("issue_id", "related_issue_id"),
    "sha": ("sha", "commit_sha", "commit_id"),
    "filename": ("filename", "file_path", "path"),
    "patch": ("patch", "diff", "diff_patch"),
    "agent": ("agent", "agent_name", "agent_product", "provided_label"),
    "created_at": ("created_at", "created", "creation_time"),
    "closed_at": ("closed_at", "closed"),
    "merged_at": ("merged_at", "merged"),
    "state": ("state", "status"),
    "base_ref": ("base_ref", "base_branch"),
    "base_sha": ("base_sha",),
    "head_sha": ("head_sha",),
    "merge_commit_sha": ("merge_commit_sha", "merge_sha"),
    "type": ("type", "task_type"),
}
ROLES = {
    "all_pull_request": "pr", "pull_request": "pr", "human_pull_request": "pr",
    "pull_requests": "pr", "prs": "pr",
    "repository": "repository", "all_repository": "repository", "repositories": "repository",
    "user": "user", "all_user": "user", "users": "user",
    "pr_commits": "commit", "commits": "commit", "pr_commit_details": "file", "files": "file",
    "pr_reviews": "review", "reviews": "review", "pr_comments": "comment", "comments": "comment",
    "pr_review_comments": "review_comment", "pr_review_comments_v2": "review_comment",
    "pr_timeline": "timeline", "timeline": "timeline", "issue": "issue", "issues": "issue",
    "related_issue": "issue_relation", "pr_task_type": "task", "human_pr_task_type": "task",
}
PR_CHILDREN = {"commit", "file", "review", "comment", "review_comment", "timeline", "issue_relation", "task"}
CONTENT_FIELDS = {"body", "title", "message", "reason", "patch", "diff", "diff_hunk", "diff_patch"}
SHA_RE = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _text(value):
    if value is None or value == "":
        return None
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _identity(url, repo=None, number=None):
    parsed = urlparse(str(url or ""))
    pattern = r"/([^/]+/[^/]+)/pull/(\d+)/?" if parsed.hostname == "github.com" else r"/repos/([^/]+/[^/]+)/pulls/(\d+)/?" if parsed.hostname == "api.github.com" else r"(?!)"
    match = re.fullmatch(pattern, parsed.path)
    if match:
        repo, number = match.groups()
    try:
        number = int(number)
    except (TypeError, ValueError):
        return None
    if number <= 0 or not repo or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", str(repo)):
        return None
    return f"{str(repo).lower()}#{number}"


def _repo(value):
    if not value:
        return None
    value = str(value).removeprefix("https://api.github.com/repos/").removeprefix("https://github.com/").removesuffix(".git").rstrip("/")
    return value.lower() if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value) else None


def _mapping(columns, custom):
    unknown = set(custom) - set(ALIASES)
    if unknown:
        raise ValueError(f"Unknown canonical columns: {sorted(unknown)}")
    result = {}
    for key, candidates in ALIASES.items():
        if key in custom:
            candidates = [custom[key]] if isinstance(custom[key], str) else custom[key]
            if not isinstance(candidates, list) or not all(isinstance(v, str) for v in candidates):
                raise ValueError("Column mappings must be a column name or list of names")
            if not any(v in columns for v in candidates):
                raise ValueError(f"Mapped column for {key} is absent")
        result[key] = next((name for name in candidates if name in columns), None)
    return result


def _patch_status(value):
    if value is None:
        return "null"
    if not isinstance(value, str):
        return "invalid"
    if not value.strip():
        return "empty"
    # Redistribution placeholders are missing evidence, never an empty/safe diff.
    if re.search(r"(?i)^(?:[\[<({\s]*)(?:null|none|masked|redacted|removed|unavailable|not available)(?:[\]>)}\s.!_-]*$)", value.strip()) or ("@@" not in value and re.search(r"(?i)licen[cs]e|copyright|not.redistribut|patch.{0,30}(?:masked|redacted)", value)):
        return "masked"
    return "present_unverified"


def _inventory(source, mapping, pq):
    tables = []
    for path in sorted(source.rglob("*.parquet")):
        item = {"table": path.stem, "path": str(path.relative_to(source)), "bytes": path.stat().st_size, "sha256": _digest(path), "role": ROLES.get(path.stem, "unrecognized"), "rows": None, "schema": None}
        with path.open("rb") as stream:
            prefix = stream.read(512)
        if prefix.startswith(b"version https://git-lfs.github.com/spec/v1"):
            text = prefix.decode("ascii", "replace")
            oid, size = re.search(r"oid sha256:([a-f0-9]{64})", text), re.search(r"size (\d+)", text)
            item.update(status="missing_lfs_object", lfs_oid=oid[1] if oid else None, expected_bytes=int(size[1]) if size else None)
        else:
            try:
                parquet = pq.ParquetFile(path)
                item.update(status="readable", rows=parquet.metadata.num_rows, schema=[{"name": field.name, "type": str(field.type)} for field in parquet.schema_arrow])
            except Exception as exc:
                item.update(status="unreadable_parquet", error_type=type(exc).__name__)
            if item["status"] == "readable":
                item["column_mapping"] = _mapping(parquet.schema_arrow.names, mapping.get(path.stem, {}))
        tables.append(item)
    if not tables:
        raise ValueError("No local Parquet files found")
    if len({v["table"] for v in tables}) != len(tables):
        raise ValueError("Duplicate Parquet table stems are ambiguous; provide one file per table")
    unknown = set(mapping) - {v["table"] for v in tables}
    if unknown:
        raise ValueError(f"Column mapping references absent tables: {sorted(unknown)}")
    return tables


def _write(path, payload):
    path.write_text(_json(payload) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _load_rows(db, source, tables, batch_size, pq):
    db.execute("""CREATE TABLE source_rows(table_name TEXT, row_number INTEGER, role TEXT, entity_id TEXT, pr_id TEXT, repo_id TEXT, repo_url TEXT, user_id TEXT, user_login TEXT, review_id TEXT, issue_id TEXT, sha TEXT, pr_key TEXT, patch_status TEXT, metadata TEXT, PRIMARY KEY(table_name,row_number))""")
    for item in tables:
        item["rows_read"] = 0
        if item["status"] != "readable":
            continue
        mapping = item["column_mapping"]
        # Only metadata and transient patch text enter memory; bodies remain in the read-only source.
        columns = list(dict.fromkeys(name for name in mapping.values() if name))
        for batch in pq.ParquetFile(source / item["path"]).iter_batches(batch_size=batch_size, columns=columns):
            rows = []
            for raw in batch.to_pylist():
                item["rows_read"] += 1
                row = {key: raw.get(name) for key, name in mapping.items() if name}
                role = item["role"]
                if role == "task":
                    row["pr_id"] = row.get("pr_id") or row.get("id")
                if role == "repository":
                    row["repo_id"] = row.get("repo_id") or row.get("id")
                    row["repo_url"] = row.get("repo_url") or row.get("pr_url")
                key = _identity(row.get("pr_url"), _repo(row.get("repository")), row.get("pr_number"))
                if role not in PR_CHILDREN | {"pr"}:
                    key = None
                patch_status = _patch_status(row.pop("patch", None)) if role == "file" else None
                row = {k: v for k, v in row.items() if v is not None}
                if "sha" in row:
                    row["sha"] = str(row["sha"]).lower()
                rows.append((item["table"], item["rows_read"], role, _text(row.get("id")), _text(row.get("pr_id")), _text(row.get("repo_id")), _text(row.get("repo_url")), _text(row.get("user_id")), _text(row.get("user")), _text(row.get("review_id")), _text(row.get("issue_id")), _text(row.get("sha")), key, patch_status, _json(row)))
            db.executemany("INSERT INTO source_rows VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            db.commit()
        item["status"] = "complete" if item["rows_read"] == item["rows"] else "row_count_mismatch"
    for column in ("role", "entity_id", "pr_id", "pr_key", "review_id", "issue_id", "user_login"):
        db.execute(f"CREATE INDEX source_{column} ON source_rows({column}) WHERE {column} IS NOT NULL")
    db.commit()


def _link(db):
    db.executescript("""
        CREATE TABLE repository_aliases(alias TEXT, repository TEXT, PRIMARY KEY(alias,repository));
        CREATE TABLE pr_aliases(alias TEXT, pr_key TEXT, PRIMARY KEY(alias,pr_key));
        CREATE TABLE prs(pr_key TEXT PRIMARY KEY, metadata TEXT);
        CREATE TABLE row_pr_links(table_name TEXT,row_number INTEGER,pr_key TEXT,method TEXT,PRIMARY KEY(table_name,row_number));
        CREATE TABLE relationship_audit(table_name TEXT,relation TEXT,status TEXT,rows INTEGER);
    """)
    for entity, url, metadata in db.execute("SELECT entity_id,repo_url,metadata FROM source_rows WHERE role='repository'"):
        row = json.loads(metadata)
        repo = _repo(row.get("repository")) or _repo(url)
        if repo:
            for alias in (entity, url, repo):
                if alias:
                    db.execute("INSERT OR IGNORE INTO repository_aliases VALUES (?,?)", (alias, repo))
    for table, number, entity, key, metadata in db.execute("SELECT table_name,row_number,entity_id,pr_key,metadata FROM source_rows WHERE role='pr' ORDER BY table_name,row_number"):
        row = json.loads(metadata)
        if not key:
            alias = _text(row.get("repo_id") or row.get("repo_url"))
            repos = db.execute("SELECT DISTINCT repository FROM repository_aliases WHERE alias=?", (alias,)).fetchall()
            repo = repos[0][0] if len(repos) == 1 else _repo(row.get("repo_url"))
            key = _identity(row.get("pr_url"), repo, row.get("pr_number"))
        if not key:
            continue
        repo, pr_number = key.rsplit("#", 1)
        previous = db.execute("SELECT metadata FROM prs WHERE pr_key=?", (key,)).fetchone()
        value = json.loads(previous[0]) if previous else {"repository": repo, "pr_number": int(pr_number), "pr_url": f"https://github.com/{repo}/pull/{pr_number}", "provided_labels": [], "source_rows": [], "metadata_conflicts": [], "aidev_pr_ids": []}
        if entity and entity not in value["aidev_pr_ids"]:
            value["aidev_pr_ids"].append(entity)
        for field in ("created_at", "merged_at", "closed_at", "state", "base_ref", "base_sha", "head_sha", "merge_commit_sha"):
            if row.get(field) is not None:
                if value.get(field) is not None and value[field] != row[field]:
                    value["metadata_conflicts"].append({"field": field, "source_table": table, "source_row": number})
                else:
                    value[field] = row[field]
        label = row.get("agent") or ("human" if table.startswith("human_") else None)
        if label and label not in value["provided_labels"]:
            value["provided_labels"].append(label)
        value["source_rows"].append({"table": table, "row": number})
        db.execute("INSERT OR REPLACE INTO prs VALUES (?,?)", (key, _json(value)))
        db.execute("INSERT INTO row_pr_links VALUES (?,?,?,?)", (table, number, key, "pr_identity"))
        if entity:
            db.execute("INSERT OR IGNORE INTO pr_aliases VALUES (?,?)", (entity, key))
    # Ambiguous global IDs never choose an arbitrary PR. Direct URL and ID disagreement is retained as a gap.
    db.executescript("""
        CREATE VIEW unique_pr_aliases AS SELECT alias,MIN(pr_key) pr_key FROM pr_aliases GROUP BY alias HAVING COUNT(*)=1;
        INSERT OR IGNORE INTO row_pr_links
          SELECT s.table_name,s.row_number,COALESCE(p.pr_key,a.pr_key),CASE WHEN p.pr_key IS NOT NULL THEN 'pr_url' ELSE 'pr_id' END
          FROM source_rows s LEFT JOIN prs p ON s.pr_key=p.pr_key LEFT JOIN unique_pr_aliases a ON s.pr_id=a.alias
          WHERE s.role IN ('commit','file','review','comment','review_comment','timeline','issue_relation','task')
            AND COALESCE(p.pr_key,a.pr_key) IS NOT NULL AND (p.pr_key IS NULL OR a.pr_key IS NULL OR p.pr_key=a.pr_key)
            AND NOT (s.pr_id IS NOT NULL AND a.pr_key IS NULL AND EXISTS(SELECT 1 FROM pr_aliases x WHERE x.alias=s.pr_id));
        CREATE VIEW unique_review_links AS
          SELECT s.entity_id,MIN(l.pr_key) pr_key FROM source_rows s JOIN row_pr_links l USING(table_name,row_number)
          WHERE s.role='review' AND s.entity_id IS NOT NULL GROUP BY s.entity_id HAVING COUNT(DISTINCT l.pr_key)=1;
        INSERT OR IGNORE INTO row_pr_links
          SELECT s.table_name,s.row_number,r.pr_key,'review_id' FROM source_rows s JOIN unique_review_links r ON s.review_id=r.entity_id
          WHERE s.role='review_comment' AND s.pr_id IS NULL AND s.pr_key IS NULL;
        CREATE VIEW unique_commit_links AS
          SELECT s.sha,MIN(l.pr_key) pr_key FROM source_rows s JOIN row_pr_links l USING(table_name,row_number)
          WHERE s.role='commit' AND s.sha IS NOT NULL GROUP BY s.sha HAVING COUNT(DISTINCT l.pr_key)=1;
        INSERT OR IGNORE INTO row_pr_links
          SELECT s.table_name,s.row_number,c.pr_key,'commit_sha' FROM source_rows s JOIN unique_commit_links c ON s.sha=c.sha
          WHERE s.role='file' AND s.pr_id IS NULL AND s.pr_key IS NULL;
        CREATE INDEX links_pr_key ON row_pr_links(pr_key);
        INSERT INTO relationship_audit
          SELECT s.table_name,'pr',CASE WHEN l.pr_key IS NULL THEN 'unresolved' ELSE 'linked' END,COUNT(*)
          FROM source_rows s LEFT JOIN row_pr_links l USING(table_name,row_number)
          WHERE s.role IN ('pr','commit','file','review','comment','review_comment','timeline','issue_relation','task')
          GROUP BY s.table_name,l.pr_key IS NULL;
        INSERT INTO relationship_audit
          SELECT s.table_name,'pr_identity','conflict',COUNT(*) FROM source_rows s
          JOIN prs p ON s.pr_key=p.pr_key JOIN unique_pr_aliases a ON s.pr_id=a.alias
          WHERE s.role!='pr' AND p.pr_key!=a.pr_key GROUP BY s.table_name;
    """)
    # Scalar foreign keys are audited independently of PR linkage: missing is not an orphan.
    relations = [("review", "review_id", "review", "entity_id"), ("issue", "issue_id", "issue", "entity_id")]
    for name, source_key, target_role, target_key in relations:
        db.execute(f"""INSERT INTO relationship_audit SELECT s.table_name,?,CASE WHEN s.{source_key} IS NULL THEN 'missing_foreign_key' WHEN EXISTS(SELECT 1 FROM source_rows t WHERE t.role=? AND t.{target_key}=s.{source_key}) THEN 'linked' ELSE 'orphan' END,COUNT(*) FROM source_rows s WHERE s.role NOT IN ('repository','user') GROUP BY s.table_name,2,3""", (name, target_role))
    db.executescript("""
        INSERT INTO relationship_audit SELECT s.table_name,'user',
          CASE WHEN s.user_id IS NULL AND s.user_login IS NULL THEN 'missing_foreign_key'
               WHEN s.user_id IS NOT NULL THEN
                 CASE WHEN EXISTS(SELECT 1 FROM source_rows u WHERE u.role='user' AND u.entity_id=s.user_id) THEN 'linked' ELSE 'orphan' END
               WHEN EXISTS(SELECT 1 FROM source_rows u WHERE u.role='user' AND u.user_login=s.user_login) THEN 'linked'
               ELSE 'orphan' END,COUNT(*) FROM source_rows s WHERE s.role NOT IN ('repository','user') GROUP BY s.table_name,2,3;
        INSERT INTO relationship_audit SELECT s.table_name,'repository',
          CASE WHEN s.repo_id IS NULL AND s.repo_url IS NULL THEN 'missing_foreign_key'
               WHEN EXISTS(SELECT 1 FROM repository_aliases r WHERE r.alias=COALESCE(s.repo_id,s.repo_url)) THEN 'linked'
               ELSE 'orphan' END,COUNT(*) FROM source_rows s WHERE s.role NOT IN ('repository','user') GROUP BY s.table_name,2,3;
    """)
    db.commit()


def _export(db, output, snapshot):
    db.executescript("""
        CREATE TABLE pr_commit_evidence AS SELECT DISTINCT l.pr_key,s.sha FROM source_rows s JOIN row_pr_links l USING(table_name,row_number) WHERE s.role IN ('commit','file') AND s.sha IS NOT NULL;
        CREATE INDEX evidence_pr_key ON pr_commit_evidence(pr_key);
        CREATE TABLE pr_related_counts AS SELECT l.pr_key,s.table_name,COUNT(*) rows FROM source_rows s JOIN row_pr_links l USING(table_name,row_number) GROUP BY l.pr_key,s.table_name;
        CREATE INDEX related_pr_key ON pr_related_counts(pr_key);
    """)
    counts = Counter()
    with (output / "normalized_prs.jsonl").open("w", encoding="utf-8") as full, (output / "mining_prs.jsonl").open("w", encoding="utf-8") as mining:
        for key, metadata in db.execute("SELECT pr_key,metadata FROM prs ORDER BY pr_key"):
            row = json.loads(metadata)
            shas = [sha for sha, in db.execute("SELECT sha FROM pr_commit_evidence WHERE pr_key=? ORDER BY sha", (key,)) if SHA_RE.fullmatch(sha)]
            labels = row["provided_labels"]
            row.update(commit_shas=shas, initial_commit_shas=shas, pr_actor_type=labels[0] if len(labels) == 1 else "unknown", provided_label=labels[0] if len(labels) == 1 else "unknown", verified_actor_type="unknown", provenance_evidence=[], metadata_source="aidev_parquet_export", metadata_evidence_status="provided_unverified", commit_list_status="dataset_snapshot_not_verified_complete", cohort="primary_cohort", is_synthetic=False, related_table_rows=dict(db.execute("SELECT table_name,rows FROM pr_related_counts WHERE pr_key=?", (key,))), source_content_location="source Parquet table + one-based row; bodies not copied", code_evidence_status="not_mined_by_pydriller", source_pr_key=key, aidev_source_snapshot=snapshot, aidev_import_coverage=str(output / "coverage.json"))
            if len(labels) > 1:
                row["collection_gaps"] = [{"stage": "ingest", "error_type": "conflicting_provided_labels", "reason": "Distinct dataset labels; none verified", "retryable": False}]
            full.write(_json(row) + "\n")
            counts["normalized_prs"] += 1
            if shas:
                mining.write(_json(row) + "\n")
                counts["mining_prs"] += 1
            else:
                counts["prs_without_commit_evidence"] += 1
    for name in ("normalized_prs.jsonl", "mining_prs.jsonl"):
        (output / name).chmod(0o600)
    return {name: counts[name] for name in ("normalized_prs", "mining_prs", "prs_without_commit_evidence")}


def import_aidev(source_dir: Path, output_dir: Path, *, resume=False, dry_run=False, batch_size=8192, column_mapping=None):
    """Scan every local Parquet table, join on disk, and export provenance-neutral PRs.

    No network, Git operation or target code execution occurs. ``resume`` only reuses a
    complete byte-identical import; incomplete runs require a NEW output directory.
    """
    source, output = Path(source_dir).resolve(), Path(output_dir).resolve()
    if not source.is_dir():
        raise ValueError("AIDev source must be a local directory")
    if output == source or source in output.parents or output in source.parents:
        raise ValueError("Output must be separate from the read-only source directory")
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")
    mapping = column_mapping or {}
    if not isinstance(mapping, dict) or any(not isinstance(v, dict) for v in mapping.values()):
        raise ValueError("column_mapping must map table names to canonical-to-actual column dictionaries")
    try:
        import pyarrow
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError("AIDev Parquet ingestion requires optional pyarrow==21.0.0 in this Python environment") from exc
    tables = _inventory(source, mapping, pq)
    signature = {"source_dir": str(source), "inputs": [{k: item[k] for k in ("path", "sha256", "bytes")} for item in tables], "implementation_sha256": _digest(Path(__file__)), "schema_version": VERSION, "pyarrow_version": pyarrow.__version__, "column_mapping": mapping}
    if dry_run:
        return {"status": "dry_run", "exit_code": 0, "complete": False, "files_written": False, "network_accessed": False, "source_signature": signature, "tables": tables, "output_dir": str(output), "planned_outputs": ["normalized_prs.jsonl", "mining_prs.jsonl", "aidev.sqlite", "coverage.json", "manifest.json"]}
    manifest_path = output / "manifest.json"
    if output.exists():
        if not resume or not manifest_path.is_file():
            raise ValueError("Output already exists; use --resume only for a complete matching import, or choose a new directory")
        previous = json.loads(manifest_path.read_text())
        if previous.get("status") != "complete" or previous.get("source_signature") != signature:
            raise ValueError("Cannot resume incomplete or changed import; choose a new output directory")
        expected = {"normalized_prs.jsonl", "mining_prs.jsonl", "aidev.sqlite", "coverage.json"}
        if set(previous.get("outputs", {})) != expected:
            raise ValueError("Cannot resume incomplete output manifest")
        for name, digest in previous["outputs"].items():
            if not (output / name).is_file() or _digest(output / name) != digest:
                raise ValueError("Cannot resume modified or missing import outputs")
        result = json.loads((output / "coverage.json").read_text())
        return dict(result, resumed=True)
    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)
    _write(manifest_path, {"status": "running", "source_signature": signature})
    db = sqlite3.connect(output / "aidev.sqlite")
    (output / "aidev.sqlite").chmod(0o600)
    try:
        _load_rows(db, source, tables, batch_size, pq)
        _link(db)
        snapshot = hashlib.sha256(_json(signature).encode()).hexdigest()
        counts = _export(db, output, snapshot)
        counts.update(source_tables=len(tables), readable_tables=sum(t["status"] == "complete" for t in tables), source_rows_read=sum(t["rows_read"] for t in tables), source_pr_rows=db.execute("SELECT COUNT(*) FROM source_rows WHERE role='pr'").fetchone()[0], unresolved_pr_rows=db.execute("SELECT COUNT(*) FROM source_rows s LEFT JOIN row_pr_links l USING(table_name,row_number) WHERE s.role='pr' AND l.pr_key IS NULL").fetchone()[0], ambiguous_pr_ids=db.execute("SELECT COUNT(*) FROM (SELECT alias FROM pr_aliases GROUP BY alias HAVING COUNT(*)>1)").fetchone()[0])
        counts["duplicate_pr_rows"] = counts["source_pr_rows"] - counts["unresolved_pr_rows"] - counts["normalized_prs"]
        counts["conflicting_metadata_prs"] = db.execute("SELECT COUNT(*) FROM prs WHERE json_array_length(json_extract(metadata,'$.metadata_conflicts'))>0 OR json_array_length(json_extract(metadata,'$.provided_labels'))>1").fetchone()[0]
        relations = [dict(zip(("table", "relation", "status", "rows"), row)) for row in db.execute("SELECT * FROM relationship_audit ORDER BY table_name,relation,status")]
        patch = {status: count for status, count in db.execute("SELECT patch_status,COUNT(*) FROM source_rows WHERE role='file' GROUP BY patch_status")}
        sha_coverage = Counter()
        for sha, count in db.execute("SELECT sha,COUNT(*) FROM source_rows WHERE role IN ('commit','file') GROUP BY sha"):
            sha_coverage["missing" if not sha else "valid_syntax_unverified" if SHA_RE.fullmatch(sha) else "invalid_syntax"] += count
        bad_tables = [t["table"] for t in tables if t["status"] != "complete" or t["role"] == "unrecognized"]
        has_gaps = bool(bad_tables or counts["unresolved_pr_rows"] or counts["ambiguous_pr_ids"] or counts["conflicting_metadata_prs"] or counts["prs_without_commit_evidence"] or sha_coverage["missing"] or sha_coverage["invalid_syntax"] or any(v["status"] in {"orphan", "unresolved", "conflict"} for v in relations) or any(status != "present_unverified" for status in patch))
        report = {"status": "complete_with_gaps" if has_gaps else "complete", "complete": True, "exit_code": 2 if has_gaps else 0, "schema_version": VERSION, "aidev_source_snapshot": snapshot, "counts": counts, "tables": tables, "relationships": relations, "patch_coverage": patch, "unavailable_or_unrecognized_tables": bad_tables, "paths": {name: str(output / name) for name in ("normalized_prs.jsonl", "mining_prs.jsonl", "aidev.sqlite", "coverage.json", "manifest.json")}, "evidence_boundary": {"all_local_tables_scanned": not bad_tables, "full_dataset_completeness_verified": False, "repository_code_mined": False, "pydriller_traversal_performed": False, "patches_are_complete_code": False, "agent_labels_verified": False, "missing_patch_is_negative_finding": False, "bodies_and_patches_exported": False, "network_accessed": False}, "resumed": False}
        report["commit_sha_coverage"] = dict(sha_coverage)
        db.commit()
        db.close()
        if sorted(str(path.relative_to(source)) for path in source.rglob("*.parquet")) != sorted(item["path"] for item in signature["inputs"]) or any(_digest(source / item["path"]) != item["sha256"] for item in signature["inputs"]):
            raise ValueError("Source changed during import; preserve this incomplete run and rerun into a new directory")
        _write(output / "coverage.json", report)
        outputs = {name: _digest(output / name) for name in ("normalized_prs.jsonl", "mining_prs.jsonl", "aidev.sqlite", "coverage.json")}
        _write(manifest_path, {"status": "complete", "source_signature": signature, "outputs": outputs})
        return report
    except (Exception, KeyboardInterrupt) as exc:
        db.close()
        _write(manifest_path, {"status": "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", "source_signature": signature, "error_type": type(exc).__name__, "recovery": "Preserve this directory; rerun into a new output directory"})
        raise
