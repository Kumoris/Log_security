"""Offline SWE-chat table census and commit contexts; no transcript classification."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path

from .aidev import SHA_RE, _digest, _json, _repo, _text, _write

TABLES = {"repositories", "checkpoints", "sessions", "session_logs", "commits", "conversations"}
ALIASES = {
    "repo_id": ("repo_id", "repository", "repo", "full_name"),
    "session_id": ("session_id", "session_pk"),
    "checkpoint_pk": ("checkpoint_pk", "canonical_checkpoint_pk", "checkpoint_id"),
    "commit_sha": ("commit_sha", "sha", "commit_id"),
    "turn_id": ("turn_id", "conversation_id"),
    "url": ("url", "repository_url"),
    "checkpoint_ids": ("checkpoint_ids", "checkpoint_pks"),
    "session_pks": ("session_pks", "session_ids"),
    "commit_shas": ("commit_shas", "commits"),
    "agent": ("agent", "agent_name"),
    "is_agent_author": ("is_agent_author",),
    "status": ("status", "collection_status"),
    "created_at": ("created_at", "author_date", "commit_date"),
    "branch": ("branch",),
    "transcript_path": ("transcript_path",),
    "role": ("role",),
    "turn_type": ("turn_type",),
    "is_conversational": ("is_conversational",),
    "tool_name": ("tool_name",),
}
CONTENT_FIELDS = {"content", "command", "pattern", "tool_input_json", "context_md", "session_metadata_raw", "checkpoint_metadata_raw", "commit_message", "patch", "diff", "full_files", "full_file_states", "files_before", "files_after", "file_contents", "agent_changes", "file_attribution", "settings", "repo_github_metadata"}
OUTPUTS = {"commit_contexts.jsonl", "swechat.sqlite", "coverage.json"}


def _checkpoint(value, repo=None):
    if value is None or value == "":
        return None
    value = str(value)
    if "#" in value:
        prefix, suffix = value.split("#", 1)
        return f"{_repo(prefix)}#{suffix}" if _repo(prefix) and suffix else value
    return f"{repo}#{value}" if repo else value


def _array(value):
    if value is None or value == "":
        return [], "missing"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return [], "invalid_json"
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        return [], "invalid_array"
    return list(dict.fromkeys(value)), "duplicate_entries" if len(set(value)) != len(value) else "valid"


def _tables(source, pq):
    tables = []
    # Dataset tables are at the root; cloned target repositories below it are unrelated input.
    for path in sorted(source.glob("*.parquet")):
        item = {"table": path.stem, "path": path.name, "sha256": _digest(path), "bytes": path.stat().st_size, "rows": None, "schema": None, "recognized": path.stem in TABLES, "rows_read": 0}
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
                names = parquet.schema_arrow.names
                item["column_mapping"] = {key: next((name for name in aliases if name in names), None) for key, aliases in ALIASES.items()}
                content = {}
                for name in sorted(CONTENT_FIELDS & set(names)):
                    chunks = [parquet.metadata.row_group(i).column(j) for i in range(parquet.metadata.num_row_groups) for j in range(parquet.metadata.row_group(i).num_columns) if parquet.metadata.row_group(i).column(j).path_in_schema == name]
                    known = len(chunks) == parquet.metadata.num_row_groups and all(c.statistics is not None and c.statistics.has_null_count for c in chunks)
                    nulls = sum(c.statistics.null_count for c in chunks) if known else None
                    content[name] = {"status": "source_reference_only", "null_rows_from_footer": nulls, "nonnull_rows_from_footer": item["rows"] - nulls if known else None, "values_read": False, "nonnull_does_not_establish_valid_content": True}
                item["content_columns"] = content
            except Exception as exc:
                item.update(status="unreadable_parquet", error_type=type(exc).__name__)
        tables.append(item)
    if not tables:
        raise ValueError("No root-level local Parquet tables found")
    return tables


def _read(db, source, tables, batch_size, pq):
    import pyarrow as pa

    db.executescript("""
        CREATE TABLE source_rows(table_name TEXT,row_number INTEGER,entity_key TEXT,repo_id TEXT,session_id TEXT,checkpoint_pk TEXT,commit_sha TEXT,metadata TEXT,PRIMARY KEY(table_name,row_number));
        CREATE TABLE references_raw(table_name TEXT,row_number INTEGER,relation TEXT,target_key TEXT,method TEXT,PRIMARY KEY(table_name,row_number,relation,target_key,method));
        CREATE TABLE array_audit(table_name TEXT,field TEXT,status TEXT,rows INTEGER);
    """)
    for item in tables:
        if item["status"] != "readable":
            continue
        counts = Counter()
        mapping = item["column_mapping"]
        columns = list(dict.fromkeys(value for value in mapping.values() if value))
        parquet = pq.ParquetFile(source / item["path"])
        for batch in parquet.iter_batches(batch_size=batch_size, columns=columns):
            # Python datetime drops nanoseconds; Arrow strings preserve precision without pandas.
            for index, field in enumerate(batch.schema):
                if pa.types.is_timestamp(field.type):
                    batch = batch.set_column(index, field.name, batch.column(index).cast(pa.string()))
            rows, refs = [], []
            for raw in batch.to_pylist():
                item["rows_read"] += 1
                rownum, table = item["rows_read"], item["table"]
                row = {key: raw.get(value) for key, value in mapping.items() if value}
                repo = _repo(row.get("repo_id")) or (_repo(row.get("url")) if table == "repositories" else None)
                session = _text(row.get("session_id"))
                checkpoint = _checkpoint(row.get("checkpoint_pk"), repo)
                sha = _text(row.get("commit_sha"))
                sha = sha.lower() if sha else None
                key = repo if table == "repositories" else checkpoint if table == "checkpoints" else session if table in {"sessions", "session_logs"} else sha if table == "commits" else _text(row.get("turn_id"))
                for field, relation in (("checkpoint_ids", "checkpoint"), ("session_pks", "session"), ("commit_shas", "commit")):
                    if field not in row:
                        continue
                    values, status = _array(row.pop(field))
                    counts[(field, status)] += 1
                    for target in values:
                        target = _checkpoint(target, repo) if relation == "checkpoint" else target.lower() if relation == "commit" else target
                        refs.append((table, rownum, relation, target, field))
                metadata = {key: value for key, value in row.items() if key not in {"repo_id", "session_id", "checkpoint_pk", "commit_sha", "turn_id", "url"} and value is not None}
                if item.get("content_columns"):
                    metadata["content_source_columns"] = sorted(item["content_columns"])
                rows.append((table, rownum, key, repo, session, checkpoint, sha, _json(metadata)))
            db.executemany("INSERT INTO source_rows VALUES (?,?,?,?,?,?,?,?)", rows)
            db.executemany("INSERT OR IGNORE INTO references_raw VALUES (?,?,?,?,?)", refs)
            db.commit()
        db.executemany("INSERT INTO array_audit VALUES (?,?,?,?)", [(item["table"], field, status, count) for (field, status), count in counts.items()])
        item["status"] = "complete" if item["rows_read"] == item["rows"] else "row_count_mismatch"
    db.executescript("""
        CREATE INDEX source_entity ON source_rows(table_name,entity_key) WHERE entity_key IS NOT NULL;
        CREATE INDEX source_session ON source_rows(table_name,session_id) WHERE session_id IS NOT NULL;
        CREATE INDEX source_checkpoint ON source_rows(table_name,checkpoint_pk) WHERE checkpoint_pk IS NOT NULL;
        CREATE INDEX source_repo_commit ON source_rows(repo_id,commit_sha) WHERE commit_sha IS NOT NULL;
        CREATE INDEX references_target ON references_raw(relation,target_key);
        CREATE VIEW references_all AS
          SELECT * FROM references_raw UNION ALL
          SELECT table_name,row_number,'repository',repo_id,'direct_field' FROM source_rows WHERE repo_id IS NOT NULL AND table_name!='repositories' UNION ALL
          SELECT table_name,row_number,'session',session_id,'direct_field' FROM source_rows WHERE session_id IS NOT NULL AND table_name!='sessions' UNION ALL
          SELECT table_name,row_number,'checkpoint',checkpoint_pk,'direct_field' FROM source_rows WHERE checkpoint_pk IS NOT NULL AND table_name!='checkpoints';
    """)
    db.commit()


def _link(db):
    db.executescript("""
        CREATE TABLE entities AS SELECT table_name,entity_key,MIN(repo_id) repo_id,COUNT(*) source_rows,COUNT(DISTINCT repo_id) repository_variants
          FROM source_rows WHERE table_name IN ('repositories','sessions','checkpoints') AND entity_key IS NOT NULL GROUP BY table_name,entity_key;
        CREATE UNIQUE INDEX entity_key ON entities(table_name,entity_key,repo_id);
        INSERT INTO entities
          SELECT s.table_name,s.entity_key,COALESCE(s.repo_id,CASE WHEN c.repository_variants=1 THEN c.repo_id END),
            COUNT(*),COUNT(DISTINCT COALESCE(s.repo_id,CASE WHEN c.repository_variants=1 THEN c.repo_id END))
          FROM source_rows s LEFT JOIN entities c ON c.table_name='checkpoints' AND c.entity_key=s.checkpoint_pk
          WHERE s.table_name='commits' AND s.entity_key IS NOT NULL GROUP BY 1,2,3;
        CREATE TABLE relationship_audit(table_name TEXT,relation TEXT,status TEXT,rows INTEGER);
        CREATE TABLE session_checkpoint_links(session_id TEXT,checkpoint_pk TEXT,method TEXT,PRIMARY KEY(session_id,checkpoint_pk,method));
        INSERT OR IGNORE INTO session_checkpoint_links SELECT s.entity_key,r.target_key,r.method FROM source_rows s JOIN references_all r USING(table_name,row_number)
          JOIN entities own ON own.table_name='sessions' AND own.entity_key=s.entity_key AND own.repository_variants<=1
          JOIN entities target ON target.table_name='checkpoints' AND target.entity_key=r.target_key
          WHERE s.table_name='sessions' AND r.relation='checkpoint' AND s.entity_key IS NOT NULL AND target.repository_variants<=1
            AND (s.repo_id IS NULL OR target.repo_id IS NULL OR s.repo_id=target.repo_id);
        INSERT OR IGNORE INTO session_checkpoint_links SELECT r.target_key,s.entity_key,r.method FROM source_rows s JOIN references_all r USING(table_name,row_number)
          JOIN entities own ON own.table_name='checkpoints' AND own.entity_key=s.entity_key AND own.repository_variants<=1
          JOIN entities target ON target.table_name='sessions' AND target.entity_key=r.target_key
          WHERE s.table_name='checkpoints' AND r.relation='session' AND s.entity_key IS NOT NULL AND target.repository_variants<=1
            AND (s.repo_id IS NULL OR target.repo_id IS NULL OR s.repo_id=target.repo_id);
        CREATE INDEX session_checkpoint_checkpoint ON session_checkpoint_links(checkpoint_pk,session_id);
    """)
    for relation, table in (("repository", "repositories"), ("session", "sessions"), ("checkpoint", "checkpoints"), ("commit", "commits")):
        if relation == "commit":
            # A shared Git object may legitimately occur in many forks. Match
            # this repository first without multiplying or conflating references.
            db.execute("""INSERT INTO relationship_audit SELECT r.table_name,?,
              CASE WHEN e.entity_key IS NOT NULL THEN 'linked'
                   WHEN EXISTS(SELECT 1 FROM entities other WHERE other.table_name='commits' AND other.entity_key=r.target_key
                     AND other.repo_id IS NOT NULL AND s.repo_id IS NOT NULL AND other.repo_id!=s.repo_id)
                   THEN 'cross_repository_reference' ELSE 'orphan' END,COUNT(*)
              FROM references_all r JOIN source_rows s USING(table_name,row_number)
              LEFT JOIN entities e ON e.table_name=? AND e.entity_key=r.target_key AND e.repo_id=s.repo_id
              WHERE r.relation=? GROUP BY r.table_name,2,3""", (relation, table, relation))
            continue
        db.execute("""INSERT INTO relationship_audit SELECT r.table_name,?,
          CASE WHEN e.entity_key IS NULL THEN 'orphan' WHEN e.repository_variants>1 THEN 'ambiguous_repository'
               WHEN s.repo_id IS NOT NULL AND e.repo_id IS NOT NULL AND s.repo_id!=e.repo_id THEN 'repository_conflict' ELSE 'linked' END,COUNT(*)
          FROM references_all r JOIN source_rows s USING(table_name,row_number)
          LEFT JOIN entities e ON e.table_name=? AND e.entity_key=r.target_key
          WHERE r.relation=? GROUP BY r.table_name,2,3""", (relation, table, relation))
    for table, field, relation in (("commits", "checkpoint_pk", "checkpoint"), ("conversations", "session_id", "session"), ("session_logs", "session_id", "session"), ("sessions", "repo_id", "repository"), ("checkpoints", "repo_id", "repository"), ("commits", "repo_id", "repository")):
        db.execute(f"INSERT INTO relationship_audit SELECT ?,?,'missing_direct_foreign_key',COUNT(*) FROM source_rows WHERE table_name=? AND {field} IS NULL HAVING COUNT(*)>0", (table, relation, table))
    db.execute("""INSERT INTO relationship_audit SELECT 'session_checkpoint_links','reciprocal_array','one_sided',COUNT(*) FROM (
      SELECT session_id,checkpoint_pk FROM session_checkpoint_links GROUP BY session_id,checkpoint_pk HAVING COUNT(DISTINCT CASE WHEN method='session_pks' THEN 'checkpoint_to_session' ELSE 'session_to_checkpoint' END)=1) HAVING COUNT(*)>0""")
    db.commit()


def _contexts(db, output, snapshot):
    db.executescript("""
        CREATE TABLE commit_references(repository TEXT,commit_sha TEXT,checkpoint_pk TEXT,table_name TEXT,row_number INTEGER,method TEXT,context_status TEXT);
        INSERT INTO commit_references
          SELECT COALESCE(s.repo_id,CASE WHEN c.repository_variants=1 THEN c.repo_id END),s.commit_sha,
            CASE WHEN c.repository_variants<=1 AND (s.repo_id IS NULL OR c.repo_id IS NULL OR s.repo_id=c.repo_id) THEN s.checkpoint_pk END,
            s.table_name,s.row_number,'commit_row',
            CASE WHEN c.entity_key IS NULL THEN 'checkpoint_missing' WHEN c.repository_variants>1 THEN 'checkpoint_ambiguous'
                 WHEN s.repo_id IS NOT NULL AND c.repo_id IS NOT NULL AND s.repo_id!=c.repo_id THEN 'checkpoint_repository_conflict' ELSE 'linked' END
          FROM source_rows s LEFT JOIN entities c ON c.table_name='checkpoints' AND c.entity_key=s.checkpoint_pk WHERE s.table_name='commits';
        INSERT INTO commit_references
          SELECT s.repo_id,r.target_key,
            CASE WHEN c.repository_variants<=1 AND (s.repo_id IS NULL OR c.repo_id IS NULL OR s.repo_id=c.repo_id) THEN s.entity_key END,
            s.table_name,s.row_number,'checkpoint_commit_array',
            CASE WHEN c.entity_key IS NULL THEN 'checkpoint_missing' WHEN c.repository_variants>1 THEN 'checkpoint_ambiguous'
                 WHEN s.repo_id IS NOT NULL AND c.repo_id IS NOT NULL AND s.repo_id!=c.repo_id THEN 'checkpoint_repository_conflict' ELSE 'provided_reference' END
          FROM source_rows s JOIN references_raw r USING(table_name,row_number)
          LEFT JOIN entities c ON c.table_name='checkpoints' AND c.entity_key=s.entity_key
          WHERE s.table_name='checkpoints' AND r.relation='commit';
        CREATE INDEX commit_reference_identity ON commit_references(repository,commit_sha);
    """)
    counts = Counter()
    with (output / "commit_contexts.jsonl").open("w", encoding="utf-8") as stream:
        for repo, sha, count in db.execute("SELECT repository,commit_sha,COUNT(*) FROM commit_references GROUP BY repository,commit_sha ORDER BY repository,commit_sha"):
            if not repo or not sha or not SHA_RE.fullmatch(sha):
                counts["unusable_commit_references"] += count
                continue
            refs = list(db.execute("SELECT checkpoint_pk,table_name,row_number,method,context_status FROM commit_references WHERE repository=? AND commit_sha=? ORDER BY table_name,row_number", (repo, sha)))
            checkpoints = sorted({cp for cp, *_ in refs if cp})
            sessions, agents, evidence_status = set(), set(), set()
            for cp in checkpoints:
                sessions.update(value for value, in db.execute("SELECT DISTINCT session_id FROM session_checkpoint_links WHERE checkpoint_pk=?", (cp,)))
            for session in sessions:
                for metadata, in db.execute("SELECT metadata FROM source_rows WHERE table_name='sessions' AND entity_key=?", (session,)):
                    agent = json.loads(metadata).get("agent")
                    if agent:
                        agents.add(str(agent))
            source_refs = [{"table": table, "row": number, "method": method, "context_status": status} for cp, table, number, method, status in refs]
            for ref in source_refs:
                evidence_status.add(ref["context_status"])
            has_commit_metadata = any(ref["table"] == "commits" for ref in source_refs)
            record = {"dataset": "SWE-chat", "source_kind": "commit_context", "source_context_id": f"swechat:{repo}@{sha}", "repository": repo, "commit_sha": sha, "commit_shas": [sha], "initial_commit_shas": [sha], "checkpoint_pks": checkpoints, "session_ids": sorted(sessions), "provided_agent_names": sorted(agents), "verified_actor_type": "unknown", "provenance_evidence": [], "is_synthetic": False, "source_rows": source_refs, "swechat_source_snapshot": snapshot, "swechat_import_coverage": str(output / "coverage.json"), "metadata_source": "swechat_parquet_export", "metadata_evidence_status": "provided_unverified", "commit_metadata_present": has_commit_metadata, "context_statuses": sorted(evidence_status), "code_evidence_status": "not_mined_by_pydriller", "selection_rule": "all_valid_repository_and_commit_references_before_log_or_sensitive_detection"}
            stream.write(_json(record) + "\n")
            counts["commit_contexts"] += 1
            counts["contexts_with_commit_metadata" if has_commit_metadata else "contexts_without_commit_metadata"] += 1
    (output / "commit_contexts.jsonl").chmod(0o600)
    return dict(counts)


def import_swechat(source_dir, output_dir, *, resume=False, dry_run=False, batch_size=8192):
    """Inventory all six root-level tables; export all usable repo+commit identities."""
    source, output = Path(source_dir).resolve(), Path(output_dir).resolve()
    if not source.is_dir() or source == output or source in output.parents or output in source.parents:
        raise ValueError("Use a local source directory and a separate new output directory")
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")
    try:
        import pyarrow
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError("SWE-chat ingestion requires pyarrow==21.0.0") from exc
    tables = _tables(source, pq)
    signature = {"source_dir": str(source), "inputs": [{key: item[key] for key in ("path", "bytes", "sha256")} for item in tables], "implementation_sha256": _digest(Path(__file__)), "shared_helpers_sha256": _digest(Path(__file__).with_name("aidev.py")), "schema_version": 1, "pyarrow_version": pyarrow.__version__}
    snapshot = hashlib.sha256(_json(signature).encode()).hexdigest()
    if dry_run:
        return {"status": "dry_run", "complete": False, "exit_code": 0, "files_written": False, "tables": tables, "source_signature": signature, "output_dir": str(output)}
    manifest_path = output / "manifest.json"
    if output.exists():
        if not resume or not manifest_path.is_file():
            raise ValueError("Output already exists; resume only a complete identical import or choose a new directory")
        previous = json.loads(manifest_path.read_text())
        if previous.get("status") != "complete" or previous.get("source_signature") != signature or set(previous.get("outputs", {})) != OUTPUTS:
            raise ValueError("Cannot resume incomplete or changed import; choose a new output directory")
        if any(not (output / name).is_file() or _digest(output / name) != digest for name, digest in previous["outputs"].items()):
            raise ValueError("Cannot resume modified or missing output")
        return dict(json.loads((output / "coverage.json").read_text()), resumed=True)
    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)
    _write(manifest_path, {"status": "running", "source_signature": signature})
    db = sqlite3.connect(output / "swechat.sqlite")
    (output / "swechat.sqlite").chmod(0o600)
    try:
        _read(db, source, tables, batch_size, pq)
        _link(db)
        counts = _contexts(db, output, snapshot)
        counts.update(source_tables=len(tables), readable_tables=sum(item["status"] == "complete" for item in tables), source_rows_read=sum(item["rows_read"] for item in tables), unique_sessions=db.execute("SELECT COUNT(*) FROM entities WHERE table_name='sessions'").fetchone()[0], unique_checkpoints=db.execute("SELECT COUNT(*) FROM entities WHERE table_name='checkpoints'").fetchone()[0], unique_repositories=db.execute("SELECT COUNT(*) FROM entities WHERE table_name='repositories'").fetchone()[0], duplicate_entity_rows=db.execute("SELECT COALESCE(SUM(source_rows-1),0) FROM entities").fetchone()[0])
        identities = [{"table": table, "status": "missing_primary_key" if missing else "present_unverified", "rows": count} for table, missing, count in db.execute("SELECT table_name,entity_key IS NULL,COUNT(*) FROM source_rows GROUP BY table_name,entity_key IS NULL")]
        counts["missing_primary_key_rows"] = sum(row["rows"] for row in identities if row["status"] == "missing_primary_key")
        counts["ambiguous_repository_entity_ids"] = db.execute("SELECT COUNT(*) FROM entities WHERE repository_variants>1").fetchone()[0]
        for name in ("commit_contexts", "contexts_with_commit_metadata", "contexts_without_commit_metadata", "unusable_commit_references"):
            counts.setdefault(name, 0)
        relationships = [dict(zip(("table", "relation", "status", "rows"), row)) for row in db.execute("SELECT * FROM relationship_audit ORDER BY table_name,relation,status")]
        arrays = [dict(zip(("table", "field", "status", "rows"), row)) for row in db.execute("SELECT * FROM array_audit ORDER BY table_name,field,status")]
        missing = sorted(TABLES - {item["table"] for item in tables})
        unavailable = [item["table"] for item in tables if item["status"] != "complete" or not item["recognized"]]
        gaps = bool(missing or unavailable or counts["unusable_commit_references"] or counts["contexts_without_commit_metadata"] or counts["missing_primary_key_rows"] or counts["ambiguous_repository_entity_ids"] or any(row["status"] != "linked" for row in relationships) or any(row["status"].startswith("invalid") for row in arrays))
        report = {"status": "complete_with_gaps" if gaps else "complete", "complete": True, "exit_code": 2 if gaps else 0, "counts": counts, "tables": tables, "relationships": relationships, "array_fields": arrays, "missing_expected_tables": missing, "unavailable_tables": unavailable, "swechat_source_snapshot": snapshot, "paths": {name: str(output / name) for name in OUTPUTS | {"manifest.json"}}, "resumed": False, "evidence_boundary": {"all_local_tables_scanned": not unavailable, "all_six_expected_tables_available": not unavailable and not missing, "full_dataset_completeness_verified": False, "repository_code_mined": False, "patches_or_full_files_loaded": False, "session_content_classified": False, "content_values_exported": False, "agent_labels_verified": False, "network_accessed": False, "target_code_executed": False}}
        report["primary_key_coverage"] = identities
        db.commit()
        db.close()
        if sorted(path.name for path in source.glob("*.parquet")) != sorted(item["path"] for item in signature["inputs"]) or any(_digest(source / item["path"]) != item["sha256"] for item in signature["inputs"]):
            raise ValueError("Source changed during import; use a new output directory")
        _write(output / "coverage.json", report)
        _write(manifest_path, {"status": "complete", "source_signature": signature, "outputs": {name: _digest(output / name) for name in OUTPUTS}})
        return report
    except (Exception, KeyboardInterrupt) as exc:
        db.close()
        _write(manifest_path, {"status": "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", "source_signature": signature, "error_type": type(exc).__name__, "recovery": "Preserve this directory; rerun into a new output directory"})
        raise
