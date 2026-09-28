"""SWE-chat -> seed manifest (REBUILD.md §5). The only file in the project that knows SWE-chat.

Offline. Six steps, each separately testable:
  1 inventory       table hashes, rows, columns (the data version)
  2 read_commits    read + status filter (drops counted per status)
  3 deduplicate     by (repo, sha); checkpoint list, branch set, attribution per file
  4 expand          file-level attribution, keep agent_only / mixed
  5 mark_log_hits   per-file patch split + regex (mark only, never filter)
  6 attach_agents   checkpoint -> session_pks (JSON string) -> sessions.agent
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..config import Config
from ..models import AgentFile, Gap, Seed, dumps, to_jsonable
from .prefilter import LOG_REGEX_VERSION, log_lines, split_patch

DATASET = "SALT-NLP/SWE-chat"
RULE_VERSION = "seeds-v1"
TABLES = ("commits", "repositories", "checkpoints", "sessions")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
META_KEYS = {"__aggregate__"}

# column aliases: small dataset revisions should not need code changes
ALIASES = {
    "commits": {
        "repo_id": ("repo_id", "repository", "repo"), "commit_sha": ("commit_sha", "sha"),
        "status": ("status",), "commit_date": ("commit_date", "author_date", "created_at"),
        "author_email": ("author_email",), "commit_message": ("commit_message", "message"),
        "file_attribution": ("file_attribution",), "patch": ("patch", "diff"),
        "checkpoint_pk": ("checkpoint_pk", "canonical_checkpoint_pk"), "branch": ("branch",),
        "agent_changes": ("agent_changes",),
    },
    "repositories": {
        "repo_id": ("repo_id", "repository"), "url": ("url", "repository_url"),
        "license_type": ("license_type", "license"), "total_repo_commits_ever": ("total_repo_commits_ever",),
        "is_fork": ("is_fork",),
    },
    "checkpoints": {"checkpoint_pk": ("checkpoint_pk",), "session_pks": ("session_pks", "session_ids")},
    "sessions": {"session_id": ("session_id", "session_pk"), "agent": ("agent", "agent_name"),
                 "strategy": ("strategy",)},
}


@dataclass
class Tally:
    counts: Counter = field(default_factory=Counter)
    dropped_by_status: Counter = field(default_factory=Counter)
    attribution: Counter = field(default_factory=Counter)
    gaps: list = field(default_factory=list)

    def gap(self, kind, **kw):
        self.gaps.append(Gap(kind, **kw))


# --------------------------------------------------------------------------- 1 inventory

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory(source_dir: Path) -> dict:
    import pyarrow.parquet as pq
    tables = {}
    for name in TABLES:
        path = source_dir / f"{name}.parquet"
        if not path.exists():
            raise FileNotFoundError(f"missing SWE-chat table {path}")
        pf = pq.ParquetFile(path)
        cols = pf.schema_arrow.names
        mapping = {}
        for key, cands in ALIASES[name].items():
            mapping[key] = next((c for c in cands if c in cols), None)
        tables[name] = {"path": str(path), "sha256": _sha256(path), "rows": pf.metadata.num_rows,
                        "columns": cols, "mapping": mapping}
    return tables


def _read(table: dict, keys: list[str], batch_size: int = 1000):
    import pyarrow.parquet as pq
    mapping = table["mapping"]
    cols = [mapping[k] for k in keys if mapping.get(k)]
    for batch in pq.ParquetFile(table["path"]).iter_batches(batch_size=batch_size, columns=cols):
        for row in batch.to_pylist():
            yield {k: row.get(mapping[k]) if mapping.get(k) else None for k in keys}


# --------------------------------------------------------------------------- 2 read + filter

def read_commits(tables: dict, cfg: Config, tally: Tally):
    keys = list(ALIASES["commits"])
    for row in _read(tables["commits"], keys, batch_size=500):
        tally.counts["rows_read"] += 1
        status = row["status"] or "missing_status"
        if status not in cfg.keep_status:
            tally.dropped_by_status[status] += 1
            continue
        yield row


# --------------------------------------------------------------------------- 3 dedup

def deduplicate(rows, tally: Tally) -> dict[tuple[str, str], dict]:
    merged: dict[tuple[str, str], dict] = {}
    for row in rows:
        repo, sha = row["repo_id"], (row["commit_sha"] or "").lower()
        if not repo or not SHA_RE.match(sha):
            tally.gap("invalid_sha", repository=repo, sha=row["commit_sha"])
            tally.counts["dropped_invalid_sha"] += 1
            continue
        key = (repo, sha)
        m = merged.get(key)
        if m is None:
            merged[key] = m = {"repo": repo, "sha": sha, "commit_date": row["commit_date"],
                               "author_email": row["author_email"], "message": row["commit_message"] or "",
                               "checkpoints": [], "branches": set(), "attributions": [], "patches": [],
                               "agent_change_ids": set()}
        else:
            tally.counts["duplicate_rows_merged"] += 1
        if row["checkpoint_pk"] and row["checkpoint_pk"] not in m["checkpoints"]:
            m["checkpoints"].append(row["checkpoint_pk"])
        if row["branch"]:
            m["branches"].add(row["branch"])
        m["attributions"].append(row["file_attribution"])
        if row["patch"] is not None and all(row["patch"] != p for p in m["patches"]):
            m["patches"].append(row["patch"])
        m["agent_change_ids"].add(hashlib.sha1((row["agent_changes"] or "").encode()).hexdigest())
    tally.counts["unique_commits"] = len(merged)
    return merged


# --------------------------------------------------------------------------- 4 attribution

def _parse_attribution(raw, repo, sha, tally: Tally) -> dict[str, dict] | None:
    if raw is None or raw == "":
        tally.gap("file_attribution_missing", repository=repo, sha=sha)
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        tally.gap("file_attribution_parse_failed", repository=repo, sha=sha, detail=str(e)[:200])
        return None
    if not isinstance(data, dict):
        tally.gap("file_attribution_not_object", repository=repo, sha=sha)
        return None
    return {k: v for k, v in data.items() if k not in META_KEYS}


def expand_attribution(m: dict, cfg: Config, tally: Tally) -> list[dict]:
    """Per-file attribution; files whose label differs across duplicate rows are gaps."""
    per_file: dict[str, set[str]] = defaultdict(set)
    versions: dict[str, tuple[bool, bool]] = {}
    for raw in m["attributions"]:
        data = _parse_attribution(raw, m["repo"], m["sha"], tally)
        if data is None:
            continue
        for path, info in data.items():
            if not isinstance(info, dict):
                tally.gap("file_attribution_entry_invalid", repository=m["repo"], sha=m["sha"], path=path)
                continue
            per_file[path].add(info.get("attribution") or "none")
            versions[path] = (info.get("agent_version") is not None, info.get("committed_version") is not None)
    out = []
    for path, labels in sorted(per_file.items()):
        if len(labels) > 1:
            tally.gap("file_attribution_conflict", repository=m["repo"], sha=m["sha"], path=path,
                      detail=",".join(sorted(labels)))
            tally.attribution["conflict"] += 1
            continue
        label = next(iter(labels))
        tally.attribution[label] += 1
        if label in cfg.agent_attributions:
            out.append({"path": path, "attribution": label,
                        "has_agent_version": versions[path][0], "has_committed_version": versions[path][1]})
    return out


# --------------------------------------------------------------------------- 5 log hits

def mark_log_hits(m: dict, files: list[dict], tally: Tally) -> list[AgentFile]:
    if len(m["patches"]) > 1:
        tally.gap("patch_conflict", repository=m["repo"], sha=m["sha"], detail=f"{len(m['patches'])} variants")
    added, gaps = split_patch(m["patches"][0]) if m["patches"] else ({}, [Gap("patch_missing")])
    for g in gaps:
        tally.gap(g.kind, repository=m["repo"], sha=m["sha"], path=g.path, detail=g.detail)
    out = []
    for f in files:
        hits = log_lines(added.get(f["path"], []))
        out.append(AgentFile(path=f["path"], attribution=f["attribution"], log_hit=bool(hits),
                             has_agent_version=f["has_agent_version"],
                             has_committed_version=f["has_committed_version"],
                             added_log_lines=tuple(hits[:50])))
    return out


# --------------------------------------------------------------------------- 6 agent names

def load_agent_links(tables: dict) -> tuple[dict, dict]:
    sessions = {r["session_id"]: r for r in _read(tables["sessions"], list(ALIASES["sessions"]))}
    checkpoints = {r["checkpoint_pk"]: r["session_pks"] for r in _read(tables["checkpoints"], list(ALIASES["checkpoints"]))}
    return checkpoints, sessions


def attach_agent_names(m: dict, checkpoints: dict, sessions: dict, tally: Tally) -> tuple[tuple[str, ...], str]:
    """Four parse states for session_pks: linked / missing / invalid_json / duplicate_entries;
    more than one distinct agent name is ``ambiguous`` and all names are kept."""
    names, states = set(), Counter()
    for cp in m["checkpoints"]:
        raw = checkpoints.get(cp)
        if raw is None:
            states["missing"] += 1
            continue
        try:
            arr = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            states["invalid_json"] += 1
            continue
        if not isinstance(arr, list) or not arr:
            states["missing"] += 1
            continue
        if len(set(arr)) != len(arr):
            states["duplicate_entries"] += 1
        found = False
        for pk in dict.fromkeys(arr):
            s = sessions.get(pk)
            if s is None:
                states["session_not_found"] += 1
                continue
            found = True
            names.add(s["agent"] or "unknown")
        if found:
            states["linked"] += 1
    if len(names) > 1:
        status = "ambiguous"
        tally.gap("session_link_ambiguous", repository=m["repo"], sha=m["sha"], detail=",".join(sorted(names)))
    elif names:
        status = "linked" if not (states["invalid_json"] or states["duplicate_entries"]) else \
            ("invalid_json" if states["invalid_json"] else "duplicate_entries")
    else:
        status = "invalid_json" if states["invalid_json"] else "missing"
        tally.gap("session_link_" + status, repository=m["repo"], sha=m["sha"])
    tally.counts["link_status:" + status] += 1
    return tuple(sorted(names)), status


# --------------------------------------------------------------------------- driver

def _date(v):
    if v is None:
        return None
    return v if isinstance(v, datetime) else datetime.fromisoformat(str(v))


def build_seeds(source_dir: Path, out_dir: Path, cfg: Config) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    tally = Tally()
    tables = inventory(source_dir)
    merged = deduplicate(read_commits(tables, cfg, tally), tally)
    checkpoints, sessions = load_agent_links(tables)

    seeds: list[Seed] = []
    for (repo, sha), m in sorted(merged.items()):
        files = expand_attribution(m, cfg, tally)
        if not files:
            continue
        agent_files = mark_log_hits(m, files, tally)
        names, link = attach_agent_names(m, checkpoints, sessions, tally)
        seeds.append(Seed(
            repository=repo, commit_sha=sha, commit_date=_date(m["commit_date"]),
            agent_files=tuple(agent_files), agent_names=names, checkpoint_pks=tuple(m["checkpoints"]),
            branches=tuple(sorted(m["branches"])), trace_id=f"swechat:{repo}@{sha[:8]}",
            link_status=link, commit_message=m["message"][:4000]))

    repos_meta = {r["repo_id"]: r for r in _read(tables["repositories"], list(ALIASES["repositories"]))}
    per_repo = defaultdict(list)
    for s in seeds:
        per_repo[s.repository].append(s)
    repo_rows = []
    for repo, ss in sorted(per_repo.items()):
        meta = repos_meta.get(repo, {})
        if not meta:
            tally.gap("repository_metadata_missing", repository=repo)
        url = meta.get("url") or f"https://github.com/{repo}"
        repo_rows.append({"repository": repo, "clone_url": url.rstrip("/") + ("" if url.endswith(".git") else ".git"),
                          "license": meta.get("license_type"), "total_commits_ever": meta.get("total_repo_commits_ever"),
                          "is_fork": meta.get("is_fork"), "seed_count": len(ss),
                          "seeds_with_log_hit": sum(any(f.log_hit for f in s.agent_files) for s in ss)})

    total_ever = sum((r.get("total_repo_commits_ever") or 0) for r in repos_meta.values())
    unique = tally.counts["unique_commits"]
    counts = {
        "rows_read": tally.counts["rows_read"],
        "dropped_by_status": dict(tally.dropped_by_status),
        "dropped_invalid_sha": tally.counts["dropped_invalid_sha"],
        "duplicate_rows_merged": tally.counts["duplicate_rows_merged"],
        "unique_commits": unique,
        "commits_with_agent_files": len(seeds),
        "commits_with_log_hit": sum(any(f.log_hit for f in s.agent_files) for s in seeds),
        "agent_files_total": sum(len(s.agent_files) for s in seeds),
        "agent_files_with_log_hit": sum(f.log_hit for s in seeds for f in s.agent_files),
        "agent_files_python": sum(f.path.endswith(".py") for s in seeds for f in s.agent_files),
        "agent_files_python_with_log_hit": sum(f.log_hit and f.path.endswith(".py") for s in seeds for f in s.agent_files),
        "commits_with_python_log_hit": sum(any(f.log_hit and f.path.endswith(".py") for f in s.agent_files) for s in seeds),
        "file_attribution_distribution": dict(tally.attribution),
        "repositories_in_dataset": len(repos_meta),
        "repositories_with_seeds": len(repo_rows),
        "total_repo_commits_ever": total_ever,
        "coverage_unique_commits_over_all_history": round(unique / total_ever, 4) if total_ever else None,
        "link_status": {k.split(":", 1)[1]: v for k, v in tally.counts.items() if k.startswith("link_status:")},
    }
    gaps = Counter(g.kind for g in tally.gaps)
    manifest = {
        "dataset": DATASET,
        "files": {f"{k}.parquet": {"sha256": v["sha256"], "rows": v["rows"], "column_mapping": v["mapping"]}
                  for k, v in tables.items()},
        "rule_version": RULE_VERSION,
        "log_regex_version": LOG_REGEX_VERSION,
        "keep_status": list(cfg.keep_status),
        "agent_attributions": list(cfg.agent_attributions),
        "counts": counts,
        "gaps": dict(gaps),
        "limitations": [
            f"数据集仅覆盖这些仓库 {counts['coverage_unique_commits_over_all_history']:.1%} 的提交（status 过滤 + (repo, sha) 去重后口径），"
            "不在数据集中不等于非 agent 所写",
            "日志粗筛使用正则，漏检率未测",
            "file_attribution 在重复行间冲突的文件已剔除（见 gaps.file_attribution_conflict）",
        ],
    }
    with (out_dir / "seeds.jsonl").open("w") as f:
        for s in seeds:
            f.write(dumps(s) + "\n")
    with (out_dir / "repos.jsonl").open("w") as f:
        for r in repo_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with (out_dir / "seed_gaps.jsonl").open("w") as f:
        for g in tally.gaps:
            f.write(dumps(g) + "\n")
    (out_dir / "manifest.json").write_text(json.dumps(to_jsonable(manifest), ensure_ascii=False, indent=2))
    return manifest
