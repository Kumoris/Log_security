"""AIDev -> PR-level seeds (stage 1). The only file in the project that knows AIDev's tables.

Offline. Outputs, in ``<out>/seeds/``:
  prs.jsonl        one seed PR per line: merged, and one of its non-merge commits adds or removes a
                   log-looking line in a non-excluded Python file (or the patch is missing there)
  pr_index.jsonl   every AIDev PR of the seed repositories (also non-seed, also unmerged): number,
                   agent, merge time and its commit SHAs -- the commit -> PR -> agent map
  repos.jsonl      one line per repository with seeds
  manifest.json    table hashes, rule versions, counts

Per-commit attribution inside a PR:
  agent_commit         author is a bot login of the PR's own agent
  agent_pr_unverified  author is the PR opener, or the agent has no bot account (Codex)
  non_agent_commit     anyone else (not identified as the agent)
Added lines are stored as short hashes so that a log statement found at the landing
commit can be attributed to the PR commit(s) that wrote it.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from ..config import Config
from ..models import write_jsonl
from .exclude import excluded_path
from .prefilter import LOG_REGEX_VERSION, log_lines, patch_lines

DATASET = "hao-li/AIDev"
RULE_VERSION = "aidev-seeds-v2"
TABLES = ("repository", "pull_request", "pr_commits", "pr_commit_details")
EXTRA_PRS = "all_pull_request.ourrepos.parquet"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MERGE_MESSAGE = re.compile(r"^Merge ")


def line_hash(line: str) -> str:
    return hashlib.sha1(line.strip().encode()).hexdigest()[:12]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def _date(v) -> datetime | None:
    if not v:
        return None
    return v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", "+00:00"))


def _read(path: Path, cols: list[str], batch_size: int = 20000):
    import pyarrow.parquet as pq
    pf = pq.ParquetFile(path)
    have = [c for c in cols if c in pf.schema_arrow.names]
    for batch in pf.iter_batches(batch_size=batch_size, columns=have):
        for row in batch.to_pylist():
            yield {c: row.get(c) for c in cols}


def _repo_from_url(url: str | None) -> str | None:
    m = re.search(r"github\.com/(?:repos/)?([^/]+/[^/]+?)(?:\.git)?/?$", url or "")
    return m.group(1) if m else None


def commit_attribution(author: str | None, agent: str, pr_user: str | None, bots: dict) -> str:
    own = bots.get(agent, frozenset())
    if author and author in own:
        return "agent_commit"
    if not own or (author and pr_user and author == pr_user):
        return "agent_pr_unverified"
    return "non_agent_commit"


def build_seeds(source_dir: Path, out_dir: Path, cfg: Config) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    counts: Counter = Counter()
    excluded: Counter = Counter()
    files_meta = {f"{t}.parquet": {"sha256": _sha256(source_dir / f"{t}.parquet")} for t in TABLES}
    if (source_dir / EXTRA_PRS).exists():
        files_meta[EXTRA_PRS] = {"sha256": _sha256(source_dir / EXTRA_PRS)}

    repo_meta = {}
    repo_by_id = {}
    for r in _read(source_dir / "repository.parquet", ["id", "full_name", "language", "stars", "license", "is_forked"]):
        repo_meta[r["full_name"]] = r
        repo_by_id[r["id"]] = r["full_name"]

    # every AIDev PR we know of, keyed by id
    prs: dict[int, dict] = {}
    cols = ["id", "number", "agent", "user", "state", "merged_at", "repo_id", "repo_url", "title"]
    sources = [source_dir / "pull_request.parquet"] + (
        [source_dir / EXTRA_PRS] if (source_dir / EXTRA_PRS).exists() else [])
    for src in sources:
        for r in _read(src, cols):
            if r["id"] in prs:
                continue
            repo = repo_by_id.get(r["repo_id"]) or _repo_from_url(r["repo_url"])
            if repo is None:
                counts["prs_repository_unresolved"] += 1
                continue
            prs[r["id"]] = {"repository": repo, "pr_id": r["id"], "number": r["number"], "agent": r["agent"] or "unknown",
                            "user": r["user"], "state": r["state"], "merged_at": _date(r["merged_at"]),
                            "title": (r["title"] or "")[:300], "commit_shas": []}
    counts["prs_known"] = len(prs)
    counts["prs_merged"] = sum(p["merged_at"] is not None for p in prs.values())

    for r in _read(source_dir / "pr_commits.parquet", ["sha", "pr_id"]):
        p = prs.get(r["pr_id"])
        if p is not None and r["sha"] and SHA_RE.match(r["sha"].lower()):
            p["commit_shas"].append(r["sha"].lower())

    bots = cfg.bots()
    commits: dict[int, dict[str, dict]] = defaultdict(dict)      # pr_id -> sha -> commit
    for row in _read(source_dir / "pr_commit_details.parquet",
                     ["sha", "pr_id", "author", "message", "filename", "status", "patch"]):
        counts["file_rows_read"] += 1
        p = prs.get(row["pr_id"])
        if p is None or p["merged_at"] is None:
            counts["file_rows_unmerged_or_unknown_pr"] += 1
            continue
        sha = (row["sha"] or "").lower()
        if not SHA_RE.match(sha):
            counts["file_rows_invalid_sha"] += 1
            continue
        c = commits[row["pr_id"]].get(sha)
        if c is None:
            message = row["message"] or ""
            c = commits[row["pr_id"]][sha] = {
                "sha": sha, "author": row["author"], "message": message[:2000],
                "is_merge_message": bool(MERGE_MESSAGE.match(message)),
                "attribution": commit_attribution(row["author"], p["agent"], p["user"], bots),
                "files": {}}
        path = row["filename"]
        if not path:
            continue
        rule = excluded_path(path, cfg)
        if rule is not None:
            if rule != "not_python":
                excluded[rule] += 1
            continue
        patch = row["patch"]
        if patch is None:
            c["files"][path] = {"patch": "missing", "status": row["status"], "added_hashes": [], "log_hit": None}
            continue
        added, removed, truncated = patch_lines(patch)
        c["files"][path] = {"patch": "truncated" if truncated else "ok", "status": row["status"],
                            "added_hashes": sorted({line_hash(x) for x in added if x.strip()}),
                            "log_hit": bool(log_lines(added) or log_lines(removed))}

    seeds, per_repo = [], defaultdict(int)
    for pr_id, cs in commits.items():
        p = prs[pr_id]
        usable = [c for c in cs.values() if not (cfg.skip_merge_commits and c["is_merge_message"])]
        counts["merge_message_commits_dropped"] += len(cs) - len(usable)
        hit = any(f["log_hit"] or f["log_hit"] is None for c in usable for f in c["files"].values())
        if not hit:
            continue
        seeds.append({**{k: v for k, v in p.items() if k != "commit_shas"},
                      "commits": [{**c, "files": [{"path": k, **v} for k, v in sorted(c["files"].items())]}
                                  for c in sorted(usable, key=lambda c: c["sha"])],
                      "patch_missing_only": not any(f["log_hit"] for c in usable for f in c["files"].values())})
        per_repo[p["repository"]] += 1
    seeds.sort(key=lambda s: (s["repository"], s["merged_at"], s["number"]))
    counts["seed_prs"] = len(seeds)
    counts["seed_prs_with_log_hit"] = sum(not s["patch_missing_only"] for s in seeds)
    counts["seed_repositories"] = len(per_repo)
    attribution = Counter(c["attribution"] for s in seeds for c in s["commits"])

    index = [{k: v for k, v in p.items() if k != "title"} for p in prs.values() if p["repository"] in per_repo]
    index.sort(key=lambda p: (p["repository"], p["number"]))
    repos = [{"repository": r, "clone_url": f"https://github.com/{r}.git", "seed_prs": n,
              "stars": (repo_meta.get(r) or {}).get("stars"), "language": (repo_meta.get(r) or {}).get("language")}
             for r, n in sorted(per_repo.items())]

    write_jsonl(out_dir / "prs.jsonl", seeds)
    write_jsonl(out_dir / "pr_index.jsonl", index)
    write_jsonl(out_dir / "repos.jsonl", repos)
    manifest = {
        "dataset": DATASET, "files": files_meta, "rule_version": RULE_VERSION, "log_regex_version": LOG_REGEX_VERSION,
        "skip_merge_commits": cfg.skip_merge_commits, "agent_bot_logins": {a: list(v) for a, v in cfg.agent_bot_logins},
        "counts": dict(counts), "commit_attribution": dict(attribution), "excluded_files_by_rule": dict(excluded),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, default=str))
    return manifest
