"""Per-repository tracking (stage 3): prescan seed logs, one forward pass, backward origins.

prescan    at every anchored PR, diff (base, target) on the first-parent chain, parse both
           sides, match statements; added and modified statements whose lines the PR's own
           commits wrote are seed logs (attribution per line, from AIDev patches)
forward    one pass along the first-parent chain, oldest first; a seed log that is already
           tracked (a later PR touching an earlier seed's log) becomes an event on that
           lineage, never a second lineage; each lineage has its own window
backward   only lineages first seen as a modification of an existing log: ``git log -L`` on
           the lines before the PR, back to the commit that created them
drill-down a first-parent merge that changes a tracked log: which commits of the merged
           branch touched those lines, and who made them
"""
from __future__ import annotations

import hashlib
import textwrap
import time
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from ..config import Config
from ..detect.python_ast import find_logs
from ..models import Gap, LocalRepo, LogStatement, to_jsonable
from ..repo.history import Commit, blob_hunks, first_parent_log, line_history, _records, _parse_head, _FORMAT
from ..repo.gitcmd import popen_git
from ..repo.materialize import CatFile, decode_source
from ..seeds.aidev import line_hash
from ..seeds.exclude import excluded_content, excluded_path
from .attribution import PrIndex, attribute
from .match import Hunk, MatchResult, change_record, match_file, same_message, similarity

PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)


def _dt(v) -> datetime:
    return datetime.fromisoformat(v) if isinstance(v, str) else v


class Sources:
    """Blob -> parsed statements, with exclusion and failure reasons."""

    def __init__(self, local: LocalRepo, cfg: Config):
        self.local, self.cfg = local, cfg
        self.cat = CatFile(local.path)
        self.cache: dict[tuple[str, str], tuple[str | None, list[LogStatement] | None, str | None]] = {}

    def close(self):
        self.cat.close()

    def text(self, blob: str | None) -> tuple[str | None, str | None]:
        if blob is None:
            return None, None
        data = self.cat.read(blob)
        if data is None:
            return None, "blob_missing"
        if len(data) > self.cfg.max_file_bytes:
            return None, "file_too_large"
        try:
            return decode_source(data), None
        except (UnicodeDecodeError, SyntaxError, LookupError):
            return None, "decode_failed"

    def parse(self, path: str, blob: str | None) -> tuple[str | None, list[LogStatement] | None, str | None]:
        """-> (source, statements, gap_kind). blob None -> (None, [], None): the file does not exist."""
        if blob is None:
            return None, [], None
        key = (path, blob)
        if key not in self.cache:
            src, gap = self.text(blob)
            stmts = None
            if src is not None:
                rule = excluded_content(src, self.cfg)
                if rule is not None:
                    gap = "excluded_" + rule
                else:
                    try:
                        stmts = list(find_logs(path, src, self.cfg.include_print).statements)
                    except PARSE_ERRORS as e:
                        gap = "parse_failed:" + type(e).__name__
            self.cache[key] = (src, stmts, gap)
        return self.cache[key]

    def hunks(self, old_blob: str | None, new_blob: str | None, new_src: str | None) -> list[Hunk]:
        if old_blob is None:
            n = len((new_src or "").splitlines())
            return [Hunk(0, 0, 1, n)] if n else []
        if new_blob is None:
            return []
        return blob_hunks(self.local.path, old_blob, new_blob)


def _stmt_hashes(st: LogStatement, minus: LogStatement | None = None) -> set[str]:
    lines = {line_hash(x) for x in st.code.splitlines() if x.strip()}
    if minus is not None:
        new = lines - {line_hash(x) for x in minus.code.splitlines() if x.strip()}
        return new or lines
    return lines


def _version(seg: str, commit: Commit | None, st: LogStatement | None, attribution: dict, *, path: str,
             blob: str | None = None, code: str | None = None, context: str = "file") -> dict:
    return {"segment": seg, "commit": commit.sha if commit else None,
            "date": commit.date.isoformat() if commit else None, "path": path, "blob": blob,
            "statement": to_jsonable(st) if st is not None else None,
            "code": st.code if st is not None else code, "context": context, **{"author": attribution}}


# --------------------------------------------------------------------------- prescan

def _line_attribution(pr: dict, path: str, hashes: set[str]) -> tuple[str, list[str]]:
    commits = [c for c in pr["commits"] for f in c["files"] if f["path"] == path and set(f["added_hashes"]) & hashes]
    if not commits:
        missing = any(f["path"] == path and f["patch"] != "ok" for c in pr["commits"] for f in c["files"])
        return ("unknown" if missing else "not_in_pr"), []
    kinds = {c["attribution"] for c in commits}
    if kinds == {"non_agent_commit"}:
        kind = "non_agent_commit"
    elif "non_agent_commit" in kinds:
        kind = "mixed_commits"
    elif "agent_pr_unverified" in kinds:
        kind = "agent_pr_unverified"
    else:
        kind = "agent_commit"
    return kind, sorted({c["sha"] for c in commits})


def _in_venv(local: LocalRepo, commit: str, path: str) -> bool:
    """A directory above the file holds pyvenv.cfg: a committed virtual environment."""
    parts = path.split("/")[:-1]
    cands = ["/".join(parts[:i] + ["pyvenv.cfg"]) for i in range(1, min(len(parts), 8) + 1)]
    if not cands:
        return False
    from ..repo.gitcmd import run_git
    out = run_git(local.path, "ls-tree", "--name-only", commit, "--", *cands, check=False).stdout
    return bool(out.strip())


def prescan(local: LocalRepo, anchors: list[dict], prs: dict[int, dict], src: Sources, cfg: Config,
            counts: Counter, gaps: list[Gap]) -> list[dict]:
    from ..repo.history import diff_tree
    seeds = []
    for an in anchors:
        if an["landing"] is None:
            continue
        pr = prs[an["pr_id"]]
        pr_files = {f["path"] for c in pr["commits"] for f in c["files"]}
        for ch in diff_tree(local.path, an["base"], an["target"]):
            path = ch.new_path or ch.old_path
            if ch.new_blob is None or path not in pr_files and ch.old_path not in pr_files:
                continue
            rule = excluded_path(path, cfg)
            if rule is not None:
                continue
            if ch.status == "A" and _in_venv(local, an["target"], path):
                counts["prescan_file_excluded_pyvenv"] += 1
                continue
            new_src, new_st, g2 = src.parse(path, ch.new_blob)
            old_src, old_st, g1 = src.parse(ch.old_path or path, ch.old_blob)
            if new_st is None or old_st is None:
                kind = g2 or g1
                counts["prescan_file_" + (kind.split(":")[0] if kind else "unreadable")] += 1
                if not (kind or "").startswith("excluded_"):
                    gaps.append(Gap("prescan_" + (kind or "unreadable"), local.repository, an["target"], path))
                continue
            res = match_file(old_st, new_st, src.hunks(ch.old_blob, ch.new_blob, new_src),
                             cfg.pair_threshold, cfg.move_threshold)
            found = [("added", a, None) for a in res.added]
            found += [("modified", p.after, p.before) for p in res.pairs
                      if p.kind in ("modified", "moved") and p.before.code.strip() != p.after.code.strip()]
            for kind, st, before in found:
                attr, commits = _line_attribution(pr, path, _stmt_hashes(st, before))
                counts[f"prescan_{kind}:{attr}"] += 1
                if attr in ("not_in_pr", "non_agent_commit"):
                    continue
                seeds.append({"pr_id": pr["pr_id"], "number": pr["number"], "agent": pr["agent"],
                              "merged_at": pr["merged_at"], "intro_kind": kind, "attribution": attr,
                              "pr_commits": commits, "target": an["target"], "base": an["base"],
                              "anchor_method": an["method"], "anchor_confidence": an["confidence"],
                              "path": path, "blob": ch.new_blob, "statement": st, "before": before,
                              "before_path": ch.old_path or path, "before_blob": ch.old_blob})
    return seeds


# --------------------------------------------------------------------------- forward

def _same(a: LogStatement, b: LogStatement) -> bool:
    return a.line == b.line and a.shash == b.shash and a.col == b.col


def seed_author(seed: dict) -> dict:
    """A seed version was written by the seed PR, whatever commit brought it into the first-parent chain."""
    return {"author_kind": "agent", "agent": seed["agent"], "pr_number": seed["number"], "evidence": "seed_pr",
            "line_attribution": seed["attribution"]}


class Lineage:
    def __init__(self, lid: str, seed: dict, commit: Commit, entry_meta: dict, window_days: int):
        self.id = lid
        self.path = seed["path"]
        self.current: LogStatement = seed["statement"]
        self.status = "alive"
        self.stop_detail = None
        self.window_end = _dt(seed["merged_at"]) + timedelta(days=window_days)
        self.started = commit
        self.first_seed = seed
        v = _version("seed", commit, seed["statement"], seed_author(seed), path=seed["path"], blob=seed["blob"])
        v["entry_author"] = entry_meta["author"]
        self.versions = [v]
        self.changes: list[dict] = []
        if seed["intro_kind"] == "modified" and seed["before"] is not None:
            # the agent's own modification of an existing log is the chain's first recorded change
            self.changes.append({"kind": "seed_modification", "confidence": seed["anchor_confidence"] or "probable",
                                 "score": None, **entry_meta, "author": seed_author(seed),
                                 "entry_author": entry_meta["author"], "path": seed["path"],
                                 "before_code": seed["before"].code, "after_code": seed["statement"].code,
                                 "days_since_start": 0, **change_record(seed["before"], seed["statement"]),
                                 "detail_commits": []})
        self.seeds = [_seed_touch(seed, commit, None)]
        self.backward: list[dict] = []
        self.origin: dict | None = None
        self.suspended: dict | None = None     # a version could not be parsed: waiting to find the log again
        self.gaps: list[dict] = []             # parse gaps that were bridged or ended the chain
        self.last_date = commit.date


def _seed_touch(seed: dict, commit: Commit, change_index: int | None) -> dict:
    return {"pr_id": seed["pr_id"], "number": seed["number"], "agent": seed["agent"], "merged_at": seed["merged_at"],
            "intro_kind": seed["intro_kind"], "attribution": seed["attribution"], "pr_commits": seed["pr_commits"],
            "commit": commit.sha, "anchor_method": seed["anchor_method"], "anchor_confidence": seed["anchor_confidence"],
            "change_index": change_index}


def _branch_details(local: LocalRepo, merge: Commit, path: str, before: LogStatement | None,
                    after: LogStatement | None, index: PrIndex) -> list[dict]:
    """Commits of the merged branch whose diff touches the statement's old or new lines."""
    if len(merge.parents) < 2:
        return []
    want_plus = {x.strip() for x in (after.code.splitlines() if after else []) if x.strip()}
    want_minus = {x.strip() for x in (before.code.splitlines() if before else []) if x.strip()}
    proc = popen_git(local.path, "log", "--no-abbrev", "-U0", "--no-color", _FORMAT,
                     f"{merge.parents[0]}..{merge.parents[1]}", "--", path)
    out = []
    try:
        for rec in _records(proc):
            head, _, patch = rec.partition(b"\x1f\n")
            try:
                c = _parse_head(head + b"\x1f")
            except Exception:
                continue
            lines = patch.decode("utf-8", "replace").splitlines()
            plus = {ln[1:].strip() for ln in lines if ln.startswith("+") and not ln.startswith("+++")}
            minus = {ln[1:].strip() for ln in lines if ln.startswith("-") and not ln.startswith("---")}
            if plus & want_plus or minus & want_minus:
                out.append({"commit": c.sha, "date": c.date.isoformat(), "message": c.message[:500],
                            "author_name": c.author_name, "author": attribute(c, index)})
    finally:
        proc.stdout.close()
        proc.kill()
        proc.wait()
    return out[:20]


def _commit_meta(c: Commit, index: PrIndex) -> dict:
    return {"commit": c.sha, "date": c.date.isoformat(), "message": c.message[:2000], "author_name": c.author_name,
            "is_merge": c.is_merge, "author": attribute(c, index)}


def forward(local: LocalRepo, seeds: list[dict], hist, src: Sources, index: PrIndex, cfg: Config,
            counts: Counter, gaps: list[Gap]) -> list[Lineage]:
    if not seeds:
        return []
    by_target: dict[str, list[dict]] = defaultdict(list)
    for s in seeds:
        by_target[s["target"]].append(s)
    targets = sorted(by_target, key=lambda t: hist.fp_pos[t])
    first = hist.fp[hist.fp_pos[targets[0]]]
    base = first.parents[0] if first.parents else None
    lineages: list[Lineage] = []
    active: list[Lineage] = []
    last_target = hist.fp_pos[targets[-1]]
    n_id = 0

    for commit, changes in first_parent_log(local.path, local.frozen_head, base, with_changes=True):
        if hist.fp_pos.get(commit.sha, 0) > last_target and not any(
                l.status == "alive" and commit.date <= l.window_end for l in active):
            break
        for lin in active:
            if lin.status == "alive" and commit.date > lin.window_end:
                lin.status = "suspended_at_window_end" if lin.suspended else "window_end"
        active = [l for l in active if l.status == "alive"]
        by_old = {ch.old_path: ch for ch in changes if ch.old_path}
        new_seeds = by_target.get(commit.sha, [])
        touched = [l for l in active if l.path in by_old]
        results: dict[str, tuple] = {}
        meta = None
        for lin in touched:
            ch = by_old[lin.path]
            if ch.old_path not in results:
                old_src, old_st, g1 = src.parse(ch.old_path, ch.old_blob)
                new_path = ch.new_path or ch.old_path
                new_src, new_st, g2 = src.parse(new_path, ch.new_blob)
                res = None
                if old_st is not None and new_st is not None:
                    res = match_file(old_st, new_st, src.hunks(ch.old_blob, ch.new_blob, new_src),
                                     cfg.pair_threshold, cfg.move_threshold)
                results[ch.old_path] = (ch, res, g1 or g2, new_st)
            ch, res, gap, new_st = results[ch.old_path]
            meta = meta or _commit_meta(commit, index)
            if res is None or lin.suspended:
                if _bridge(lin, commit, ch, new_st, gap, meta, local, gaps, counts):
                    continue
                res = None
            if res is None:
                continue
            pair = next((p for p in res.pairs if _same(p.before, lin.current)), None)
            if pair is not None and pair.kind == "unchanged":
                lin.current, lin.path = pair.after, ch.new_path or lin.path
                continue
            if pair is None and ch.new_blob is not None and not any(_same(d, lin.current) for d in res.deleted):
                # the statement was not in the parsed old version: should not happen, stop honestly
                lin.status, lin.stop_detail = "blocked", f"statement_not_found@{commit.sha[:10]}"
                continue
            if pair is None:
                pair = _cross_file(lin, commit, changes, ch, src, cfg)
            if pair is None:
                kind = "file_deleted" if ch.new_blob is None else "deleted"
                lin.changes.append({"kind": kind, "confidence": "certain", **meta, "path": lin.path,
                                    "before_code": lin.current.code, "after_code": None,
                                    "days_since_start": (commit.date - lin.started.date).days,
                                    "detail_commits": _branch_details(local, commit, lin.path, lin.current, None, index)
                                    if commit.is_merge else []})
                lin.status = kind
                continue
            new_path = pair.after.path
            rec = change_record(pair.before, pair.after)
            lin.changes.append({"kind": pair.kind, "confidence": pair.confidence, "score": pair.score, **meta,
                                "path": new_path, "before_code": pair.before.code, "after_code": pair.after.code,
                                "days_since_start": (commit.date - lin.started.date).days, **rec,
                                "detail_commits": _branch_details(local, commit, lin.path, pair.before, pair.after, index)
                                if commit.is_merge else []})
            blob = ch.new_blob if new_path == (ch.new_path or ch.old_path) else _blob_of(changes, new_path)
            lin.versions.append(_version("forward", commit, pair.after, meta["author"], path=new_path, blob=blob))
            lin.current, lin.path = pair.after, new_path

        # seeds landing at this commit: attach to an existing lineage or start a new one
        for s in new_seeds:
            # already tracked: the lineage's current statement is exactly this seed's statement
            host = next((l for l in lineages if l.status == "alive" and l.path == s["path"]
                         and _same(l.current, s["statement"])), None)
            if host is not None:
                idx = len(host.changes) - 1 if host.changes and host.changes[-1]["commit"] == commit.sha else None
                if idx is not None:
                    # this change was made by the seed PR, not by whoever merged it into the chain
                    host.changes[idx]["entry_author"] = host.changes[idx]["author"]
                    host.changes[idx]["author"] = seed_author(s)
                    if host.versions[-1]["commit"] == commit.sha:
                        host.versions[-1]["entry_author"] = host.versions[-1]["author"]
                        host.versions[-1]["author"] = seed_author(s)
                host.seeds.append(_seed_touch(s, commit, idx))
                counts["seed_logs_merged_into_existing_lineage"] += 1
                continue
            n_id += 1
            lid = hashlib.sha1(f"{local.repository}|{s['path']}|{commit.sha}|{s['statement'].line}|{n_id}".encode()).hexdigest()[:16]
            meta = meta or _commit_meta(commit, index)
            lin = Lineage(lid, s, commit, meta, cfg.window_days)
            lineages.append(lin)
            active.append(lin)
    for lin in lineages:
        if lin.status == "alive":
            done = lin.window_end <= local.frozen_at
            if lin.suspended:
                lin.status = "suspended_at_window_end" if done else "suspended_at_frozen_head"
            else:
                lin.status = "window_end" if done else "alive_at_frozen_head"
    return lineages


def _bridge(lin: Lineage, commit: Commit, ch, new_st, gap: str | None, meta: dict, local: LocalRepo,
            gaps: list[Gap], counts: Counter) -> bool:
    """A side of the diff could not be parsed, or the lineage is waiting after such a version.

    Suspend on an unparsable new version; on the next parsable version look for the log by its
    exact code (whitespace-insensitive): one match resumes the chain (the gap is recorded), none
    or several end it. Returns True when the lineage was handled here."""
    new_path = ch.new_path or ch.old_path
    if ch.new_blob is None:                               # file deleted while suspended / unreadable
        lin.changes.append({"kind": "file_deleted", "confidence": "certain", **meta, "path": lin.path,
                            "before_code": lin.current.code, "after_code": None,
                            "days_since_start": (commit.date - lin.started.date).days, "detail_commits": []})
        lin.status = "file_deleted"
        return True
    if new_st is None:                                    # still unparsable: suspend (or stay suspended)
        if lin.suspended is None:
            lin.suspended = {"since": commit.sha, "date": commit.date.isoformat(), "reason": gap}
            gaps.append(Gap("track_" + (gap or "unreadable"), local.repository, commit.sha, lin.path))
            counts["lineage_suspended"] += 1
        lin.path = new_path
        return True
    if lin.suspended is None:                             # old side unparsable but not suspended: treat as suspended
        lin.suspended = {"since": commit.sha, "date": commit.date.isoformat(), "reason": gap}
    target = _norm_code(lin.current.code)
    found = [a for a in new_st if _norm_code(a.code) == target]
    rec = {**lin.suspended, "until": commit.sha, "until_date": commit.date.isoformat()}
    lin.suspended = None
    if len(found) == 1:
        rec["outcome"] = "resumed"
        lin.gaps.append(rec)
        lin.current, lin.path = found[0], new_path
        counts["lineage_resumed_after_parse_gap"] += 1
        return True
    rec["outcome"] = "lost" if not found else "ambiguous"
    lin.gaps.append(rec)
    lin.status = "lost_after_parse_gap" if not found else "ambiguous_after_parse_gap"
    lin.stop_detail = f"{rec['reason']}@{rec['since'][:10]}"
    counts["lineage_" + lin.status] += 1
    return True


def _norm_code(code: str) -> str:
    return "".join(code.split())


def _blob_of(changes, path):
    for ch in changes:
        if ch.new_path == path:
            return ch.new_blob
    return None


def _cross_file(lin: Lineage, commit: Commit, changes, ch, src: Sources, cfg: Config):
    """The statement vanished from its file: was it moved to another file changed in this commit?"""
    from .match import Pair
    best = None
    for other in changes:
        if other is ch or other.new_blob is None or not other.new_path:
            continue
        if excluded_path(other.new_path, cfg) is not None:
            continue
        new_src, new_st, _ = src.parse(other.new_path, other.new_blob)
        if not new_st:
            continue
        _, old_st, _ = src.parse(other.old_path, other.old_blob) if other.old_blob else (None, [], None)
        old_keys = {(s.shash) for s in (old_st or [])}
        for a in new_st:
            if a.shash in old_keys and a.shash != lin.current.shash:
                continue
            if not same_message(lin.current, a):
                continue
            s = similarity(lin.current, a)
            if s >= cfg.move_threshold and (best is None or s > best[0]):
                best = (s, a)
    if best is None:
        return None
    return Pair(lin.current, best[1], "moved", "probable", round(best[0], 3))


# --------------------------------------------------------------------------- backward

def backward(local: LocalRepo, lin: Lineage, index: PrIndex, cfg: Config) -> None:
    s = lin.first_seed
    before: LogStatement | None = s["before"]
    if s["intro_kind"] != "modified" or before is None:
        return
    base = s["base"]
    hist = line_history(local.path, before.line, before.end_line, s["before_path"], base, timeout=120)
    versions = []
    for commit, added in hist:
        # git log -L hunks can carry neighbouring code: keep only the statement that is this log
        st = _snippet_statement(s["before_path"], added, before, cfg.pair_threshold)
        v = _version("backward", commit, st, attribute(commit, index), path=s["before_path"],
                     code=None, context="snippet" if st is not None else "snippet_unmatched")
        versions.append(v)
    lin.backward = list(reversed(versions))            # oldest first
    if versions:
        lin.origin = {"commit": versions[-1]["commit"], "date": versions[-1]["date"], "author": versions[-1]["author"]}
    else:
        lin.origin = None


def _snippet_statement(path: str, lines: list[str], like: LogStatement, threshold: float) -> LogStatement | None:
    """The log statement in a ``git log -L`` hunk that is the tracked log (most similar, above threshold)."""
    text = textwrap.dedent("\n".join(lines))
    try:
        sts = find_logs(path, text, True).statements
    except PARSE_ERRORS:
        # the hunk may be a fragment: try each line group that starts a log call on its own
        sts = []
        for i, ln in enumerate(lines):
            try:
                sts += list(find_logs(path, textwrap.dedent("\n".join(lines[i:i + 12])), True).statements[:1])
            except PARSE_ERRORS:
                continue
    best = max(sts, key=lambda x: similarity(like, x), default=None)
    return best if best is not None and similarity(like, best) >= threshold else None


# --------------------------------------------------------------------------- driver

def track_repository(local: LocalRepo, anchors: list[dict], prs: dict[int, dict], hist, index: PrIndex,
                     cfg: Config) -> tuple[list[dict], list[dict], Counter, list[Gap]]:
    counts: Counter = Counter()
    gaps: list[Gap] = []
    src = Sources(local, cfg)
    try:
        seeds = prescan(local, anchors, prs, src, cfg, counts, gaps)
        counts["seed_logs"] = len(seeds)
        lineages = forward(local, seeds, hist, src, index, cfg, counts, gaps)
        for lin in lineages:
            try:
                backward(local, lin, index, cfg)
            except Exception:
                gaps.append(Gap("backward_failed", local.repository, lin.started.sha, lin.path,
                                detail=traceback.format_exc()[-300:]))
    finally:
        src.close()
    seed_rows = [{**{k: v for k, v in s.items() if k not in ("statement", "before")},
                  "statement": to_jsonable(s["statement"]), "before": to_jsonable(s["before"])} for s in seeds]
    rows = []
    for lin in lineages:
        rows.append({
            "lineage_id": lin.id, "repository": local.repository, "path": lin.path,
            "start_commit": lin.started.sha, "start_date": lin.started.date.isoformat(),
            "window_end": lin.window_end.isoformat(), "observation_complete": lin.window_end <= local.frozen_at,
            "status": lin.status, "stop_detail": lin.stop_detail,
            "intro_kind": lin.first_seed["intro_kind"], "seeds": lin.seeds,
            "agents": sorted({s["agent"] for s in lin.seeds}),
            "origin": lin.origin, "versions": lin.backward + lin.versions, "changes": lin.changes,
            "gaps": lin.gaps + ([{**lin.suspended, "outcome": "unresolved"}] if lin.suspended else []),
        })
        counts["lineages"] += 1
        counts["lineage_status:" + lin.status] += 1
    return seed_rows, rows, counts, gaps
