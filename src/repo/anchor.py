"""Where each seed PR's code entered the default branch (stage 2, per repository). Local only.

Three methods, in order:
  1 pr_number  a commit whose subject is "... (#N)" or "Merge pull request #N", validated by
               containing at least one line the PR added (so an issue reference is not taken)
  2 patch_id   after fetching refs/pull/N/head: a first-parent commit in the window with the same
               patch-id as the whole PR (squash) or as its last commits (rebase)
  3 text       a first-parent commit in the window adding >= 50% of the PR's added lines (probable)

Two points per PR:
  landing  the commit that carries the PR's code (may sit on a side branch such as ``next``)
  entry    the first first-parent commit that contains the landing; tracking starts there
and the prescan range (base, target) on the first-parent chain whose diff introduced the code.
"""
from __future__ import annotations

import hashlib
import subprocess
from bisect import bisect_left
from dataclasses import dataclass
from datetime import datetime, timedelta

from ..config import Config
from ..models import LocalRepo
from ..track.attribution import pr_number_in
from .history import (Commit, added_lines, all_commits, diff_tree, fetch_pr_heads, first_parent_log, is_ancestor,
                      patch_ids, range_patch_id, rev)
from .gitcmd import run_git


EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"      # git's empty tree: base of a root commit


def _h(line: str) -> str:
    return hashlib.sha1(line.strip().encode()).hexdigest()[:12]


@dataclass
class History:
    fp: list[Commit]                         # first-parent chain, oldest first
    fp_pos: dict[str, int]
    fp_dates: list[datetime]
    by_number: dict[int, list[Commit]]       # every reachable commit whose subject names a PR
    by_sha: dict[str, Commit]

    @classmethod
    def load(cls, local: LocalRepo) -> "History":
        fp = [c for c, _ in first_parent_log(local.path, local.frozen_head)]
        by_number, by_sha = {}, {}
        for c in all_commits(local.path, local.frozen_head):
            by_sha[c.sha] = c
            n = pr_number_in(c.message)
            if n is not None:
                by_number.setdefault(n, []).append(c)
        return cls(fp, {c.sha: i for i, c in enumerate(fp)}, [c.date for c in fp], by_number, by_sha)

    def window(self, start: datetime, days: int) -> list[Commit]:
        i = bisect_left(self.fp_dates, start - timedelta(days=2))
        end = start + timedelta(days=days)
        out = []
        for c in self.fp[i:]:
            if c.date > end:
                break
            out.append(c)
        return out


def pr_added_hashes(pr: dict) -> set[str]:
    return {h for c in pr["commits"] for f in c["files"] for h in f["added_hashes"]}


def pr_paths(pr: dict) -> list[str]:
    return sorted({f["path"] for c in pr["commits"] for f in c["files"]})


def _touching(local: LocalRepo, hist: History, paths: list[str], merged_at: datetime, cfg: Config) -> list[Commit]:
    """First-parent commits in the window that change one of ``paths`` (path-limited git log, in chunks)."""
    window = hist.window(merged_at, cfg.anchor_window_days)
    if not window or not paths:
        return []
    lo, hi = window[0], window[-1]
    rng = f"{lo.parents[0]}..{hi.sha}" if lo.parents else hi.sha
    keep: set[str] = set()
    for i in range(0, len(paths), 200):
        keep.update(run_git(local.path, "log", "--first-parent", "--format=%H", rng, "--", *paths[i:i + 200],
                            timeout=cfg.git_timeout_s).stdout.decode().split())
    return [c for c in window if c.sha in keep]


def _entry(local: LocalRepo, hist: History, landing: str) -> str | None:
    """First first-parent commit containing ``landing`` (ancestry is monotone along the chain)."""
    if landing in hist.fp_pos:
        return landing
    lo, hi = 0, len(hist.fp) - 1
    if hi < 0 or not is_ancestor(local.path, landing, hist.fp[hi].sha):
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        if is_ancestor(local.path, landing, hist.fp[mid].sha):
            hi = mid
        else:
            lo = mid + 1
    return hist.fp[lo].sha


def _validated(local: LocalRepo, commit: Commit, hashes: set[str], paths: list[str]) -> bool | None:
    """Does the commit (vs its first parent) add at least one of the PR's added lines?"""
    if not hashes:
        return None                                  # nothing to check against (patches missing)
    if not commit.parents:
        return False
    got = added_lines(local.path, commit.parents[0], commit.sha, paths)
    return any(_h(x) in hashes for lines in got.values() for x in lines if x.strip())


def _record(pr: dict, method: str | None, confidence: str | None, landing: str | None,
            base: str | None, target: str | None, entry: str | None, reason: str | None, **extra) -> dict:
    return {"repository": pr["repository"], "pr_id": pr["pr_id"], "number": pr["number"], "agent": pr["agent"],
            "merged_at": pr["merged_at"], "method": method, "confidence": confidence, "landing": landing,
            "base": base, "target": target, "entry": entry, "on_first_parent": landing is not None and landing == entry,
            "reason": reason, **extra}


def _by_number(local: LocalRepo, hist: History, pr: dict, merged_at: datetime, cfg: Config) -> dict | None:
    cands = hist.by_number.get(pr["number"], [])
    lo, hi = merged_at - timedelta(days=3), merged_at + timedelta(days=cfg.anchor_window_days)
    cands = [c for c in cands if lo <= c.date <= hi] or []
    cands.sort(key=lambda c: (c.sha not in hist.fp_pos, abs((c.date - merged_at).total_seconds())))
    hashes, paths = pr_added_hashes(pr), pr_paths(pr)
    for c in cands:
        ok = _validated(local, c, hashes, paths)
        if ok is False:
            continue
        entry = _entry(local, hist, c.sha)
        if entry is None:
            continue
        on_fp = entry == c.sha
        base = (c.parents[0] if c.parents else EMPTY_TREE) if on_fp else hist.by_sha[entry].parents[0]
        return _record(pr, "pr_number", "certain" if ok else "probable", c.sha, base, entry, entry, None,
                       validated=ok)
    return None


def _by_patch_id(local: LocalRepo, hist: History, pr: dict, merged_at: datetime, cfg: Config,
                 fetched: set[int]) -> dict | None:
    if pr["number"] not in fetched:
        return None
    head = rev(local.path, f"refs/logtrace/pr/{pr['number']}")
    if head is None:
        return None
    if is_ancestor(local.path, head, local.frozen_head):
        # the PR's own commits are in the history (fast-forward / pushed as is)
        mine = sorted((c["sha"] for c in pr["commits"] if c["sha"] in hist.fp_pos), key=hist.fp_pos.get)
        entry = _entry(local, hist, head)
        if entry is None:
            return None
        if head in hist.fp_pos:
            first = hist.by_sha[mine[0]] if mine else hist.by_sha[head]
            return _record(pr, "pr_head_in_history", "certain", head, first.parents[0] if first.parents else EMPTY_TREE,
                           head, head, None, kind="fast_forward")
        return _record(pr, "pr_head_in_history", "certain", head, hist.by_sha[entry].parents[0], entry, entry, None,
                       kind="merged_branch")
    base = run_git(local.path, "merge-base", head, local.frozen_head, check=False).stdout.decode().strip()
    if not base:
        return None
    # the files the PR branch really changes (tree diff: no file contents needed); AIDev's file
    # lists can be incomplete or polluted by unrelated commits, so they are not used here
    real = run_git(local.path, "diff", "--name-only", "--no-renames", base, head, check=False).stdout.decode().split("\n")
    window = [c for c in _touching(local, hist, [p for p in real if p], merged_at, cfg) if not c.is_merge and c.parents]
    if not window:
        return None
    wpid = patch_ids(local.path, [c.sha for c in window])
    by_pid = {}
    for c in window:
        if c.sha in wpid:
            by_pid.setdefault(wpid[c.sha], c)
    whole = range_patch_id(local.path, base, head)
    if whole and whole in by_pid:
        c = by_pid[whole]
        return _record(pr, "patch_id", "certain", c.sha, c.parents[0], c.sha, c.sha, None, kind="squash")
    own = run_git(local.path, "rev-list", "--reverse", "--no-merges", f"{base}..{head}").stdout.decode().split()
    ppid = patch_ids(local.path, own)
    matched = [by_pid[ppid[s]] for s in own if s in ppid and ppid[s] in by_pid]
    if matched and len(matched) >= max(1, len(own) // 2):
        matched.sort(key=lambda c: hist.fp_pos[c.sha])
        first, last = matched[0], matched[-1]
        return _record(pr, "patch_id", "certain" if len(matched) == len(own) else "probable",
                       last.sha, first.parents[0], last.sha, last.sha, None, kind="rebase",
                       matched_commits=len(matched), pr_commits=len(own))
    return None


def _by_text(local: LocalRepo, hist: History, pr: dict, merged_at: datetime, cfg: Config) -> dict | None:
    hashes, paths = pr_added_hashes(pr), pr_paths(pr)
    if not hashes or not paths:
        return None
    scored = []
    for c in _touching(local, hist, paths, merged_at, cfg):
        if not c.parents:
            continue
        got = added_lines(local.path, c.parents[0], c.sha, paths)
        mine = {_h(x) for lines in got.values() for x in lines if x.strip()}
        if mine:
            scored.append((len(mine & hashes) / len(hashes), c))
    scored.sort(key=lambda t: -t[0])
    if not scored or scored[0][0] < 0.5:
        return None
    if len(scored) > 1 and scored[1][0] >= scored[0][0] - 0.05:
        return _record(pr, None, None, None, None, None, None, "text_match_ambiguous")
    c = scored[0][1]
    return _record(pr, "text", "probable", c.sha, c.parents[0], c.sha, c.sha, None, overlap=round(scored[0][0], 3))


def _other_branches(local: LocalRepo, number: int) -> list[str]:
    """Branches (outside the default branch's history) holding a commit whose subject names PR #number."""
    out = run_git(local.path, "log", "--remotes", "--branches", "--format=%H%x1f%s", "-E",
                  f"--grep=\\(#{number}\\)|Merge pull request #{number}\\b", check=False).stdout.decode("utf-8", "replace")
    shas = [ln.split("\x1f")[0] for ln in out.splitlines()
            if pr_number_in(ln.split("\x1f", 1)[-1]) == number]
    branches: list[str] = []
    for sha in shas[:3]:
        if is_ancestor(local.path, sha, local.frozen_head):
            continue
        refs = run_git(local.path, "for-each-ref", "--contains", sha, "--format=%(refname:short)",
                       "refs/remotes", check=False).stdout.decode().split()
        branches += [r for r in refs if not r.endswith("/HEAD")]
    return sorted(set(branches))


def anchor_prs(local: LocalRepo, prs: list[dict], cfg: Config) -> tuple[list[dict], History]:
    hist = History.load(local)
    out, pending = [], []
    for pr in prs:
        merged_at = datetime.fromisoformat(pr["merged_at"]) if isinstance(pr["merged_at"], str) else pr["merged_at"]
        if merged_at > local.frozen_at:
            out.append(_record(pr, None, None, None, None, None, None, "merged_after_frozen_head"))
            continue
        rec = _by_number(local, hist, pr, merged_at, cfg)
        if rec is None:
            pending.append((pr, merged_at))
        else:
            out.append(rec)
    fetched, err = set(), None
    if pending and cfg.fetch_pr_refs:
        fetched, err = fetch_pr_heads(local.path, [pr["number"] for pr, _ in pending], cfg.git_timeout_s)
    for pr, merged_at in pending:
        try:
            rec = _by_patch_id(local, hist, pr, merged_at, cfg, fetched) or _by_text(local, hist, pr, merged_at, cfg)
        except subprocess.TimeoutExpired:
            out.append(_record(pr, None, None, None, None, None, None, "anchor_timeout"))
            continue
        if rec is None:
            has_number = pr["number"] in hist.by_number
            elsewhere = [] if has_number else _other_branches(local, pr["number"])
            reason = ("pr_number_found_but_unvalidated" if has_number else
                      "merged_into_non_default_branch" if elsewhere else
                      "pr_ref_unavailable" if cfg.fetch_pr_refs and pr["number"] not in fetched else
                      "no_matching_commit_in_window")
            rec = _record(pr, None, None, None, None, None, None, reason, fetch_error=err,
                          other_branches=elsewhere[:10] or None)
        out.append(rec)
    return out, hist
