"""Git history primitives: first-parent log, change lists, blob diffs, PR refs, line history.

All reads go through the hardened git wrapper; nothing is checked out.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ..track.match import Hunk
from .gitcmd import git_argv, git_env, popen_git, run_git

RS, US = b"\x1e", b"\x1f"
NULL_SHA = "0" * 40
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_FORMAT = "--format=%x1e%H%x1f%P%x1f%ct%x1f%an%x1f%ae%x1f%B%x1f"


@dataclass(frozen=True)
class Commit:
    sha: str
    parents: tuple[str, ...]
    date: datetime
    author_name: str
    author_email: str
    message: str

    @property
    def is_merge(self) -> bool:
        return len(self.parents) > 1


@dataclass(frozen=True)
class Change:
    status: str                      # A M D R C T
    old_path: str | None
    new_path: str | None
    old_blob: str | None
    new_blob: str | None


_SHA_HEAD = re.compile(rb"^[0-9a-f]{40}\x1f")


def _raw_records(proc) -> Iterator[bytes]:
    buf = b""
    while True:
        chunk = proc.stdout.read(1 << 20)
        if not chunk:
            break
        buf += chunk
        parts = buf.split(RS)
        buf = parts.pop()
        for p in parts:
            if p:
                yield p
    if buf:
        yield buf


def _records(proc) -> Iterator[bytes]:
    """Records start with a SHA; a separator byte inside a commit message is glued back."""
    pending = None
    for rec in _raw_records(proc):
        if _SHA_HEAD.match(rec) or pending is None:
            if pending is not None:
                yield pending
            pending = rec
        else:
            pending += RS + rec
    if pending is not None:
        yield pending


def _parse_head(head: bytes) -> Commit:
    f = head.split(US, 5)
    f += [b""] * (6 - len(f))
    return Commit(sha=f[0].decode(), parents=tuple(f[1].decode().split()),
                  date=datetime.fromtimestamp(int(f[2] or 0), tz=timezone.utc),
                  author_name=f[3].decode("utf-8", "replace"), author_email=f[4].decode("utf-8", "replace"),
                  message=f[5].decode("utf-8", "replace").rstrip("\x1f"))


def _parse_raw(rest: bytes) -> list[Change]:
    toks = rest.lstrip(b"\n").split(b"\x00")
    out, i = [], 0
    while i < len(toks):
        t = toks[i]
        if not t.startswith(b":"):
            i += 1
            continue
        old_mode, new_mode, old_sha, new_sha, status = t[1:].decode().split()[:5]
        if status[0] in "RC":
            p1, p2 = toks[i + 1].decode("utf-8", "surrogateescape"), toks[i + 2].decode("utf-8", "surrogateescape")
            i += 3
        else:
            p1 = p2 = toks[i + 1].decode("utf-8", "surrogateescape")
            i += 2
        skip = {"160000", "120000"}
        ob = None if old_sha == NULL_SHA or old_mode in skip else old_sha
        nb = None if new_sha == NULL_SHA or new_mode in skip else new_sha
        out.append(Change(status[0], p1 if ob else None, p2 if nb else None, ob, nb))
    return out


def first_parent_log(repo: Path, head: str, base: str | None = None,
                     with_changes: bool = False) -> Iterator[tuple[Commit, list[Change]]]:
    """Oldest first. ``base`` excluded. With changes: diff against the first parent (merges too)."""
    args = ["log", "--first-parent", "--reverse", "--no-abbrev", _FORMAT]
    if with_changes:
        args += ["--raw", "-z", "-M", "--diff-merges=first-parent"]
    args.append(f"{base}..{head}" if base else head)
    proc = popen_git(repo, *args)
    try:
        for rec in _records(proc):
            head_part, _, rest = rec.partition(US + (b"\x00" if with_changes else b"\n"))
            if not with_changes:
                head_part = rec.rstrip(b"\n").rstrip(US)
                yield _parse_head(head_part), []
            else:
                yield _parse_head(head_part), _parse_raw(rest)
    finally:
        proc.stdout.close()
        proc.kill()
        proc.wait()


def all_commits(repo: Path, head: str) -> Iterator[Commit]:
    """Every commit reachable from head (not only first parent), newest first, no diffs."""
    proc = popen_git(repo, "log", "--no-abbrev", _FORMAT, head)
    try:
        for rec in _records(proc):
            yield _parse_head(rec.rstrip(b"\n").rstrip(US))
    finally:
        proc.stdout.close()
        proc.kill()
        proc.wait()


def diff_tree(repo: Path, a: str, b: str) -> list[Change]:
    out = run_git(repo, "diff-tree", "-r", "-M", "--raw", "-z", "--no-abbrev", a, b).stdout
    return _parse_raw(out)


def blob_hunks(repo: Path, old_blob: str, new_blob: str) -> list[Hunk]:
    out = run_git(repo, "diff", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", old_blob, new_blob,
                  check=False).stdout.decode("utf-8", "replace")
    hunks = []
    for line in out.splitlines():
        m = _HUNK.match(line)
        if m:
            hunks.append(Hunk(int(m.group(1)), int(m.group(2)) if m.group(2) is not None else 1,
                              int(m.group(3)), int(m.group(4)) if m.group(4) is not None else 1))
    return hunks


def added_lines(repo: Path, a: str, b: str, paths: list[str]) -> dict[str, list[str]]:
    """Added lines per path of the diff a..b (used to validate an anchor)."""
    if not paths:
        return {}
    out = run_git(repo, "diff", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", a, b, "--", *paths,
                  check=False).stdout.decode("utf-8", "replace")
    res: dict[str, list[str]] = {}
    cur = None
    for line in out.splitlines():
        if line.startswith("+++ "):
            cur = line[6:] if line.startswith("+++ b/") else None
            if cur is not None:
                res.setdefault(cur, [])
        elif line.startswith("+") and cur is not None:
            res[cur].append(line[1:])
    return res


def is_ancestor(repo: Path, a: str, b: str) -> bool:
    return run_git(repo, "merge-base", "--is-ancestor", a, b, check=False).returncode == 0


def object_exists(repo: Path, sha: str) -> bool:
    return run_git(repo, "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode == 0


def fetch_pr_heads(repo: Path, numbers: list[int], timeout: int) -> tuple[set[int], str | None]:
    """Fetch refs/pull/N/head into refs/logtrace/pr/N. Returns (fetched numbers, error)."""
    want = [n for n in numbers if run_git(repo, "rev-parse", "--verify", "--quiet", f"refs/logtrace/pr/{n}",
                                          check=False).returncode != 0]
    err = None
    for i in range(0, len(want), 200):
        specs = [f"+refs/pull/{n}/head:refs/logtrace/pr/{n}" for n in want[i:i + 200]]
        try:
            r = run_git(repo, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "origin", *specs,
                        timeout=timeout, check=False)
            if r.returncode != 0:
                # one missing ref fails the whole batch: fall back to one by one
                for s in specs:
                    run_git(repo, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "origin", s,
                            timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            err = "fetch_timeout"
            break
    got = set()
    for n in numbers:
        if run_git(repo, "rev-parse", "--verify", "--quiet", f"refs/logtrace/pr/{n}", check=False).returncode == 0:
            got.add(n)
    return got, err


def rev(repo: Path, spec: str) -> str | None:
    r = run_git(repo, "rev-parse", "--verify", "--quiet", spec + "^{commit}", check=False)
    return r.stdout.decode().strip() if r.returncode == 0 else None


def patch_ids(repo: Path, commits: list[str]) -> dict[str, str]:
    """patch-id (stable) per non-merge commit."""
    if not commits:
        return {}
    show = subprocess.run(git_argv(repo, "show", "--no-color", "--no-ext-diff", "--format=commit %H", *commits),
                          env=git_env(), capture_output=True, timeout=600)
    pid = subprocess.run(git_argv(repo, "patch-id", "--stable"), env=git_env(), input=show.stdout,
                         capture_output=True, timeout=600)
    out = {}
    for line in pid.stdout.decode().splitlines():
        p, c = line.split()
        out[c] = p
    return out


def range_patch_id(repo: Path, a: str, b: str) -> str | None:
    diff = subprocess.run(git_argv(repo, "diff", "--no-color", "--no-ext-diff", a, b), env=git_env(),
                          capture_output=True, timeout=600).stdout
    if not diff:
        return None
    pid = subprocess.run(git_argv(repo, "patch-id", "--stable"), env=git_env(), input=b"commit " + b"0" * 40 + b"\n" + diff,
                         capture_output=True, timeout=600).stdout.decode().split()
    return pid[0] if pid else None


def line_history(repo: Path, start: int, end: int, path: str, rev_: str, timeout: int) -> list[tuple[Commit, list[str]]]:
    """``git log -L start,end:path rev``: commits that touched those lines, newest first,
    each with the added lines of its hunk for that range."""
    try:
        out = run_git(repo, "log", "--no-abbrev", "--no-color", _FORMAT.replace("%B%x1f", "%B%x1f%x1d"),
                      f"-L{start},{end}:{path}", rev_, timeout=timeout, check=False).stdout
    except subprocess.TimeoutExpired:
        return []
    res = []
    recs, pending = [], None
    for rec in out.split(RS):
        if _SHA_HEAD.match(rec) or pending is None:
            if pending is not None:
                recs.append(pending)
            pending = rec
        else:
            pending += RS + rec
    if pending is not None:
        recs.append(pending)
    for rec in recs:
        if not rec.strip():
            continue
        head, _, patch = rec.partition(b"\x1d")
        commit = _parse_head(head.rstrip(b"\n").rstrip(US))
        added = [ln[1:] for ln in patch.decode("utf-8", "replace").splitlines()
                 if ln.startswith("+") and not ln.startswith("+++")]
        res.append((commit, added))
    return res
