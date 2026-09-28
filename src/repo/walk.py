"""walk_history (REBUILD.md §8): stream every commit of the frozen head, parents first.

Two long-lived processes instead of per-commit subprocesses:
  * ``git log --topo-order --reverse --raw -z -M --root`` for change lists
  * ``git cat-file --batch`` for contents

Merge commits carry no diff (``--raw`` omits it for merges): the branch commits are
analysed individually already. A merge whose ``--cc`` diff shows hand-made conflict
resolution in a .py file yields a ``merge_resolution_unanalyzed`` gap instead.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

from ..config import Config
from ..models import CommitWork, FileVersions, Gap, LocalRepo
from ..seeds.prefilter import _UNPARSEABLE, _unquote_c_style
from .gitcmd import popen_git
from .materialize import CatFile, Unavailable, materialize

NULL_SHA = "0" * 40
_SKIP_MODES = {"160000", "120000"}          # submodule, symlink
RS, US = b"\x1e", b"\x1f"


def _records(proc) -> Iterator[bytes]:
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


def merge_resolutions(local: LocalRepo, cfg: Config) -> dict[str, list[str]]:
    """sha -> .py paths whose merge result differs from every parent in some hunk."""
    proc = popen_git(local.path, "log", "--merges", "--cc", "-p", "--format=%x1e%H", local.frozen_head)
    out: dict[str, list[str]] = {}
    for rec in _records(proc):
        lines = rec.split(b"\n")
        sha = lines[0].decode().strip()
        for ln in lines[1:]:
            if ln.startswith(b"diff --cc "):
                raw = ln[len(b"diff --cc "):].decode("utf-8", "replace")
                path = _unquote_c_style(raw) if raw.startswith('"') else raw
                if path is not _UNPARSEABLE and path.endswith(tuple(cfg.suffixes)):
                    out.setdefault(sha, []).append(path)
    proc.wait()
    return out


def _parse_record(rec: bytes):
    head, _, rest = rec.partition(US + b"\x00")
    fields = head.split(US)
    sha = fields[0].decode()
    parents = tuple(fields[1].decode().split()) if len(fields) > 1 else ()
    ts = int(fields[2]) if len(fields) > 2 and fields[2] else 0
    email = fields[3].decode("utf-8", "replace") if len(fields) > 3 else ""
    body = fields[4].decode("utf-8", "replace") if len(fields) > 4 else ""
    changes = []
    toks = rest.lstrip(b"\n").split(b"\x00")
    i = 0
    while i < len(toks):
        t = toks[i]
        if not t.startswith(b":"):
            i += 1
            continue
        meta = t[1:].decode().split()
        old_mode, new_mode, old_sha, new_sha, status = meta[:5]
        if status[0] in "RC":
            p1, p2 = toks[i + 1].decode("utf-8", "surrogateescape"), toks[i + 2].decode("utf-8", "surrogateescape")
            changes.append((status, old_mode, new_mode, old_sha, new_sha, p1, p2))
            i += 3
        else:
            p = toks[i + 1].decode("utf-8", "surrogateescape")
            changes.append((status, old_mode, new_mode, old_sha, new_sha, p, p))
            i += 2
    return sha, parents, ts, email, body, changes


def walk_history(local: LocalRepo, cfg: Config) -> Iterator[CommitWork]:
    resolutions = merge_resolutions(local, cfg)
    sfx = tuple(cfg.suffixes)
    proc = popen_git(local.path, "log", "--topo-order", "--reverse", "--raw", "-z", "-M", "--no-abbrev",
                     "--root",
                     "--format=%x1e%H%x1f%P%x1f%ct%x1f%ae%x1f%B%x1f", local.frozen_head)
    with CatFile(local.path) as cat:
        for rec in _records(proc):
            sha, parents, ts, email, body, changes = _parse_record(rec)
            date = datetime.fromtimestamp(ts, tz=timezone.utc)
            is_merge = len(parents) > 1
            gaps: list[Gap] = []
            files: list[FileVersions] = []
            if is_merge:
                for path in resolutions.get(sha, []):
                    gaps.append(Gap("merge_resolution_unanalyzed", local.repository, sha, path))
            else:
                for status, om, nm, osha, nsha, p_old, p_new in changes:
                    old_ok = p_old.endswith(sfx) and om not in _SKIP_MODES and osha != NULL_SHA
                    new_ok = p_new.endswith(sfx) and nm not in _SKIP_MODES and nsha != NULL_SHA
                    if not (old_ok or new_ok):
                        continue
                    renamed = status[0] == "R" and old_ok and new_ok and p_old != p_new
                    path = p_new if new_ok else p_old
                    before, g1 = materialize(cat, osha if old_ok else None, cfg.max_file_bytes)
                    after, g2 = materialize(cat, nsha if new_ok else None, cfg.max_file_bytes)
                    bad = False
                    for side, g in (("before", g1), ("after", g2)):
                        if g:
                            gaps.append(Gap(g, local.repository, sha, path, side))
                            bad = True
                    if bad or isinstance(before, Unavailable) or isinstance(after, Unavailable):
                        continue
                    files.append(FileVersions(
                        path=path, old_path=p_old if renamed else None,
                        rename_score=int(status[1:]) if renamed and status[1:].isdigit() else None,
                        before=before, after=after,
                        before_blob=osha if old_ok else None, after_blob=nsha if new_ok else None))
            yield CommitWork(local.repository, sha, parents, date, email, body, is_merge, tuple(files), tuple(gaps))
    proc.wait()
    if proc.returncode not in (0, None):
        raise RuntimeError(f"git log failed for {local.repository} (exit {proc.returncode})")
