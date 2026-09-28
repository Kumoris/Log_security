"""The ledger (REBUILD.md §8): all log events + gaps of one repository, with indexes.

Written to JSONL while walking (one line per record, ``type`` distinguishes event /
gap / commit), indexed in memory at the same time. ``load_ledger`` rebuilds the same
object from disk so tracking can be rerun without git.
"""
from __future__ import annotations

import json
from collections import OrderedDict, deque
from pathlib import Path

from ..models import Gap, LogEvent, dumps, event_from_dict, gap_from_dict


class Ledger:
    def __init__(self):
        self.by_before_fp: dict[str, list[LogEvent]] = {}
        self.by_sha: dict[str, list[LogEvent]] = {}
        self.gaps_by_path: dict[str, list[Gap]] = {}
        self.gaps_by_sha: dict[str, list[Gap]] = {}
        self.parents: dict[str, tuple[str, ...]] = {}
        self.children: dict[str, list[str]] = {}
        self.commit_order: dict[str, int] = {}
        self.commit_date: dict[str, object] = {}
        self.commit_message: dict[str, str] = {}
        self.n_events = 0
        self._desc_cache: OrderedDict[str, frozenset[str]] = OrderedDict()

    # building ---------------------------------------------------------------

    def add_commit(self, sha: str, parents: tuple[str, ...], date=None, message: str = "") -> None:
        self.commit_order[sha] = len(self.commit_order)
        self.parents[sha] = parents
        self.commit_date[sha] = date
        self.commit_message[sha] = message[:2000]
        self.children.setdefault(sha, [])
        for p in parents:
            self.children.setdefault(p, []).append(sha)

    def extend(self, events: list[LogEvent]) -> None:
        for e in events:
            self.n_events += 1
            self.by_sha.setdefault(e.sha, []).append(e)
            if e.before_fp is not None:
                self.by_before_fp.setdefault(e.before_fp, []).append(e)

    def add_gaps(self, gaps: list[Gap]) -> None:
        for g in gaps:
            if g.sha:
                self.gaps_by_sha.setdefault(g.sha, []).append(g)
            if g.path:
                self.gaps_by_path.setdefault(g.path, []).append(g)

    # graph queries -----------------------------------------------------------

    def descendants(self, sha: str) -> frozenset[str]:
        """sha and every commit that has it as an ancestor (BFS over children, cached)."""
        hit = self._desc_cache.get(sha)
        if hit is not None:
            self._desc_cache.move_to_end(sha)
            return hit
        seen = {sha}
        q = deque([sha])
        while q:
            for c in self.children.get(q.popleft(), ()):
                if c not in seen:
                    seen.add(c)
                    q.append(c)
        out = frozenset(seen)
        self._desc_cache[sha] = out
        if len(self._desc_cache) > 256:
            self._desc_cache.popitem(last=False)
        return out

    def is_ancestor(self, a: str, b: str) -> bool:
        return b in self.descendants(a)

    def gaps_between(self, path: str, prev_sha: str, next_sha: str | None, end_date=None) -> list[Gap]:
        """Gaps on ``path`` in a commit that descends from prev_sha (exclusive) and is an
        ancestor of next_sha (inclusive); with next_sha None, any descendant up to end_date."""
        out = []
        after_prev = self.descendants(prev_sha)
        for g in self.gaps_by_path.get(path, ()):
            if g.sha == prev_sha or g.sha not in after_prev:
                continue
            if next_sha is not None:
                if g.sha == next_sha or self.is_ancestor(g.sha, next_sha):
                    out.append(g)
            elif end_date is None or (self.commit_date.get(g.sha) and self.commit_date[g.sha] <= end_date):
                out.append(g)
        return out


class LedgerWriter:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.tmp = path.with_suffix(".jsonl.partial")
        self.f = self.tmp.open("w")

    def commit(self, sha, parents, date, message):
        self.f.write(json.dumps({"type": "commit", "sha": sha, "parents": list(parents),
                                 "date": date.isoformat(), "message": message[:2000]}) + "\n")

    def write(self, events, gaps):
        for e in events:
            self.f.write('{"type": "event", "data": ' + dumps(e) + "}\n")
        for g in gaps:
            self.f.write('{"type": "gap", "data": ' + dumps(g) + "}\n")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *rest):
        self.f.close()
        if exc_type is None:
            self.tmp.replace(self.path)          # only a complete walk becomes the ledger


def load_ledger(path: Path) -> tuple[Ledger, list[Gap]]:
    from datetime import datetime
    ledger, gaps = Ledger(), []
    with path.open() as f:
        for line in f:
            rec = json.loads(line)
            t = rec["type"]
            if t == "commit":
                ledger.add_commit(rec["sha"], tuple(rec["parents"]), datetime.fromisoformat(rec["date"]),
                                  rec.get("message", ""))
            elif t == "event":
                ledger.extend([event_from_dict(rec["data"])])
            elif t == "gap":
                g = gap_from_dict(rec["data"])
                ledger.add_gaps([g])
                gaps.append(g)
    return ledger, gaps
