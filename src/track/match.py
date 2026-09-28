"""Which log statement of the new file version is which statement of the old one. Pure.

1. line mapping: a statement whose lines no diff hunk touches is mapped to its new line
   number; if the same statement sits there it is *unchanged* (certain). Duplicates are
   told apart by position, so identical statements are not ambiguous.
2. inside one diff region (hunks joined by the statements spanning them): optimal
   assignment (Hungarian) on a similarity score, not greedy; confidence from the margin.
3. leftovers anywhere in the file: pairs above a higher threshold are *moved*.
4. what is left: deleted (old) / added (new).

Also: the factual record of what changed between two paired statements.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from ..models import LogStatement

CERTAIN, PROBABLE, UNCERTAIN = "certain", "probable", "uncertain"


@dataclass(frozen=True)
class Hunk:
    old_start: int
    old_len: int
    new_start: int
    new_len: int


@dataclass(frozen=True)
class Pair:
    before: LogStatement
    after: LogStatement
    kind: str                        # unchanged | modified | moved
    confidence: str
    score: float


@dataclass
class MatchResult:
    pairs: list[Pair]
    deleted: list[LogStatement]
    added: list[LogStatement]

    def after_of(self, st: LogStatement) -> Pair | None:
        for p in self.pairs:
            if p.before is st:
                return p
        return None


# --------------------------------------------------------------------------- hunks

def hunks_from_texts(a: str, b: str) -> list[Hunk]:
    """difflib fallback (tests, or when blobs are not in git)."""
    sm = difflib.SequenceMatcher(None, a.splitlines(), b.splitlines(), autojunk=False)
    out = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        old_start = i1 + 1 if i2 > i1 else i1       # git: insertion is "after line i1"
        new_start = j1 + 1 if j2 > j1 else j1
        out.append(Hunk(old_start, i2 - i1, new_start, j2 - j1))
    return out


def _touches_old(h: Hunk, lo: int, hi: int) -> bool:
    if h.old_len == 0:
        return lo <= h.old_start < hi              # text inserted strictly inside the statement
    return not (h.old_start + h.old_len - 1 < lo or h.old_start > hi)


def _touches_new(h: Hunk, lo: int, hi: int) -> bool:
    if h.new_len == 0:
        return False
    return not (h.new_start + h.new_len - 1 < lo or h.new_start > hi)


def _map_line(line: int, hunks: list[Hunk]) -> int:
    delta = 0
    for h in hunks:
        before = (h.old_start + h.old_len - 1 < line) if h.old_len else (h.old_start < line)
        if before:
            delta += h.new_len - h.old_len
    return line + delta


# --------------------------------------------------------------------------- similarity

_WS = re.compile(r"\s+")


def _norm(code: str) -> str:
    return _WS.sub(" ", code).strip()


def _ratio(a: str, b: str) -> float:
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def similarity(b: LogStatement, a: LogStatement) -> float:
    code = _ratio(_norm(b.code), _norm(a.code))
    if b.template and a.template:
        tmpl = _ratio(b.template, a.template)
    elif not b.template and not a.template:
        tmpl = code
    else:
        tmpl = 0.0
    cb, ca = {i.core for i in b.items}, {i.core for i in a.items}
    items = 1.0 if not cb and not ca else len(cb & ca) / len(cb | ca)
    return (0.35 * code + 0.25 * tmpl + 0.2 * items + 0.1 * (b.scope == a.scope)
            + 0.05 * (b.method == a.method) + 0.05 * (b.receiver == a.receiver))


def hungarian(weights: list[list[float]]) -> list[tuple[int, int]]:
    """Maximum-weight assignment on a rectangular matrix (rows <= or > cols both fine)."""
    n_r, n_c = len(weights), len(weights[0]) if weights else 0
    if not n_r or not n_c:
        return []
    n = max(n_r, n_c)
    big = max(max(r) for r in weights) + 1.0
    cost = [[(big - weights[i][j]) if i < n_r and j < n_c else big for j in range(n)] for i in range(n)]
    inf = float("inf")
    u, v, p, way = [0.0] * (n + 1), [0.0] * (n + 1), [0] * (n + 1), [0] * (n + 1)
    for i in range(1, n + 1):
        p[0], j0 = i, 0
        minv, used = [inf] * (n + 1), [False] * (n + 1)
        while True:
            used[j0] = True
            i0, delta, j1 = p[j0], inf, 0
            for j in range(1, n + 1):
                if not used[j]:
                    cur = cost[i0 - 1][j - 1] - u[i0] - v[j]
                    if cur < minv[j]:
                        minv[j], way[j] = cur, j0
                    if minv[j] < delta:
                        delta, j1 = minv[j], j
            for j in range(n + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while True:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
            if j0 == 0:
                break
    return [(p[j] - 1, j - 1) for j in range(1, n + 1) if p[j] and p[j] - 1 < n_r and j - 1 < n_c]


def same_message(b: LogStatement, a: LogStatement) -> bool:
    """A move keeps what the log says: same template, or (no template) the same items."""
    if b.template or a.template:
        return b.template == a.template
    return {i.core for i in b.items} == {i.core for i in a.items} and b.method == a.method


def _assign(bs: list[LogStatement], as_: list[LogStatement], threshold: float, kind_if_changed: str) -> list[Pair]:
    if not bs or not as_:
        return []
    sims = [[similarity(b, a) for a in as_] for b in bs]
    if kind_if_changed == "moved":
        # outside a diff region only a real move counts: "Cache hit" is not "Cache miss"
        sims = [[s if same_message(b, a) else 0.0 for s, a in zip(row, as_)] for row, b in zip(sims, bs)]
    out = []
    for i, j in hungarian(sims):
        s = sims[i][j]
        if s < threshold:
            continue
        others = [sims[i][k] for k in range(len(as_)) if k != j] + [sims[k][j] for k in range(len(bs)) if k != i]
        margin = s - max(others) if others else s
        if len(bs) == 1 and len(as_) == 1:
            conf = CERTAIN if s >= 0.8 else PROBABLE
        elif s >= 0.9 and margin >= 0.2:
            conf = CERTAIN
        elif margin >= 0.1:
            conf = PROBABLE
        else:
            conf = UNCERTAIN
        b, a = bs[i], as_[j]
        kind = "unchanged" if b.shash == a.shash and kind_if_changed == "modified" else kind_if_changed
        out.append(Pair(b, a, kind, conf, round(s, 3)))
    return out


def match_file(before: list[LogStatement], after: list[LogStatement], hunks: list[Hunk],
               pair_threshold: float = 0.5, move_threshold: float = 0.8) -> MatchResult:
    pairs: list[Pair] = []
    by_line = {}
    for a in after:
        by_line.setdefault(a.line, []).append(a)
    claimed: set[int] = set()
    touched_b = []
    for b in before:
        if any(_touches_old(h, b.line, b.end_line) for h in hunks):
            touched_b.append(b)
            continue
        cands = [a for a in by_line.get(_map_line(b.line, hunks), ())
                 if a.shash == b.shash and id(a) not in claimed]
        if cands:
            a = min(cands, key=lambda x: abs(x.col - b.col))
            claimed.add(id(a))
            pairs.append(Pair(b, a, "unchanged", CERTAIN, 1.0))
        else:
            touched_b.append(b)
    rest_a = [a for a in after if id(a) not in claimed]

    # regions: union of hunks touched by one statement
    parent = list(range(len(hunks)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def region(ids):
        ids = list(ids)
        for x in ids[1:]:
            parent[find(x)] = find(ids[0])
        return ids

    b_hunks = {id(b): region([k for k, h in enumerate(hunks) if _touches_old(h, b.line, b.end_line)]) for b in touched_b}
    a_hunks = {id(a): region([k for k, h in enumerate(hunks) if _touches_new(h, a.line, a.end_line)]) for a in rest_a}
    groups: dict[int, tuple[list, list]] = {}
    for b in touched_b:
        if b_hunks[id(b)]:
            groups.setdefault(find(b_hunks[id(b)][0]), ([], []))[0].append(b)
    for a in rest_a:
        if a_hunks[id(a)]:
            groups.setdefault(find(a_hunks[id(a)][0]), ([], []))[1].append(a)
    used_b, used_a = set(), set()
    for bs, as_ in groups.values():
        for p in _assign(bs, as_, pair_threshold, "modified"):
            pairs.append(p)
            used_b.add(id(p.before))
            used_a.add(id(p.after))

    left_b = [b for b in touched_b if id(b) not in used_b]
    left_a = [a for a in rest_a if id(a) not in used_a]
    for p in _assign(left_b, left_a, move_threshold, "moved"):
        pairs.append(p)
        used_b.add(id(p.before))
        used_a.add(id(p.after))
    return MatchResult(pairs=pairs,
                       deleted=[b for b in left_b if id(b) not in used_b],
                       added=[a for a in left_a if id(a) not in used_a])


# --------------------------------------------------------------------------- change record

def change_record(b: LogStatement, a: LogStatement) -> dict:
    """What changed between two versions of one statement -- facts only."""
    eb, ea = {i.expr for i in b.items if i.role != "exception"}, {i.expr for i in a.items if i.role != "exception"}
    wb = {i.core: list(i.wrappers) for i in b.items}
    wa = {i.core: list(i.wrappers) for i in a.items}
    wrap = [{"core": c, "before": wb[c], "after": wa[c]} for c in sorted(wb.keys() & wa.keys()) if wb[c] != wa[c]]
    exc_b = any(i.role == "exception" for i in b.items)
    exc_a = any(i.role == "exception" for i in a.items)
    rec = {
        "message_changed": b.template != a.template,
        "items_added": sorted(ea - eb), "items_removed": sorted(eb - ea), "wrapper_changes": wrap,
        "level_before": b.method, "level_after": a.method, "level_changed": b.method != a.method,
        "sink_changed": (b.sink, b.receiver) != (a.sink, a.receiver),
        "conditions_before": list(b.conditions), "conditions_after": list(a.conditions),
        "condition_changed": b.conditions != a.conditions,
        "exception_changed": exc_b != exc_a,
        "moved": b.path != a.path or b.scope != a.scope,
    }
    rec["items_changed"] = bool(rec["items_added"] or rec["items_removed"] or wrap)
    rec["code_changed"] = _norm(b.code) != _norm(a.code)
    return rec
