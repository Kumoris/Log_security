"""Before/after pairing of log statements (REBUILD.md §11.2 match rounds).

Each round only sees what the previous rounds left. Nothing is guessed: whenever more
than one equivalent candidate exists the pairing is emitted with confidence
``ambiguous`` so the tracker stops there.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..models import ChangeKind, LogStatement, SensLevel


@dataclass(frozen=True)
class Pairing:
    change: ChangeKind
    before: LogStatement | None
    after: LogStatement | None
    confidence: str
    labels: tuple[str, ...] = ()
    fix_effect: str = "unknown"


def _args_signature(s: LogStatement) -> frozenset[str]:
    return frozenset(s.sensitivity.flows) | frozenset(s.sensitivity.data_types)


def _similarity(a: LogStatement, b: LogStatement) -> float:
    score = 0.0
    if a.template and a.template == b.template:
        score += 2
    if a.method == b.method:
        score += 0.5
    if a.receiver == b.receiver:
        score += 0.5
    sa, sb = _args_signature(a), _args_signature(b)
    if sa or sb:
        score += len(sa & sb) / len(sa | sb)
    score -= abs(a.line - b.line) / 1000
    return score


def change_labels(before: LogStatement | None, after: LogStatement | None,
                  moved: bool = False) -> tuple[tuple[str, ...], str]:
    """agentlog_unified ``lineage.change_labels`` (followup_change_types, fix_effect),
    ported line for line onto logtrace statements; relation is always a direct call change."""
    if after is None:
        return ("delete_feature",), "unknown"
    if before is None:
        return ("unclear",), "unknown"
    bs, as_ = before.sensitivity, after.sensitivity
    old, new = bs.sensitive_sources(), as_.sensitive_sources()
    labels = []
    if bs.log_level != after.sensitivity.log_level or bs.trigger_conditions != as_.trigger_conditions:
        labels.append("level_or_condition_change")
    if moved or before.path != after.path:
        labels.append("refactor_or_move")
    if old - new and bs.level == SensLevel.SUPPORTED:
        if as_.sanitization:
            labels.append("add_redaction")
        labels.append("remove_sensitive_field")
        if as_.level == SensLevel.NOT_SUPPORTED and not new:
            return tuple(labels), "eliminates_observed_flow"
        return tuple(labels), "partial" if as_.level == SensLevel.SUPPORTED and new else "unknown"
    if labels:
        return tuple(labels), "unknown" if "level_or_condition_change" in labels and old else "not_privacy_related"
    if before.code != after.code:
        return ("message_or_format",), "not_privacy_related" if not old else "unknown"
    return ("unclear",), "not_privacy_related" if not old else "unknown"


def _pair(kind, b, a, conf, extra=()) -> Pairing:
    labels, effect = change_labels(b, a, moved=kind in (ChangeKind.MOVED, ChangeKind.MOVED_MODIFIED))
    return Pairing(kind, b, a, conf, tuple(extra) + labels, effect)


def match_file(before: list[LogStatement], after: list[LogStatement], *,
               renamed: bool, file_deleted: bool, after_scopes: frozenset[str] | None) -> list[Pairing]:
    out: list[Pairing] = []
    B = list(before)
    A = list(after)

    # group sizes: duplicate (scope, structure) groups whose size changed are unsafe
    def gsize(xs):
        d = {}
        for s in xs:
            d[(s.scope, s.structure_hash)] = d.get((s.scope, s.structure_hash), 0) + 1
        return d
    gb, ga = gsize(B), gsize(A)
    shaky = {k for k in set(gb) | set(ga) if max(gb.get(k, 0), ga.get(k, 0)) > 1 and gb.get(k, 0) != ga.get(k, 0)}

    # round 1: same scope + structure + occurrence -> unchanged (or moved if the file was renamed)
    idx_a = {(s.scope, s.structure_hash, s.occurrence): s for s in A}
    rest_b = []
    for s in B:
        m = idx_a.pop((s.scope, s.structure_hash, s.occurrence), None)
        if m is None:
            rest_b.append(s)
            continue
        key = (s.scope, s.structure_hash)
        if key in shaky:
            out.append(_pair(ChangeKind.MODIFIED, s, m, "ambiguous", ("duplicate_group_shift",)))
        elif renamed:
            out.append(_pair(ChangeKind.MOVED, s, m, "exact", ("file_renamed",)))
        # else: identical, no event
    rest_a = list(idx_a.values())

    # round 2/3: same scope, structure changed
    by_scope_b, by_scope_a = {}, {}
    for s in rest_b:
        by_scope_b.setdefault(s.scope, []).append(s)
    for s in rest_a:
        by_scope_a.setdefault(s.scope, []).append(s)
    used_b, used_a = set(), set()
    for scope in by_scope_b.keys() & by_scope_a.keys():
        bs, as_ = by_scope_b[scope], by_scope_a[scope]
        if len(bs) == 1 and len(as_) == 1:
            b, a = bs[0], as_[0]
            conf = "ambiguous" if (scope, b.structure_hash) in shaky or (scope, a.structure_hash) in shaky else "exact"
            out.append(_pair(ChangeKind.MODIFIED, b, a, conf))
            used_b.add(id(b)); used_a.add(id(a))
            continue
        # m x n: greedy by similarity, every pairing ambiguous
        cands = sorted(((_similarity(b, a), i, j) for i, b in enumerate(bs) for j, a in enumerate(as_)), reverse=True)
        taken_b, taken_a = set(), set()
        for score, i, j in cands:
            if score < 2 or i in taken_b or j in taken_a:     # need at least a shared template
                continue
            taken_b.add(i); taken_a.add(j)
            out.append(_pair(ChangeKind.MODIFIED, bs[i], as_[j], "ambiguous", ("many_to_many_scope",)))
            used_b.add(id(bs[i])); used_a.add(id(as_[j]))
    rest_b = [s for s in rest_b if id(s) not in used_b]
    rest_a = [s for s in rest_a if id(s) not in used_a]

    # round 4: cross-scope within the file, identical structure
    def by_key(xs, key):
        d = {}
        for s in xs:
            d.setdefault(key(s), []).append(s)
        return d
    used_b, used_a = set(), set()
    kb, ka = by_key(rest_b, lambda s: s.structure_hash), by_key(rest_a, lambda s: s.structure_hash)
    for h in kb.keys() & ka.keys():
        bs, as_ = kb[h], ka[h]
        conf = "exact" if len(bs) == 1 and len(as_) == 1 else "ambiguous"
        for b, a in zip(bs, as_):
            out.append(_pair(ChangeKind.MOVED, b, a, conf, ("scope_changed",)))
            used_b.add(id(b)); used_a.add(id(a))
    rest_b = [s for s in rest_b if id(s) not in used_b]
    rest_a = [s for s in rest_a if id(s) not in used_a]

    # round 5: cross-scope, same non-empty message template only
    used_b, used_a = set(), set()
    kb = by_key([s for s in rest_b if s.template], lambda s: s.template)
    ka = by_key([s for s in rest_a if s.template], lambda s: s.template)
    for t in kb.keys() & ka.keys():
        bs, as_ = kb[t], ka[t]
        conf = "probable" if len(bs) == 1 and len(as_) == 1 else "ambiguous"
        for b, a in zip(bs, as_):
            out.append(_pair(ChangeKind.MOVED_MODIFIED, b, a, conf, ("template_only",)))
            used_b.add(id(b)); used_a.add(id(a))
    rest_b = [s for s in rest_b if id(s) not in used_b]
    rest_a = [s for s in rest_a if id(s) not in used_a]

    # round 8: leftovers
    for a in rest_a:
        conf = "ambiguous" if (a.scope, a.structure_hash) in shaky else "exact"
        out.append(Pairing(ChangeKind.ADDED, None, a, conf, ("unclear",)))
    for b in rest_b:
        if file_deleted:
            out.append(Pairing(ChangeKind.FILE_REMOVED, b, None, "probable", ("delete_feature",)))
        elif after_scopes is not None and b.scope not in after_scopes:
            out.append(Pairing(ChangeKind.SCOPE_REMOVED, b, None, "probable", ("delete_feature",)))
        else:
            conf = "ambiguous" if (b.scope, b.structure_hash) in shaky else "exact"
            out.append(Pairing(ChangeKind.DELETED, b, None, conf, ("delete_feature",)))
    return out


def match_across_files(pairings: list[Pairing]) -> list[Pairing]:
    """Round 6: a removal in one file + an addition with identical structure in another
    file of the same commit, unique on both sides -> moved (exact)."""
    removals = [p for p in pairings if p.change in (ChangeKind.DELETED, ChangeKind.SCOPE_REMOVED, ChangeKind.FILE_REMOVED)]
    adds = [p for p in pairings if p.change == ChangeKind.ADDED]
    rb, ra = {}, {}
    for p in removals:
        rb.setdefault(p.before.structure_hash, []).append(p)
    for p in adds:
        ra.setdefault(p.after.structure_hash, []).append(p)
    drop, new = set(), []
    for h in rb.keys() & ra.keys():
        bs = [p for p in rb[h]]
        as_ = [p for p in ra[h] if all(p.after.path != b.before.path for b in bs)]
        if not as_:
            continue
        conf = "exact" if len(bs) == 1 and len(as_) == 1 else "ambiguous"
        for b, a in zip(bs, as_):
            drop.add(id(b)); drop.add(id(a))
            new.append(_pair(ChangeKind.MOVED, b.before, a.after, conf, ("cross_file",)))
    return [p for p in pairings if id(p) not in drop] + new
