"""analyze_commit (REBUILD.md §8): one commit's changed files -> log events + gaps.

Pure: no network, no file reads, no git. A parse failure is a Gap, never "the logs
disappeared".
"""
from __future__ import annotations

from ..detect.match import Pairing, match_across_files, match_file
from ..detect.python_ast import find_logs
from ..models import CommitWork, Gap, LogEvent

PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)


def analyze_commit(work: CommitWork, include_print: bool = True) -> tuple[list[LogEvent], list[Gap]]:
    gaps: list[Gap] = list(work.gaps)
    pairings: list[tuple[Pairing, str, str | None]] = []
    for fv in work.files:
        try:
            before = find_logs(fv.old_path or fv.path, fv.before, include_print) if fv.before is not None else None
        except PARSE_ERRORS as e:
            gaps.append(Gap("parse_failed", work.repository, work.sha, fv.path, "before", type(e).__name__))
            continue
        try:
            after = find_logs(fv.path, fv.after, include_print) if fv.after is not None else None
        except PARSE_ERRORS as e:
            gaps.append(Gap("parse_failed", work.repository, work.sha, fv.path, "after", type(e).__name__))
            continue
        ps = match_file(list(before.statements) if before else [], list(after.statements) if after else [],
                        renamed=fv.old_path is not None, file_deleted=fv.after is None,
                        after_scopes=after.scopes if after else None)
        pairings += [(p, fv.path, fv.old_path) for p in ps]

    old_path_of = {id(p): old for p, _, old in pairings}
    merged = match_across_files([p for p, _, _ in pairings])
    events = []
    for p in merged:
        path = p.after.path if p.after is not None else p.before.path
        old_path = None
        if p.before is not None and p.after is not None and p.before.path != p.after.path:
            old_path = p.before.path
        elif id(p) in old_path_of:
            old_path = old_path_of[id(p)]
        labels = p.labels
        events.append(LogEvent(
            repository=work.repository, sha=work.sha, parents=work.parents, date=work.date,
            path=path, old_path=old_path,
            before_fp=p.before.fingerprint if p.before else None,
            after_fp=p.after.fingerprint if p.after else None,
            change=p.change, before=p.before, after=p.after,
            confidence=p.confidence, labels=labels, fix_effect=p.fix_effect))
    return events, gaps
