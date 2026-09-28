"""build_ledger (REBUILD.md §8): walk once, write while walking, index at the same time."""
from __future__ import annotations

from pathlib import Path

from ..config import Config
from ..models import Gap, LocalRepo
from ..track.ledger import Ledger, LedgerWriter
from .analyze import analyze_commit
from .walk import walk_history


def build_ledger(local: LocalRepo, cfg: Config, out_path: Path) -> tuple[Ledger, list[Gap], dict]:
    ledger, gaps = Ledger(), []
    metrics = {"commits": 0, "merge_commits": 0, "file_versions": 0, "events": 0}
    with LedgerWriter(out_path) as writer:
        for work in walk_history(local, cfg):
            metrics["commits"] += 1
            metrics["merge_commits"] += work.is_merge
            metrics["file_versions"] += sum((f.before is not None) + (f.after is not None) for f in work.files)
            ledger.add_commit(work.sha, work.parents, work.date, work.message)
            writer.commit(work.sha, work.parents, work.date, work.message)
            events, work_gaps = analyze_commit(work, cfg.include_print)
            writer.write(events, work_gaps)
            ledger.extend(events)
            ledger.add_gaps(work_gaps)
            gaps += work_gaps
            metrics["events"] += len(events)
    return ledger, gaps, metrics
