"""Whole-revision Python snapshot for agentlog_unified's judgement of intro logs.

agentlog_unified judges each log inside a snapshot of the revision (so one-hop imports
resolve across files), capped at 3000 files / 2 MiB per file (its config.example.yaml).
Only the few anchor commits need this; the ledger keeps using changed files only.
"""
from __future__ import annotations

from ..models import Gap, LocalRepo
from .gitcmd import run_git
from .materialize import CatFile, decode_source

MAX_FILES = 3000
MAX_BYTES = 2_097_152


def anchor_snapshot(local: LocalRepo, sha: str, suffixes: tuple[str, ...]) -> tuple[dict[str, str], list[Gap]]:
    out = run_git(local.path, "ls-tree", "-r", "-z", "--long", sha).stdout
    entries = []
    for rec in out.split(b"\x00"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        mode, kind, blob, size = meta.split()
        p = path.decode("utf-8", "surrogateescape")
        if kind == b"blob" and mode not in (b"120000",) and p.endswith(suffixes):
            entries.append((p, blob.decode(), int(size) if size != b"-" else 0))
    gaps = []
    if len(entries) > MAX_FILES:
        gaps.append(Gap("snapshot_truncated", local.repository, sha, detail=f"{len(entries)} files > {MAX_FILES}"))
        entries = sorted(entries)[:MAX_FILES]
    files = {}
    with CatFile(local.path) as cat:
        for p, blob, size in entries:
            if size > MAX_BYTES:
                gaps.append(Gap("snapshot_file_too_large", local.repository, sha, p))
                continue
            data = cat.read(blob)
            try:
                files[p] = decode_source(data) if data is not None else None
            except (UnicodeDecodeError, SyntaxError, LookupError):
                gaps.append(Gap("snapshot_decode_failed", local.repository, sha, p))
    return {k: v for k, v in files.items() if v is not None}, gaps
