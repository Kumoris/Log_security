"""resolve_seeds (REBUILD.md §7): are the seed SHAs in the frozen history? If not, relocate.

The ledger covers exactly the ancestors of the frozen head, so "sha is in the ledger"
is the same test as ``git merge-base --is-ancestor sha frozen_head`` without a
subprocess per seed. ``cat-file -e`` separates side-branch objects from missing ones.

Squash relocation: a mainline commit within N days after the seed that *adds* logs in
the seed's agent files whose structure (exists_unreachable) or source line (missing)
matches the seed's own added logs. Exactly one candidate -> ``relocated`` (probable).
"""
from __future__ import annotations

from datetime import timedelta
from typing import Sequence

from ..config import Config
from ..detect.python_ast import find_logs
from ..models import ChangeKind, Gap, LocalRepo, ResolvedSeed, Seed
from ..track.ledger import Ledger
from .gitcmd import run_git
from .materialize import decode_source

_MIN_OVERLAP = 0.5


def _object_exists(local: LocalRepo, sha: str) -> bool:
    return run_git(local.path, "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode == 0


def _show(local: LocalRepo, rev_path: str) -> str | None:
    r = run_git(local.path, "cat-file", "blob", rev_path, check=False)
    if r.returncode != 0:
        return None
    try:
        return decode_source(r.stdout)
    except Exception:
        return None


def _seed_added_hashes(local: LocalRepo, seed: Seed, paths: list[str], cfg: Config) -> set[str]:
    """Structure hashes of logs the (unreachable) seed commit itself added in its agent files."""
    out = set()
    for p in paths:
        after = _show(local, f"{seed.commit_sha}:{p}")
        if after is None:
            continue
        before = _show(local, f"{seed.commit_sha}^:{p}")
        try:
            a = {s.structure_hash for s in find_logs(p, after, cfg.include_print).statements}
            b = {s.structure_hash for s in find_logs(p, before, cfg.include_print).statements} if before else set()
        except (SyntaxError, ValueError, RecursionError):
            continue
        out |= a - b
    return out


def _candidates(ledger: Ledger, seed: Seed, paths: set[str], cfg: Config) -> dict[str, list]:
    if seed.commit_date is None:
        return {}
    lo, hi = seed.commit_date - timedelta(days=1), seed.commit_date + timedelta(days=cfg.relocation_window_days)
    out = {}
    for sha, date in ledger.commit_date.items():
        if date is None or not (lo <= date <= hi):
            continue
        adds = [e for e in ledger.by_sha.get(sha, ()) if e.change == ChangeKind.ADDED and e.path in paths]
        if adds:
            out[sha] = adds
    return out


def resolve_seeds(local: LocalRepo, seeds: Sequence[Seed], ledger: Ledger,
                  cfg: Config) -> tuple[list[ResolvedSeed], list[Gap]]:
    resolved, gaps = [], []
    reachable_shas = {s.commit_sha for s in seeds if s.commit_sha in ledger.commit_order}
    for seed in seeds:
        if seed.commit_sha in ledger.commit_order:
            resolved.append(ResolvedSeed(seed, "reachable", seed.commit_sha, "exact"))
            continue
        state = "exists_unreachable" if _object_exists(local, seed.commit_sha) else "missing"
        py_paths = [f.path for f in seed.agent_files if f.path.endswith(tuple(cfg.suffixes))]
        cands = _candidates(ledger, seed, set(py_paths), cfg) if py_paths else {}
        matched = []
        if cands:
            if state == "exists_unreachable":
                want = _seed_added_hashes(local, seed, py_paths, cfg)
                for sha, adds in cands.items():
                    got = {e.after.structure_hash for e in adds}
                    if want and len(want & got) / len(want) >= _MIN_OVERLAP:
                        matched.append(sha)
            else:
                want = {ln.strip() for f in seed.agent_files if f.path in py_paths for ln in f.added_log_lines}
                for sha, adds in cands.items():
                    got = {line.strip() for e in adds for line in e.after.code.splitlines()}
                    if want and len(want & got) / len(want) >= _MIN_OVERLAP:
                        matched.append(sha)
        if len(matched) == 1 and matched[0] in reachable_shas:
            resolved.append(ResolvedSeed(seed, "relocated_to_other_seed", None, "probable"))
            gaps.append(Gap("seed_relocated_to_other_seed", local.repository, seed.commit_sha, detail=matched[0]))
        elif len(matched) == 1:
            resolved.append(ResolvedSeed(seed, "relocated", matched[0], "probable"))
        elif len(matched) > 1:
            resolved.append(ResolvedSeed(seed, "relocation_ambiguous", None, "probable"))
            gaps.append(Gap("seed_relocation_ambiguous", local.repository, seed.commit_sha,
                            detail=",".join(sorted(matched))[:300]))
        else:
            resolved.append(ResolvedSeed(seed, state, None, "exact"))
            gaps.append(Gap("seed_" + state, local.repository, seed.commit_sha))
    return resolved, gaps
