"""Command line: argument parsing only, no business logic.

  seeds     AIDev tables -> <out>/seeds/{prs,pr_index,repos}.jsonl, manifest.json   (stage 1)
  track     per repository: clone, anchors, prescan, forward / backward tracking    (stages 2-3)
  features  per repository: explicit privacy features of every chain version        (stage 4)
  dataset   select chains and write the tables                                      (stage 5)
  samples   manual verification samples
  run       track + features + dataset
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Config


def _cfg(a) -> Config:
    return Config(out=Path(a.out), repos_dir=Path(a.repos_dir), source_dir=Path(a.source),
                  workers=getattr(a, "workers", 4), window_days=getattr(a, "window_days", 90),
                  include_print=not getattr(a, "no_print", False),
                  fetch_pr_refs=not getattr(a, "no_fetch_pr_refs", False))


def _seeds_dir(a) -> Path:
    return Path(a.seeds) if a.seeds else Path(a.out) / "seeds"


def cmd_seeds(a):
    from .seeds.aidev import build_seeds
    m = build_seeds(Path(a.source), _seeds_dir(a), _cfg(a))
    print(json.dumps({k: m[k] for k in ("counts", "commit_attribution", "excluded_files_by_rule")},
                     ensure_ascii=False, indent=1))


def _select(a, cfg: Config) -> list[str]:
    from .pipeline import load_seed_layer, repo_out
    _, _, repos = load_seed_layer(_seeds_dir(a))
    names = sorted(repos)
    if a.repo:
        names = [r for r in a.repo]
    if a.repos_file:
        wanted = [ln.strip() for ln in Path(a.repos_file).read_text().splitlines() if ln.strip()]
        names = [r for r in wanted if r in repos]
    if a.max_stars is not None:
        names = [r for r in names if (repos.get(r, {}).get("stars") or 0) <= a.max_stars]
    if a.smallest:
        names = sorted(names, key=lambda r: repos.get(r, {}).get("stars") or 0)[:a.smallest]
    if getattr(a, "skip_done", False):
        def done(r):
            f = repo_out(cfg, r) / "result.json"
            return f.exists() and json.loads(f.read_text()).get("status") != "failed"
        names = [r for r in names if not done(r)]
    # large repositories first: no long tail
    return sorted(names, key=lambda r: -(repos.get(r, {}).get("stars") or 0))


def _log(s):
    print(s, file=sys.stderr, flush=True)


def cmd_track(a):
    from .pipeline import track_all
    cfg = _cfg(a)
    tasks = _select(a, cfg)
    _log(f"{len(tasks)} repositories")
    track_all(tasks, cfg, _seeds_dir(a), log=_log)


def cmd_features(a):
    from .pipeline import features_all
    cfg = _cfg(a)
    a.skip_done = False
    features_all(_select(a, cfg), cfg, log=_log)


def cmd_dataset(a):
    from .report.dataset import build_dataset
    mf = _seeds_dir(a) / "manifest.json"
    summary = build_dataset(Path(a.out), json.loads(mf.read_text()) if mf.exists() else None)
    print(json.dumps(summary, ensure_ascii=False, indent=1))


def cmd_samples(a):
    from .report.samples import build_samples
    print(json.dumps(build_samples(Path(a.out)), ensure_ascii=False))


def cmd_run(a):
    cmd_track(a)
    a.skip_done = False
    cmd_features(a)
    cmd_dataset(a)


def main(argv=None):
    p = argparse.ArgumentParser(prog="logtrace")
    p.add_argument("--out", default="out/aidev", help="results root")
    p.add_argument("--repos-dir", default="data/repos", help="clones")
    p.add_argument("--source", default="data/aidev", help="AIDev tables")
    p.add_argument("--seeds", help="seed layer directory (default: <out>/seeds)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seeds", help="AIDev -> PR-level seeds").set_defaults(f=cmd_seeds)
    for name, fn, h in (("track", cmd_track, "clone, anchor, track (per repository)"),
                        ("features", cmd_features, "explicit privacy features (per repository)"),
                        ("run", cmd_run, "track + features + dataset")):
        sp = sub.add_parser(name, help=h)
        sp.add_argument("--repo", action="append", help="owner/name (repeatable); default: all with seeds")
        sp.add_argument("--repos-file", help="file with one owner/name per line")
        sp.add_argument("--max-stars", type=int, help="skip repositories with more stars than this")
        sp.add_argument("--smallest", type=int, help="only the N repositories with fewest stars")
        sp.add_argument("--skip-done", action="store_true", help="skip repositories that already have a result")
        sp.add_argument("--workers", type=int, default=4)
        sp.add_argument("--window-days", type=int, default=90)
        sp.add_argument("--no-print", action="store_true", help="do not count print() as a log sink")
        sp.add_argument("--no-fetch-pr-refs", action="store_true", help="do not fetch refs/pull/N/head")
        sp.set_defaults(f=fn)
    sub.add_parser("dataset", help="select chains and write the tables").set_defaults(f=cmd_dataset)
    sub.add_parser("samples", help="manual verification samples (CSV with empty label columns)").set_defaults(f=cmd_samples)
    a = p.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    main()
