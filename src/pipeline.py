"""Orchestration. One repository is the unit of parallelism, retry and testing.

Per repository (``<out>/repos/<owner__name>/``):
  stage 2-3  track     lock.json, anchors.jsonl, seedlogs.jsonl, lineages.jsonl, result.json
  stage 4    features  items.jsonl (one row per version: its output items and their evidence)
Stage 5 (dataset) reads every repository directory, see report/dataset.py.
"""
from __future__ import annotations

import json
import time
import traceback
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from .config import Config
from .models import Gap, dumps, read_jsonl, statement_from_dict, to_jsonable, write_jsonl


def repo_out(cfg: Config, repository: str) -> Path:
    return cfg.out / "repos" / repository.replace("/", "__")


def load_seed_layer(seeds_dir: Path) -> tuple[dict[str, list[dict]], dict[str, list[dict]], dict[str, dict]]:
    prs, index, repos = defaultdict(list), defaultdict(list), {}
    for p in read_jsonl(seeds_dir / "prs.jsonl"):
        prs[p["repository"]].append(p)
    for p in read_jsonl(seeds_dir / "pr_index.jsonl"):
        index[p["repository"]].append(p)
    for r in read_jsonl(seeds_dir / "repos.jsonl"):
        repos[r["repository"]] = r
    return prs, index, repos


# --------------------------------------------------------------------------- stage 2-3

def track_one(repository: str, cfg: Config, seeds_dir: Path) -> dict:
    from .repo.anchor import anchor_prs
    from .repo.clone import ensure_repo
    from .track.attribution import PrIndex
    from .track.tracker import track_repository
    t0 = time.time()
    out = repo_out(cfg, repository)
    out.mkdir(parents=True, exist_ok=True)
    prs_by_repo, index_by_repo, repos = load_seed_layer(seeds_dir)
    prs = prs_by_repo.get(repository, [])
    result = {"repository": repository, "status": "failed", "counts": {}, "gaps": [], "seed_prs": len(prs)}
    try:
        local, gaps = ensure_repo(repository, cfg, (repos.get(repository) or {}).get("clone_url"))
        if local is None:
            result["gaps"] = [to_jsonable(g) for g in gaps]
            return _finish(out, result, t0)
        result["frozen_head"] = local.frozen_head
        anchors, hist = anchor_prs(local, prs, cfg)
        write_jsonl(out / "anchors.jsonl", anchors)
        index = PrIndex.build(index_by_repo.get(repository, []))
        seedlogs, lineages, counts, tgaps = track_repository(
            local, anchors, {p["pr_id"]: p for p in prs}, hist, index, cfg)
        write_jsonl(out / "seedlogs.jsonl", seedlogs)
        write_jsonl(out / "lineages.jsonl", lineages)
        for a in anchors:
            counts["anchor:" + (a["method"] or "missing:" + (a["reason"] or "unknown"))] += 1
        counts["first_parent_commits"] = len(hist.fp)
        result.update(status="partial" if tgaps else "complete", counts=dict(counts),
                      gaps=[to_jsonable(g) for g in tgaps[:500]], n_gaps=len(tgaps))
    except Exception as e:
        result["gaps"].append(to_jsonable(Gap("repository_failed", repository, detail=f"{type(e).__name__}: {e}"[:300])))
        result["traceback"] = traceback.format_exc()[-2000:]
    return _finish(out, result, t0)


def _finish(out: Path, result: dict, t0: float) -> dict:
    result["seconds"] = round(time.time() - t0, 1)
    (out / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=1, default=str))
    return result


# --------------------------------------------------------------------------- stage 4

def features_one(repository: str, cfg: Config) -> dict:
    from .features.identify import identify_statement
    from .repo.clone import repo_dir
    from .repo.materialize import CatFile, decode_source
    out = repo_out(cfg, repository)
    lineages = read_jsonl(out / "lineages.jsonl")
    rows, counts = [], Counter()
    with CatFile(repo_dir(cfg, repository)) as cat:
        sources: dict[str, str | None] = {}

        def source_of(v: dict) -> str | None:
            key = v.get("blob") or (f"{v['commit']}:{v['path']}" if v.get("commit") else None)
            if key is None:
                return None
            if key not in sources:
                data = cat.read(key)
                try:
                    sources[key] = decode_source(data) if data is not None and len(data) <= cfg.max_file_bytes else None
                except (UnicodeDecodeError, SyntaxError, LookupError):
                    sources[key] = None
            return sources[key]

        for lin in lineages:
            for vi, v in enumerate(lin["versions"]):
                if v.get("statement") is None:
                    rows.append({"lineage_id": lin["lineage_id"], "version": vi, "items": [], "parsed": False})
                    counts["versions_unparsed"] += 1
                    continue
                st = statement_from_dict(v["statement"])
                src = source_of(v) if v.get("context") == "file" else st.code
                items = identify_statement(st, src)
                rows.append({"lineage_id": lin["lineage_id"], "version": vi, "items": items, "parsed": True,
                             "context": v.get("context") if src is not None else "none"})
                counts["versions"] += 1
                counts["items"] += len(items)
                counts["items_with_features"] += sum(bool(i["categories"]) for i in items)
    write_jsonl(out / "items.jsonl", rows)
    return {"repository": repository, **counts}


# --------------------------------------------------------------------------- scheduling

def _run(fn, tasks: list[str], workers: int, log, *args) -> list[dict]:
    results = []
    if workers <= 1:
        for t in tasks:
            r = fn(t, *args)
            results.append(r)
            log(f"[{len(results)}/{len(tasks)}] {t}: {r.get('status', 'ok')} {r.get('seconds', '')}")
        return results
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(fn, t, *args): t for t in tasks}
        for fut in as_completed(futs):
            t = futs[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = {"repository": t, "status": "worker_crashed", "error": repr(e)[:300]}
            results.append(r)
            log(f"[{len(results)}/{len(tasks)}] {t}: {r.get('status', 'ok')} {r.get('seconds', '')}")
    return results


def track_all(tasks: list[str], cfg: Config, seeds_dir: Path, log=print) -> list[dict]:
    return _run(track_one, tasks, cfg.workers, log, cfg, seeds_dir)


def features_all(tasks: list[str], cfg: Config, log=print) -> list[dict]:
    tasks = [t for t in tasks if (repo_out(cfg, t) / "lineages.jsonl").exists()]
    return _run(features_one, tasks, cfg.workers, log, cfg)
