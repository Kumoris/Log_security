"""Stage 5: select chains and write the dataset.

Selection: a chain is selected when any output item of any of its versions (backward
history included) has at least one explicit feature. Carrier categories and wrapped
items count; unclassified items do not. Nothing about the direction of changes is judged.

Tables (Parquet + CSV, in ``<out>/dataset/``):
  chains, all_chains, versions, items, changes, unclassified_items, coverage
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from ..features.identify import has_data
from ..models import read_jsonl


_KINDS = (
    ("test", {"test", "tests", "testing", "__tests__"}),
    ("example", {"examples", "example", "demo", "demos", "samples", "sample", "notebooks", "tutorials",
                 "tutorial", "cookbook", "playground"}),
    ("docs", {"docs", "doc", "documentation"}),
    ("benchmark", {"benchmarks", "benchmark", "bench"}),
    ("script", {"scripts", "script", "tools", "bin", "utils_scripts"}),
)


def path_kind(path: str) -> str:
    """Where a file sits, by path only: test / example / docs / benchmark / script / source."""
    parts = [p.lower() for p in path.split("/")]
    name = parts[-1]
    if name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py":
        return "test"
    dirs = set(parts[:-1])
    for kind, names in _KINDS:
        if dirs & names:
            return kind
    return "source"


def _gh(repo: str, sha: str | None) -> str | None:
    return f"https://github.com/{repo}/commit/{sha}" if sha else None


def _write(table: list[dict], out: Path, name: str) -> None:
    import pyarrow as pa
    import pyarrow.csv as pcsv
    import pyarrow.parquet as pq
    out.mkdir(parents=True, exist_ok=True)
    if not table:
        (out / f"{name}.csv").write_text("")
        return
    cols = list(dict.fromkeys(k for r in table for k in r))
    norm = [{c: r.get(c) for c in cols} for r in table]
    # Parquet: nested values as JSON text too, so columns have one stable type
    flat = [{c: (json.dumps(v, ensure_ascii=False, default=str) if isinstance(v, (list, dict)) else v)
             for c, v in r.items()} for r in norm]
    t = pa.Table.from_pylist(flat)
    pq.write_table(t, out / f"{name}.parquet")
    pcsv.write_csv(t, out / f"{name}.csv")


def build_dataset(out_root: Path, seed_manifest: dict | None = None) -> dict:
    repos_dir = out_root / "repos"
    all_chains, chains, versions, items_t, changes_t = [], [], [], [], []
    unclassified: dict[str, dict] = {}
    cov = Counter()
    results = []
    for d in sorted(p for p in repos_dir.iterdir() if p.is_dir()) if repos_dir.exists() else []:
        rf = d / "result.json"
        if not rf.exists():
            continue
        res = json.loads(rf.read_text())
        results.append(res)
        cov["repositories_" + res["status"]] += 1
        for k, v in res.get("counts", {}).items():
            cov[k] += v
        lineages = read_jsonl(d / "lineages.jsonl")
        items_by = {(r["lineage_id"], r["version"]): r for r in read_jsonl(d / "items.jsonl")}
        # objective context: how many seed logs each PR brought, how many tracked logs each commit changed
        pr_seed_count = Counter(s["pr_id"] for s in read_jsonl(d / "seedlogs.jsonl"))
        bulk = Counter(c["commit"] for l in lineages for c in l["changes"] if c["kind"] != "seed_modification")
        for lin in lineages:
            repo = lin["repository"]
            cats_all, matched_versions = set(), []
            vrows, irows = [], []
            for vi, v in enumerate(lin["versions"]):
                ir = items_by.get((lin["lineage_id"], vi), {"items": [], "parsed": False})
                vcats = sorted({c for it in ir["items"] for c in it["categories"]})
                if vcats:
                    matched_versions.append(vi)
                    cats_all.update(vcats)
                st = v.get("statement") or {}
                a = v.get("author") or {}
                vrows.append({"lineage_id": lin["lineage_id"], "repository": repo, "version": vi,
                              "segment": v["segment"], "commit": v["commit"], "date": v["date"], "path": v["path"],
                              "author_kind": a.get("author_kind"), "author_agent": a.get("agent"),
                              "author_evidence": a.get("evidence"), "pr_number": a.get("pr_number"),
                              "line_attribution": a.get("line_attribution"),
                              "entry_author_kind": (v.get("entry_author") or {}).get("author_kind"),
                              "scope": st.get("scope"), "line": st.get("line"), "sink": st.get("sink"),
                              "method": st.get("method"), "detection": st.get("detection"),
                              "template": st.get("template"), "conditions": st.get("conditions"),
                              "path_kind": path_kind(v["path"]),
                              "code": v.get("code"), "context": v.get("context"), "parsed": ir.get("parsed"),
                              "categories": vcats, "github": _gh(repo, v["commit"])})
                for it in ir["items"]:
                    irows.append({"lineage_id": lin["lineage_id"], "repository": repo, "version": vi, **{
                        k: it[k] for k in ("expr", "core", "key", "role", "wrappers", "definition", "categories")},
                        "evidence_kinds": sorted({e["kind"] for e in it["evidence"]}),
                        "carrier_only": bool(it["evidence"]) and all(e["carrier"] for e in it["evidence"]),
                        "evidence": it["evidence"]})
                    if not it["categories"] and it["role"] == "value" and has_data(it["core"]):
                        u = unclassified.setdefault(it["core"], {"core": it["core"], "occurrences": 0, "lineages": set(),
                                                                "repositories": set(), "example_code": v.get("code"),
                                                                "example_lineage": lin["lineage_id"]})
                        u["occurrences"] += 1
                        u["lineages"].add(lin["lineage_id"])
                        u["repositories"].add(repo)
            seeds = lin["seeds"]
            first = seeds[0]
            origin = lin.get("origin") or {}
            oa = origin.get("author") or {}
            chg = lin["changes"]
            fwd = [c for c in chg if c["kind"] != "seed_modification"]
            end = fwd[-1] if fwd and lin["status"] in ("deleted", "file_deleted") else None
            seed_path = next((v["path"] for v in lin["versions"] if v["segment"] == "seed"), lin["path"])
            row = {
                "lineage_id": lin["lineage_id"], "repository": repo, "path": lin["path"],
                "intro_kind": lin["intro_kind"], "agents": lin["agents"],
                "seed_prs": [s["number"] for s in seeds], "seed_attributions": [s["attribution"] for s in seeds],
                "anchor_method": first["anchor_method"], "anchor_confidence": first["anchor_confidence"],
                "start_commit": lin["start_commit"], "start_date": lin["start_date"], "window_end": lin["window_end"],
                "observation_complete": lin["observation_complete"], "final_status": lin["status"],
                "stop_detail": lin["stop_detail"], "n_versions": len(lin["versions"]),
                "n_backward_versions": sum(v["segment"] == "backward" for v in lin["versions"]),
                "path_kind": path_kind(seed_path),
                "pr_seed_count": pr_seed_count.get(first["pr_id"], 0),
                "max_pr_seed_count": max((pr_seed_count.get(x["pr_id"], 0) for x in seeds), default=0),
                "n_changes": len(chg), "n_forward_changes": len(fwd),
                "first_change_days": fwd[0]["days_since_start"] if fwd else None,
                "end_change_bulk_size": bulk[end["commit"]] if end else None,
                "max_bulk_change_size": max((bulk[c["commit"]] for c in fwd), default=None),
                "parse_gaps": lin.get("gaps", []),
                "min_change_confidence": (min((c["confidence"] for c in chg),
                                              key=["uncertain", "probable", "certain"].index) if chg else None),
                "origin_commit": origin.get("commit"), "origin_date": origin.get("date"),
                "origin_author_kind": oa.get("author_kind"), "origin_agent": oa.get("agent"),
                "categories": sorted(cats_all), "matched_versions": matched_versions,
                "selected": bool(cats_all), "github": _gh(repo, lin["start_commit"]),
                "start_code": next((v["code"] for v in lin["versions"] if v["segment"] == "seed"), None),
            }
            all_chains.append(row)
            cov["chains"] += 1
            if row["selected"]:
                chains.append(row)
                cov["chains_selected"] += 1
                versions += vrows
                items_t += irows
                for ci, c in enumerate(chg):
                    a = c.get("author") or {}
                    changes_t.append({"lineage_id": lin["lineage_id"], "repository": repo, "change": ci,
                                      **{k: c.get(k) for k in (
                                          "kind", "confidence", "score", "commit", "date", "days_since_start",
                                          "message", "author_name", "is_merge", "path", "message_changed",
                                          "items_changed", "items_added", "items_removed", "wrapper_changes",
                                          "level_before", "level_after", "level_changed", "sink_changed",
                                          "condition_changed", "conditions_before", "conditions_after",
                                          "exception_changed", "moved", "code_changed", "before_code",
                                          "after_code", "detail_commits")},
                                      "author_kind": a.get("author_kind"), "author_agent": a.get("agent"),
                                      "author_evidence": a.get("evidence"), "pr_number": a.get("pr_number"),
                                      "bulk_change_size": bulk[c["commit"]] if c["kind"] != "seed_modification" else None,
                                      "path_kind": path_kind(c.get("path") or lin["path"]),
                                      "seed_touch": [s["number"] for s in seeds if s.get("change_index") == ci],
                                      "github": _gh(repo, c.get("commit"))})
    unc = sorted(({**u, "lineages": len(u["lineages"]), "repositories": len(u["repositories"])}
                  for u in unclassified.values()), key=lambda u: (-u["occurrences"], u["core"]))
    cov_rows = [{"step": k, "count": v} for k, v in sorted(cov.items())]
    if seed_manifest:
        cov_rows = [{"step": "seed:" + k, "count": v} for k, v in seed_manifest.get("counts", {}).items()] + cov_rows
    out = out_root / "dataset"
    for name, table in (("chains", chains), ("all_chains", all_chains), ("versions", versions), ("items", items_t),
                        ("changes", changes_t), ("unclassified_items", unc), ("coverage", cov_rows)):
        _write(table, out, name)
    summary = {"repositories": len(results), "chains": len(all_chains), "chains_selected": len(chains),
               "versions": len(versions), "items": len(items_t), "changes": len(changes_t),
               "unclassified_distinct": len(unc),
               "selected_by_category": dict(Counter(c for r in chains for c in r["categories"]).most_common()),
               "selected_by_agent": dict(Counter(a for r in chains for a in r["agents"]).most_common()),
               "selected_by_intro_kind": dict(Counter(r["intro_kind"] for r in chains))}
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1))
    return summary
