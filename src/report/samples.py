"""Manual verification samples (REDESIGN_AIDEV.md, 验证). Fixed seed, tool conclusions kept in
separate columns so they can be hidden for blind labelling.

  samples/anchors.csv        PRs: is this the commit that brought the PR's code into the default branch?
  samples/tracking.csv       change steps, stratified by confidence: is before -> after the same log?
  samples/authorship.csv     versions of chains touched by more than one PR: is the author right?
  samples/features.csv       matched items: is the category right? (precision)
  samples/unclassified.csv   unclassified items: is privacy data missed? (recall clues)
Each file has empty ``label_*`` columns for the annotators.
"""
from __future__ import annotations

import csv
import json
import random
from pathlib import Path

from ..models import read_jsonl


def _write(rows: list[dict], path: Path, labels: list[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return 0
    cols = list(dict.fromkeys(k for r in rows for k in r)) + labels
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: (json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v)
                        for k, v in r.items()})
    return len(rows)


def build_samples(out_root: Path, seed: int = 20260928, n_anchor: int = 200, n_track: int = 150,
                  n_author: int = 50, n_feat: int = 200, n_unc: int = 200) -> dict:
    rng = random.Random(seed)
    anchors, changes, multi, feats, unc = [], [], [], [], []
    for d in sorted(p for p in (out_root / "repos").iterdir() if p.is_dir()):
        for a in read_jsonl(d / "anchors.jsonl"):
            anchors.append({"repository": a["repository"], "pr_number": a["number"], "agent": a["agent"],
                            "pr_url": f"https://github.com/{a['repository']}/pull/{a['number']}",
                            "tool_method": a["method"], "tool_confidence": a["confidence"],
                            "tool_landing": a["landing"], "tool_reason": a["reason"],
                            "landing_url": f"https://github.com/{a['repository']}/commit/{a['landing']}" if a["landing"] else None})
        items = {(r["lineage_id"], r["version"]): r for r in read_jsonl(d / "items.jsonl")}
        for lin in read_jsonl(d / "lineages.jsonl"):
            repo = lin["repository"]
            for i, c in enumerate(lin["changes"]):
                if c["kind"] in ("seed_modification",):
                    continue
                changes.append({"repository": repo, "lineage_id": lin["lineage_id"], "change": i,
                                "commit_url": f"https://github.com/{repo}/commit/{c['commit']}",
                                "before_code": c["before_code"], "after_code": c.get("after_code"),
                                "tool_kind": c["kind"], "tool_confidence": c["confidence"], "tool_score": c.get("score")})
            if len({s["number"] for s in lin["seeds"]}) > 1 or lin["versions"][0]["segment"] == "backward":
                for vi, v in enumerate(lin["versions"]):
                    a = v.get("author") or {}
                    multi.append({"repository": repo, "lineage_id": lin["lineage_id"], "version": vi,
                                  "segment": v["segment"], "commit_url": f"https://github.com/{repo}/commit/{v['commit']}",
                                  "code": v.get("code"), "tool_author_kind": a.get("author_kind"),
                                  "tool_agent": a.get("agent"), "tool_pr_number": a.get("pr_number"),
                                  "tool_evidence": a.get("evidence")})
            for vi, v in enumerate(lin["versions"]):
                for it in items.get((lin["lineage_id"], vi), {}).get("items", []):
                    row = {"repository": repo, "lineage_id": lin["lineage_id"], "version": vi,
                           "commit_url": f"https://github.com/{repo}/commit/{v['commit']}", "code": v.get("code"),
                           "expr": it["expr"], "definition": it["definition"]}
                    if it["categories"]:
                        feats.append({**row, "tool_categories": it["categories"],
                                      "tool_evidence": [f"{e['kind']}:{e['matched']}" for e in it["evidence"]]})
                    elif it["role"] == "value":
                        unc.append(row)
    # stratified tracking sample: every confidence level represented
    by_conf: dict[str, list] = {}
    for c in changes:
        by_conf.setdefault(c["tool_confidence"], []).append(c)
    track = []
    for conf, rows in sorted(by_conf.items()):
        track += rng.sample(rows, min(len(rows), max(1, n_track // max(1, len(by_conf)))))
    chains = sorted({r["lineage_id"] for r in multi})
    pick = set(rng.sample(chains, min(n_author, len(chains))))
    out = out_root / "samples"
    counts = {
        "anchors": _write(rng.sample(anchors, min(n_anchor, len(anchors))), out / "anchors.csv",
                          ["label_landing_correct", "label_note"]),
        "tracking": _write(track, out / "tracking.csv", ["label_same_log", "label_kind_correct", "label_note"]),
        "authorship": _write([r for r in multi if r["lineage_id"] in pick], out / "authorship.csv",
                             ["label_author_correct", "label_note"]),
        "features": _write(rng.sample(feats, min(n_feat, len(feats))), out / "features.csv",
                           ["label_category_correct", "label_note"]),
        "unclassified": _write(rng.sample(unc, min(n_unc, len(unc))), out / "unclassified.csv",
                               ["label_privacy_related", "label_category", "label_note"]),
    }
    (out / "README.md").write_text(
        "# 人工核验样本\n\n固定随机种子 %d。`tool_*` 列是工具的结论，盲标时先隐藏；`label_*` 列留给标注者填写。\n\n"
        "| 文件 | 行数 | 要回答的问题 |\n|---|---|---|\n"
        "| anchors.csv | %d | 工具给出的提交是否就是把这个 PR 的代码带进默认分支的提交 |\n"
        "| tracking.csv | %d | 改前改后是否同一条日志；改动类型是否正确（按置信度分层抽样） |\n"
        "| authorship.csv | %d | 被多个 PR 碰过或有向前历史的链：每个版本的作者认定是否正确 |\n"
        "| features.csv | %d | 命中的类别是否正确（精确率） |\n"
        "| unclassified.csv | %d | 未分类的输出项里有没有隐私数据（召回线索） |\n"
        % (seed, counts["anchors"], counts["tracking"], counts["authorship"], counts["features"], counts["unclassified"]))
    return counts
