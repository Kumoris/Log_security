"""Coverage report (REBUILD.md §10): every number derived from result/gap records."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

LIMITATIONS = [
    "所有结论都是静态候选，不等于运行时确有泄露",
    "只解析变更文件：依赖（如脱敏函数本身）变化导致的敏感性变化看不到",
    "第一版只分析 Python；其他语言的 agent 文件只计数不分析",
    "合并提交的冲突解决内容未分析，只记缺口",
    "被修复只能说明「后续提交修改了它」，不能说「被人类修复」（数据集覆盖率低）",
    "mixed 文件里新增的日志未逐行确认是否出自 agent",
    "敏感类型表与判定规则直接调用 agentlog_unified 原代码（src/reference），其误报与漏报一并继承",
]


def load_results(out: Path) -> tuple[list[dict], list[dict]]:
    results, cases = [], []
    for d in sorted((out / "repos").glob("*/result.json")):
        results.append(json.loads(d.read_text()))
        cf = d.parent / "cases.jsonl"
        if cf.exists():
            cases += [json.loads(line) for line in cf.open()]
    return results, cases


def unique_cases(cases: list[dict]) -> list[dict]:
    """One row per log: the same statement claimed by rebased/cherry-picked copies of a
    seed commit appears once (first by case_id)."""
    seen, out = set(), []
    for c in sorted(cases, key=lambda c: c["case_id"]):
        intro = c["introduced"]
        key = (c["repository"], c["file_path"], intro["after_fp"] if intro else c["case_id"])
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def coverage(results: list[dict], cases: list[dict], seed_manifest: dict | None = None) -> dict:
    status = Counter(r["status"] for r in results)
    clone_fail = Counter()
    for r in results:
        if r["status"] == "failed":
            for g in r["gaps"]:
                clone_fail[f"{g['kind']}: {g.get('detail') or ''}"[:160]] += 1
    seed_states = Counter()
    for r in results:
        seed_states.update(r.get("seed_states", {}))
    m = Counter()
    for r in results:
        for k in ("seeds", "commits", "merge_commits", "file_versions", "events",
                  "seeds_with_python_agent_files", "trackable_python_seeds"):
            m[k] += r.get("metrics", {}).get(k, 0) or 0
    gap_kinds = Counter()
    parse_reasons = Counter()
    for r in results:
        for g in r["gaps"]:
            gap_kinds[g["kind"]] += 1
            if g["kind"] == "parse_failed":
                parse_reasons[g.get("detail") or "?"] += 1
    uniq = unique_cases(cases)
    verdicts = Counter(c["verdict"] for c in uniq)
    risks = Counter(c["privacy_assessment"] for c in uniq)
    cands = [c for c in uniq if c["privacy_review_candidate"]]
    cand_types = Counter(t for c in cands for t in c["data_types"])
    cand_labels = Counter(lab.split(":")[0] for c in cands for lab in (c["sensitivity_at_intro"] or {}).get("taxonomy_labels", []))
    cand_sink = Counter("print" if c["introduced"]["after"]["method"] == "print" else "logger/wrapper" for c in cands)
    stops = Counter(c["stop_reason"] for c in uniq)
    by_resolution = Counter(c["seed_resolution"] for c in uniq)
    no_ref = sum(1 for c in uniq if c["sensitivity_at_intro"] and not c["sensitivity_at_intro"].get("reference_found", True))
    rep = {
        "repositories": {"total": len(results), "processed": status["complete"] + status["partial"],
                         "complete": status["complete"], "partial": status["partial"],
                         "failed": status["failed"], "failure_reasons": dict(clone_fail)},
        "seeds": {"total": m["seeds"], "by_state": dict(seed_states),
                  "with_python_agent_files": m["seeds_with_python_agent_files"],
                  "trackable_with_python_agent_files": m["trackable_python_seeds"]},
        "history": {"commits_walked": m["commits"], "merge_commits_no_diff": m["merge_commits"],
                    "merge_resolution_unanalyzed": gap_kinds["merge_resolution_unanalyzed"],
                    "python_file_versions_read": m["file_versions"],
                    "parse_failed": gap_kinds["parse_failed"], "parse_failed_by_reason": dict(parse_reasons),
                    "decode_failed": gap_kinds["decode_failed"], "file_too_large": gap_kinds["file_too_large"]},
        "log_events": m["events"],
        "cases": {"total_rows": len(cases), "unique_logs": len(uniq),
                  "by_screening_bucket": dict(verdicts), "by_privacy_assessment": dict(risks),
                  "privacy_review_candidates": len(cands),
                  "candidates_by_data_type": dict(cand_types.most_common()),
                  "candidates_by_taxonomy_label": dict(cand_labels.most_common()),
                  "candidates_by_sink": dict(cand_sink),
                  "by_stop_reason": dict(stops), "by_seed_resolution": dict(by_resolution),
                  "reference_detector_saw_no_log": no_ref},
        "gaps_by_kind": dict(gap_kinds),
        "limitations": LIMITATIONS,
    }
    if seed_manifest:
        rep["seed_layer"] = seed_manifest.get("counts")
    return rep


def render_markdown(rep: dict) -> str:
    r, s, h, c = rep["repositories"], rep["seeds"], rep["history"], rep["cases"]
    L = ["# 覆盖率报告", "", "```"]
    L.append(f"仓库            {r['total']:>8,} 个")
    L.append(f"  成功处理      {r['processed']:>8,}   (完整 {r['complete']}, 有缺口 {r['partial']})")
    L.append(f"  失败          {r['failed']:>8,}")
    for k, v in r["failure_reasons"].items():
        L.append(f"      {v:>4} × {k}")
    L.append("")
    L.append(f"种子提交        {s['total']:>8,} 个（去重后，仅已处理仓库）")
    for k, v in sorted(s["by_state"].items(), key=lambda kv: -kv[1]):
        L.append(f"  {k:<26}{v:>8,}")
    L.append(f"  含 Python agent 文件    {s['with_python_agent_files']:>8,}")
    L.append(f"    其中可追踪            {s['trackable_with_python_agent_files']:>8,}")
    L.append("")
    L.append(f"提交遍历        {h['commits_walked']:>8,} 个")
    L.append(f"  合并提交（不做 diff）   {h['merge_commits_no_diff']:>8,}")
    L.append(f"    其中冲突解决未分析    {h['merge_resolution_unanalyzed']:>8,}")
    L.append(f"  Python 文件版本读取     {h['python_file_versions_read']:>8,}")
    L.append(f"  解析失败                {h['parse_failed']:>8,}   {h['parse_failed_by_reason']}")
    L.append(f"  解码失败 / 超大文件     {h['decode_failed']:>8,} / {h['file_too_large']:,}")
    L.append("")
    L.append(f"日志事件        {rep['log_events']:>8,} 条")
    L.append(f"案例（agent 新增的日志）{c['unique_logs']:>6,} 条（去掉 rebase 副本重复；原始行数 {c['total_rows']:,}）")
    L.append(f"  判定为 possible/supported 的（交给人看的）  {c['privacy_review_candidates']:>6,}")
    L.append("")
    L.append("按 agentlog_unified 分桶：")
    for k in ("REVIEW_READY", "NEEDS_CONTEXT", "NO_OBSERVED_PRIVACY_FIX", "OUT_OF_SCOPE_OR_FALSE_POSITIVE", "BLOCKED_BY_DATA"):
        L.append(f"  {k:<32}{c['by_screening_bucket'].get(k, 0):>8,}")
    L.append(f"敏感性判定      {c['by_privacy_assessment']}")
    L.append(f"候选的数据类型  {c['candidates_by_data_type']}")
    L.append(f"候选的类型标签  {c['candidates_by_taxonomy_label']}")
    L.append(f"候选的输出方式  {c['candidates_by_sink']}")
    L.append(f"追踪停止原因    {c['by_stop_reason']}")
    L.append(f"参照检测器没认出是日志的 {c['reference_detector_saw_no_log']}")
    L.append("```")
    L += ["", "## 缺口（按类型）", "", "| 类型 | 数量 |", "|---|---|"]
    L += [f"| {k} | {v:,} |" for k, v in sorted(rep["gaps_by_kind"].items(), key=lambda kv: -kv[1])]
    L += ["", "## 局限", ""] + [f"- {x}" for x in rep["limitations"]]
    return "\n".join(L) + "\n"
