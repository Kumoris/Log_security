"""Exports (REBUILD.md §10): case list, evidence packs, coverage report."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .coverage import coverage, load_results, render_markdown, unique_cases


def _link(repo: str, sha: str) -> str:
    return f"https://github.com/{repo}/commit/{sha}"


def _stmt_block(title: str, st: dict | None) -> list[str]:
    if not st:
        return []
    s = st["sensitivity"]
    return [f"**{title}** `{st['path']}` · `{st['scope']}` · 行 {st['line']} · 检出方式 `{st['detection']}`", "",
            "```python", st["code"], "```", "",
            f"敏感性 `{s['level']}` · 数据类型 {s['data_types']} · 类型标签 {s['taxonomy_labels']}",
            f"值来源 {s['flows']} · 已有脱敏 {s['sanitization']}", ""]


def evidence_markdown(c: dict) -> str:
    repo = c["repository"]
    L = [f"# 案例 {c['case_id']}", "",
         "> 静态候选，不等于运行时确有泄露。",
         "", f"- 仓库：`{repo}`", f"- 文件：`{c['file_path']}`（{c['attribution']}）",
         f"- 分桶：**{c['verdict']}**（{c['priority']}） · 敏感性 **{c['privacy_assessment']}** · 数据类型 {c['data_types']}",
         f"- 引入关系：{c['introduction_relation']} · 追踪状态：{c['lineage_status']} · 标记：{c['review_flags']}",
         f"- 种子：[{c['seed_sha'][:10]}]({_link(repo, c['seed_sha'])})（{c['seed_resolution']}）"
         f" agent={c['agent_names']} trace_id=`{c['trace_id']}`",
         f"- 观察期：{c['observation']['start']} → {c['observation']['end']}（完整={c['observation']['complete']}）",
         f"- 追踪停止：{c['stop_reason']} {c['stop_detail'] or ''}",
         f"- 缺失证据：{c['missing_evidence']}", "", "## 起点", ""]
    intro = c["introduced"]
    if intro:
        L += [f"[{intro['sha'][:10]}]({_link(repo, intro['sha'])}) {intro['date']}", ""]
        L += _stmt_block("新增", intro["after"])
    L += ["## 时间线", ""]
    for i, t in enumerate(c["timeline"], 1):
        e = t["event"]
        mark = "" if t["in_window"] else "（观察期外）"
        L += [f"### {i}. {e['change']} · [{e['sha'][:10]}]({_link(repo, e['sha'])}) · {e['date']} {mark}",
              f"标签 {e['labels']} · 修复效果 {e.get('fix_effect')} · 置信度 {e['confidence']}", ""]
        L += _stmt_block("改前", e["before"]) + _stmt_block("改后", e["after"])
    if c.get("stop_event"):
        e = c["stop_event"]
        L += ["## 停止处的非精确事件", "", f"{e['change']} · [{e['sha'][:10]}]({_link(repo, e['sha'])}) · {e['confidence']}", ""]
        L += _stmt_block("改前", e["before"]) + _stmt_block("改后", e["after"])
    return "\n".join(L) + "\n"


def export(out: Path, seed_manifest_path: Path | None = None) -> dict:
    results, cases = load_results(out)
    manifest = json.loads(seed_manifest_path.read_text()) if seed_manifest_path and seed_manifest_path.exists() else None
    rep = coverage(results, cases, manifest)
    report_dir = out / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    with (report_dir / "cases.jsonl").open("w") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    (report_dir / "coverage.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2))
    (report_dir / "coverage.md").write_text(render_markdown(rep))
    uniq = unique_cases(cases)
    cands = [c for c in uniq if c["privacy_review_candidate"]]
    with (report_dir / "privacy_review_candidates.jsonl").open("w") as f:
        for c in cands:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    for sub in ("evidence", "review_queue", "candidates"):
        shutil.rmtree(report_dir / sub, ignore_errors=True)
    n_ev = n_q = 0
    for c in cands:
        # every candidate gets a readable folder; REVIEW_READY ones also go to evidence/
        sub = "evidence" if c["verdict"] == "REVIEW_READY" else "candidates"
        target = report_dir / sub / c["repository"].replace("/", "__") / c["case_id"]
        n_ev += sub == "evidence"
        n_q += sub == "candidates"
        target.mkdir(parents=True, exist_ok=True)
        (target / "case.json").write_text(json.dumps(c, ensure_ascii=False, indent=1))
        (target / "README.md").write_text(evidence_markdown(c))
    _write_candidate_table(report_dir / "privacy_review_candidates.md", cands)
    rep["exported"] = {"review_ready": n_ev, "privacy_review_candidates": n_ev + n_q}
    return rep


def _write_candidate_table(path: Path, cands: list[dict]) -> None:
    """One table a person can read top to bottom: every log handed over for review."""
    L = ["# 待人工查看的日志（agentlog_unified 判定 possible / supported）", "",
         f"共 {len(cands)} 条。每条的详细材料在 candidates/ 或 evidence/ 下同名目录。", "",
         "| # | 仓库 | 文件:行 | 日志语句 | 敏感性 | 数据类型 | 分桶 | 之后的经历 |", "|---|---|---|---|---|---|---|---|"]
    order = {"supported": 0, "possible": 1}
    for i, c in enumerate(sorted(cands, key=lambda c: (order.get(c["privacy_assessment"], 9), c["repository"])), 1):
        a = c["introduced"]["after"]
        code = " ".join(a["code"].split())[:90].replace("|", "\\|")
        life = ", ".join(t["event"]["change"] for t in c["timeline"]) or "未变"
        L.append(f"| {i} | {c['repository']} | `{a['path']}:{a['line']}` | `{code}` | {c['privacy_assessment']} | "
                 f"{', '.join(c['data_types'])} | {c['verdict']} | {c['stop_reason']}: {life} |")
    path.write_text("\n".join(L) + "\n")
