#!/usr/bin/env python3
"""Inventory local Codex sessions that may support session-to-PR attribution."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

if __package__:
    from .extract_codex_session_pr_evidence import PR_RE, _command, _cwd
else:
    from extract_codex_session_pr_evidence import PR_RE, _command, _cwd


DEFAULT_SESSIONS = Path.home() / ".codex/sessions"
DEFAULT_OUTPUT = Path("outputs/local_codex_pr_session_inventory_v1")
FIELDS = (
    "inventory_id", "session_id", "session_log_path", "session_log_sha256", "pr_url",
    "repo", "pr_number", "repo_root", "repo_root_exists", "local_origin_matches_pr",
    "file_change_events_before_pr", "commit_events_before_pr", "push_events_before_pr",
    "clean_status_checks_before_first_change", "pr_create_event_ordinal", "candidate_status",
    "missing_requirements",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_root(cwd: Path | None) -> Path | None:
    if cwd is None or not cwd.exists():
        return None
    result = subprocess.run(
        ["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False,
    )
    return Path(result.stdout.strip()).resolve() if result.returncode == 0 else None


def git_origin(root: Path | None) -> str:
    if root is None:
        return ""
    result = subprocess.run(
        ["git", "-C", str(root), "remote", "get-url", "origin"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def origin_repo(origin: str) -> str:
    match = re.search(r"(?:github\.com[:/])([^/]+/[^/]+?)(?:\.git)?$", origin)
    return match.group(1) if match else ""


def completed_events(path: Path) -> tuple[str, list[dict], int]:
    session_id = ""
    events = []
    malformed = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            malformed += 1
            continue
        payload = value.get("payload") or {}
        session_id = session_id or str(payload.get("thread_id") or "")
        item = payload.get("item") or {}
        if value.get("type") != "event_msg" or payload.get("type") != "item_completed":
            continue
        item_type = item.get("type")
        successful = (
            item_type == "CommandExecution" and item.get("status") == "completed" and item.get("exit_code") == 0
        ) or (item_type == "FileChange" and item.get("status") == "completed")
        if successful:
            events.append({
                "ordinal": int(value.get("ordinal") or 0),
                "type": item_type,
                "cwd": _cwd(item.get("cwd")),
                "command": _command(item),
                "stdout": str(item.get("stdout") or ""),
            })
    return session_id or path.stem, events, malformed


def inventory_session(path: Path) -> list[dict]:
    session_id, events, malformed = completed_events(path)
    output = []
    pr_events = [
        event for event in events
        if event["type"] == "CommandExecution"
        and re.search(r"\bgh\s+pr\s+create\b", event["command"])
        and PR_RE.search(event["stdout"])
    ]
    for pr_event in pr_events:
        match = PR_RE.search(pr_event["stdout"])
        assert match
        repo, number = match.group(1), match.group(2)
        ordinal = pr_event["ordinal"]
        before = [event for event in events if event["ordinal"] < ordinal]
        file_events = [event for event in before if event["type"] == "FileChange"]
        commits = [
            event for event in before
            if event["type"] == "CommandExecution" and re.search(r"\bgit\s+commit\b", event["command"])
        ]
        pushes = [
            event for event in before
            if event["type"] == "CommandExecution" and re.search(r"\bgit\s+push\b", event["command"])
        ]
        first_change = min((event["ordinal"] for event in file_events), default=ordinal)
        clean_checks = [
            event for event in before
            if event["type"] == "CommandExecution"
            and event["ordinal"] < first_change
            and "git status --porcelain" in event["command"]
        ]
        roots = [git_root(event["cwd"]) for event in file_events + [pr_event]]
        roots = [root for root in roots if root is not None]
        root = Counter(str(value) for value in roots).most_common(1)[0][0] if roots else ""
        local_repo = origin_repo(git_origin(Path(root) if root else None))
        missing = []
        if malformed:
            missing.append("malformed_session_jsonl")
        if not file_events:
            missing.append("no_file_change_before_pr")
        if not commits:
            missing.append("no_commit_before_pr")
        if not pushes:
            missing.append("no_push_before_pr")
        if not clean_checks:
            missing.append("no_prechange_clean_status_check")
        if not root:
            missing.append("local_repo_root_unavailable")
        if root and local_repo.lower() != repo.lower():
            missing.append("local_origin_pr_mismatch")
        status = "READY_FOR_LIVE_BINDING" if not missing else "INSUFFICIENT_LOCAL_EVIDENCE"
        output.append({
            "inventory_id": hashlib.sha256(f"{session_id}|{repo}|{number}".encode()).hexdigest()[:20],
            "session_id": session_id,
            "session_log_path": str(path),
            "session_log_sha256": sha256(path),
            "pr_url": match.group(0),
            "repo": repo,
            "pr_number": number,
            "repo_root": root,
            "repo_root_exists": bool(root),
            "local_origin_matches_pr": bool(root and local_repo.lower() == repo.lower()),
            "file_change_events_before_pr": len(file_events),
            "commit_events_before_pr": len(commits),
            "push_events_before_pr": len(pushes),
            "clean_status_checks_before_first_change": len(clean_checks),
            "pr_create_event_ordinal": ordinal,
            "candidate_status": status,
            "missing_requirements": ";".join(missing),
        })
    return output


def run(sessions_root: Path, output_dir: Path) -> dict:
    paths = sorted(sessions_root.rglob("*.jsonl"))
    rows = []
    for path in paths:
        rows.extend(inventory_session(path))
    unique = {}
    for row in rows:
        unique[(row["session_id"], row["pr_url"])] = row
    rows = sorted(unique.values(), key=lambda row: (row["candidate_status"], row["repo"], row["pr_number"]))
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "candidates.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    statuses = Counter(row["candidate_status"] for row in rows)
    missing = Counter(
        item for row in rows for item in row["missing_requirements"].split(";") if item
    )
    summary = {
        "status": "LOCAL_SESSION_PR_INVENTORY_COMPLETE",
        "session_files_scanned": len(paths),
        "structured_pr_create_candidates": len(rows),
        "candidate_status_counts": dict(sorted(statuses.items())),
        "missing_requirement_counts": dict(sorted(missing.items())),
        "privacy_policy": "no_prompt_or_raw_tool_output_copied",
        "runtime_leak_claim": False,
        "causal_claim": False,
        "fallacy_scan_coverage": "11/11",
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(f"""# 本地 Codex 会话→PR 行级来源容量审计

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: validate
- Origin Date: 2026-09-03
- Verification Status: LOCAL_SESSION_PR_INVENTORY_COMPLETE
- Version Label: local_codex_pr_session_inventory_v1

## 结果

- 扫描本地会话文件：{len(paths):,} 个。
- 同一结构化会话中出现成功 `gh pr create` 与 PR URL：{len(rows)} 个。
- 同时具有 PR 前文件修改、commit、push、修改前 clean-status 检查、可用本地仓库且 origin 匹配：{statuses.get('READY_FOR_LIVE_BINDING', 0)} 个。
- 证据不足：{statuses.get('INSUFFICIENT_LOCAL_EVIDENCE', 0)} 个；原因计数：{json.dumps(dict(sorted(missing.items())), ensure_ascii=False)}。

## 解释

PR 链接出现在会话中不是 Agent 来源证据。只有 `READY_FOR_LIVE_BINDING` 项才值得进一步读取 GitHub base/head/commit/tree/diff，并通过现有绑定器升级为 A/B 级行来源证据。本轮没有复制提示词、stdout/stderr 或完整工具输出。

## 谬误扫描

- Coverage: 11/11 checked.
- Simpson's paradox: 未计算 Agent/Human 差异。
- Ecological fallacy: 单位是会话→PR 候选。
- Berkson's paradox: 仅包含本地会话中成功 `gh pr create` 的记录。
- Collider bias: clean-status 门槛可能选中规范工作流。
- Base-rate neglect: 报告扫描总数与候选数。
- Regression to the mean: 不涉及极值前后比较。
- Survivorship bias: 本地会话和仓库仍存在是硬性条件。
- Look-elsewhere effect: 未进行多重特征检验。
- Garden of forking paths: 候选门槛在脚本中固定。
- Correlation != causation: 候选不是作者因果证明。
- Reverse causality: 用户可能决定何时要求 Agent 创建 PR。

## 可复现性

`candidates.csv` 只保留最小元数据和会话哈希；不保留原始命令或输出。
""", encoding="utf-8")
    artifacts = ("candidates.csv", "summary.json", "report.md")
    manifest = {
        "hash_algorithm": "SHA-256",
        "input_inventory": {
            "sessions_root": str(sessions_root),
            "session_files_scanned": len(paths),
            "session_path_list_sha256": hashlib.sha256("\n".join(map(str, paths)).encode()).hexdigest(),
        },
        "script_sha256": sha256(Path(__file__)),
        "artifact_sha256": {name: sha256(output_dir / name) for name in artifacts},
        "deterministic_for_current_local_snapshot": True,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--sessions-root", type=Path, default=DEFAULT_SESSIONS)
    value.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    return value


def main() -> int:
    args = parser().parse_args()
    print(json.dumps(run(args.sessions_root, args.output_dir), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
