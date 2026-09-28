#!/usr/bin/env python3
"""Extract privacy-preserving Codex session -> commit -> GitHub PR evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlparse

if __package__:
    from .screen_github_agent_logs import (
        AGENT_NATIVE_RISK_FEATURES, SHARED_SENSITIVE_RISK_FEATURES,
        GitHubClient, _atomic_write_text, _raw_diff_files, added_lines,
        canonical_patch_sha256, classify_log, is_production_path,
        patch_content_sha256, redact_excerpt, sha256_json, sha256_text,
    )
    from .verify_session_pr_binding import run as run_binding, verify_bindings
else:
    from screen_github_agent_logs import (
        AGENT_NATIVE_RISK_FEATURES, SHARED_SENSITIVE_RISK_FEATURES,
        GitHubClient, _atomic_write_text, _raw_diff_files, added_lines,
        canonical_patch_sha256, classify_log, is_production_path,
        patch_content_sha256, redact_excerpt, sha256_json, sha256_text,
    )
    from verify_session_pr_binding import run as run_binding, verify_bindings


PR_RE = re.compile(r"https://github\.com/([^/\s]+/[^/\s]+)/pull/(\d+)")
PORCELAIN_RE = re.compile(r"^(?:[ MADRCU?!]{2})\s+.+$", re.MULTILINE)
OUTPUT_PATH_RE = re.compile(r"--output-file(?:=|\s+)(?:['\"])?([^\s'\"]+)")
OUTPUT_NAMES = (
    "session_evidence.jsonl", "pr_evidence.jsonl", "extraction_rejections.jsonl",
    "agent_log_candidates.csv", "summary.json", "report.md",
)
LOG_FIELDS = (
    "pr_key", "pr_url", "repo", "file", "line", "path_scope", "static_risk_candidate",
    "risk_features", "log_concepts", "log_text_redacted",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cwd(value: object) -> Path | None:
    if not value:
        return None
    parsed = urlparse(str(value))
    return Path(unquote(parsed.path)) if parsed.scheme == "file" else Path(str(value))


def _inside(path: Path | None, root: Path) -> bool:
    if path is None:
        return False
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _command(item: dict) -> str:
    command = item.get("command") or []
    return str(command[-1]) if isinstance(command, list) and command else str(command or "")


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=60,
    )
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()[-300:]}")
    return result.stdout.strip()


def _repo_name(root: Path) -> str:
    remote = _git(root, "remote", "get-url", "origin")
    match = re.search(r"(?:github\.com[:/])([^/]+/[^/]+?)(?:\.git)?$", remote)
    if not match:
        raise RuntimeError("origin is not a GitHub repository: " + remote)
    return match.group(1)


def _resolve_commit(root: Path, value: str) -> str:
    return _git(root, "rev-parse", f"{value}^{{commit}}") if value else ""


def parse_session(path: Path, repo_root: Path, repo: str) -> tuple[dict | None, dict | None]:
    events: list[dict] = []
    session_id = ""
    started = ended = ""
    parse_errors = 0
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            timestamp = str(value.get("timestamp") or "")
            started = started or timestamp
            ended = timestamp or ended
            payload = value.get("payload") or {}
            session_id = session_id or str(payload.get("thread_id") or "")
            item = payload.get("item") or {}
            if value.get("type") != "event_msg" or payload.get("type") != "item_completed":
                continue
            if item.get("type") == "CommandExecution":
                successful = item.get("status") == "completed" and item.get("exit_code") == 0
            elif item.get("type") == "FileChange":
                successful = item.get("status") == "completed"
            else:
                continue
            if not successful:
                continue
            cwd = _cwd(item.get("cwd"))
            changes = item.get("changes") or {}
            relevant = _inside(cwd, repo_root) or any(_inside(Path(name), repo_root) for name in changes)
            if relevant:
                events.append({
                    "ordinal": int(value.get("ordinal") or 0), "timestamp": timestamp,
                    "type": item.get("type"), "cwd": cwd, "command": _command(item),
                    "stdout": str(item.get("stdout") or ""), "changes": changes,
                })
    except OSError as exc:
        return None, {"session_log_path": str(path), "reason": "unreadable_session", "detail": str(exc)[:300]}
    if not events:
        return None, None

    file_events = [event for event in events if event["type"] == "FileChange"]
    pr_events = [event for event in events if event["type"] == "CommandExecution" and PR_RE.search(event["stdout"])]
    if not file_events or not pr_events:
        return None, {
            "session_id": session_id, "session_log_path": str(path),
            "reason": "missing_file_change_or_pr_url",
        }
    if parse_errors:
        return None, {
            "session_id": session_id, "session_log_path": str(path),
            "reason": "incomplete_session_jsonl", "malformed_line_count": parse_errors,
        }
    first_mutation = min(event["ordinal"] for event in file_events)
    clean_events = [
        event for event in events
        if event["type"] == "CommandExecution" and event["ordinal"] < first_mutation
        and "git status --porcelain" in event["command"]
    ]
    clean_event = clean_events[-1] if clean_events else None
    clean = bool(clean_event and not PORCELAIN_RE.search(clean_event["stdout"]))
    checked_head = ""
    if clean_event:
        match = re.search(r"(?:^|\n)\*?\s*([0-9a-f]{7,40})(?:\s+.*\bHEAD\b|\s*$)", clean_event["stdout"])
        if match:
            checked_head = _resolve_commit(repo_root, match.group(1))

    changed_paths = set()
    for event in file_events:
        for name, change in event["changes"].items():
            target = Path(str((change or {}).get("move_path") or name))
            if _inside(target, repo_root):
                changed_paths.add(target.resolve().relative_to(repo_root.resolve()).as_posix())
    generated_paths = set()
    for event in events:
        if event["type"] != "CommandExecution":
            continue
        for name in OUTPUT_PATH_RE.findall(event["command"]):
            target = Path(name)
            target = target if target.is_absolute() else (event["cwd"] or repo_root) / target
            if _inside(target, repo_root):
                generated_paths.add(target.resolve().relative_to(repo_root.resolve()).as_posix())

    created_commits = []
    commit_events = []
    for event in events:
        if event["type"] != "CommandExecution" or not re.search(r"\bgit\s+commit\b", event["command"]):
            continue
        match = re.search(r"\[[^\]]+\s+([0-9a-f]{7,40})\]", event["stdout"])
        if match:
            created_commits.append(_resolve_commit(repo_root, match.group(1)))
            commit_events.append(event["ordinal"])
    create_events = [event for event in pr_events if re.search(r"\bgh\s+pr\s+create\b", event["command"])]
    push_events = [
        event for event in events
        if event["type"] == "CommandExecution" and re.search(r"\bgit\s+push\b", event["command"])
    ]
    pr_match = PR_RE.search(pr_events[-1]["stdout"])
    assert pr_match
    pr_repo, pr_number = pr_match.group(1), int(pr_match.group(2))
    if pr_repo.lower() != repo.lower():
        return None, {"session_id": session_id, "reason": "pr_repository_mismatch", "pr_repo": pr_repo, "repo": repo}
    return {
        "session_id": session_id or path.stem.rsplit("-", 5)[-1],
        "session_log_path": str(path),
        "session_log_sha256": _sha256_file(path),
        "session_started_at": started,
        "ended_at": ended,
        "repo": repo,
        "repo_root": str(repo_root),
        "pr_key": f"{repo}#{pr_number}",
        "pr_url": pr_match.group(0),
        "pr_created_in_session": bool(create_events),
        "pr_create_event_ordinal": create_events[-1]["ordinal"] if create_events else "",
        "push_event_ordinals": [event["ordinal"] for event in push_events],
        "known_clean_base": clean,
        "clean_base_check_at": clean_event["timestamp"] if clean_event else "",
        "clean_base_check_event_ordinal": clean_event["ordinal"] if clean_event else "",
        "clean_base_head_sha": checked_head,
        "unaccounted_pre_session_worktree_changes": not clean,
        "file_change_event_count": len(file_events),
        "file_change_final_paths": sorted(changed_paths),
        "file_change_final_path_count": len(changed_paths),
        "command_generated_final_paths": sorted(generated_paths),
        "created_commit_shas": created_commits,
        "commit_created_in_session": bool(created_commits),
        "commit_event_ordinals": commit_events,
        "generation_stage": "agent_session_final",
    }, None


def fetch_pr(session: dict, root: Path, client: GitHubClient) -> tuple[dict, str]:
    repo, number = session["pr_key"].rsplit("#", 1)
    api = f"{client.base_url}/repos/{repo}/pulls/{number}"
    metadata, _ = client.get_json(api)
    commits, _ = client.paginate(api + "/commits?per_page=100", None, 20)
    diff, _ = client.get_text(session["pr_url"] + ".diff")
    if not isinstance(metadata, dict):
        raise RuntimeError("GitHub PR metadata is not an object")
    head_sha = str((metadata.get("head") or {}).get("sha") or "")
    base_sha = str((metadata.get("base") or {}).get("sha") or "")
    commit_shas = [str(row.get("sha") or "") for row in commits if row.get("sha")]
    tree_sha = _git(root, "show", "-s", "--format=%T", head_sha)
    local_diff = _git(root, "diff", "--binary", base_sha, head_sha) + "\n"
    paths = set(_git(root, "diff", "--name-only", base_sha, head_sha).splitlines())
    accounted = set(session["file_change_final_paths"]) | set(session["command_generated_final_paths"])
    clean_base = bool(session["known_clean_base"] and session.get("clean_base_head_sha") == base_sha)
    session.update({
        "base_sha": base_sha,
        "commit_sha": head_sha,
        "tree_sha": tree_sha,
        "artifact_created_at": _git(root, "show", "-s", "--format=%cI", head_sha),
        "canonical_patch_sha256": canonical_patch_sha256(local_diff),
        "patch_content_sha256": patch_content_sha256(local_diff),
        "known_clean_base": clean_base,
        "unaccounted_pre_session_worktree_changes": not clean_base,
        "full_pr_commit_chain_created_in_session": bool(commit_shas) and set(commit_shas) <= set(session["created_commit_shas"]),
        "changed_path_count": len(paths),
        "changed_path_coverage": len(paths & accounted) / len(paths) if paths else 1.0,
        "unaccounted_changed_paths": sorted(paths - accounted),
        "full_patch_accounted": paths <= accounted,
    })
    state = "MERGED" if metadata.get("merged_at") else str(metadata.get("state") or "").upper()
    snapshot = {
        "number": metadata.get("number"), "url": metadata.get("html_url"), "state": state,
        "title": metadata.get("title"), "created_at": metadata.get("created_at"),
        "merged_at": metadata.get("merged_at"), "base_sha": base_sha, "head_sha": head_sha,
        "changed_files": metadata.get("changed_files"), "additions": metadata.get("additions"),
        "deletions": metadata.get("deletions"), "actor_login": (metadata.get("user") or {}).get("login", ""),
        "commit_shas": commit_shas,
    }
    pr = {
        "provenance": "AGENT_SOURCE_CANDIDATE",
        "provenance_evidence": "local_codex_session_to_commit_to_pr_hard_anchor",
        "repo": repo, "pr_number": int(number), "pr_key": session["pr_key"],
        "pr_url": session["pr_url"], "state": state, "title": str(metadata.get("title") or ""),
        "actor_login": str((metadata.get("user") or {}).get("login") or ""),
        "created_at": str(metadata.get("created_at") or ""), "merged_at": str(metadata.get("merged_at") or ""),
        "base_sha": base_sha, "head_sha": head_sha, "head_tree_sha": tree_sha,
        "head_committed_at": _git(root, "show", "-s", "--format=%cI", head_sha),
        "merge_commit_sha": str(metadata.get("merge_commit_sha") or ""),
        "changed_files": int(metadata.get("changed_files") or 0),
        "additions": int(metadata.get("additions") or 0), "deletions": int(metadata.get("deletions") or 0),
        "pr_diff_sha256": sha256_text(diff), "canonical_patch_sha256": canonical_patch_sha256(diff),
        "patch_content_sha256": patch_content_sha256(diff), "commit_list_sha256": sha256_json(commit_shas),
        "metadata_sha256": sha256_json(snapshot), "pr_metadata_snapshot": snapshot,
        "evidence_chain_status": "live_pr_metadata_raw_diff_commits_and_local_git_objects",
    }
    return pr, diff


def log_candidates(pr: dict, diff: str) -> list[dict]:
    rows = []
    for path, section in _raw_diff_files(diff):
        for line_number, text in added_lines(section):
            executable, features, concepts = classify_log(path, text)
            if executable:
                rows.append({
                    "pr_key": pr["pr_key"], "pr_url": pr["pr_url"], "repo": pr["repo"],
                    "file": path, "line": line_number,
                    "path_scope": "production" if is_production_path(path) else "non_production",
                    "static_risk_candidate": bool(features), "risk_features": ";".join(features),
                    "log_concepts": ";".join(concepts), "log_text_redacted": redact_excerpt(text),
                })
    return rows


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    _atomic_write_text(path, "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows))


def _write_csv(path: Path, rows: list[dict]) -> None:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=LOG_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    _atomic_write_text(path, buffer.getvalue())


def verify_outputs(output_dir: Path) -> list[str]:
    errors = [f"missing output: {name}" for name in OUTPUT_NAMES if not (output_dir / name).exists()]
    binding = output_dir / "binding" / "provenance_bindings.jsonl"
    if not binding.exists():
        errors.append("missing output: binding/provenance_bindings.jsonl")
        return errors
    rows = [json.loads(line) for line in binding.read_text(encoding="utf-8").splitlines() if line]
    errors.extend(verify_bindings(rows))
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8")) if not errors else {}
    if summary and summary.get("n_bindings") != len(rows):
        errors.append("summary binding count mismatch")
    return errors


def run(args: argparse.Namespace) -> dict:
    roots = [path.resolve() for path in args.repo_root]
    repo_by_root = {root: _repo_name(root) for root in roots}
    client = GitHubClient(
        "https://api.github.com", args.token, args.output_dir / ".cache", args.offline, args.refresh
    )
    sessions, prs, rejections, logs = [], [], [], []
    for path in sorted(args.sessions_root.rglob("*.jsonl")):
        for root, repo in repo_by_root.items():
            session, rejection = parse_session(path, root, repo)
            if rejection:
                rejections.append(rejection)
            if not session:
                continue
            try:
                pr, diff = fetch_pr(session, root, client)
            except (RuntimeError, ValueError) as exc:
                rejections.append({"session_id": session["session_id"], "reason": "pr_evidence_failed", "detail": str(exc)[:300]})
                continue
            sessions.append(session)
            prs.append(pr)
            logs.extend(log_candidates(pr, diff))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(args.output_dir / OUTPUT_NAMES[0], sessions)
    _write_jsonl(args.output_dir / OUTPUT_NAMES[1], prs)
    _write_jsonl(args.output_dir / OUTPUT_NAMES[2], rejections)
    _write_csv(args.output_dir / OUTPUT_NAMES[3], logs)
    binding_summary = run_binding(
        args.output_dir / OUTPUT_NAMES[0], args.output_dir / OUTPUT_NAMES[1], args.output_dir / "binding"
    )
    binding_rows = [
        json.loads(line) for line in (args.output_dir / "binding" / "provenance_bindings.jsonl").read_text(encoding="utf-8").splitlines() if line
    ]
    summary = {
        "n_sessions": len(sessions), "n_prs": len(prs), "n_bindings": len(binding_rows),
        "n_rejections": len(rejections), "n_added_logs": len(logs),
        "n_static_risk_candidates": sum(bool(row["static_risk_candidate"]) for row in logs),
        "n_sensitive_content_candidates": sum(
            bool(set(str(row["risk_features"]).split(";")) & (AGENT_NATIVE_RISK_FEATURES | SHARED_SENSITIVE_RISK_FEATURES))
            for row in logs
        ),
        "provenance_grade_counts": dict(sorted(Counter(row["provenance_grade"] for row in binding_rows).items())),
        "analysis_eligibility_counts": dict(sorted(Counter(row["analysis_eligibility"] for row in binding_rows).items())),
        "binding_summary": binding_summary,
    }
    _atomic_write_text(args.output_dir / OUTPUT_NAMES[4], json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    _atomic_write_text(args.output_dir / OUTPUT_NAMES[5], "\n".join([
        "# Codex 会话—PR 证据链提取", "",
        f"- 有效会话 / PR：{len(sessions)} / {len(prs)}",
        f"- 绑定等级：{json.dumps(summary['provenance_grade_counts'], ensure_ascii=False)}",
        f"- 分析资格：{json.dumps(summary['analysis_eligibility_counts'], ensure_ascii=False)}",
        f"- 新增日志 / 静态风险候选：{len(logs)} / {summary['n_static_risk_candidates']}", "",
        f"- 涉及敏感内容特征的候选：{summary['n_sensitive_content_candidates']}", "",
        "原始提示词、stdout/stderr 和工具返回值未写入产物；只保留路径、摘要、哈希和最小元数据。", "",
    ]))
    errors = verify_outputs(args.output_dir)
    if errors:
        raise RuntimeError("; ".join(errors))
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sessions-root", type=Path)
    parser.add_argument("--repo-root", action="append", type=Path, default=[])
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.verify_only:
        errors = verify_outputs(args.output_dir)
        print(json.dumps({"ok": not errors, "errors": errors}, ensure_ascii=False, sort_keys=True))
        return 1 if errors else 0
    if not args.sessions_root or not args.repo_root:
        parser.error("--sessions-root and at least one --repo-root are required")
    print(json.dumps(run(args), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
