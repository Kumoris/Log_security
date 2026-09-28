#!/usr/bin/env python3
"""Match human PR controls and mine exact-string log lineage with stdlib + git."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import subprocess
import time
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlencode

if __package__:
    from .screen_github_agent_logs import (
        GitHubClient,
        _atomic_write_text,
        _raw_diff_files,
        _wilson,
        added_lines,
        classify_log,
        is_production_path,
        is_source_file,
        redact_excerpt,
    )
else:
    from screen_github_agent_logs import (
        GitHubClient,
        _atomic_write_text,
        _raw_diff_files,
        _wilson,
        added_lines,
        classify_log,
        is_production_path,
        is_source_file,
        redact_excerpt,
    )


PAIR_FIELDS = (
    "pair_id", "repo", "human_repo", "match_tier", "agent_pr_key", "agent_pr_url", "agent_name",
    "agent_created_at", "agent_merged_at", "human_pr_key", "human_pr_url",
    "human_actor_login", "human_actor_type", "human_created_at", "human_merged_at",
    "date_distance_days", "agent_added_lines", "human_added_lines",
    "agent_deleted_lines", "human_deleted_lines", "agent_production_source_files",
    "human_production_source_files", "agent_extensions", "human_extensions",
    "match_score", "matching_method", "provenance_boundary",
    "agent_base_sha", "agent_head_sha", "agent_merge_commit_sha", "agent_head_tree_sha",
    "agent_head_committed_at", "agent_pr_diff_sha256", "agent_canonical_patch_sha256",
    "agent_commit_list_sha256", "agent_metadata_sha256", "agent_provenance_grade",
    "agent_evidence_chain_status", "agent_analysis_eligibility",
    "human_provenance_tier", "human_verification_method", "human_evidence_ref",
    "human_evidence_sha256", "human_verified_at", "pair_analysis_eligibility",
)
LINEAGE_FIELDS = (
    "lineage_id", "provenance", "provenance_evidence", "repo", "pr_key",
    "pr_url", "merged_at", "file", "line", "path_scope", "risk_features",
    "log_concepts", "static_risk_candidate", "log_text_redacted",
    "lineage_method", "lineage_status", "lineage_confidence", "event_commit",
    "event_time", "current_head_sha", "current_head_time", "right_censored",
    "base_sha", "pr_head_sha", "merge_commit_sha", "head_tree_sha", "head_committed_at",
    "pr_diff_sha256", "canonical_patch_sha256", "commit_list_sha256", "metadata_sha256",
    "provenance_grade", "generation_stage", "evidence_chain_status", "binding_id",
    "binding_status", "line_authorship_proof", "runtime_leak_claim",
    "human_provenance_tier", "pair_analysis_eligibility", "analysis_eligibility",
)
OUTPUT_NAMES = (
    "matched_prs.csv",
    "human_pr_evidence.jsonl",
    "log_lineage.csv",
    "summary.json",
    "report.md",
)


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _changed_lines(section: str) -> tuple[int, int]:
    added = deleted = 0
    for line in section.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            deleted += 1
    return added, deleted


def diff_profile(diff: str) -> dict:
    profile = {
        "added_lines": 0,
        "deleted_lines": 0,
        "source_files": 0,
        "production_source_files": 0,
        "extensions": [],
        "logs": [],
    }
    extensions = set()
    for path, section in _raw_diff_files(diff):
        if not is_source_file(path):
            continue
        profile["source_files"] += 1
        production = is_production_path(path)
        if production:
            profile["production_source_files"] += 1
            added, deleted = _changed_lines(section)
            profile["added_lines"] += added
            profile["deleted_lines"] += deleted
            extension = PurePosixPath(path.lower()).suffix
            if extension:
                extensions.add(extension)
        for line_number, text in added_lines(section):
            executable, features, concepts = classify_log(path, text)
            if executable:
                profile["logs"].append(
                    {
                        "file": path,
                        "line": line_number,
                        "path_scope": "production" if production else "non_production",
                        "risk_features": list(features),
                        "log_concepts": list(concepts),
                        "static_risk_candidate": bool(features),
                        "log_text_redacted": redact_excerpt(text),
                        "_exact_text": text,
                    }
                )
    profile["extensions"] = sorted(extensions)
    return profile


def is_human_pr(item: dict, agent_keys: set[str], repo: str) -> bool:
    user = item.get("user") or {}
    pull = item.get("pull_request") or {}
    key = f"{repo}#{item.get('number')}"
    return bool(
        item.get("number")
        and user.get("type") == "User"
        and not item.get("performed_via_github_app")
        and pull.get("merged_at")
        and key not in agent_keys
    )


def _score(agent: dict, human: dict, profiles: dict[str, dict]) -> float:
    left = profiles[agent["pr_key"]]
    right = profiles[human["pr_key"]]
    left_ext, right_ext = set(left["extensions"]), set(right["extensions"])
    union = left_ext | right_ext
    language = 1 - len(left_ext & right_ext) / len(union) if union else 0
    left_size = left["added_lines"] + left["deleted_lines"]
    right_size = right["added_lines"] + right["deleted_lines"]
    size = abs(math.log1p(left_size) - math.log1p(right_size))
    files = abs(left["production_source_files"] - right["production_source_files"])
    days = abs((_iso(agent["created_at"]) - _iso(human["created_at"])).total_seconds()) / 86400
    return 2 * language + size + 0.25 * files + days / 365


def match_human_prs(agent_rows: list[dict], human_rows: list[dict], profiles: dict[str, dict]) -> list[dict]:
    humans_by_repo = defaultdict(list)
    for row in human_rows:
        humans_by_repo[row["repo"]].append(row)
    pairs = []
    used_agents, used_humans = set(), set()

    def consume(agents: list[dict], humans: list[dict], tier: str) -> None:
        choices = sorted(
            (_score(agent, human, profiles), agent["pr_key"], human["pr_key"], agent, human)
            for agent in agents if agent["pr_key"] not in used_agents
            for human in humans if human["pr_key"] not in used_humans
        )
        for score, agent_key, human_key, agent, human in choices:
            if agent_key in used_agents or human_key in used_humans:
                continue
            used_agents.add(agent_key)
            used_humans.add(human_key)
            left, right = profiles[agent_key], profiles[human_key]
            pairs.append(
                {
                    "pair_id": hashlib.sha256(f"{agent_key}|{human_key}".encode()).hexdigest()[:16],
                    "repo": agent["repo"],
                    "human_repo": human["repo"],
                    "match_tier": tier,
                    "agent_pr_key": agent_key,
                    "agent_pr_url": agent.get("pr_url", ""),
                    "agent_name": agent.get("agent", ""),
                    "agent_created_at": agent["created_at"],
                    "agent_merged_at": agent.get("merged_at", ""),
                    "human_pr_key": human_key,
                    "human_pr_url": human.get("pr_url", ""),
                    "human_actor_login": human.get("actor_login", ""),
                    "human_actor_type": human.get("actor_type", ""),
                    "human_created_at": human["created_at"],
                    "human_merged_at": human.get("merged_at", ""),
                    "date_distance_days": round(
                        abs((_iso(agent["created_at"]) - _iso(human["created_at"])).total_seconds()) / 86400,
                        3,
                    ),
                    "agent_added_lines": left["added_lines"],
                    "human_added_lines": right["added_lines"],
                    "agent_deleted_lines": left["deleted_lines"],
                    "human_deleted_lines": right["deleted_lines"],
                    "agent_production_source_files": left["production_source_files"],
                    "human_production_source_files": right["production_source_files"],
                    "agent_extensions": ";".join(left["extensions"]),
                    "human_extensions": ";".join(right["extensions"]),
                    "match_score": round(score, 6),
                    "matching_method": f"{tier}_greedy_date_size_language_v1",
                    "provenance_boundary": "PR_LEVEL_SOURCE_CANDIDATE_NOT_LINE_AUTHORSHIP",
                    "agent_base_sha": agent.get("base_sha", ""),
                    "agent_head_sha": agent.get("head_sha", ""),
                    "agent_merge_commit_sha": agent.get("merge_commit_sha", ""),
                    "agent_head_tree_sha": agent.get("head_tree_sha", ""),
                    "agent_head_committed_at": agent.get("head_committed_at", ""),
                    "agent_pr_diff_sha256": agent.get("pr_diff_sha256", ""),
                    "agent_canonical_patch_sha256": agent.get("canonical_patch_sha256", ""),
                    "agent_commit_list_sha256": agent.get("commit_list_sha256", ""),
                    "agent_metadata_sha256": agent.get("metadata_sha256", ""),
                    "agent_provenance_grade": agent.get("provenance_grade", "C"),
                    "agent_evidence_chain_status": agent.get("evidence_chain_status", "legacy_unhashed_snapshot"),
                    "agent_analysis_eligibility": agent.get("analysis_eligibility", "sensitivity_only"),
                    "human_provenance_tier": human.get("human_provenance_tier", "human_likely"),
                    "human_verification_method": human.get("verification_method", ""),
                    "human_evidence_ref": human.get("evidence_ref", ""),
                    "human_evidence_sha256": human.get("evidence_sha256", ""),
                    "human_verified_at": human.get("verified_at", ""),
                    "pair_analysis_eligibility": (
                        "provenance_primary"
                        if tier == "same_repository"
                        and agent.get("analysis_eligibility") == "provenance_primary"
                        and human.get("human_provenance_tier") == "human_verified"
                        else "sensitivity_only"
                    ),
                }
            )

    for repo in sorted({row["repo"] for row in agent_rows}):
        agents = sorted((row for row in agent_rows if row["repo"] == repo), key=lambda row: row["pr_key"])
        consume(agents, humans_by_repo[repo], "same_repository")
    consume(agent_rows, human_rows, "cross_repository")
    if len(used_agents) != len(agent_rows):
        missing = sorted(row["pr_key"] for row in agent_rows if row["pr_key"] not in used_agents)
        raise RuntimeError(f"not enough unique human PRs overall: {missing}")
    return sorted(pairs, key=lambda row: row["agent_pr_key"])


def verify_cohort(
    pairs: list[dict], agent_rows: list[dict], human_rows: list[dict], expected: int
) -> list[str]:
    errors = []
    agent_keys = {row["pr_key"] for row in agent_rows}
    human_by_key = {row["pr_key"]: row for row in human_rows}
    if len(pairs) != expected:
        errors.append(f"pair count {len(pairs)} != {expected}")
    paired_agents = [row["agent_pr_key"] for row in pairs]
    paired_humans = [row["human_pr_key"] for row in pairs]
    if len(paired_agents) != len(set(paired_agents)):
        errors.append("agent PRs are not unique")
    if len(paired_humans) != len(set(paired_humans)):
        errors.append("human PRs are not unique")
    if set(paired_agents) != agent_keys:
        errors.append("paired agent PRs do not equal input cohort")
    for pair in pairs:
        human = human_by_key.get(pair["human_pr_key"])
        if pair.get("human_repo", pair["repo"]) != (human or {}).get("repo"):
            errors.append("human repository mismatch: " + pair["pair_id"])
        same_repo = pair["repo"] == (human or {}).get("repo")
        if same_repo != (pair.get("match_tier", "same_repository") == "same_repository"):
            errors.append("incorrect match tier: " + pair["pair_id"])
        if (human or {}).get("actor_type") != "User":
            errors.append("non-human actor match: " + pair["human_pr_key"])
        if pair["human_pr_key"] in agent_keys:
            errors.append("agent PR reused as human control: " + pair["human_pr_key"])
    return errors


def load_agent_bindings(path: Path | None) -> dict[str, dict]:
    if path is None or not path.exists():
        return {}
    return {
        row["pr_key"]: row
        for row in (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line)
    }


def load_human_verification(path: Path | None) -> dict[str, dict]:
    if path is None or not path.exists():
        return {}
    output = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        required = ("pr_key", "verification_method", "evidence_ref", "evidence_sha256", "verified_at")
        if not all(row.get(name) for name in required) or row.get("agent_assistance_excluded") is not True:
            raise ValueError("invalid human verification record: " + str(row.get("pr_key") or "<missing>"))
        if not re.fullmatch(r"[0-9a-f]{64}", str(row["evidence_sha256"])):
            raise ValueError("invalid human evidence hash: " + str(row["pr_key"]))
        output[str(row["pr_key"])] = row
    return output


def apply_human_verification(rows: list[dict], verified: dict[str, dict]) -> list[dict]:
    output = []
    for row in rows:
        evidence = verified.get(row["pr_key"], {})
        output.append({
            **row,
            "human_provenance_tier": "human_verified" if evidence else "human_likely",
            "verification_method": evidence.get("verification_method", ""),
            "evidence_ref": evidence.get("evidence_ref", ""),
            "evidence_sha256": evidence.get("evidence_sha256", ""),
            "verified_at": evidence.get("verified_at", ""),
            "agent_assistance_excluded": bool(evidence),
        })
    return output


def classify_lineage(current_present: bool, removal_diff: str, path: str) -> dict:
    if current_present:
        return {"status": "PRESENT_AT_CURRENT_HEAD", "confidence": "medium", "right_censored": True}
    if removal_diff:
        has_replacement_log = any(
            classify_log(path, line[1:])[0]
            for line in removal_diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        return {
            "status": "MODIFIED_AFTER_MERGE" if has_replacement_log else "DELETED_AFTER_MERGE",
            "confidence": "medium",
            "right_censored": False,
        }
    return {"status": "UNRESOLVED", "confidence": "low", "right_censored": False}


def _search_humans(
    agent_rows: list[dict], client: GitHubClient, start: date, end: date, search_delay: float
) -> list[dict]:
    agent_keys = {row["pr_key"] for row in agent_rows}
    rows = []
    repos = sorted({row["repo"] for row in agent_rows})
    last_live = 0.0
    for index, repo in enumerate(repos, 1):
        query = f"repo:{repo} is:pr is:merged created:{start.isoformat()}..{end.isoformat()}"
        url = client.base_url + "/search/issues?" + urlencode(
            {"q": query, "sort": "created", "order": "desc", "per_page": 100}
        )
        cached = client._cache_path(url).exists() and not client.refresh
        if not cached and last_live:
            time.sleep(max(0.0, search_delay - (time.monotonic() - last_live)))
        for attempt in range(3):
            try:
                data, _ = client.get_json(url)
                break
            except RuntimeError as exc:
                if "HTTP 422" in str(exc):
                    data = {"items": []}
                    _atomic_write_text(
                        client._cache_path(url),
                        json.dumps(
                            {"url": url, "headers": {"synthetic-status": "422"}, "data": data},
                            ensure_ascii=False,
                            sort_keys=True,
                        ) + "\n",
                    )
                    print(f"[search {index}/{len(repos)}] {repo}: unavailable to public search", flush=True)
                    break
                if attempt == 2:
                    raise
                if "HTTP 403" in str(exc):
                    print(f"[search {index}/{len(repos)}] rate limited; waiting 65s", flush=True)
                    time.sleep(65)
                elif "request failed" in str(exc) or any(f"HTTP {code}" in str(exc) for code in range(500, 600)):
                    wait = min(search_delay, 5.0)
                    print(f"[search {index}/{len(repos)}] transient error; retrying in {wait:.1f}s", flush=True)
                    time.sleep(wait)
                else:
                    raise
        if not cached:
            last_live = time.monotonic()
        items = data.get("items", []) if isinstance(data, dict) else []
        accepted = []
        for item in items:
            if not is_human_pr(item, agent_keys, repo):
                continue
            pull = item.get("pull_request") or {}
            accepted.append(
                {
                    "dataset": "GitHub",
                    "provenance": "HUMAN_PR_SOURCE_CANDIDATE",
                    "provenance_granularity": "pull_request",
                    "repo": repo,
                    "pr_number": item["number"],
                    "pr_key": f"{repo}#{item['number']}",
                    "pr_url": item.get("html_url", ""),
                    "diff_url": pull.get("diff_url") or item.get("html_url", "") + ".diff",
                    "created_at": item.get("created_at", ""),
                    "merged_at": pull.get("merged_at", ""),
                    "actor_login": (item.get("user") or {}).get("login", ""),
                    "actor_type": (item.get("user") or {}).get("type", ""),
                    "title": item.get("title", ""),
                    "search_window": f"{start.isoformat()}..{end.isoformat()}",
                }
            )
        rows.extend(accepted)
        print(f"[search {index}/{len(repos)}] {repo}: {len(accepted)} human candidates", flush=True)
    return rows


def _fetch_profiles(
    agent_rows: list[dict], human_rows: list[dict], agent_client: GitHubClient,
    human_client: GitHubClient, diff_delay: float,
) -> tuple[dict[str, dict], list[dict]]:
    profiles = {}
    for index, row in enumerate(agent_rows, 1):
        diff, _ = agent_client.get_text(row["pr_url"] + ".diff")
        profiles[row["pr_key"]] = diff_profile(diff)
        if index % 20 == 0:
            print(f"[agent diff {index}/{len(agent_rows)}]", flush=True)

    agents_by_repo = Counter(row["repo"] for row in agent_rows)
    selected = []
    selected_keys = set()

    def fetch(row: dict) -> bool:
        try:
            diff, _ = human_client.get_text(row["diff_url"])
        except RuntimeError as exc:
            row["diff_error"] = str(exc)[:300]
            return False
        profiles[row["pr_key"]] = diff_profile(diff)
        row["diff_error"] = ""
        selected.append(row)
        selected_keys.add(row["pr_key"])
        if diff_delay:
            time.sleep(diff_delay)
        return True

    for repo in sorted(agents_by_repo):
        anchor = min(_iso(row["created_at"]) for row in agent_rows if row["repo"] == repo)
        candidates = sorted(
            (row for row in human_rows if row["repo"] == repo),
            key=lambda row: (abs((_iso(row["created_at"]) - anchor).total_seconds()), row["pr_key"]),
        )
        target = max(agents_by_repo[repo] * 2, agents_by_repo[repo] + 3, 5)
        for row in candidates:
            if sum(item["repo"] == repo for item in selected) >= target:
                break
            fetch(row)
        count = sum(item["repo"] == repo for item in selected)
        print(f"[human diff] {repo}: {count} profiled", flush=True)
    if len(selected) < len(agent_rows):
        anchors = [_iso(row["created_at"]) for row in agent_rows]
        remaining = sorted(
            (row for row in human_rows if row["pr_key"] not in selected_keys),
            key=lambda row: (min(abs((_iso(row["created_at"]) - anchor).total_seconds()) for anchor in anchors), row["pr_key"]),
        )
        for row in remaining:
            fetch(row)
            if len(selected) >= len(agent_rows):
                break
    if len(selected) < len(agent_rows):
        raise RuntimeError(f"only {len(selected)} usable human PRs for {len(agent_rows)} agent PRs")
    return profiles, selected


def _git(args: list[str], *, cwd: Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def _ensure_bare_repo(repo: str, root: Path, since: str) -> tuple[Path | None, str]:
    target = root / repo.replace("/", "__")
    if target.exists():
        check = _git(["git", "rev-parse", "--is-bare-repository"], cwd=target, timeout=30)
        return (target, "") if check.returncode == 0 and check.stdout.strip() == "true" else (None, "invalid cache")
    root.mkdir(parents=True, exist_ok=True)
    result = _git(
        [
            "git", "clone", "--bare", "--filter=blob:none", "--no-tags",
            f"--shallow-since={since}", f"https://github.com/{repo}.git", str(target),
        ],
        timeout=600,
    )
    return (target, "") if result.returncode == 0 else (None, result.stderr.strip()[-500:])


def _mine_one(repo_dir: Path, row: dict) -> dict:
    text = row["_exact_text"]
    path = row["file"]
    grep = _git(["git", "grep", "-F", "-n", "-e", text, "HEAD", "--", path], cwd=repo_dir)
    current_present = grep.returncode == 0
    removal_diff = event_commit = event_time = ""
    if not current_present:
        history = _git(
            [
                "git", "log", "--follow", "--reverse", "--format=%H%x09%cI",
                f"--since={row['merged_at']}", f"-S{text}", "--", path,
            ],
            cwd=repo_dir,
        )
        for item in history.stdout.splitlines():
            commit, _, committed_at = item.partition("\t")
            shown = _git(["git", "show", "--format=", "--unified=0", commit, "--", path], cwd=repo_dir)
            if any(
                line.startswith("-") and not line.startswith("---") and line[1:].strip() == text.strip()
                for line in shown.stdout.splitlines()
            ):
                removal_diff, event_commit, event_time = shown.stdout, commit, committed_at
                break
    result = classify_lineage(current_present, removal_diff, path)
    head = _git(["git", "show", "-s", "--format=%H%x09%cI", "HEAD"], cwd=repo_dir, timeout=30)
    head_sha, _, head_time = head.stdout.strip().partition("\t")
    return {
        **result,
        "event_commit": event_commit,
        "event_time": event_time,
        "current_head_sha": head_sha,
        "current_head_time": head_time,
    }


def _lineage_rows(
    pairs: list[dict], agent_rows: list[dict], human_rows: list[dict], profiles: dict[str, dict], repo_root: Path
) -> list[dict]:
    paired_humans = {row["human_pr_key"] for row in pairs}
    selected = agent_rows + [row for row in human_rows if row["pr_key"] in paired_humans]
    pair_by_pr = {
        key: pair
        for pair in pairs
        for key in (pair["agent_pr_key"], pair["human_pr_key"])
    }
    logs = []
    for pr in selected:
        provenance = pr.get("provenance", "AGENT_SOURCE_CANDIDATE")
        for log in profiles[pr["pr_key"]]["logs"]:
            logs.append({**pr, **log, "provenance": provenance, "_pair": pair_by_pr[pr["pr_key"]]})
    by_repo = defaultdict(list)
    for row in logs:
        by_repo[row["repo"]].append(row)
    output = []
    for index, repo in enumerate(sorted(by_repo), 1):
        since = (min(_iso(row["merged_at"]) for row in by_repo[repo]) - timedelta(days=1)).date().isoformat()
        print(f"[git {index}/{len(by_repo)}] {repo}: {len(by_repo[repo])} logs", flush=True)
        repo_dir, error = _ensure_bare_repo(repo, repo_root, since)
        for row in by_repo[repo]:
            if repo_dir is None:
                mined = {
                    "status": "REPOSITORY_UNAVAILABLE", "confidence": "low", "right_censored": False,
                    "event_commit": "", "event_time": "", "current_head_sha": "", "current_head_time": "",
                }
            else:
                mined = _mine_one(repo_dir, row)
            identity = f"{row['pr_key']}|{row['file']}|{row['line']}|{row['_exact_text']}"
            output.append(
                {
                    "lineage_id": hashlib.sha256(identity.encode()).hexdigest()[:20],
                    "provenance": row["provenance"],
                    "provenance_evidence": (
                        row.get("source_app_slug", "") or f"github_user:{row.get('actor_login', '')}"
                    ),
                    "repo": repo,
                    "pr_key": row["pr_key"],
                    "pr_url": row["pr_url"],
                    "merged_at": row["merged_at"],
                    "file": row["file"],
                    "line": row["line"],
                    "path_scope": row["path_scope"],
                    "risk_features": ";".join(row["risk_features"]),
                    "log_concepts": ";".join(row["log_concepts"]),
                    "static_risk_candidate": row["static_risk_candidate"],
                    "log_text_redacted": row["log_text_redacted"],
                    "lineage_method": "exact_string_git_pickaxe_v1",
                    "lineage_status": mined["status"],
                    "lineage_confidence": mined["confidence"],
                    "event_commit": mined["event_commit"],
                    "event_time": mined["event_time"],
                    "current_head_sha": mined["current_head_sha"],
                    "current_head_time": mined["current_head_time"],
                    "right_censored": mined["right_censored"],
                    "base_sha": row.get("base_sha", ""),
                    "pr_head_sha": row.get("head_sha", ""),
                    "merge_commit_sha": row.get("merge_commit_sha", ""),
                    "head_tree_sha": row.get("head_tree_sha", ""),
                    "head_committed_at": row.get("head_committed_at", ""),
                    "pr_diff_sha256": row.get("pr_diff_sha256", ""),
                    "canonical_patch_sha256": row.get("canonical_patch_sha256", ""),
                    "commit_list_sha256": row.get("commit_list_sha256", ""),
                    "metadata_sha256": row.get("metadata_sha256", ""),
                    "provenance_grade": row.get("provenance_grade", "") or "C",
                    "generation_stage": row.get("generation_stage", "") or "merged_final_unresolved_actor",
                    "evidence_chain_status": row.get("evidence_chain_status", "") or "legacy_unhashed_snapshot",
                    "binding_id": row.get("binding_id", ""),
                    "binding_status": row.get("binding_status", "not_evaluated"),
                    "line_authorship_proof": bool(row.get("line_authorship_proof", False)),
                    "runtime_leak_claim": False,
                    "human_provenance_tier": row.get("human_provenance_tier", ""),
                    "pair_analysis_eligibility": row["_pair"]["pair_analysis_eligibility"],
                    "analysis_eligibility": row["_pair"]["pair_analysis_eligibility"],
                }
            )
        if error:
            print(f"  repository unavailable: {error}", flush=True)
    return sorted(output, key=lambda row: (row["provenance"], row["pr_key"], row["file"], int(row["line"])))


def _summary(pairs: list[dict], human_rows: list[dict], lineage: list[dict], start: date, end: date) -> dict:
    paired_humans = {row["human_pr_key"] for row in pairs}
    by_provenance = {}
    for provenance in ("AGENT_SOURCE_CANDIDATE", "HUMAN_PR_SOURCE_CANDIDATE"):
        rows = [row for row in lineage if row["provenance"] == provenance]
        candidates = sum(str(row["static_risk_candidate"]) == "True" for row in rows)
        present = sum(row["lineage_status"] == "PRESENT_AT_CURRENT_HEAD" for row in rows)
        low, high = _wilson(candidates, len(rows))
        survival_low, survival_high = _wilson(present, len(rows))
        by_provenance[provenance] = {
            "n_prs": len(pairs),
            "n_logs": len(rows),
            "n_production_logs": sum(row["path_scope"] == "production" for row in rows),
            "n_static_risk_candidates": candidates,
            "candidate_rate": candidates / len(rows) if rows else 0.0,
            "candidate_wilson95_low": low,
            "candidate_wilson95_high": high,
            "n_present_current_head": present,
            "exact_survival_rate": present / len(rows) if rows else 0.0,
            "survival_wilson95_low": survival_low,
            "survival_wilson95_high": survival_high,
            "lineage_status_counts": dict(sorted(Counter(row["lineage_status"] for row in rows).items())),
        }
    return {
        "study": "GitHub provenance-eligible agent PR + matched human PR lineage",
        "search_window": f"{start.isoformat()}..{end.isoformat()}",
        "n_pairs": len(pairs),
        "n_agent_prs": len({row["agent_pr_key"] for row in pairs}),
        "n_human_prs": len(paired_humans),
        "n_repositories": len({row["repo"] for row in pairs}),
        "n_human_repositories": len({row["human_repo"] for row in pairs}),
        "n_lineage_rows": len(lineage),
        "match_tier_counts": dict(sorted(Counter(row["match_tier"] for row in pairs).items())),
        "matching_method": "same_repository_first_then_cross_repository_date_size_language_v1",
        "lineage_method": "exact_string_git_pickaxe_v1",
        "provenance_granularity": "pull_request",
        "runtime_leak_claim": False,
        "by_provenance": by_provenance,
    }


def _report(summary: dict) -> str:
    agent = summary["by_provenance"]["AGENT_SOURCE_CANDIDATE"]
    human = summary["by_provenance"]["HUMAN_PR_SOURCE_CANDIDATE"]
    lines = [
        "# GitHub Agent / 人类 PR 日志谱系 PoC",
        "",
        "## 样本",
        "",
        f"- 配对：{summary['n_pairs']} 组（Agent PR {summary['n_agent_prs']}，唯一人类 PR {summary['n_human_prs']}）",
        f"- Agent 仓库：{summary['n_repositories']}；人类对照仓库：{summary['n_human_repositories']}。",
        (
            "- 匹配：优先同仓库，缺少人类 PR 时跨仓库；两级都按日期距离、生产代码变更规模、"
            "生产源文件数和语言扩展名确定性匹配。"
        ),
        f"- 匹配层级：{json.dumps(summary['match_tier_counts'], ensure_ascii=False, sort_keys=True)}。",
        "",
        "## 描述性结果",
        "",
        "| PR 级来源候选 | 新增日志 | 生产日志 | 静态风险候选 | 候选率（Wilson 95% CI） | 当前 HEAD 精确保留 |",
        "| --- | ---: | ---: | ---: | --- | ---: |",
        (
            f"| Agent | {agent['n_logs']} | {agent['n_production_logs']} | {agent['n_static_risk_candidates']} | "
            f"{agent['candidate_rate']:.3f} [{agent['candidate_wilson95_low']:.3f}, {agent['candidate_wilson95_high']:.3f}] | "
            f"{agent['n_present_current_head']} |"
        ),
        (
            f"| 人类 | {human['n_logs']} | {human['n_production_logs']} | {human['n_static_risk_candidates']} | "
            f"{human['candidate_rate']:.3f} [{human['candidate_wilson95_low']:.3f}, {human['candidate_wilson95_high']:.3f}] | "
            f"{human['n_present_current_head']} |"
        ),
        "",
        "## 谱系状态",
        "",
        "| 状态 | Agent | 人类 |",
        "| --- | ---: | ---: |",
    ]
    statuses = sorted(set(agent["lineage_status_counts"]) | set(human["lineage_status_counts"]))
    for status in statuses:
        lines.append(
            f"| {status} | {agent['lineage_status_counts'].get(status, 0)} | "
            f"{human['lineage_status_counts'].get(status, 0)} |"
        )
    lines.extend(
        [
            "",
            "## 证据边界",
            "",
            "- `human_likely` 仅表示已合并 GitHub User PR 且没有已知 App 来源链；只有附带排除 Agent 协助证据的 `human_verified` 才可进入主分析。",
            "- 日志命中是静态候选；`runtime_leak_claim=false`，不代表日志已执行、包含真实敏感值或被外发。",
            "- `PRESENT_AT_CURRENT_HEAD` 只表示同路径仍能找到精确字符串；重命名、格式化、squash/rebase 会产生 `UNRESOLVED`。",
            "- 跨仓库回退降低了环境可比性；PoC 未控制任务类型，也不支持“Agent 导致更多泄露”的因果结论。",
            "",
        ]
    )
    return "\n".join(lines)


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> None:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    _atomic_write_text(path, buffer.getvalue())


def write_outputs(output_dir: Path, pairs: list[dict], humans: list[dict], lineage: list[dict], summary: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(output_dir / OUTPUT_NAMES[0], PAIR_FIELDS, pairs)
    _atomic_write_text(
        output_dir / OUTPUT_NAMES[1],
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in humans),
    )
    _write_csv(output_dir / OUTPUT_NAMES[2], LINEAGE_FIELDS, lineage)
    _atomic_write_text(output_dir / OUTPUT_NAMES[3], json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    _atomic_write_text(output_dir / OUTPUT_NAMES[4], _report(summary))


def verify_outputs(output_dir: Path, expected: int | None = None) -> list[str]:
    errors = []
    for name in OUTPUT_NAMES:
        if not (output_dir / name).exists():
            errors.append("missing output: " + name)
    if errors:
        return errors
    with (output_dir / OUTPUT_NAMES[0]).open(encoding="utf-8", newline="") as handle:
        pairs = list(csv.DictReader(handle))
    humans = [json.loads(line) for line in (output_dir / OUTPUT_NAMES[1]).read_text(encoding="utf-8").splitlines() if line]
    with (output_dir / OUTPUT_NAMES[2]).open(encoding="utf-8", newline="") as handle:
        lineage = list(csv.DictReader(handle))
    summary = json.loads((output_dir / OUTPUT_NAMES[3]).read_text(encoding="utf-8"))
    agent_keys = [row["agent_pr_key"] for row in pairs]
    human_keys = [row["human_pr_key"] for row in pairs]
    if expected is not None and len(pairs) != expected:
        errors.append(f"pair count {len(pairs)} != {expected}")
    if len(agent_keys) != len(set(agent_keys)):
        errors.append("duplicate agent PR match")
    if len(human_keys) != len(set(human_keys)):
        errors.append("duplicate human PR match")
    human_by_key = {row["pr_key"]: row for row in humans}
    for pair in pairs:
        human = human_by_key.get(pair["human_pr_key"])
        if not human or human.get("actor_type") != "User" or human.get("provenance") != "HUMAN_PR_SOURCE_CANDIDATE":
            errors.append("invalid human evidence: " + pair["human_pr_key"])
        elif human["repo"] != pair["human_repo"]:
            errors.append("human repository mismatch: " + pair["pair_id"])
        same_repo = pair["repo"] == pair["human_repo"]
        if same_repo != (pair["match_tier"] == "same_repository"):
            errors.append("incorrect match tier: " + pair["pair_id"])
    allowed = set(agent_keys) | set(human_keys)
    for row in lineage:
        if row["pr_key"] not in allowed:
            errors.append("lineage outside matched cohort: " + row["lineage_id"])
        if row["runtime_leak_claim"] != "False":
            errors.append("runtime claim must remain false: " + row["lineage_id"])
        if row.get("line_authorship_proof", "False") == "True" and row.get("provenance_grade") not in {"A", "B"}:
            errors.append("line authorship proof lacks A/B grade: " + row["lineage_id"])
        if row.get("provenance_grade", "C") not in {"A", "B", "C", "D"}:
            errors.append("invalid provenance grade: " + row["lineage_id"])
        if row["static_risk_candidate"] != str(bool(row["risk_features"])):
            errors.append("risk flag mismatch: " + row["lineage_id"])
    recomputed = {
        "n_pairs": len(pairs),
        "n_agent_prs": len(set(agent_keys)),
        "n_human_prs": len(set(human_keys)),
        "n_repositories": len({row["repo"] for row in pairs}),
        "n_human_repositories": len({row["human_repo"] for row in pairs}),
        "n_lineage_rows": len(lineage),
    }
    for key, value in recomputed.items():
        if summary.get(key) != value:
            errors.append(f"summary mismatch for {key}: {summary.get(key)!r} != {value!r}")
    return errors


def run(args: argparse.Namespace) -> dict:
    agent_rows = [
        json.loads(line)
        for line in args.agent_evidence.read_text(encoding="utf-8").splitlines()
        if line
    ]
    bindings = load_agent_bindings(args.agent_bindings)
    for row in agent_rows:
        binding = bindings.get(row["pr_key"], {})
        row.update({
            "binding_id": binding.get("binding_id", ""),
            "binding_status": binding.get("binding_status", "not_evaluated"),
            "provenance_grade": binding.get("provenance_grade", row.get("provenance_grade", "C")),
            "line_authorship_proof": binding.get("line_authorship_proof", False),
            "analysis_eligibility": binding.get("analysis_eligibility", "sensitivity_only"),
            "pr_state": str(
                binding.get("pr_state") or row.get("state") or ("MERGED" if row.get("merged_at") else "")
            ).upper(),
        })
    agent_rows = [
        row for row in agent_rows
        if row["pr_state"] == "MERGED" and row["analysis_eligibility"] != "provenance_validation_only"
    ]
    expected = len(agent_rows) if args.expected is None else args.expected
    if len(agent_rows) != expected:
        raise RuntimeError(f"eligible agent evidence has {len(agent_rows)} rows, expected {expected}")
    if not agent_rows:
        today = date.today()
        summary = _summary([], [], [], today, today)
        write_outputs(args.output_dir, [], [], [], summary)
        errors = verify_outputs(args.output_dir, expected)
        if errors:
            raise RuntimeError("; ".join(errors))
        return summary
    start = min(_iso(row["created_at"]).date() for row in agent_rows) - timedelta(days=args.lookback_days)
    end = date.fromisoformat(args.search_end) if args.search_end else date.today()
    search_client = GitHubClient(
        "https://api.github.com", args.token, args.cache_dir / "search", args.offline, args.refresh
    )
    agent_client = GitHubClient(
        "https://api.github.com", args.token, args.agent_cache, args.offline, False
    )
    human_client = GitHubClient(
        "https://api.github.com", args.token, args.cache_dir / "diffs", args.offline, args.refresh
    )
    humans = apply_human_verification(
        _search_humans(agent_rows, search_client, start, end, args.search_delay),
        load_human_verification(args.human_verification_manifest),
    )
    profiles, profiled_humans = _fetch_profiles(
        agent_rows, humans, agent_client, human_client, args.diff_delay
    )
    pairs = match_human_prs(agent_rows, profiled_humans, profiles)
    cohort_errors = verify_cohort(pairs, agent_rows, profiled_humans, expected)
    if cohort_errors:
        raise RuntimeError("; ".join(cohort_errors))
    computed_agent_logs = sum(len(profiles[row["pr_key"]]["logs"]) for row in agent_rows)
    expected_agent_logs = sum(int(row.get("n_added_logs", 0)) for row in agent_rows)
    if computed_agent_logs != expected_agent_logs:
        raise RuntimeError(f"agent log count drift: {computed_agent_logs} != {expected_agent_logs}")
    lineage = _lineage_rows(pairs, agent_rows, profiled_humans, profiles, args.repo_cache)
    summary = _summary(pairs, profiled_humans, lineage, start, end)
    paired_human_keys = {row["human_pr_key"] for row in pairs}
    matched_humans = [row for row in profiled_humans if row["pr_key"] in paired_human_keys]
    write_outputs(args.output_dir, pairs, matched_humans, lineage, summary)
    errors = verify_outputs(args.output_dir, expected)
    if errors:
        raise RuntimeError("; ".join(errors))
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--agent-evidence", type=Path,
        default=Path("outputs/github_agent_screening/github_agent_pr_evidence.jsonl"),
    )
    parser.add_argument("--agent-cache", type=Path, default=Path("data/res/github_agent_logs"))
    parser.add_argument("--cache-dir", type=Path, default=Path("data/res/github_log_lineage"))
    parser.add_argument("--repo-cache", type=Path, default=Path("data/res/github_log_lineage/repos"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/github_log_lineage_poc"))
    parser.add_argument("--agent-bindings", type=Path)
    parser.add_argument("--human-verification-manifest", type=Path)
    parser.add_argument("--expected", type=int)
    parser.add_argument("--lookback-days", type=int, default=730)
    parser.add_argument("--search-end", default="")
    parser.add_argument("--search-delay", type=float, default=6.2)
    parser.add_argument("--diff-delay", type=float, default=0.15)
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.verify_only:
        errors = verify_outputs(args.output_dir, args.expected)
        print(json.dumps({"ok": not errors, "errors": errors}, ensure_ascii=False))
        return 1 if errors else 0
    summary = run(args)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
