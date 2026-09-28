"""Small real Git fixtures, explicitly synthetic and never public PR claims."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from agentlog_unified.analysis import detect_history
from agentlog_unified.lineage import assess, trace_logs
from agentlog_unified.miner import mine_repository

HEADER = 'import logging\nlogger = logging.getLogger(__name__)\n'
SAFE = HEADER + 'payload = {"active": True}\nlogger.info("user=%s", payload)\n'
RISK = HEADER + 'payload = {"active": True, "password": "DUMMY_RESEARCH_SECRET_NOT_VALID"}\nlogger.info("user=%s", payload)\n'


def git(repo: Path, *args: str, actor: str = "agent", day: int = 1,
        check: bool = True) -> str:
    date = f"2025-01-{day:02d}T12:00:00+0000"
    process = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "-C", str(repo), *args],
        capture_output=True, text=True, check=check,
        env={**os.environ, "GIT_AUTHOR_NAME": f"Synthetic {actor}",
             "GIT_AUTHOR_EMAIL": f"{actor}@example.invalid",
             "GIT_COMMITTER_NAME": f"Synthetic {actor}",
             "GIT_COMMITTER_EMAIL": f"{actor}@example.invalid",
             "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date})
    return process.stdout.strip()


def init(repo: Path) -> str:
    repo.mkdir(exist_ok=True)
    git(repo, "init", "-q", "-b", "main")
    return commit(repo, {"README.md": "Synthetic calibration fixture.\n"}, "base")


def commit(repo: Path, files: dict[str, str], message: str,
           actor: str = "agent", day: int = 2) -> str:
    for path, source in files.items():
        destination = repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source)
    git(repo, "add", "--all")
    git(repo, "commit", "-qm", message, actor=actor, day=day)
    return git(repo, "rev-parse", "HEAD")


def pipeline(repo: Path, tip: str, initials: list[str], extras: list[str] | None = None,
             merge: str | None = None, merge_day: int = 3, days: int = 90) -> dict:
    pr = {"id": "fixture-pr", "repository": None, "pr_number": None, "pr_url": None,
          "cohort": "calibration_only", "is_synthetic": True, "pr_actor_type": "agent",
          "provided_label": "agent", "commit_shas": initials,
          "initial_commit_shas": initials, "head_sha": initials[-1],
          "merge_commit_sha": merge,
          "merged_at": f"2025-01-{merge_day:02d}T12:00:00+00:00" if merge else None,
          "synthetic_author_mapping": {"agent@example.invalid": "agent",
              "human@example.invalid": "human_led", "ci@example.invalid": "automation_non_agent"}}
    repository = {"id": "synthetic-repository", "repository_id": "synthetic-repository",
                  "local_repo_path": str(repo), "target_ref": "main", "frozen_target_tip": tip,
                  "shallow": False, "missing_shas": [], "pr_ids": [pr["id"]],
                  "is_synthetic": True, "local_snapshot_only": True}
    initial = list(dict.fromkeys(initials + (extras or []) + ([merge] if merge else [])))
    mined = mine_repository(str(repo), tip, initial)
    mined["repository_id"] = repository["id"]
    config = {"mining": {"max_snapshot_files": 100, "max_source_file_bytes": 2097152},
              "languages": ["python", "javascript", "typescript", "go", "csharp"]}
    detected = detect_history(repository, mined, config)
    traced = trace_logs([repository], [pr], [mined], detected["events"],
                        detected["snapshots"], "2025-05-01T12:00:00+00:00", days,
                        mined["gaps"] + detected["gaps"])
    return {**traced, "mined": mined, "detected": detected,
            "candidates": assess(traced["log_changes"], traced["followups"])}
