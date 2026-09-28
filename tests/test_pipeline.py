"""End-to-end on a synthetic local repository: clone -> walk -> resolve -> track -> verdict."""
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.config import Config
from src.models import AgentFile, ChangeKind, RepoTask, Seed
from src.pipeline import process_repository, retrack_repository
from src.report.export import export
from src.track.ledger import load_ledger

HEAD = ("import logging\nfrom pydantic import BaseModel, EmailStr\nlog = logging.getLogger(__name__)\n\n"
        "class User(BaseModel):\n    email: EmailStr\n\n")


def git(repo, *args, date=None):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@x")
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    return subprocess.run(["git", "-C", str(repo), *args], env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def commit(repo, files, msg, date):
    for p, content in files.items():
        f = repo / p
        if content is None:
            git(repo, "rm", "-q", p)
            continue
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
        git(repo, "add", p)
    git(repo, "commit", "-q", "-m", msg, date=date)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def world(tmp_path):
    up = tmp_path / "upstream"
    up.mkdir()
    git(up, "init", "-q", "-b", "main")
    d = "2026-01-{:02d}T12:00:00+00:00"
    shas = {}
    shas["root"] = commit(up, {"app/auth.py": HEAD + "def ping():\n    log.info('ping')\n"}, "root", d.format(1))
    # seed: agent adds two logs, one leaking email
    shas["seed"] = commit(up, {"app/auth.py": HEAD + "def ping():\n    log.info('ping')\n\n"
                               "def login(user: User):\n    log.info('login %s', user.email)\n    log.debug('login done')\n"},
                          "add login", d.format(2))
    # side branch adds unrelated file with a syntax error, merged later
    git(up, "checkout", "-q", "-b", "side")
    shas["side"] = commit(up, {"app/other.py": "def (:\n"}, "broken", d.format(3))
    git(up, "checkout", "-q", "main")
    # rename the file
    git(up, "mv", "app/auth.py", "app/authn.py")
    shas["rename"] = commit(up, {}, "rename", d.format(4))
    # redaction fix
    shas["fix"] = commit(up, {"app/authn.py": HEAD + "def ping():\n    log.info('ping')\n\n"
                              "def login(user: User):\n    log.info('login ok')\n    log.debug('login done')\n"},
                         "Redact email in auth logs", d.format(5))
    git(up, "merge", "-q", "--no-edit", "side", date=d.format(6))
    # later: syntax-broken version of authn.py, then repaired (gap on the lineage of 'login done')
    shas["broken"] = commit(up, {"app/authn.py": "def (:\n"}, "wip", d.format(7))
    shas["repair"] = commit(up, {"app/authn.py": HEAD + "def ping():\n    log.info('ping')\n\n"
                                 "def login(user: User):\n    log.info('login ok')\n    log.debug('login done')\n"},
                            "repair", d.format(8))
    cfg = Config(out=tmp_path / "out", repos_dir=tmp_path / "repos", workers=1, window_days=90)

    def seed(sha, path="app/auth.py", date=d.format(2)):
        return Seed("o/r", sha, datetime.fromisoformat(date),
                    (AgentFile(path, "agent_only", True, True, True, ("log.info('login %s', user.email)",)),),
                    ("Claude Code",), (), ("main",), f"swechat:o/r@{sha[:8]}", "linked")
    # "e"*40: absent object whose patch lines match the real seed -> relocates onto it (a duplicate)
    # "f"*40: absent object far outside any relocation window -> stays missing
    task = RepoTask("o/r", (seed(shas["seed"]), seed("e" * 40), seed("f" * 40, date="2025-01-01T00:00:00+00:00")),
                    clone_url=str(up), estimated_commits=10)
    return up, shas, cfg, task


def test_end_to_end(world, monkeypatch):
    up, shas, cfg, task = world
    # the hardening forbids the file transport; the fixture upstream is a local path
    monkeypatch.setenv("LOGTRACE_TEST_ALLOW_FILE_PROTOCOL", "1")

    r = process_repository(task, cfg)
    assert r.status == "partial"                      # parse failures are gaps
    assert r.seed_states == {"reachable": 1, "missing": 1, "relocated_to_other_seed": 1}

    ledger, gaps = load_ledger(Path(r.ledger_path))
    kinds = {g.kind for g in gaps}
    assert "parse_failed" in kinds
    # rename produced MOVED events, not delete+add
    rename_events = ledger.by_sha[shas["rename"]]
    assert rename_events and all(e.change == ChangeKind.MOVED for e in rename_events)

    cases = {c.introduced.after.template: c for c in r.cases}
    leak = cases["login %s"]
    assert leak.first_fix is not None and leak.first_fix.sha == shas["fix"]
    assert leak.first_fix.fix_effect == "eliminates_observed_flow"
    assert leak.privacy_assessment == "supported" and leak.sensitive_flow_introduced_sha == shas["seed"]
    # agentlog_unified assess: a coverage gap on the observed lineage wins over the repair
    assert leak.verdict == "NEEDS_CONTEXT" and leak.privacy_review_candidate
    # after the fix the statement is a different log ('login ok'): its chain continues until the broken commit
    assert leak.stop_reason == "blocked"

    done = cases["login done"]
    assert done.first_fix is None
    assert done.stop_reason == "blocked"              # broken version of the file on its lineage
    assert done.verdict == "NEEDS_CONTEXT"            # agentlog_unified: observation gap -> NEEDS_CONTEXT

    # rerun is deterministic thanks to the lock file
    r2 = retrack_repository(task, cfg)
    assert sorted(c.case_id for c in r2.cases) == sorted(c.case_id for c in r.cases)
    assert r2.frozen_head == r.frozen_head

    rep = export(cfg.out)
    assert rep["cases"]["privacy_review_candidates"] == 1
    assert rep["exported"]["privacy_review_candidates"] == 1
    assert rep["seeds"]["by_state"] == {"reachable": 1, "missing": 1, "relocated_to_other_seed": 1}


def test_parallel_duplicate_edits_are_one_step(tmp_path, monkeypatch):
    """A cherry-picked fix on two branches is one edit; differing parallel edits stop the chain."""
    monkeypatch.setenv("LOGTRACE_TEST_ALLOW_FILE_PROTOCOL", "1")
    up = tmp_path / "up"
    up.mkdir()
    git(up, "init", "-q", "-b", "main")
    d = "2026-02-{:02d}T12:00:00+00:00"
    body = HEAD + "def login(user: User):\n    log.info('login %s', {})\n"
    commit(up, {"a.py": HEAD}, "root", d.format(1))
    seed_sha = commit(up, {"a.py": body.format("user.email")}, "seed", d.format(2))
    git(up, "checkout", "-q", "-b", "b1")
    fixed = HEAD + "def login(user: User):\n    log.info('login ok')\n"
    commit(up, {"a.py": fixed}, "drop email on b1", d.format(3))
    git(up, "checkout", "-q", "-b", "b2", seed_sha)
    commit(up, {"a.py": fixed}, "drop email on b2", d.format(4))
    git(up, "checkout", "-q", "main")
    git(up, "merge", "-q", "--no-edit", "b1", date=d.format(5))
    git(up, "merge", "-q", "--no-edit", "b2", date=d.format(6))
    cfg = Config(out=tmp_path / "out", repos_dir=tmp_path / "repos", workers=1)
    seed = Seed("o/p", seed_sha, datetime.fromisoformat(d.format(2)),
                (AgentFile("a.py", "agent_only", True, True, True),), ("Claude Code",), (), (), "t", "linked")
    r = process_repository(RepoTask("o/p", (seed,), clone_url=str(up)), cfg)
    (c,) = r.cases
    assert c.stop_reason == "alive" and len(c.timeline) == 1
    assert c.first_fix is not None and c.verdict == "REVIEW_READY" and c.priority == "P1"
