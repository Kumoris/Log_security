"""End to end on a synthetic repository: seeds -> anchors -> tracking -> features -> dataset.

History of ``o/r`` (main):
  d1  root (no PR)          auth.py: start() logs 'start' and 'boot %s' (mode)
  d2  "Add login (#10)"     Copilot squash: login() logs user.email + two identical print('done');
                            also a vendored virtualenv file with a log (must be excluded)
  d3  "Reword (#11)"        PR 11 is not in AIDev: rewords the login log
  d4  "Log user id (#23)"   Codex squash: adds user.id to the same log (seed touching a tracked log)
  d5  "Log token (#40)"     Cursor squash: adds token to the *root* 'boot' log (modified existing log)
  d6  merge of PR #30       Devin branch moves the login log to util.py (cross-file move, via a merge)
  d7  PR #50 rebased        two Cursor commits cherry-picked without PR number (anchor via patch-id)
  d8  direct push           deletes the second print('done')
  also: PR #10 adds extra.py; a direct push breaks its syntax and the next one repairs it (the chain
        must resume across the gap); PR #60 is merged only into a branch that never reaches main
"""
import json
import os
import subprocess

import pytest

from src.config import Config
from src.models import read_jsonl, write_jsonl
from src.pipeline import features_one, repo_out, track_one
from src.report.dataset import build_dataset
from src.seeds.aidev import commit_attribution, line_hash

HEAD = "import logging\nlog = logging.getLogger(__name__)\n\n"
ROOT = HEAD + "def start(mode, token):\n    log.info('start')\n    log.info('boot %s', mode)\n"
LOGIN = "\n\ndef login(user):\n    log.info('login %s', user.email)\n    print('done')\n    print('done')\n"
D = "2026-01-{:02d}T12:00:00+00:00"
EXTRA = HEAD + "def extra(user_email):\n    log.info('extra %s', user_email)\n"


def git(repo, *args, date=None, author=("t", "t@x")):
    env = dict(os.environ, GIT_AUTHOR_NAME=author[0], GIT_AUTHOR_EMAIL=author[1],
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@x")
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    return subprocess.run(["git", "-C", str(repo), *args], env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def commit(repo, files, msg, date, author=("t", "t@x")):
    for p, content in files.items():
        f = repo / p
        if content is None:
            git(repo, "rm", "-q", p)
            continue
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
        git(repo, "add", p)
    git(repo, "commit", "-q", "-m", msg, date=date, author=author)
    return git(repo, "rev-parse", "HEAD")


def hashes(repo, sha, path):
    out = git(repo, "show", "--format=", "-U0", sha, "--", path)
    return sorted({line_hash(ln[1:]) for ln in out.splitlines()
                   if ln.startswith("+") and not ln.startswith("+++") and ln[1:].strip()})


def pr(number, agent, user, merged, commits):
    bots = Config().bots()
    return {"repository": "o/r", "pr_id": 1000 + number, "number": number, "agent": agent, "user": user,
            "state": "closed", "merged_at": merged, "title": f"PR {number}", "patch_missing_only": False,
            "commits": [{"sha": sha, "author": author, "message": "m", "is_merge_message": False,
                         "attribution": commit_attribution(author, agent, user, bots),
                         "files": [{"path": p, "patch": "ok", "status": "modified", "added_hashes": h, "log_hit": True}
                                   for p, h in files.items()]} for sha, author, files in commits]}


@pytest.fixture(params=["rebase", "fast_forward"])
def world(request, tmp_path, monkeypatch):
    monkeypatch.setenv("LOGTRACE_TEST_ALLOW_FILE_PROTOCOL", "1")
    up = tmp_path / "upstream"
    up.mkdir()
    git(up, "init", "-q", "-b", "main")
    s = {}
    s["root"] = commit(up, {"app/auth.py": ROOT}, "root", D.format(1))
    s["p10"] = commit(up, {"app/auth.py": ROOT + LOGIN, "app/extra.py": EXTRA,
                           "app/.venv/lib/site-packages/pkg/mod.py": "import logging\nlogging.info('v %s', password)\n"},
                      "Add login (#10)", D.format(2), ("alice", "alice@x"))
    s["p11"] = commit(up, {"app/auth.py": ROOT + LOGIN.replace("'login %s'", "'user login %s'")},
                      "Reword (#11)", D.format(3), ("bob", "bob@x"))
    s["broken"] = commit(up, {"app/extra.py": "def (:\n"}, "wip", "2026-01-03T15:00:00+00:00", ("eve", "eve@x"))
    s["repair"] = commit(up, {"app/extra.py": EXTRA + "\n\n# repaired\n"}, "repair", "2026-01-03T18:00:00+00:00",
                         ("eve", "eve@x"))
    login23 = LOGIN.replace("log.info('login %s', user.email)", "log.info('user login %s %s', user.email, user.id)")
    s["p23"] = commit(up, {"app/auth.py": ROOT + login23}, "Log user id (#23)", D.format(4), ("alice", "alice@x"))
    root40 = ROOT.replace("log.info('boot %s', mode)", "log.info('boot %s %s', mode, token)")
    s["p40"] = commit(up, {"app/auth.py": root40 + login23}, "Log token (#40)", D.format(5), ("carol", "carol@x"))
    # PR 30: Devin branch moves the login log to util.py, merged with a merge commit
    git(up, "checkout", "-q", "-b", "devin/move")
    moved = login23.replace("    log.info('user login %s %s', user.email, user.id)\n", "    audit(user)\n")
    util = HEAD + "def audit(user):\n    log.info('user login %s %s', user.email, user.id)\n"
    s["b30"] = commit(up, {"app/auth.py": root40 + moved, "app/util.py": util}, "move log", D.format(6),
                      ("Devin AI", "158243242+devin-ai-integration[bot]@users.noreply.github.com"))
    git(up, "checkout", "-q", "main")
    git(up, "merge", "-q", "--no-ff", "-m", "Merge pull request #30 from o/devin-move", "devin/move", date=D.format(6))
    s["m30"] = git(up, "rev-parse", "HEAD")
    # PR 50: two Cursor commits on a PR branch, rebased onto main without PR number
    git(up, "checkout", "-q", "-b", "cursor/jobs")
    jobs1 = HEAD + "def run(job_id):\n    log.info('job %s', job_id)\n"
    s["a50"] = commit(up, {"app/jobs.py": jobs1}, "Add jobs", D.format(7), ("cursoragent", "cursoragent@cursor.com"))
    jobs2 = jobs1 + "    try:\n        pass\n    except Exception as err:\n        log.warning('job failed %s', err)\n"
    s["b50"] = commit(up, {"app/jobs.py": jobs2}, "Handle failure", D.format(7), ("cursoragent", "cursoragent@cursor.com"))
    git(up, "update-ref", "refs/pull/50/head", s["b50"])
    git(up, "checkout", "-q", "main")
    # rebase: new SHAs (patch-id anchor); fast_forward: identical commits land as they are
    git(up, "cherry-pick", s["a50"], s["b50"],
        date="2026-01-07T13:00:00+00:00" if request.param == "rebase" else D.format(7))
    s["main50"] = git(up, "rev-parse", "HEAD")
    # d8: direct push deletes the second print('done')
    final = (root40 + moved).replace("    print('done')\n    print('done')\n", "    print('done')\n")
    s["d8"] = commit(up, {"app/auth.py": final}, "cleanup", D.format(8), ("dave", "dave@x"))
    # PR 60: merged only into a side branch that never reaches main
    git(up, "checkout", "-q", "-b", "release-old")
    s["p60"] = commit(up, {"app/stats.py": HEAD + "def stats(n):\n    log.info('stats %s', n)\n"},
                      "Add stats (#60)", D.format(8), ("frank", "frank@x"))
    git(up, "checkout", "-q", "main")

    seeds = tmp_path / "seeds"
    fake = lambda n: f"{n:040x}"
    prs = [
        pr(10, "Copilot", "Copilot", D.format(2), [(fake(10), "Copilot", {"app/auth.py": hashes(up, s["p10"], "app/auth.py"),
                                                                          "app/extra.py": hashes(up, s["p10"], "app/extra.py")})]),
        pr(60, "Copilot", "Copilot", D.format(8), [(fake(60), "Copilot", {"app/stats.py": hashes(up, s["p60"], "app/stats.py")})]),
        pr(23, "OpenAI_Codex", "alice", D.format(4), [(fake(23), "alice", {"app/auth.py": hashes(up, s["p23"], "app/auth.py")})]),
        pr(40, "Cursor", "Cursor", D.format(5), [(fake(40), "cursoragent", {"app/auth.py": hashes(up, s["p40"], "app/auth.py")})]),
        pr(30, "Devin", "devin-ai-integration[bot]", D.format(6),
           [(s["b30"], "devin-ai-integration[bot]", {"app/auth.py": hashes(up, s["b30"], "app/auth.py"),
                                                     "app/util.py": hashes(up, s["b30"], "app/util.py")})]),
        pr(50, "Cursor", "Cursor", D.format(7), [(s["a50"], "cursoragent", {"app/jobs.py": hashes(up, s["a50"], "app/jobs.py")}),
                                                 (s["b50"], "cursoragent", {"app/jobs.py": hashes(up, s["b50"], "app/jobs.py")})]),
    ]
    write_jsonl(seeds / "prs.jsonl", prs)
    write_jsonl(seeds / "pr_index.jsonl", [
        {"repository": "o/r", "pr_id": p["pr_id"], "number": p["number"], "agent": p["agent"], "user": p["user"],
         "state": "closed", "merged_at": p["merged_at"], "commit_shas": [c["sha"] for c in p["commits"]]} for p in prs])
    write_jsonl(seeds / "repos.jsonl", [{"repository": "o/r", "clone_url": str(up), "seed_prs": len(prs), "stars": 1}])
    cfg = Config(out=tmp_path / "out", repos_dir=tmp_path / "repos", workers=1)
    return cfg, seeds, s, request.param


def test_end_to_end(world):
    cfg, seeds, s, mode = world
    res = track_one("o/r", cfg, seeds)
    assert res["status"] in ("complete", "partial"), res
    out = repo_out(cfg, "o/r")
    anchors = {a["number"]: a for a in read_jsonl(out / "anchors.jsonl")}
    pr50 = "patch_id" if mode == "rebase" else "pr_head_in_history"
    assert {n: a["method"] for n, a in anchors.items()} == {10: "pr_number", 23: "pr_number", 40: "pr_number",
                                                             30: "pr_number", 50: pr50, 60: None}
    assert anchors[60]["reason"] == "merged_into_non_default_branch"
    assert "origin/release-old" in anchors[60]["other_branches"]
    assert anchors[50]["kind"] == mode and anchors[50]["target"] == s["main50"]
    assert anchors[30]["landing"] == s["m30"] and anchors[10]["confidence"] == "certain"

    lins = read_jsonl(out / "lineages.jsonl")
    assert not any("site-packages" in l["path"] for l in lins)          # vendored code never analysed
    assert len(lins) == 7, [(l["path"], l["versions"][-1]["code"]) for l in lins]

    # a syntax error in one commit does not end the chain: suspended, then found again by its code
    (extra,) = [l for l in lins if l["path"] == "app/extra.py"]
    assert extra["status"] == "alive_at_frozen_head"
    assert [(g["since"], g["until"], g["outcome"]) for g in extra["gaps"]] == [(s["broken"], s["repair"], "resumed")]

    # the login log: one chain, created by PR 10, touched by PR 23 and PR 30 -- never a second lineage
    (login,) = [l for l in lins if "user.email" in l["versions"][-1]["code"]]
    assert [x["number"] for x in login["seeds"]] == [10, 23, 30]
    assert login["path"] == "app/util.py"
    ch = login["changes"]
    assert [c["kind"] for c in ch] == ["modified", "modified", "moved"]
    assert ch[0]["author"]["author_kind"] == "not_agent" and ch[0]["message_changed"]          # PR 11
    assert ch[1]["author"] == {**ch[1]["author"], "author_kind": "agent", "agent": "OpenAI_Codex", "pr_number": 23}
    assert ch[1]["items_added"] == ["user.id"]
    assert ch[2]["author"]["agent"] == "Devin" and ch[2]["detail_commits"][0]["commit"] == s["b30"]
    assert login["versions"][0]["author"]["agent"] == "Copilot"

    # duplicates told apart by position; the second one deleted by a direct push (author unknown)
    prints = sorted((l for l in lins if l["versions"][0]["code"].strip() == "print('done')"),
                    key=lambda l: l["versions"][0]["statement"]["line"])
    assert [p["status"] for p in prints] == ["alive_at_frozen_head", "deleted"]
    assert prints[1]["changes"][-1]["author"]["author_kind"] == "unknown"

    # PR 40 modified an existing (root) log: backward history to the origin, agent's change recorded
    (boot,) = [l for l in lins if "boot" in l["versions"][-1]["code"]]
    assert boot["intro_kind"] == "modified"
    assert boot["versions"][0]["segment"] == "backward" and boot["origin"]["commit"] == s["root"]
    assert boot["origin"]["author"]["author_kind"] == "unknown"
    assert boot["changes"][0]["kind"] == "seed_modification" and boot["changes"][0]["items_added"] == ["token"]

    # PR 50: two lineages from the rebased commits
    assert sorted(l["versions"][0]["code"].strip() for l in lins if l["path"] == "app/jobs.py") == [
        "log.info('job %s', job_id)", "log.warning('job failed %s', err)"]

    features_one("o/r", cfg)
    summary = build_dataset(cfg.out)
    assert summary["chains"] == 7 and summary["chains_selected"] == 4, summary
    cats = summary["selected_by_category"]
    assert {"PII.email", "AUTH.access_token", "DIAG.exception_message"} <= set(cats)
    assert (cfg.out / "dataset" / "chains.csv").read_text().count("\n") == 5
    import pyarrow.parquet as pq
    ch_rows = {r["lineage_id"]: r for r in pq.read_table(cfg.out / "dataset" / "all_chains.parquet").to_pylist()}
    assert ch_rows[prints[1]["lineage_id"]]["end_change_bulk_size"] == 1
    assert {r["path_kind"] for r in ch_rows.values()} == {"source"}
    assert ch_rows[login["lineage_id"]]["pr_seed_count"] == 4          # PR 10: login log, 2 prints, extra
    assert ch_rows[boot["lineage_id"]]["first_change_days"] is None    # the seed modification is not a later change
    assert (cfg.out / "dataset" / "unclassified_items.csv").read_text()
    from src.report.samples import build_samples
    counts = build_samples(cfg.out)
    assert counts["anchors"] == 6 and counts["tracking"] > 0 and counts["authorship"] > 0
