"""ensure_repo: clone once (partial: no blobs until read), freeze the head in a lock file, reuse it."""
from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ..config import Config
from ..models import Gap, LocalRepo
from .gitcmd import run_git


def repo_dir(cfg: Config, repository: str) -> Path:
    return cfg.repos_dir / repository.replace("/", "__")


def lock_path(cfg: Config, repository: str) -> Path:
    return cfg.out / "repos" / repository.replace("/", "__") / "lock.json"


def _commit_time(path: Path, sha: str) -> datetime:
    out = run_git(path, "show", "-s", "--format=%ct", sha).stdout.decode().strip()
    return datetime.fromtimestamp(int(out), tz=timezone.utc)


def _exists(path: Path, sha: str) -> bool:
    return run_git(path, "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode == 0


def ensure_repo(repository: str, cfg: Config, clone_url: str | None = None) -> tuple[LocalRepo | None, list[Gap]]:
    path = repo_dir(cfg, repository)
    lock = lock_path(cfg, repository)
    url = clone_url or f"https://github.com/{repository}.git"

    if not (path / "HEAD").exists() and not (path / ".git").exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".partial")
        shutil.rmtree(tmp, ignore_errors=True)
        try:
            extra = ["--filter=blob:none"] if cfg.partial_clone else []
            run_git(None, "clone", "--no-checkout", "--no-recurse-submodules", "--quiet", *extra, url, str(tmp),
                    timeout=cfg.clone_timeout_s)
        except subprocess.TimeoutExpired:
            shutil.rmtree(tmp, ignore_errors=True)
            return None, [Gap("clone_failed", repository, detail="timeout")]
        except subprocess.CalledProcessError as e:
            shutil.rmtree(tmp, ignore_errors=True)
            msg = e.stderr.decode(errors="replace").strip().splitlines()
            return None, [Gap("clone_failed", repository, detail=(msg[-1] if msg else "unknown")[:300])]
        tmp.rename(path)

    try:
        branch = run_git(path, "symbolic-ref", "--short", "HEAD").stdout.decode().strip()
    except subprocess.CalledProcessError:
        branch = "HEAD"

    if lock.exists():
        data = json.loads(lock.read_text())
        head = data["frozen_head"]
        if not _exists(path, head):
            return None, [Gap("frozen_head_lost", repository, sha=head,
                              detail="lock.json points to a commit absent locally; delete the lock to refreeze")]
        return LocalRepo(repository, path, data.get("default_branch", branch), head,
                         datetime.fromisoformat(data["frozen_at"])), []

    res = run_git(path, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", check=False)
    if res.returncode != 0:
        return None, [Gap("empty_repository", repository)]
    head = res.stdout.decode().strip()
    at = _commit_time(path, head)
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(json.dumps({"repository": repository, "clone_url": url, "default_branch": branch,
                                "frozen_head": head, "frozen_at": at.isoformat(),
                                "locked_at": datetime.now(timezone.utc).isoformat()}, indent=2))
    return LocalRepo(repository, path, branch, head, at), []
