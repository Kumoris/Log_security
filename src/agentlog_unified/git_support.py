"""Read-only Git helpers for graphs, explicit merge comparison and blob access.

Normal commit traversal and extraction belong to :mod:`miner` and PyDriller.
No helper checks out revisions, executes target code, or writes repository refs.
"""
from __future__ import annotations

import configparser
import os
import subprocess
from pathlib import Path

from git import Repo
from pydriller.domain.commit import ModifiedFile


def disable_implicit_fetch() -> None:
    """Keep every GitPython/PyDriller child process local, even on promisor repos.

    This is process-wide and deliberately not restored: all network object
    acquisition belongs to the explicit collect phase, including online runs.
    """
    os.environ["GIT_NO_LAZY_FETCH"] = "1"
    os.environ["GIT_TERMINAL_PROMPT"] = "0"


def run_git(repo_path: str, args: list[str], check: bool = True,
            timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a bounded, read-only Git operation using an argument array."""
    if not args or args[0] not in {"rev-parse", "rev-list", "merge-base", "diff",
                                    "ls-tree", "cat-file", "show", "version"}:
        raise ValueError("git_support permits only read-only Git operations")
    if any(x in {"--ext-diff", "--textconv", "--output", "--exec"}
           or x.startswith(("--output=", "--exec=")) for x in args):
        raise ValueError("external execution and output options are forbidden")
    return subprocess.run(
        ["git", "--no-pager", "-c", "core.hooksPath=/dev/null",
         "-c", "core.fsmonitor=false", "-C", str(Path(repo_path).resolve()), *args],
        text=True, encoding="utf-8", errors="replace", capture_output=True,
        check=check, timeout=timeout,
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"},
    )


def repository_object_state(repo_path: str) -> dict:
    """Read only object-availability configuration; never return remote URLs."""
    git_dir = Path(run_git(repo_path, ["rev-parse", "--absolute-git-dir"]).stdout.strip())
    config = configparser.RawConfigParser(strict=False)
    config.read(git_dir / "config")
    promisor = any(config.get(section, "promisor", fallback="").lower() == "true"
                   for section in config.sections() if section.startswith('remote "'))
    filters = sorted({config.get(section, "partialclonefilter") for section in config.sections()
                      if section.startswith('remote "') and config.has_option(section, "partialclonefilter")})
    return {"shallow": (git_dir / "shallow").exists(), "promisor_configured": promisor,
            "partial_clone_filters": filters, "implicit_lazy_fetch_enabled": False}


def resolve_ref(repo_path: str, ref: str) -> str | None:
    if not ref or ref.startswith("-") or "\x00" in ref:
        return None
    result = run_git(repo_path, ["rev-parse", "--verify", "--end-of-options",
                                 f"{ref}^{{commit}}"], check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def is_ancestor(repo_path: str, older: str, newer: str) -> bool:
    a, b = resolve_ref(repo_path, older), resolve_ref(repo_path, newer)
    if not a or not b:
        return False
    return run_git(repo_path, ["merge-base", "--is-ancestor", a, b],
                   check=False).returncode == 0


def commit_graph(repo_path: str, refs: list[str]) -> list[dict]:
    resolved = [resolve_ref(repo_path, ref) for ref in refs]
    if any(sha is None for sha in resolved):
        raise ValueError("commit graph contains a missing ref")
    if not resolved:
        return []
    output = run_git(repo_path, ["rev-list", "--topo-order", "--reverse", "--parents",
                                 *dict.fromkeys(resolved)]).stdout
    return [{"sha": row[0], "parents": row[1:]}
            for line in output.splitlines() if (row := line.split())]


def diff_paths(repo_path: str, parent: str, target: str) -> set[tuple]:
    """Independent path-level validation of PyDriller's explicit merge diff."""
    tokens = run_git(repo_path, ["diff", "--no-ext-diff", "--no-textconv",
                                 "--name-status", "-z", "--find-renames", parent, target,
                                 "--"]).stdout.split("\x00")
    paths, index = set(), 0
    while index < len(tokens) and tokens[index]:
        status, first = tokens[index], tokens[index + 1]
        index += 2
        if status.startswith(("R", "C")):
            paths.add((first, tokens[index]))
            index += 1
        elif status.startswith("A"):
            paths.add((None, first))
        elif status.startswith("D"):
            paths.add((first, None))
        else:
            paths.add((first, first))
    return paths


def merge_diff_fallback(repo_path: str, parent: str, target: str) -> list[ModifiedFile]:
    """GitPython's explicit trees, wrapped in real PyDriller ModifiedFile objects."""
    disable_implicit_fetch()
    with Repo(repo_path) as repo:
        diffs = repo.commit(parent).diff(
            repo.commit(target), create_patch=True, M=True,
            no_ext_diff=True, no_textconv=True)
        for diff in diffs:
            # GitPython retains both paths for binary additions/deletions.
            # PyDriller reads the paths directly, so normalize the absent side.
            if diff.new_file:
                diff.a_rawpath = None
            if diff.deleted_file:
                diff.b_rawpath = None
        return [ModifiedFile(diff) for diff in diffs]


def read_blob(repo_path: str, sha: str, path: str, max_bytes: int) -> tuple[str | None, str]:
    """Auxiliary object read; never substitutes the checked-out worktree."""
    disable_implicit_fetch()
    with Repo(repo_path) as repo:
        try:
            blob = repo.commit(sha).tree / path
        except KeyError:
            return None, "path_absent"
        if blob.type != "blob":
            return None, "non_blob"
        if blob.size > max_bytes:
            return None, "source_budget_exceeded"
        raw = blob.data_stream.read()
        if b"\x00" in raw:
            return None, "binary"
        try:
            return raw.decode("utf-8"), "ok"
        except UnicodeDecodeError:
            return None, "decode_error"
