"""Hardened, read-only git invocation.

The cloned repository's own config and hooks are not transferred by clone; the real
risks are submodules, LFS/filter drivers and the machine's global/system config.
So: never recurse submodules, never check out, only plumbing commands, no system
config, no terminal prompts.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

HARDEN = ["-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
          "-c", "submodule.recurse=false", "-c", "core.fsmonitor=false",
          "-c", "diff.external=", "-c", "core.quotePath=true"]


def git_env() -> dict:
    env = dict(os.environ)
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_LFS_SKIP_SMUDGE="1",
               GIT_ASKPASS="/bin/true", LC_ALL="C")
    env.pop("GIT_DIR", None)
    return env


def git_argv(repo: Path | None, *args: str) -> list[str]:
    harden = HARDEN
    if os.environ.get("LOGTRACE_TEST_ALLOW_FILE_PROTOCOL") == "1":     # tests clone local fixtures only
        harden = [x if x != "protocol.file.allow=never" else "protocol.file.allow=always" for x in HARDEN]
    base = ["git"] + harden
    if repo is not None:
        base += ["-C", str(repo)]
    return base + list(args)


def run_git(repo: Path | None, *args: str, timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(git_argv(repo, *args), env=git_env(), capture_output=True,
                          timeout=timeout, check=check)


def popen_git(repo: Path, *args: str, stdin=None, stderr=subprocess.DEVNULL) -> subprocess.Popen:
    # stderr is not piped by default: an unread pipe can fill up and deadlock the stream
    return subprocess.Popen(git_argv(repo, *args), env=git_env(), stdout=subprocess.PIPE,
                            stdin=stdin, stderr=stderr, bufsize=1 << 20)
