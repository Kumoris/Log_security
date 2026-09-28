"""Per-file patch parsing and the log-line regex used to pick seed PRs.

The regex is a coarse filter on AIDev patches only: a PR becomes a seed when one of
its commits adds or removes a line that looks like a log call in a Python file.
The real log statements are found later by parsing the code at the landing commit.
"""
from __future__ import annotations

import re

LOG_REGEX_VERSION = "v1"
LOG_RE = re.compile(
    r'(?:logger|logging|log|console)\s*\.\s*'
    r'(?:debug|info|warn|warning|error|exception|critical|fatal|trace)\s*\('
    r'|\bprint\s*\(', re.IGNORECASE)

_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


def patch_lines(patch: str) -> tuple[list[str], list[str], bool]:
    """One file's hunks without file headers (GitHub API ``patch``) -> (added, removed, truncated)."""
    added: list[str] = []
    removed: list[str] = []
    in_hunk, remaining_new, truncated = False, 0, False
    for line in patch.split("\n"):
        if line.startswith("@@"):
            if in_hunk and remaining_new > 0:
                truncated = True
            m = _HUNK.match(line)
            in_hunk = True
            remaining_new = int(m.group(2)) if m and m.group(2) is not None else 1
        elif in_hunk and line.startswith("+"):
            remaining_new -= 1
            added.append(line[1:])
        elif in_hunk and line.startswith("-"):
            removed.append(line[1:])
        elif in_hunk and (line.startswith(" ") or line == ""):
            remaining_new -= 1
    return added, removed, truncated or (in_hunk and remaining_new > 0)


def log_lines(lines: list[str]) -> list[str]:
    return [ln.strip() for ln in lines if LOG_RE.search(ln)]
