"""Paths that are never analysed: vendored / third-party code, build output, generated code.

Two checks: by path (cheap, used on AIDev file names and git change lists) and by
content header (used once a file version is read). Each returns the rule that fired,
so exclusions can be counted per rule.
"""
from __future__ import annotations

from ..config import Config


def excluded_path(path: str, cfg: Config) -> str | None:
    parts = path.split("/")
    dirs = set(parts[:-1])
    for d in cfg.exclude_dirs:
        if d in dirs:
            return f"dir:{d}"
    if any(p.endswith(".egg-info") for p in parts[:-1]):
        return "dir:*.egg-info"
    for s in cfg.exclude_suffixes:
        if path.endswith(s):
            return f"suffix:{s}"
    if not path.endswith(tuple(cfg.suffixes)):
        return "not_python"
    return None


def excluded_content(source: str, cfg: Config) -> str | None:
    head = "\n".join(source.splitlines()[:15]).lower()
    for marker in cfg.generated_markers:
        if marker in head:
            return f"generated:{marker}"
    return None
