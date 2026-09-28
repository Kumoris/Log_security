"""Resolve known pre-flattening locations without rewriting research evidence."""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re

PROJECT = Path(__file__).resolve().parents[2]
MOVED = {
    'cache': 'data/cache', 'inputs': 'data/inputs',
    'semantic-inputs': 'data/semantic-inputs', 'dataset.json': 'data/dataset.json',
    **{name: 'outputs/' + name for name in (
        'runs', 'batches', 'content-runs', 'schema-runs', 'semantic-runs',
        'structured-runs', 'repair-runs', 'reconciled-runs')},
    'reports': 'outputs/tool-reports', 'report': 'outputs/presentations',
}
ROOT_FOLDERS = set(MOVED) | {
    'src', 'tests', 'configs', 'schemas', 'examples', 'docs', 'research',
    'scripts', 'outputs', 'papers', 'data', 'archive',
}


def _native(value):
    text = str(value).replace('\\', '/')
    if os.name == 'nt' and re.match(r'^/mnt/[a-zA-Z]/', text):
        text = text[5].upper() + ':/' + text[7:]
    elif os.name != 'nt' and re.match(r'^[a-zA-Z]:/', text):
        text = '/mnt/' + text[0].lower() + '/' + text[3:]
    return Path(text).expanduser()


def _mapped(relative, project):
    parts = PurePosixPath(str(relative).replace('\\', '/')).parts
    if not parts or parts[0] not in ROOT_FOLDERS:
        return None
    # A relocation must never turn an untrusted suffix into a path outside root.
    if '..' in parts:
        raise ValueError('Parent traversal is not allowed in a relocated project path')
    result = (project / MOVED.get(parts[0], parts[0])).joinpath(*parts[1:]).resolve()
    if not result.is_relative_to(project):
        raise ValueError('Relocated project path escapes project root')
    return result


def resolve_path(value, *, project=None, base=None):
    """Prefer an existing path; remap only known old project roots when missing.

    Relative record paths are interpreted beside the input file (``base``).
    Unknown external paths remain missing; no name-based repository search occurs.
    This resolves locations only, never bypassing guards or frozen hashes.
    """
    project = Path(project if project is not None else PROJECT).resolve()
    base = Path(base).resolve() if base is not None else project
    native = _native(value)
    direct = (base / native).resolve()
    if direct.exists():
        return direct
    if direct.is_relative_to(project):
        relative = direct.relative_to(project).as_posix()
        # Former outer workspace and inner project prefixes.
        relative = relative.removeprefix('workspace/')
        relative = relative.removeprefix('agentlog_unified/')
        mapped = _mapped(relative, project)
        if mapped is not None:
            return mapped
    normalized = str(value).replace('\\', '/')
    if '/agent_log_privacy/' in normalized:
        suffix = normalized.rsplit('/agent_log_privacy/', 1)[1]
        first, _, rest = suffix.partition('/')
        if first in {'cache', 'runs'}:
            return _mapped(first + '/legacy-privacy/' + rest, project)
    for marker in ('/agentlog/workspace/agentlog_unified/', '/agentlog/workspace/',
                   '/agentlog_unified/', '/agentlog/', '/Log 研究/'):
        if marker in normalized:
            mapped = _mapped(normalized.rsplit(marker, 1)[1], project)
            if mapped is not None:
                return mapped
    return direct


def project_path(value, project):
    """Canonical project configuration paths, including not-yet-created caches."""
    native = _native(value)
    if not native.is_absolute():
        mapped = _mapped(str(value), Path(project).resolve())
        if mapped is not None:
            return mapped
    return resolve_path(value, project=project)
