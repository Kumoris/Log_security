"""Data classes shared across layers, and JSON helpers.

Anything the pipeline did not see is an explicit ``Gap``. Records written to disk
(anchors, lineages, versions, changes, items) are plain dicts built by the layer
that owns them; the classes here are the in-memory core.
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Gap:
    """A place the pipeline did not see. Never silently dropped."""
    kind: str
    repository: str | None = None
    sha: str | None = None
    path: str | None = None
    side: str | None = None          # before | after, for per-version failures
    detail: str | None = None


@dataclass(frozen=True)
class LocalRepo:
    repository: str
    path: Path
    default_branch: str
    frozen_head: str
    frozen_at: datetime


# --------------------------------------------------------------------------- log statements

@dataclass(frozen=True)
class LogItem:
    """One thing a log statement outputs."""
    expr: str                        # normalized expression text, e.g. "user.email", "mask(token)"
    core: str                        # expr without wrapping calls / slices, e.g. "token"
    wrappers: tuple[str, ...] = ()   # outermost first, e.g. ("mask",) or ("slice",)
    key: str | None = None           # field name for extra={...} / keyword arguments
    role: str = "value"              # value | exception | message


@dataclass(frozen=True)
class LogStatement:
    path: str
    scope: str                       # qualified name, "<module>" at top level
    line: int
    end_line: int
    col: int
    code: str
    receiver: str                    # e.g. "logger", "self.log", "print", "<wrapper:log_event>"
    method: str                      # info / warning / ... / print / wrapper name
    sink: str                        # logger | wrapper | print
    detection: str                   # tracked | name_heuristic | wrapper | print
    template: str                    # constant message template ("" if none)
    items: tuple[LogItem, ...] = ()
    conditions: tuple[str, ...] = () # enclosing if / while tests inside the function, outermost first
    shash: str = ""                  # formatting-insensitive structure hash

    @property
    def item_exprs(self) -> frozenset[str]:
        return frozenset(i.expr for i in self.items)


@dataclass(frozen=True)
class ParsedFile:
    path: str
    statements: tuple[LogStatement, ...]


# --------------------------------------------------------------------------- serialisation

def to_jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted(to_jsonable(x) for x in obj)
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    return obj


def dumps(obj: Any) -> str:
    return json.dumps(to_jsonable(obj), ensure_ascii=False, sort_keys=True)


def statement_from_dict(d: dict) -> LogStatement:
    d = dict(d)
    d["items"] = tuple(LogItem(**{**i, "wrappers": tuple(i.get("wrappers", ()))}) for i in d.get("items", ()))
    d["conditions"] = tuple(d.get("conditions", ()))
    return LogStatement(**d)


def write_jsonl(path: Path, rows) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    tmp = path.with_suffix(path.suffix + ".partial")
    with tmp.open("w") as f:
        for r in rows:
            f.write(dumps(r) + "\n")
            n += 1
    tmp.replace(path)
    return n


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open() as f:
        return [json.loads(line) for line in f if line.strip()]
