"""Transactional checkpoints and private raw evidence, deterministic public exports."""
from __future__ import annotations
import hashlib
import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from .taxonomy import _matches


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def stable_id(*values: Any) -> str:
    return hashlib.sha256(canonical(["2.0", *values]).encode()).hexdigest()[:24]


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


# Reuses the existing screen_github_agent_logs.redact_excerpt patterns, without its
# 800-character truncation; adds assignment/connection-string handling.
SECRET_PATTERNS = [
    (r"\b(?:gh[opsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b", "<REDACTED:CREDENTIAL>"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "<REDACTED:JWT>"),
    (r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer <REDACTED:CREDENTIAL>"),
    (r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<REDACTED:EMAIL>"),
    (r"(?i)([a-z][a-z0-9+.-]*://)[^\s/:]+:[^\s/@]+@", r"\1<REDACTED:USERINFO>@"),
    (r"(?i)((?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)[\"']?\s*[:=]\s*)([\"'])([^\n]*?)\2", r"\1\2<REDACTED:CREDENTIAL>\2"),
    (r"(?i)([?&](?:token|key|secret|password)=)[^&\s]+", r"\1<REDACTED:CREDENTIAL>"),
    (r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----", "<REDACTED:PRIVATE_KEY>"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<REDACTED:IP>"),
]


def redact(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {k: redact(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, key) for v in value]
    if not isinstance(value, str):
        return value
    # AST dumps encode literals differently from source assignments. Keep raw
    # semantics private, publish only an equality fingerprint in every export.
    if key in {"semantic_statement", "semantic_code"}:
        return "<SEMANTIC_SHA256:" + hashlib.sha256(value.encode("utf-8")).hexdigest() + ">"
    if any(row[0] == "AUTH" or (row[0], row[1]) == ("PII", "email") for row in _matches(key)):
        return "<REDACTED:VALUE>" if value else value
    for pattern, replacement in SECRET_PATTERNS:
        value = re.sub(pattern, replacement, value)
    return value


def csv_cell(value: Any) -> str:
    value = canonical(value) if isinstance(value, (dict, list)) else "" if value is None else str(value)
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path)
        os.chmod(path, 0o600)
        self.db.execute("CREATE TABLE IF NOT EXISTS records(kind TEXT,id TEXT,data TEXT,PRIMARY KEY(kind,id))")
        self.db.execute("CREATE TABLE IF NOT EXISTS stages(name TEXT PRIMARY KEY,status TEXT,details TEXT)")
        self.db.commit()

    def rows(self, kind: str) -> list[dict]:
        return [json.loads(r[0]) for r in self.db.execute("SELECT data FROM records WHERE kind=? ORDER BY id", (kind,))]

    def replace(self, kind: str, rows: list[dict]) -> None:
        self.db.execute("DELETE FROM records WHERE kind=?", (kind,))
        self.db.executemany("INSERT OR REPLACE INTO records VALUES(?,?,?)", [(kind, str(r.get("id") or stable_id(r)), canonical(r)) for r in rows])

    def status(self, stage: str) -> str | None:
        row = self.db.execute("SELECT status FROM stages WHERE name=?", (stage,)).fetchone()
        return row[0] if row else None

    def finish(self, stage: str, status: str = "complete", **details: Any) -> None:
        self.db.execute("INSERT OR REPLACE INTO stages VALUES(?,?,?)", (stage, status, canonical(details)))

    def close(self) -> None:
        self.db.close()
