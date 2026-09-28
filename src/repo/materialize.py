"""File contents through one long-lived ``git cat-file --batch`` process.

Decoding: PEP 263 declaration first, then UTF-8. Failure is a Gap and the version is
*unavailable* -- never ``None``, which means "file does not exist".
"""
from __future__ import annotations

import io
import subprocess
import tokenize
from pathlib import Path

from .gitcmd import popen_git


class Unavailable(str):
    """Marker content for a version that exists but could not be materialised."""


class CatFile:
    def __init__(self, repo: Path):
        self.proc = popen_git(repo, "cat-file", "--batch", stdin=subprocess.PIPE)

    def read(self, sha: str) -> bytes | None:
        self.proc.stdin.write(sha.encode() + b"\n")
        self.proc.stdin.flush()
        header = self.proc.stdout.readline()
        if not header or header.endswith(b"missing\n"):
            return None
        size = int(header.split()[2])
        data = self.proc.stdout.read(size)
        self.proc.stdout.read(1)                    # trailing LF
        return data

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=30)
        except Exception:
            self.proc.kill()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def decode_source(data: bytes) -> str:
    """Raises UnicodeDecodeError / SyntaxError (bad coding cookie) / LookupError."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    except SyntaxError:
        encoding = "utf-8"
    text = data.decode(encoding)
    return text[1:] if text.startswith("﻿") else text


def materialize(cat: CatFile, blob: str | None, max_bytes: int) -> tuple[str | None, str | None]:
    """-> (content, gap_kind). content None with gap None means the file did not exist."""
    if blob is None:
        return None, None
    data = cat.read(blob)
    if data is None:
        return Unavailable(""), "blob_missing"
    if len(data) > max_bytes:
        return Unavailable(""), "file_too_large"
    try:
        return decode_source(data), None
    except (UnicodeDecodeError, SyntaxError, LookupError):
        return Unavailable(""), "decode_failed"
