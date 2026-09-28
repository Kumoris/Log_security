"""Structural fingerprints (REBUILD.md §11.2).

A fingerprint names *one statement in one file version*. It is not the identity of a
log across its life: change an argument and the fingerprint changes. Lineage is
carried by events (before_fp -> after_fp) and by the tracker's lineage_id.
"""
from __future__ import annotations

import ast
import hashlib


def structure_hash(node: ast.AST) -> str:
    """Formatting-insensitive hash: whitespace/line moves do not matter, arguments do."""
    return hashlib.sha1(ast.dump(node, include_attributes=False).encode()).hexdigest()[:16]


def fingerprint(path: str, scope: str, shash: str, occurrence: int) -> str:
    return hashlib.sha1(f"{path}\0{scope}\0{shash}\0{occurrence}".encode()).hexdigest()[:20]
