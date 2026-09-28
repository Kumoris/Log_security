"""Bridge to agentlog_unified's own judgement (src/reference, copied verbatim).

Every sensitivity decision in logtrace goes through ``reference.detector.detect_snapshot``
so the type table (taxonomy 1.2.0) and the supported/possible/not_supported/unknown
rules are exactly agentlog_unified's. This module only converts its output.
"""
from __future__ import annotations

from functools import lru_cache

from ..models import LogStatement, SensLevel, Sensitivity
from ..reference.detector import detect_snapshot

NO_REFERENCE = Sensitivity(level=SensLevel.UNKNOWN, reference_found=False,
                           missing_evidence=("reference_detector_saw_no_log_here",))


def to_sensitivity(entity: dict) -> Sensitivity:
    flows = sorted({f"{e.get('source')}={'|'.join(sorted(e.get('types') or []))}"
                    for e in entity.get("source_to_sink", []) if e.get("types")})
    labels = sorted({f"{t['category']}.{t['subtype']}:{t.get('evidence_status', '')}"
                     for t in entity.get("taxonomy_labels", [])})
    return Sensitivity(
        level=SensLevel(entity.get("privacy_assessment", "unknown")),
        data_types=tuple(sorted(entity.get("data_types", []))),
        flows=tuple(flows),
        taxonomy_labels=tuple(labels),
        sanitization=tuple(entity.get("existing_sanitization", [])),
        log_level=entity.get("level"),
        trigger_conditions=tuple(entity.get("trigger_conditions", [])),
        detection_status=entity.get("log_detection_status"),
        parser_status=entity.get("parser_status"),
        taxonomy_status=entity.get("taxonomy_status"),
        missing_evidence=tuple(entity.get("missing_evidence", []))[:20],
    )


def _index(entities: list[dict]) -> dict[tuple[str, int], list[dict]]:
    idx: dict[tuple[str, int], list[dict]] = {}
    for e in entities:
        idx.setdefault((e["path"], e["start_line"]), []).append(e)
    return idx


def _pick(cands: list[dict], st: LogStatement) -> dict | None:
    if not cands:
        return None
    for e in cands:
        callee = str(e.get("callee") or "")
        if callee == st.method or callee.endswith("." + st.method):
            return e
    return cands[0]


@lru_cache(maxsize=512)
def _judge_single(path: str, source: str) -> dict[tuple[str, int], list[dict]]:
    return _index(detect_snapshot({path: source}, ["python"])["entities"])


def judge_file(path: str, source: str, statements: list[LogStatement]) -> list[Sensitivity]:
    """Judge statements of one file version with the file as the whole snapshot."""
    idx = _judge_single(path, source)
    out = []
    for st in statements:
        e = _pick(idx.get((path, st.line), []), st)
        out.append(to_sensitivity(e) if e is not None else NO_REFERENCE)
    return out


def judge_snapshot(files: dict[str, str]) -> dict[tuple[str, int], list[dict]]:
    """Judge a whole revision (agentlog_unified's normal mode: one-hop imports resolve
    across files of the same snapshot). Returns the raw entity index."""
    return _index(detect_snapshot(files, ["python"])["entities"])


def pick_sensitivity(index: dict[tuple[str, int], list[dict]], st: LogStatement) -> Sensitivity:
    e = _pick(index.get((st.path, st.line), []), st)
    return to_sensitivity(e) if e is not None else NO_REFERENCE
