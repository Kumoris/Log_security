"""Screening bucket, priority and review-candidate flag: agentlog_unified ``lineage.assess``.

Ported rule for rule (agentlog_unified/src/agentlog_unified/lineage.py, ``assess``):

  1 intro could not be extracted                                   -> BLOCKED_BY_DATA
  2 a coverage gap lies on the observed lineage                    -> NEEDS_CONTEXT
  3 risk (privacy_assessment) is not_supported                     -> OUT_OF_SCOPE_OR_FALSE_POSITIVE
  4 risk supported, a repair observed, lineage not ambiguous,
    a sensitive flow was introduced, parser not lexical-only       -> REVIEW_READY
  5 risk unknown/possible, or lineage ambiguous                    -> NEEDS_CONTEXT
  6 otherwise                                                      -> NO_OBSERVED_PRIVACY_FIX

priority: P1 = REVIEW_READY with high provenance; P2 = risk possible/supported; P3 otherwise.
privacy_review_candidate (agentlog_unified export ``privacy_review_candidates``):
risk possible/supported and bucket not OUT_OF_SCOPE -- the list handed to people.
"""
from __future__ import annotations


def assess(*, extraction_ok: bool, observation_gaps: tuple, risk: str, has_repair: bool,
           lineage_status: str, sensitive_flow_introduced_sha: str | None, parser_status: str | None,
           provenance_high: bool) -> tuple[str, str, bool]:
    if not extraction_ok:
        bucket = "BLOCKED_BY_DATA"
    elif observation_gaps:
        bucket = "NEEDS_CONTEXT"
    elif risk == "not_supported":
        bucket = "OUT_OF_SCOPE_OR_FALSE_POSITIVE"
    elif (risk == "supported" and has_repair and lineage_status != "ambiguous"
          and sensitive_flow_introduced_sha and parser_status != "lexical_only"):
        bucket = "REVIEW_READY"
    elif risk in {"unknown", "possible"} or lineage_status == "ambiguous":
        bucket = "NEEDS_CONTEXT"
    else:
        bucket = "NO_OBSERVED_PRIVACY_FIX"
    priority = "P1" if bucket == "REVIEW_READY" and provenance_high else "P2" if risk in {"possible", "supported"} else "P3"
    candidate = risk in {"possible", "supported"} and bucket != "OUT_OF_SCOPE_OR_FALSE_POSITIVE"
    return bucket, priority, candidate
