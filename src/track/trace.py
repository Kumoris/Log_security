"""track_seed (REBUILD.md §9): claim the logs a seed commit added, follow each forward.

In-memory only; never touches git. Two disciplines:
  1. not exact -> stop (the non-exact event is kept as ``stop_event``, not in the timeline)
  2. a gap on the lineage's file between two events -> stop as ``blocked``
Only descendants of the current commit are followed: a higher topological index on a
parallel branch is not "later on this code".
"""
from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import timedelta

from ..config import Config
from ..detect.judge import pick_sensitivity
from ..models import (REMOVAL_KINDS, Case, ChangeKind, LogEvent, Observation, ResolvedSeed, SensLevel,
                      TimelineEntry)
from .ledger import Ledger
from .verdict import assess

V1_LIMITS = ("static_candidate_only", "dependency_changes_not_tracked")


def _observation(rs: ResolvedSeed, ledger: Ledger, cfg: Config, frozen_at) -> Observation:
    start = rs.seed.commit_date or ledger.commit_date[rs.anchor_sha]
    if rs.state == "relocated":
        start = ledger.commit_date[rs.anchor_sha]
    target = start + timedelta(days=cfg.window_days)
    return Observation(start=start, end=min(target, frozen_at), window_days=cfg.window_days,
                       complete=target <= frozen_at)


def _equivalent(a: LogEvent, b: LogEvent) -> bool:
    """Same edit replayed on another branch (rebase / cherry-pick duplicates)."""
    return (a.change == b.change and a.path == b.path and a.after_fp == b.after_fp
            and a.confidence == b.confidence and set(a.labels) == set(b.labels))


def _follow(intro: LogEvent, anchor: str, ledger: Ledger, obs: Observation):
    timeline: list[TimelineEntry] = []
    # cur is a *set*: a patch-equivalent edit replayed on parallel branches is one step,
    # and the lineage continues on the descendants of every copy
    cur, cursor, path = (anchor,), intro.after_fp, intro.path
    while True:
        after_cur = frozenset().union(*(ledger.descendants(c) for c in cur))
        cands = [e for e in ledger.by_before_fp.get(cursor, ()) if e.sha not in cur and e.sha in after_cur]
        if not cands:
            gaps = [g for c in cur for g in ledger.gaps_between(path, c, None, obs.end)]
            if gaps:
                return timeline, "blocked", f"{gaps[0].kind}@{gaps[0].sha[:10]}", None
            return timeline, "alive", None, None
        cands.sort(key=lambda e: ledger.commit_order[e.sha])
        e = cands[0]
        # candidates that descend from an earlier candidate are the fingerprint reappearing, not a copy
        copies = [c for c in cands[1:] if not any(ledger.is_ancestor(x.sha, c.sha) for x in cands if x is not c)]
        gaps = []
        for c in cur:
            for x in [e] + copies:
                gaps += ledger.gaps_between(path, c, x.sha) if ledger.is_ancestor(c, x.sha) else []
                if x.old_path and x.old_path != path and ledger.is_ancestor(c, x.sha):
                    gaps += ledger.gaps_between(x.old_path, c, x.sha)
        if gaps:
            return timeline, "blocked", f"{gaps[0].kind}@{gaps[0].sha[:10]}", None
        if len(cands) > 1:
            if len(copies) != len(cands) - 1 or not all(_equivalent(e, c) for c in copies):
                return timeline, "ambiguous", "parallel_or_reappearing_edits", e
        if e.confidence != "exact":
            return timeline, "ambiguous", f"lineage_match_not_exact:{e.change.value}", e
        timeline.append(TimelineEntry(e, e.date <= obs.end))
        if e.change in REMOVAL_KINDS:
            return timeline, e.change.value, None, None
        cur, cursor, path = tuple(x.sha for x in [e] + copies), e.after_fp, e.path


def _missing_evidence(case: Case) -> tuple[str, ...]:
    out = list(V1_LIMITS)
    s = case.sensitivity_at_intro
    if s is not None:
        out += list(s.missing_evidence)
        if not s.reference_found:
            out.append("reference_detector_saw_no_log_here")
    if not case.observation.complete:
        out.append("observation_incomplete")
    if case.seed_resolution == "relocated":
        out.append("seed_relocated_probable")
    if case.lineage_status == "ambiguous":
        out.append("ambiguous_entity_mapping")
    if case.stop_reason in ("blocked", "intro_blocked"):
        out.append(f"data_gap:{case.stop_detail}")
    if case.attribution == "mixed":
        out.append("mixed_file_log_author_unverified")
    return tuple(dict.fromkeys(out))


def _finish(case: Case, has_repair: bool, risk_parser: str | None) -> Case:
    bucket, priority, candidate = assess(
        extraction_ok=case.introduced is not None and case.stop_reason != "intro_blocked",
        observation_gaps=case.observation_gaps, risk=case.privacy_assessment, has_repair=has_repair,
        lineage_status=case.lineage_status, sensitive_flow_introduced_sha=case.sensitive_flow_introduced_sha,
        parser_status=risk_parser,
        provenance_high=case.seed_resolution == "reachable" and case.attribution == "agent_only")
    case = replace(case, verdict=bucket, priority=priority, privacy_review_candidate=candidate)
    return replace(case, missing_evidence=_missing_evidence(case))


def track_seed(rs: ResolvedSeed, ledger: Ledger, cfg: Config, frozen_at,
               intro_index: dict | None = None) -> list[Case]:
    """``intro_index``: agentlog_unified's judgement of the whole anchor revision
    ((path, line) -> entities); the intro's risk is taken from it, as agentlog_unified does."""
    seed, anchor = rs.seed, rs.anchor_sha
    agent = {f.path: f for f in seed.agent_files if f.path.endswith(tuple(cfg.suffixes))}
    if not agent:
        return []
    obs = _observation(rs, ledger, cfg, frozen_at)
    base_flags = ("relocated",) if rs.state == "relocated" else ()
    cases: list[Case] = []

    def mk(**kw) -> Case:
        return Case(trace_id=seed.trace_id, repository=seed.repository, seed_sha=seed.commit_sha,
                    anchor_sha=anchor, seed_resolution=rs.state, agent_names=seed.agent_names,
                    observation=obs, review_flags=base_flags, verdict="", priority="", privacy_review_candidate=False,
                    missing_evidence=(), **kw)

    # agent files that could not be read at the anchor: file-level blocked cases
    blocked_paths = set()
    for g in ledger.gaps_by_sha.get(anchor, ()):
        if g.path in agent and g.path not in blocked_paths:
            blocked_paths.add(g.path)
            cid = hashlib.sha1(f"{seed.trace_id}|{anchor}|{g.path}|file".encode()).hexdigest()[:16]
            cases.append(_finish(mk(
                case_id=cid, lineage_id=cid, file_path=g.path, attribution=agent[g.path].attribution,
                introduced=None, sensitivity_at_intro=None, timeline=(), stop_reason="intro_blocked",
                stop_detail=f"{g.kind}:{g.side}", stop_event=None, first_fix=None,
                lineage_status="tracked", observation_gaps=(), introduction_relation="unknown",
                sensitive_flow_introduced_sha=None, privacy_assessment="unknown", data_types=()), False, None))

    intros = sorted((e for e in ledger.by_sha.get(anchor, ())
                     if e.change == ChangeKind.ADDED and e.path in agent and e.path not in blocked_paths),
                    key=lambda e: (e.path, e.after.line))
    for intro in intros:
        lineage = hashlib.sha1(f"{seed.trace_id}|{anchor}|{intro.after_fp}".encode()).hexdigest()[:16]
        if intro.confidence != "exact":
            timeline, stop, detail, stop_event = [], "intro_ambiguous", "duplicate_statement_group", intro
        else:
            timeline, stop, detail, stop_event = _follow(intro, anchor, ledger, obs)
        intro_sens = pick_sensitivity(intro_index, intro.after) if intro_index is not None else intro.after.sensitivity
        lineage_status = "ambiguous" if stop in ("ambiguous", "intro_ambiguous") else "tracked"

        # agentlog_unified: introduction_relation / sensitive_flow_introduced_sha / later_activated
        new_sources = intro_sens.sensitive_sources()
        relation = "new_sensitive_flow" if new_sources else "unknown"
        sfi_sha = intro.sha if new_sources and intro_sens.level == SensLevel.SUPPORTED else None
        risk_sens = intro_sens
        if lineage_status != "ambiguous" and sfi_sha is None:
            for t in timeline:
                after = t.event.after
                if after is not None and after.sensitivity.level == SensLevel.SUPPORTED:
                    relation, sfi_sha, risk_sens = "later_activated", t.event.sha, after.sensitivity
                    break
        repairs = [t.event for t in timeline if t.in_window and t.event.is_privacy_fix]
        cases.append(_finish(mk(
            case_id=lineage, lineage_id=lineage, file_path=intro.path, attribution=agent[intro.path].attribution,
            introduced=intro, sensitivity_at_intro=intro_sens, timeline=tuple(timeline),
            stop_reason=stop, stop_detail=detail, stop_event=stop_event,
            first_fix=repairs[0] if repairs else None,
            lineage_status=lineage_status,
            observation_gaps=(detail,) if stop == "blocked" else (),
            introduction_relation=relation, sensitive_flow_introduced_sha=sfi_sha,
            privacy_assessment=risk_sens.level.value, data_types=risk_sens.data_types),
            bool(repairs), risk_sens.parser_status))
    return cases
