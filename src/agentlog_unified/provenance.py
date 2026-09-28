"""Commit-bound attribution; PR labels and author-name guesses remain evidence clues."""
from __future__ import annotations

import re

ACTORS = {"agent", "human_led", "mixed", "automation_non_agent", "unknown"}
STRONG_KINDS = {"platform_commit_binding", "local_session_commit_binding", "human_authorship_review", "automation_platform_binding"}


def classify_actor(commit: dict, pr: dict | None = None, evidence: list | None = None) -> dict:
    pr = pr or {}
    author = commit.get("author") or {}
    if not isinstance(author, dict):
        author = {"name": str(author)}
    email = commit.get("author_email") or author.get("email")
    name = commit.get("author_name") or author.get("name")
    sha = commit.get("hash") or commit.get("sha") or commit.get("commit_sha")
    label = pr.get("provided_label", pr.get("pr_actor_type"))
    collected = list(evidence or [])
    extra = pr.get("provenance_evidence")
    if isinstance(extra, list):
        collected.extend(extra)
    elif extra:
        collected.append({"kind": "provided_pr_evidence", "value": extra})
    extra = commit.get("provenance_evidence")
    if isinstance(extra, list):
        collected.extend(extra)
    result = {"actor_type": "unknown", "confidence": "unknown", "evidence": collected, "provided_label": label}
    if pr.get("is_synthetic") is True or commit.get("is_synthetic") is True:
        mapping = pr.get("synthetic_author_mapping") or pr.get("author_mapping") or commit.get("synthetic_author_mapping") or {}
        actor = mapping.get(email) or mapping.get(name) if isinstance(mapping, dict) else None
        if isinstance(actor, dict):
            actor = actor.get("actor_type")
        if actor in ACTORS and actor != "unknown":
            result.update(actor_type=actor, confidence="high")
            collected.append({"kind": "synthetic_author_mapping", "commit_sha": sha, "actor_type": actor, "is_synthetic": True, "evidence_ref": pr.get("metadata_source") or "local_fixture_metadata"})
            return result
    verified = set()
    for item in collected:
        if not isinstance(item, dict):
            continue
        actor = item.get("actor_type")
        binding = item.get("commit_sha") or item.get("sha")
        reference = item.get("evidence_ref") or item.get("url") or item.get("path")
        if actor in ACTORS - {"unknown"} and binding and binding == sha and reference and item.get("verified") is True and item.get("kind") in STRONG_KINDS:
            verified.add(actor)
        # Existing workspace verifier output is accepted only with the exact SHA binding,
        # explicit local evidence path, all integrity gates and no recorded hard failures.
        if item.get("binding_status") == "high_confidence_commit_or_tree" and reference and item.get("commit_match") is True and item.get("line_authorship_proof") is True and not item.get("hard_failures") and item.get("session_commit_sha") == sha and item.get("pr_head_sha") == sha and item.get("same_repository") is True and item.get("temporal_order_valid") is True:
            verified.add("agent")
    if verified:
        result.update(actor_type=next(iter(verified)) if len(verified) == 1 else "mixed", confidence="high")
        return result
    platform = commit.get("github_author") or commit.get("platform_author") or {}
    if isinstance(platform, dict) and platform.get("type") == "Bot" and platform.get("html_url") and platform.get("login") in {"dependabot[bot]", "renovate[bot]", "github-actions[bot]", "pre-commit-ci[bot]"}:
        result.update(actor_type="automation_non_agent", confidence="medium")
        collected.append({"kind": "known_non_agent_platform_account", "commit_sha": sha, "evidence_ref": platform["html_url"], "login": platform["login"]})
    message = commit.get("message") or commit.get("msg") or ""
    coauthors = re.findall(r"(?im)^Co-authored-by:\s*(.+)$", message)
    if coauthors:
        # Keep identity clues without converting a trailer into line-authorship proof.
        collected.append({"kind": "coauthor_trailer_clue", "commit_sha": sha, "coauthors": coauthors, "evidence_ref": commit.get("evidence_ref") or f"git:{sha}"})
    if re.search(r"(?i)bot|codex|agent|copilot|claude", str(name or "")):
        collected.append({"kind": "author_name_clue", "commit_sha": sha, "author_name": name, "evidence_ref": commit.get("evidence_ref") or f"git:{sha}"})
    if result["confidence"] == "unknown" and (coauthors or collected or label):
        result["confidence"] = "low"
    return result
