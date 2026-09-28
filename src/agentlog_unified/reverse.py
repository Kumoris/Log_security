"""Optional fix-first enrichment. Never changes the forward cohort or verdicts."""
from __future__ import annotations

import re
from collections import defaultdict
from pydriller import Git
from .detector import detect_snapshot
from .git_support import disable_implicit_fetch
from .provenance import classify_actor
from .storage import stable_id

DEFAULT_KEYWORDS = [r"\bredact", r"\bmask(?:ed|ing)?\b", r"\bsaniti[sz]",
                    r"\bprivacy\b", r"\bPII\b", r"\bleak", r"do(?:n't| not) log"]


class LogLinesOnly:
    """A view of a real ModifiedFile restricting SZZ to this complete log span."""
    def __init__(self, modified, deleted):
        self.modified = modified
        self.diff_parsed = {"added": [], "deleted": deleted}

    def __getattr__(self, name):
        return getattr(self.modified, name)


def scan_reverse(repositories, mined_rows, prs, config, evidence=None):
    disable_implicit_fetch()
    patterns = [re.compile(p, re.I) for p in config.get("keywords", DEFAULT_KEYWORDS)]
    limit = int(config.get("max_commits", 20000))
    if limit < 1:
        raise ValueError("reverse.max_commits must be positive")
    candidates, gaps = [], []
    metrics = {"commits_scanned": 0, "keyword_matches": 0, "pydriller_szz_calls": 0}
    for repo in repositories:
        mined = next(m for m in mined_rows if m["repository_id"] == repo["id"])
        changes = defaultdict(list)
        for change in mined["changes"]:
            changes[change["sha"]].append(change)
        commits = [c for c in mined["commits"] if c["on_target_first_parent"]]
        if len(commits) > limit:
            gaps.append({"stage": "reverse", "repository_id": repo["id"],
                         "error_type": "reverse_budget_exceeded", "retryable": False})
        g = Git(repo["local_repo_path"])
        try:
            for meta in commits[-limit:]:
                metrics["commits_scanned"] += 1
                hits = [p.pattern for p in patterns if p.search(meta["message"] or "")]
                if not hits:
                    continue
                metrics["keyword_matches"] += 1
                if len(meta["parents"]) != 1:
                    gaps.append({"stage": "reverse", "repository_id": repo["id"], "sha": meta["sha"],
                                 "error_type": "merge_or_root_szz_unresolved", "retryable": False})
                    continue
                commit = g.get_commit(meta["sha"])
                modifications = {(m.old_path, m.new_path): m for m in commit.modified_files}
                for change in changes[meta["sha"]]:
                    if not change["before_source"] or not change["deleted"]:
                        continue
                    path = change["old_path"]
                    parsed = detect_snapshot({path: change["before_source"]})
                    for log in parsed["entities"]:
                        # Includes edits confined to multiline arguments; no per-line logger regex.
                        deleted = [(n, text) for n, text in change["deleted"]
                                   if log["start_line"] <= n <= log["end_line"]]
                        if not deleted:
                            continue
                        modified = modifications.get((change["old_path"], change["new_path"]))
                        origins, errors = [], []
                        try:
                            if modified is None:
                                raise ValueError("matching_ModifiedFile_unavailable")
                            metrics["pydriller_szz_calls"] += 1
                            blamed = g.get_commits_last_modified_lines(commit, LogLinesOnly(modified, deleted))
                            for sha in sorted({s for values in blamed.values() for s in values}):
                                original = g.get_commit(sha)
                                origin_meta = {"sha": sha, "author_name": original.author.name,
                                               "author_email": original.author.email, "message": original.msg}
                                bound = [p for p in prs if p["id"] in repo["pr_ids"] and sha in
                                         (p.get("commit_shas") or p.get("initial_commit_shas") or [])]
                                pr = bound[0] if len(bound) == 1 else {}
                                origins.append({"sha": sha, "attribution": classify_actor(origin_meta, pr, evidence or []),
                                                "relation": "last_touch_of_deleted_log_span_not_proven_introduction"})
                        except Exception as exc:
                            errors.append(type(exc).__name__)
                            gaps.append({"stage": "reverse", "repository_id": repo["id"], "sha": meta["sha"],
                                         "path": path, "error_type": "szz_unavailable", "retryable": False})
                        candidates.append({"id": stable_id("reverse", repo["id"], meta["sha"], path, log["identity"]),
                            "repository_id": repo["id"], "repository": repo.get("repository"),
                            "cohort": "repair_enriched", "is_synthetic": repo.get("is_synthetic", False),
                            "discovery_method": "fix_message_keyword_then_deleted_complete_log_span",
                            "history_scope": "already_mined_target_first_parent", "fix_sha": meta["sha"],
                            "before_sha": meta["parents"][0], "path": path, "statement": log["statement"],
                            "deleted_line_numbers": [n for n, _ in deleted], "matched_keywords": hits,
                            "introducing_commit_candidates": origins, "errors": errors,
                            "backend": "pydriller.Git.get_commits_last_modified_lines(filtered_log_span)",
                            "diff_backend": change["diff_backend"], "fallback_reason": change["fallback_reason"],
                            "human_review_status": "pending", "privacy_repair_confirmed": False,
                            "agent_introduction_confirmed": False, "runtime_leak_claim": False})
        finally:
            g.clear()
    return {"reverse_candidates": candidates, "gaps": gaps, "metrics": metrics}
