"""Real PyDriller histories retain ambiguous alternatives without inventing fixes."""
from synthetic_histories import HEADER, commit, init, pipeline


DUPLICATES = HEADER + '''def handle():
    logger.info("received", extra={"password": "DUMMY_RESEARCH_SECRET_NOT_VALID"})
    logger.info("received", extra={"access_token": "DUMMY_RESEARCH_SECRET_NOT_VALID"})
'''
ONE_REMAINING = HEADER + '''def handle():
    logger.info("received", extra={"refresh_token": "DUMMY_RESEARCH_SECRET_NOT_VALID"})
'''
REMOVED_FIELDS = HEADER + '''def handle():
    logger.info("received", extra={"token_count": 2})
'''


def test_duplicate_templates_keep_multiple_possible_followup_candidates(tmp_path):
    init(tmp_path)
    intro = commit(tmp_path, {"app.py": DUPLICATES}, "two same-template logs", day=2)
    deletion = commit(tmp_path, {"app.py": ONE_REMAINING}, "remove one duplicate", actor="human", day=3)
    terminal = commit(tmp_path, {"app.py": REMOVED_FIELDS}, "narrow remaining fields", actor="human", day=4)
    result = pipeline(tmp_path, terminal, [intro])

    assert result["mined"]["metrics"]["pydriller_commits"] >= 3
    assert any(c["sha"] == deletion and c["diff_backend"] == "pydriller.Commit.modified_files"
               for c in result["mined"]["changes"])
    origins = [row for row in result["log_changes"] if row["intro_sha"] == intro]
    assert len(origins) == 2
    for origin in origins:
        changes = [f for f in result["followups"] if f["case_id"] == origin["case_id"] and f["followup_sha"] == deletion]
        alternatives = [f for f in changes if f["before"] is not None]
        assert len({f["before"]["identity"] for f in alternatives}) >= 2
        assert all(f["behavior_relation"] == "same_symbol" for f in alternatives)
        assert all(f["behavior_confidence"] == "possible" for f in alternatives)
        assert all(f["fix_effect"] == "unknown" for f in changes)
        assert origin["lineage_status"] == "ambiguous"
        assert origin["fix_sha"] is None
        assert origin["first_eliminated_flow_sha"] is None
        # Choosing an uncertain deletion must not kill the branch of alternatives.
        later = [f for f in result["followups"] if f["case_id"] == origin["case_id"] and f["followup_sha"] == terminal]
        assert later
        assert all(f["fix_effect"] == "unknown" for f in later)
    assert all(row["screening_bucket"] != "REVIEW_READY" for row in result["candidates"])


def test_ambiguous_same_pr_edits_do_not_force_sensitive_flow_attribution(tmp_path):
    init(tmp_path)
    safe_duplicates = HEADER + '''def handle():
    logger.info("received", extra={"token_count": 1})
    logger.info("received", extra={"token_count": 2})
'''
    intro = commit(tmp_path, {"app.py": safe_duplicates}, "two safe duplicate logs", day=2)
    activation = commit(tmp_path, {"app.py": ONE_REMAINING}, "one retained log with credential", actor="human", day=3)
    result = pipeline(tmp_path, activation, [intro, activation])
    original_rows = [row for row in result["log_changes"] if row["intro_sha"] == intro]
    assert len(original_rows) == 2
    for origin in original_rows:
        possible = [f for f in result["followups"] if f["case_id"] == origin["case_id"]]
        assert possible
        assert all(f["behavior_confidence"] == "possible" for f in possible)
        assert origin["sensitive_flow_introduced_sha"] is None
        assert origin["risk_introducer_type"] == "unknown"
        assert origin["introduction_relation"] != "later_activated"
