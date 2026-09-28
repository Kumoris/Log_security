"""Exercise full PyDriller -> detector -> lineage against synthetic Git DAGs."""
import pytest

from synthetic_histories import HEADER, RISK, SAFE, commit, git, init, pipeline


def test_same_pr_human_introduction_is_not_attributed_to_agent(tmp_path):
    init(tmp_path)
    safe = commit(tmp_path, {"app.py": SAFE}, "agent safe log", day=2)
    risk = commit(tmp_path, {"app.py": RISK}, "human adds secret", actor="human", day=3)
    repair = commit(tmp_path, {"app.py": SAFE}, "agent follows correction", day=4)
    result = pipeline(tmp_path, repair, [safe, risk, repair])
    assert len(result["log_changes"]) == 3
    row = next(x for x in result["candidates"] if x["intro_sha"] == risk)
    assert row["risk_introducer_type"] == "human_led"
    assert row["log_change_actor_type"] == "human_led"
    assert row["fix_executor_type"] == "agent"
    assert row["issue_raiser_type"] == "unknown"
    assert row["human_review_status"] == "pending"
    assert row["new_type_status"] == "not_established"


def test_unmerged_side_repair_is_not_effective_on_target(tmp_path):
    init(tmp_path)
    intro = commit(tmp_path, {"app.py": RISK}, "agent log", day=2)
    git(tmp_path, "checkout", "-qb", "repair")
    repair = commit(tmp_path, {"app.py": SAFE}, "unmerged repair", actor="human", day=3)
    git(tmp_path, "checkout", "-q", "main")
    result = pipeline(tmp_path, intro, [intro], extras=[repair])
    assert any(e["sha"] == repair for e in result["detected"]["events"])
    assert result["log_changes"][0]["behavior_present_at_integration"] is True
    assert result["followups"] == []
    assert result["candidates"][0]["fix_sha"] is None


def test_side_repair_counts_once_at_merge_integration(tmp_path):
    init(tmp_path)
    intro = commit(tmp_path, {"app.py": RISK}, "agent log", day=2)
    git(tmp_path, "checkout", "-qb", "repair")
    repair = commit(tmp_path, {"app.py": SAFE}, "side fix", actor="human", day=3)
    git(tmp_path, "checkout", "-q", "main")
    commit(tmp_path, {"unrelated.py": "counter = 1\n"}, "unrelated main", day=4)
    git(tmp_path, "merge", "--no-ff", "repair", "-m", "integrate repair", actor="human", day=5)
    merged = git(tmp_path, "rev-parse", "HEAD")
    result = pipeline(tmp_path, merged, [intro])
    assert {f["followup_sha"] for f in result["followups"]} == {merged}
    followup = result["followups"][0]
    assert followup["effective_on_target"] is True
    assert followup["phase"] == "post_merge"
    assert followup["followup_pr_number"] is None
    assert followup["fix_effect"] == "eliminates_observed_flow"
    assert repair != followup["effective_target_sha"]


@pytest.mark.parametrize("method", ["squash", "rebase"])
def test_rewritten_initial_maps_using_frozen_integration_tree(tmp_path, method):
    init(tmp_path)
    git(tmp_path, "checkout", "-qb", "topic")
    original = commit(tmp_path, {"app.py": RISK}, "agent original", day=2)
    git(tmp_path, "checkout", "-q", "main")
    commit(tmp_path, {"unrelated.py": "count = 1\n"}, "target progresses", actor="human", day=3)
    if method == "squash":
        git(tmp_path, "merge", "--squash", "topic")
        integration = commit(tmp_path, {}, "squashed integration", actor="human", day=4)
    else:
        git(tmp_path, "checkout", "-q", "topic")
        git(tmp_path, "rebase", "main", day=4)
        integration = git(tmp_path, "rev-parse", "HEAD")
        git(tmp_path, "checkout", "-q", "main")
        git(tmp_path, "merge", "--ff-only", "topic")
    repair = commit(tmp_path, {"app.py": SAFE}, "target human repair", actor="human", day=5)
    result = pipeline(tmp_path, repair, [original], merge=integration, merge_day=4)
    row = result["candidates"][0]
    assert original != integration
    assert row["pr_to_target_mapping"] == "metadata_integration_sha"
    assert row["behavior_present_at_integration"] is True
    assert row["integration_sha"] == integration
    assert row["fix_sha"] == repair
    assert row["risk_introducer_type"] == "agent"
    assert len(result["log_changes"]) == 1


def test_rename_out_of_order_author_date_and_unrelated_edit(tmp_path):
    init(tmp_path)
    intro = commit(tmp_path, {"auth.py": RISK}, "initial", day=6)
    git(tmp_path, "mv", "auth.py", "login.py")
    moved = commit(tmp_path, {}, "rename", day=7)
    repair = commit(tmp_path, {"login.py": SAFE}, "human fix with earlier date", actor="human", day=3)
    irrelevant = commit(tmp_path, {"login.py": SAFE + "\ndef unrelated():\n    return 1\n"}, "unrelated", day=8)
    result = pipeline(tmp_path, irrelevant, [intro])
    assert {f["followup_sha"] for f in result["followups"]} == {moved, repair}
    assert result["candidates"][0]["fix_sha"] == repair
    assert result["candidates"][0]["censoring_reason"] == "nonmonotonic_commit_time"
    assert not any(e["sha"] == irrelevant for e in result["detected"]["events"])


def test_later_data_model_activation_has_distinct_risk_introducer(tmp_path):
    init(tmp_path)
    code = HEADER + 'from models import User\ndef run(user: User):\n    logger.info("user %s", vars(user))\n'
    model = 'from dataclasses import dataclass\n@dataclass\nclass User:\n    id: int\n'
    initial = commit(tmp_path, {"app.py": code, "models.py": model}, "safe object log", day=2)
    activation = commit(tmp_path, {"models.py": model + "    password: str\n"}, "model gains secret", actor="human", day=3)
    repair = commit(tmp_path, {"app.py": code.replace("vars(user)", '{"id": user.id}')}, "allowlist", day=4)
    result = pipeline(tmp_path, repair, [initial])
    row = result["candidates"][0]
    assert row["log_added_sha"] == initial
    assert row["sensitive_flow_introduced_sha"] == activation
    assert row["introduction_relation"] == "later_activated"
    assert row["risk_introducer_type"] == "human_led"
    assert row["fix_sha"] == repair


def test_one_hop_cross_file_fix_and_indirect_initial_change(tmp_path):
    init(tmp_path)
    code = HEADER + 'from serialization import serialize\ndef run():\n    user = {"id": 1, "password": "DUMMY_RESEARCH_SECRET_NOT_VALID"}\n    logger.info("user %s", serialize(user))\n'
    safe = 'def serialize(user):\n    return {"id": user["id"]}\n'
    commit(tmp_path, {"app.py": code, "serialization.py": safe}, "already safe wrapper", day=2)
    intro = commit(tmp_path, {"serialization.py": "def serialize(user):\n    return user\n"}, "only serializer changed", day=3)
    repair = commit(tmp_path, {"serialization.py": safe}, "human narrows fields", actor="human", day=4)
    result = pipeline(tmp_path, repair, [intro])
    row = result["candidates"][0]
    assert row["relation"] == "dependency_change"
    assert row["before"]["statement"] == row["after"]["statement"]
    assert row["fix_sha"] == repair
    assert row["fix_effect"] == "eliminates_observed_flow"


def test_level_change_without_configuration_is_not_a_confirmed_fix(tmp_path):
    init(tmp_path)
    intro = commit(tmp_path, {"app.py": RISK}, "risky", day=2)
    change = commit(tmp_path, {"app.py": RISK.replace("logger.info", "logger.debug")}, "lower level", actor="human", day=3)
    result = pipeline(tmp_path, change, [intro])
    assert result["followups"][0]["fix_effect"] == "unknown"
    assert "level_or_condition_change" in result["followups"][0]["followup_change_types"]
    assert result["candidates"][0]["privacy_assessment"] == "supported"
    assert result["candidates"][0]["fix_sha"] is None


def test_merge_resolution_only_log_is_retained_in_initial_pr_scope(tmp_path):
    init(tmp_path)
    commit(tmp_path, {"app.py": 'value = "base"\n'}, "shared base", day=2)
    git(tmp_path, "checkout", "-qb", "topic")
    original = commit(tmp_path, {"app.py": 'value = "topic"\n'}, "agent nonlog change", day=3)
    git(tmp_path, "checkout", "-q", "main")
    commit(tmp_path, {"app.py": 'value = "main"\n'}, "human nonlog change", actor="human", day=4)
    git(tmp_path, "merge", "--no-ff", "topic", "-m", "merge conflict", check=False)
    merged = commit(tmp_path, {"app.py": RISK}, "resolution adds log", actor="human", day=5)
    result = pipeline(tmp_path, merged, [original], merge=merged, merge_day=5)
    assert len(result["log_changes"]) == 1
    row = result["log_changes"][0]
    assert row["intro_sha"] == merged
    assert row["risk_introducer_type"] == "human_led"
    assert "pydriller.Git.diff" in row["diff_backend"]


def test_nonprivacy_log_and_unknown_author_followup_are_retained(tmp_path):
    init(tmp_path)
    original = commit(tmp_path, {"app.py": SAFE}, "safe agent log", day=2)
    changed = commit(tmp_path, {"app.py": SAFE.replace("user=%s", "user state=%s")},
                     "unknown author reformats safe log", actor="unverified", day=3)
    result = pipeline(tmp_path, changed, [original])
    assert len(result["log_changes"]) == len(result["followups"]) == 1
    assert result["followups"][0]["fix_executor_type"] == "unknown"
    assert result["followups"][0]["fix_effect"] == "not_privacy_related"
    assert result["candidates"][0]["privacy_assessment"] == "not_supported"


def test_multiple_repairs_keep_final_sha_effect_and_actor_together(tmp_path):
    init(tmp_path)
    risky = RISK.replace('"active": True,', '"email": "fixture@example.invalid",')
    initial = commit(tmp_path, {"app.py": risky}, "two sensitive data types", day=2)
    partial_source = HEADER + 'payload = {"email": "fixture@example.invalid"}\nlogger.info("user=%s", payload)\n'
    partial = commit(tmp_path, {"app.py": partial_source}, "human removes credential only", actor="human", day=3)
    final = commit(tmp_path, {"app.py": SAFE}, "agent removes remaining personal field", actor="agent", day=4)
    result = pipeline(tmp_path, final, [initial])
    row = result["candidates"][0]
    assert [f["fix_effect"] for f in result["followups"]] == ["partial", "eliminates_observed_flow"]
    assert row["first_mitigation_sha"] == partial
    assert row["first_eliminated_flow_sha"] == final
    assert row["fix_sha"] == final
    assert row["pre_fix_sha"] == partial
    assert row["fix_executor_type"] == "agent"
    assert row["fix_effect"] == "eliminates_observed_flow"
