import unittest
from datetime import date
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.mine_github_log_lineage import (
    LINEAGE_FIELDS,
    apply_human_verification,
    classify_lineage,
    _search_humans,
    diff_profile,
    is_human_pr,
    match_human_prs,
    verify_cohort,
)


class LineageRulesTest(unittest.TestCase):
    def test_unsearchable_repository_yields_no_human_candidates(self):
        with TemporaryDirectory() as directory:
            class MissingRepoClient:
                base_url = "https://api.github.com"
                refresh = False
                cache = Path(directory) / "missing.json"

                @classmethod
                def _cache_path(cls, url):
                    return cls.cache

                @staticmethod
                def get_json(url):
                    raise RuntimeError("GitHub API HTTP 422: repository cannot be searched")

            agents = [{"pr_key": "gone/repo#1", "repo": "gone/repo"}]
            self.assertEqual(
                _search_humans(agents, MissingRepoClient(), date(2026, 1, 1), date(2026, 8, 19), 0),
                [],
            )
            self.assertEqual(json.loads(MissingRepoClient.cache.read_text())["data"], {"items": []})

    def test_transient_search_timeout_is_retried(self):
        class FlakyClient:
            base_url = "https://api.github.com"
            refresh = False
            calls = 0

            @staticmethod
            def _cache_path(url):
                return Path("/definitely/not/cached")

            @classmethod
            def get_json(cls, url):
                cls.calls += 1
                if cls.calls == 1:
                    raise RuntimeError("GitHub API request failed: handshake timed out")
                return {"items": []}, {}

        agents = [{"pr_key": "live/repo#1", "repo": "live/repo"}]
        self.assertEqual(
            _search_humans(agents, FlakyClient(), date(2026, 1, 1), date(2026, 8, 19), 0),
            [],
        )
        self.assertEqual(FlakyClient.calls, 2)

    def test_diff_profile_counts_production_source_changes_and_added_logs(self):
        diff = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,3 @@
-old()
+new()
+logger.info("token=%s", token)
 keep()
diff --git a/tests/test_app.py b/tests/test_app.py
--- a/tests/test_app.py
+++ b/tests/test_app.py
@@ -1 +1,2 @@
 pass
+print(response)
"""
        profile = diff_profile(diff)
        self.assertEqual(profile["added_lines"], 2)
        self.assertEqual(profile["deleted_lines"], 1)
        self.assertEqual(profile["source_files"], 2)
        self.assertEqual(profile["production_source_files"], 1)
        self.assertEqual(profile["extensions"], [".py"])
        self.assertEqual(
            [(row["file"], row["line"], row["path_scope"]) for row in profile["logs"]],
            [("src/app.py", 2, "production"), ("tests/test_app.py", 2, "non_production")],
        )

    def test_human_pr_requires_merged_user_and_excludes_agent_sample(self):
        item = {
            "number": 7,
            "html_url": "https://github.com/acme/repo/pull/7",
            "user": {"login": "alice", "type": "User"},
            "pull_request": {"merged_at": "2026-07-20T00:00:00Z"},
        }
        self.assertTrue(is_human_pr(item, {"acme/repo#8"}, "acme/repo"))
        self.assertFalse(is_human_pr({**item, "user": {"login": "bot", "type": "Bot"}}, set(), "acme/repo"))
        self.assertFalse(is_human_pr({**item, "performed_via_github_app": {"slug": "agent"}}, set(), "acme/repo"))
        self.assertFalse(is_human_pr(item, {"acme/repo#7"}, "acme/repo"))

    def test_matching_is_same_repo_unique_and_deterministic(self):
        agents = [
            {
                "pr_key": "acme/repo#10", "repo": "acme/repo", "created_at": "2026-08-01T00:00:00Z",
                "base_sha": "base10", "head_sha": "head10", "head_tree_sha": "tree10",
                "pr_diff_sha256": "a" * 64, "provenance_grade": "C",
            },
            {"pr_key": "acme/repo#11", "repo": "acme/repo", "created_at": "2026-08-02T00:00:00Z"},
        ]
        humans = [
            {
                "pr_key": "acme/repo#20", "repo": "acme/repo",
                "created_at": "2026-07-31T00:00:00Z", "actor_type": "User",
            },
            {
                "pr_key": "acme/repo#21", "repo": "acme/repo",
                "created_at": "2026-08-03T00:00:00Z", "actor_type": "User",
            },
        ]
        profiles = {
            "acme/repo#10": {"added_lines": 10, "deleted_lines": 2, "production_source_files": 1, "extensions": [".py"]},
            "acme/repo#11": {"added_lines": 100, "deleted_lines": 20, "production_source_files": 4, "extensions": [".ts"]},
            "acme/repo#20": {"added_lines": 11, "deleted_lines": 2, "production_source_files": 1, "extensions": [".py"]},
            "acme/repo#21": {"added_lines": 95, "deleted_lines": 18, "production_source_files": 4, "extensions": [".ts"]},
        }
        pairs = match_human_prs(agents, humans, profiles)
        self.assertEqual(
            [(row["agent_pr_key"], row["human_pr_key"]) for row in pairs],
            [("acme/repo#10", "acme/repo#20"), ("acme/repo#11", "acme/repo#21")],
        )
        first = pairs[0]
        self.assertEqual(first["agent_base_sha"], "base10")
        self.assertEqual(first["agent_head_sha"], "head10")
        self.assertEqual(first["agent_head_tree_sha"], "tree10")
        self.assertEqual(first["agent_pr_diff_sha256"], "a" * 64)
        self.assertEqual(first["agent_provenance_grade"], "C")
        self.assertEqual(first["human_provenance_tier"], "human_likely")
        self.assertEqual(first["pair_analysis_eligibility"], "sensitivity_only")
        self.assertEqual(verify_cohort(pairs, agents, humans, expected=2), [])

    def test_verified_human_and_merged_bound_agent_make_primary_same_repo_pair(self):
        agent = {
            "pr_key": "acme/repo#1", "repo": "acme/repo", "created_at": "2026-08-01T00:00:00Z",
            "analysis_eligibility": "provenance_primary",
        }
        human = apply_human_verification(
            [{"pr_key": "acme/repo#2", "repo": "acme/repo", "created_at": "2026-08-02T00:00:00Z"}],
            {"acme/repo#2": {
                "verification_method": "signed_declaration", "evidence_ref": "local/evidence",
                "evidence_sha256": "a" * 64, "verified_at": "2026-08-03T00:00:00Z",
            }},
        )[0]
        profile = {"added_lines": 1, "deleted_lines": 0, "production_source_files": 1, "extensions": [".py"]}
        pair = match_human_prs([agent], [human], {agent["pr_key"]: profile, human["pr_key"]: profile})[0]
        self.assertEqual(pair["human_provenance_tier"], "human_verified")
        self.assertEqual(pair["pair_analysis_eligibility"], "provenance_primary")

    def test_lineage_schema_carries_pr_snapshot_and_binding_fields(self):
        self.assertTrue({
            "base_sha", "pr_head_sha", "head_tree_sha", "pr_diff_sha256",
            "provenance_grade", "generation_stage", "binding_status", "line_authorship_proof",
        } <= set(LINEAGE_FIELDS))

    def test_matching_falls_back_across_repositories_and_labels_the_tier(self):
        agents = [{
            "pr_key": "agent/repo#1", "repo": "agent/repo",
            "created_at": "2026-08-01T00:00:00Z",
        }]
        humans = [{
            "pr_key": "control/repo#2", "repo": "control/repo",
            "created_at": "2026-08-02T00:00:00Z", "actor_type": "User",
        }]
        profile = {"added_lines": 5, "deleted_lines": 1, "production_source_files": 1, "extensions": [".py"]}
        pairs = match_human_prs(
            agents,
            humans,
            {"agent/repo#1": profile, "control/repo#2": profile},
        )
        self.assertEqual(pairs[0]["human_repo"], "control/repo")
        self.assertEqual(pairs[0]["match_tier"], "cross_repository")
        self.assertEqual(verify_cohort(pairs, agents, humans, expected=1), [])

    def test_lineage_status_uses_current_presence_then_first_change_diff(self):
        self.assertEqual(classify_lineage(True, "", "src/app.py")["status"], "PRESENT_AT_CURRENT_HEAD")
        modified = '-logger.info("x=%s", value)\n+logger.debug("x=%s", value)\n'
        self.assertEqual(classify_lineage(False, modified, "src/app.py")["status"], "MODIFIED_AFTER_MERGE")
        self.assertEqual(
            classify_lineage(False, '-logger.info("x=%s", value)\n', "src/app.py")["status"],
            "DELETED_AFTER_MERGE",
        )
        self.assertEqual(classify_lineage(False, "", "src/app.py")["status"], "UNRESOLVED")


if __name__ == "__main__":
    unittest.main()
