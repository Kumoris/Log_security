import unittest

from scripts.match_aidev_human_prs import best_match, human_exclusion_reason
from scripts.build_aidev_primary_queue import ranked_agent_candidates


class AIDevHumanMatchingTest(unittest.TestCase):
    def test_best_match_respects_size_date_and_uniqueness(self):
        human = {"created_at": "2025-03-01T00:00:00Z", "size": 20}
        agents = [
            {"id": 1, "created_at": "2025-02-28T00:00:00Z", "size": 200},
            {"id": 2, "created_at": "2025-02-20T00:00:00Z", "size": 22},
        ]
        agent, metrics = best_match(human, agents, set(), 180, 10)
        self.assertEqual(agent["id"], 2)
        self.assertLess(metrics["size_ratio"], 1.1)
        self.assertIsNone(best_match(human, agents, {1, 2}, 180, 10))

    def test_excludes_agent_overlap_bots_and_explicit_ai_markers(self):
        self.assertEqual(
            human_exclusion_reason({"html_url": "https://example/pr/1"}, {"https://example/pr/1"}),
            "canonical_pr_also_in_agent_table",
        )
        self.assertEqual(human_exclusion_reason({"user": "dependabot[bot]"}, set()), "bot_login")
        self.assertEqual(
            human_exclusion_reason({"body": "Generated with Claude Code"}, set()),
            "explicit_ai_assistance_marker",
        )

    def test_primary_ranking_does_not_use_log_outcomes(self):
        human = {"created_at": "2025-03-01T00:00:00Z", "size": 20}
        agents = [
            {"id": 1, "created_at": "2025-02-28T00:00:00Z", "size": 21, "n_logs": 0},
            {"id": 2, "created_at": "2025-02-28T00:00:00Z", "size": 22, "n_logs": 99},
            {"id": 3, "created_at": "2020-01-01T00:00:00Z", "size": 20, "n_logs": 0},
        ]
        ranked = ranked_agent_candidates(human, agents, set(), 180)
        self.assertEqual([row["id"] for row in ranked], [1, 2])
        self.assertEqual(
            [row["id"] for row in ranked_agent_candidates(human, agents, {1}, 180)], [2]
        )


if __name__ == "__main__":
    unittest.main()
