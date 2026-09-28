import unittest

from scripts.analyze_swe_chat_blind_privacy_audit import bootstrap_effects, fisher_two_sided, repository_sensitivity


class SWEChatBlindAuditAnalysisTest(unittest.TestCase):
    def test_fisher_exact_is_symmetric_and_bounded(self):
        self.assertAlmostEqual(fisher_two_sided(8, 2, 2, 8), fisher_two_sided(2, 8, 8, 2))
        self.assertLess(fisher_two_sided(8, 2, 2, 8), 0.05)
        self.assertEqual(fisher_two_sided(1, 1, 1, 1), 1.0)

    def test_bootstrap_is_deterministic(self):
        args = ([True, False, True], [False, False, True], 0.2, 0.3, 100, 7)
        self.assertEqual(bootstrap_effects(*args), bootstrap_effects(*args))

    def test_repository_sensitivity_detects_top_repo_concentration(self):
        rows = []
        for side, repo, values in (
            ("agent_only", "large", [True, True]),
            ("agent_only", "common", [False]),
            ("human_only", "common", [False]),
            ("human_only", "other", [False]),
        ):
            rows.extend({
                "attribution": side, "repo": repo,
                "decision": "YES" if value else "NO", "type": "AGENT_CTX" if value else "NONE",
            } for value in values)
        result = {row["outcome"]: row for row in repository_sensitivity(rows, 100, 7)}["type_AGENT_CTX"]
        self.assertEqual(result["agent_top_positive_repo"], "large")
        self.assertEqual(result["agent_top_positive_repo_share"], 1.0)
        self.assertFalse(result["repository_robust_direction"])


if __name__ == "__main__":
    unittest.main()
