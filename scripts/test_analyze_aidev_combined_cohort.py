import unittest

from scripts.analyze_aidev_combined_cohort import subgroup_descriptives


class CombinedAnalysisTests(unittest.TestCase):
    def test_subgroups_use_pr_level_presence(self):
        rows = [
            {"agent_product": "x", "language": "py", "task_type": "fix", "a": i % 2, "h": 0}
            for i in range(20)
        ]
        result = subgroup_descriptives(rows, lambda row: row["a"], lambda row: row["h"])
        self.assertEqual(len(result), 3)
        self.assertTrue(all(row["n_pairs"] == 20 for row in result))
        self.assertTrue(all(row["risk_difference"] == 0.5 for row in result))


if __name__ == "__main__":
    unittest.main()
