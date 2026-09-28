import unittest

from scripts.analyze_aidev_primary_queue import (
    bh_adjust,
    cluster_bootstrap,
    exact_mcnemar,
    wilson,
)


class PrimaryAnalysisTest(unittest.TestCase):
    def test_statistical_helpers_are_bounded_and_reproducible(self):
        low, high = wilson(43, 300)
        self.assertLess(low, 43 / 300)
        self.assertGreater(high, 43 / 300)
        self.assertAlmostEqual(exact_mcnemar(23, 35), exact_mcnemar(35, 23))
        adjusted = bh_adjust([0.01, 0.04, 0.20])
        self.assertEqual(adjusted, sorted(adjusted))
        rows = [
            {"repo": "a", "agent": 1, "human": 0},
            {"repo": "b", "agent": 0, "human": 1},
        ]
        first = cluster_bootstrap(rows, lambda row: row["agent"], lambda row: row["human"], 100, 7)
        second = cluster_bootstrap(rows, lambda row: row["agent"], lambda row: row["human"], 100, 7)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
