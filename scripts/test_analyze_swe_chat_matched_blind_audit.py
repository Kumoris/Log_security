import unittest

from analyze_swe_chat_matched_blind_audit import (
    cluster_bootstrap,
    holm_adjust,
    leave_one_repo_out,
    statistics,
)


def row(decision="NO", semantic_type="NONE"):
    return {"decision": decision, "type": semantic_type}


class MatchedBlindAuditTests(unittest.TestCase):
    def setUp(self):
        self.pairs = [
            {
                "pair_id": "P1",
                "repo": "r1",
                "agent_only": row("YES", "AGENT_CTX"),
                "human_only": row(),
            },
            {
                "pair_id": "P2",
                "repo": "r2",
                "agent_only": row("CARRIER", "DIAG"),
                "human_only": row("YES", "CFG"),
            },
            {
                "pair_id": "P3",
                "repo": "r2",
                "agent_only": row(),
                "human_only": row("CARRIER", "DIAG"),
            },
        ]

    def test_holm_adjustment_is_monotone_in_rank(self):
        adjusted = holm_adjust([0.01, 0.04, 0.03])
        self.assertEqual(adjusted, [0.03, 0.06, 0.06])

    def test_cluster_bootstrap_is_reproducible(self):
        first = cluster_bootstrap(self.pairs, "type_AGENT_CTX", 200, 7)
        second = cluster_bootstrap(self.pairs, "type_AGENT_CTX", 200, 7)
        self.assertEqual(first, second)
        self.assertAlmostEqual(first[0], 1 / 3)

    def test_leave_one_repo_out_reports_extremes(self):
        low, high = leave_one_repo_out(self.pairs, "type_CFG")
        self.assertLessEqual(low, high)
        self.assertEqual((low, high), (-0.5, 0.0))

    def test_statistics_preserve_pairing_and_families(self):
        results = statistics(self.pairs, 200, 11)
        by_name = {result["outcome"]: result for result in results}
        self.assertEqual(len(results), 10)
        self.assertEqual(by_name["type_AGENT_CTX"]["family"], "preregistered_primary")
        self.assertEqual(by_name["type_CFG"]["family"], "preregistered_primary")
        self.assertEqual(by_name["strict_static_sensitive"]["family"], "exploratory_secondary")
        self.assertEqual(by_name["type_AGENT_CTX"]["agent_only"], 1)
        self.assertEqual(by_name["type_AGENT_CTX"]["human_only"], 0)


if __name__ == "__main__":
    unittest.main()
