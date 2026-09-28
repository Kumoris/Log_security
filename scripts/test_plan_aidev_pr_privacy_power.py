import unittest

from plan_aidev_pr_privacy_power import build_plan, strict_outcome


class AIDevPrPowerTests(unittest.TestCase):
    def test_strict_outcome_and_capacity_are_kept_separate(self):
        audit = {"statistics": [{
            "outcome": "strict_static_sensitive", "n_pairs": 300, "agent_n": 6,
            "human_n": 4, "agent_only": 5, "human_only": 3, "effect": 2 / 300,
        }]}
        capacity = {"aidev_default_scenario": {"metadata_feasible_total_pairs": 950}}
        observed, scenarios = build_plan(audit, capacity, 1.5)
        self.assertEqual(strict_outcome(audit)["agent_only"], 5)
        self.assertEqual(observed["local_metadata_capacity_pairs"], 950)
        self.assertFalse(observed["local_capacity_can_detect_observed_effect"])
        self.assertTrue(any(row["within_local_metadata_capacity_80"] for row in scenarios))


if __name__ == "__main__":
    unittest.main()
