import unittest

from plan_swe_chat_matched_power import (
    minimum_detectable_effect,
    normal_approx_power,
    required_pairs,
)


class MatchedPowerPlanTests(unittest.TestCase):
    def test_power_increases_with_pairs_and_effect(self):
        self.assertLess(
            normal_approx_power(100, 0.05, 0.25, 0.025),
            normal_approx_power(500, 0.05, 0.25, 0.025),
        )
        self.assertLess(
            normal_approx_power(200, 0.05, 0.25, 0.025),
            normal_approx_power(200, 0.10, 0.25, 0.025),
        )

    def test_required_pairs_is_minimal(self):
        required = required_pairs(0.05, 0.25, 0.80, 0.025)
        self.assertIsNotNone(required)
        self.assertGreaterEqual(normal_approx_power(required, 0.05, 0.25, 0.025), 0.80)
        self.assertLess(normal_approx_power(required - 1, 0.05, 0.25, 0.025), 0.80)

    def test_mde_hits_target_when_attainable(self):
        mde = minimum_detectable_effect(500, 0.25, 0.80, 0.025)
        self.assertIsNotNone(mde)
        self.assertAlmostEqual(normal_approx_power(500, mde, 0.25, 0.025), 0.80, places=9)

    def test_mde_reports_unattainable_target(self):
        self.assertIsNone(minimum_detectable_effect(5, 0.01, 0.90, 0.025))

    def test_invalid_effect_is_rejected(self):
        with self.assertRaises(ValueError):
            normal_approx_power(100, 0.30, 0.25, 0.025)


if __name__ == "__main__":
    unittest.main()
