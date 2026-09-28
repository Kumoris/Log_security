import unittest

from scripts.audit_aidev_combined_cohort import audit_sample, categorical_shift


class CombinedAuditTests(unittest.TestCase):
    def test_shift_and_manual_sample_are_deterministic(self):
        _, summary = categorical_shift(
            [{"language": "A"}, {"language": "B"}],
            [{"language": "A"}], "x", "agent", ("language",),
        )
        self.assertAlmostEqual(summary[0]["total_variation_distance"], 0.5)
        rows = [
            {"evidence_id": str(i), "cohort": "c", "pair_id": str(i), "provenance": side,
             "repo": "r", "pr_key": f"r#{i}", "file": "x.py", "line": str(i),
             "path_scope": "production", "risk_features": "unstructured_stdio" if i % 2 else "",
             "log_concepts": "", "log_text_redacted": f"print({i})"}
            for side in ("agent", "human") for i in range(4)
        ]
        first = audit_sample(rows, 2, 7)
        second = audit_sample(rows, 2, 7)
        self.assertEqual(first, second)
        self.assertEqual(len(first[0]), 4)


if __name__ == "__main__":
    unittest.main()
