import unittest

from consolidate_aidev_expansion_evidence import evidence_id, truth


class ConsolidationTests(unittest.TestCase):
    def test_ids_are_stable_and_truth_is_strict(self):
        self.assertEqual(evidence_id("a", "b"), evidence_id("a", "b"))
        self.assertNotEqual(evidence_id("a", "b"), evidence_id("b", "a"))
        self.assertTrue(truth("True"))
        self.assertFalse(truth("unknown"))


if __name__ == "__main__":
    unittest.main()
