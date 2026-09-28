import unittest

from scripts.prepare_aidev_blind_manual_context import source_window


class BlindContextTests(unittest.TestCase):
    def test_extracts_added_target_without_provenance(self):
        diff = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1,2 @@\n old\n+print(value)\n"
        status, context = source_window(diff, "x.py", 2, 1)
        self.assertEqual(status, "FOUND_REDACTED_WINDOW")
        self.assertIn("print(value)", context)


if __name__ == "__main__":
    unittest.main()
