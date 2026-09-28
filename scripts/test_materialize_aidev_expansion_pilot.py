import unittest

from materialize_aidev_expansion_pilot import evaluate, fetch_diff


AGENT_DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1,2 @@
+value = 1
+print(value)
"""
HUMAN_DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1 @@
+value = 2
"""


class MaterializePilotTests(unittest.TestCase):
    def test_accepts_nonidentical_production_diffs_within_caliper(self):
        metrics, reason = evaluate(AGENT_DIFF, HUMAN_DIFF, 10)
        self.assertEqual(reason, "")
        self.assertGreater(metrics["agent_size"], 0)

    def test_rejects_identical_diffs(self):
        _, reason = evaluate(AGENT_DIFF, AGENT_DIFF, 10)
        self.assertEqual(reason, "identical_final_diff")

    def test_rejects_size_outlier(self):
        large = AGENT_DIFF.replace("+value = 1", "+value = 1\n" + "+x = 1\n" * 20)
        _, reason = evaluate(large, HUMAN_DIFF, 2)
        self.assertEqual(reason, "final_size_caliper")

    def test_retries_rate_limit_only(self):
        class Client:
            calls = 0

            def get_text(self, _url):
                self.calls += 1
                if self.calls < 3:
                    raise RuntimeError("GitHub diff HTTP 429")
                return "diff", {}

        client = Client()
        self.assertEqual(fetch_diff(client, "https://github.com/o/r/pull/1", 3, 0), "diff")
        self.assertEqual(client.calls, 3)


if __name__ == "__main__":
    unittest.main()
