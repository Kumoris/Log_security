import unittest

from scripts.prepare_swe_chat_blind_privacy_audit import prepare, source_hash


class BlindAuditPreparationTests(unittest.TestCase):
    def rows(self):
        base = {
            "repo": "owner/repo", "commit": "abc", "checkpoint_pk": "1",
            "file": "src/app.ts", "line": "12", "path_scope": "production",
            "sink_family": "console", "evidence_grade": "A", "statement_lines": "1",
            "privacy_features": "whole_object_dump", "mechanism_features": "",
            "static_privacy_candidate": "true", "dynamic_values_redacted": "value",
            "statement_redacted": "console.log(value)", "context_redacted": "const value = body",
        }
        return [{**base, "attribution": side, "commit": str(i)} for i, side in enumerate(
            ("agent_only", "human_only", "mixed"), 1
        )]

    def test_blind_sheet_omits_provenance_and_automated_labels(self):
        review, key = prepare(self.rows(), 7)
        self.assertEqual(len(review), 3)
        self.assertEqual(len(key), 3)
        for row in review:
            self.assertNotIn("attribution", row)
            self.assertNotIn("repo", row)
            self.assertNotIn("privacy_features", row)
            self.assertEqual(row["manual_runtime_reachable"], "UNKNOWN")

    def test_order_and_mapping_are_deterministic(self):
        review_a, key_a = prepare(self.rows(), 20260805)
        review_b, key_b = prepare(self.rows(), 20260805)
        self.assertEqual(review_a, review_b)
        self.assertEqual(key_a, key_b)
        self.assertEqual({r["blind_id"] for r in review_a}, {r["blind_id"] for r in key_a})
        self.assertEqual(key_a[0]["source_sha256_16"], source_hash(self.rows()[int(key_a[0]["source_row"]) - 1]))


if __name__ == "__main__":
    unittest.main()
