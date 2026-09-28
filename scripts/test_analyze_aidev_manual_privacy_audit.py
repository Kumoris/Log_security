import unittest

from scripts.analyze_aidev_manual_privacy_audit import apply_labels, paired_rows


class AIDevManualAuditTest(unittest.TestCase):
    def test_hash_guard_and_pair_aggregation(self):
        queue = [{
            "pair_id": "p", "provenance": "agent", "repo": "r", "pr_key": "r#1",
            "statement_redacted": "log.info(user_id)", "privacy_features": "personal_session_value",
        }]
        import hashlib
        digest = hashlib.sha256(queue[0]["statement_redacted"].encode()).hexdigest()[:16]
        doc = {"labels": [{
            "row": 1, "statement_sha256_16": digest, "decision": "YES", "type": "QID",
            "value_form": "DIRECT_VALUE", "severity": "S2", "notes": "id",
        }]}
        annotated = apply_labels(queue, doc)
        values = paired_rows([{"pair_id": "p", "repo": "r"}], annotated)
        self.assertTrue(values[0]["agent_strict_static_sensitive"])
        self.assertFalse(values[0]["human_strict_static_sensitive"])
        self.assertTrue(values[0]["agent_type_QID"])

    def test_rejects_statement_drift(self):
        with self.assertRaises(ValueError):
            apply_labels([{"statement_redacted": "changed"}], {"labels": [{
                "row": 1, "statement_sha256_16": "bad", "decision": "NO", "type": "NONE",
                "value_form": "NO_VALUE", "severity": "S1", "notes": "",
            }]})


if __name__ == "__main__":
    unittest.main()
