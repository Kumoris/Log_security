import unittest

from scripts.analyze_swe_chat_log_privacy_semantics import audit_enriched_sample, audit_sample, bh_adjust, lineage_deduplicate, repository_balanced_result, wilson


class SWEChatPrivacyAnalysisTest(unittest.TestCase):
    def test_probability_audit_sample_records_equal_group_inclusion_probability(self):
        rows = []
        for attribution in ("agent_only", "human_only", "mixed"):
            for index in range(5):
                rows.append({
                    "attribution": attribution, "static_privacy_candidate": True,
                    "privacy_features": "credential_auth_value" if index == 0 else "whole_object_dump",
                    "row": str(index),
                })
        sample = audit_sample(rows, 7, per_group=2)
        self.assertEqual(len(sample), 6)
        self.assertTrue(all(row["audit_inclusion_probability"] == 0.4 for row in sample))
        self.assertTrue(all(row["audit_sampling_design"].startswith("simple_random") for row in sample))
        self.assertEqual(sample, audit_sample(rows, 7, per_group=2))

    def test_enriched_audit_sample_is_marked_discovery_only(self):
        rows = [{
            "attribution": attribution, "static_privacy_candidate": True,
            "privacy_features": "credential_auth_value", "row": attribution,
        } for attribution in ("agent_only", "human_only", "mixed")]
        sample = audit_enriched_sample(rows, 7, per_group=1)
        self.assertTrue(all(row["audit_sampling_design"] == "priority_enriched_discovery_only" for row in sample))
        self.assertTrue(all(row["audit_inclusion_probability"] == "" for row in sample))

    def test_wilson_bounds_rate(self):
        low, high = wilson(3, 10)
        self.assertLess(low, 0.3)
        self.assertGreater(high, 0.3)

    def test_bh_is_monotone_in_ranked_order(self):
        adjusted = bh_adjust([0.01, 0.04, 0.03])
        self.assertEqual(adjusted, [0.03, 0.04, 0.04])

    def test_repository_balanced_effect_weights_repositories_equally(self):
        rows = [
            {"repo": "a", "attribution": "agent_only", "static_privacy_candidate": True, "privacy_features": ""},
            {"repo": "a", "attribution": "human_only", "static_privacy_candidate": False, "privacy_features": ""},
            {"repo": "b", "attribution": "agent_only", "static_privacy_candidate": False, "privacy_features": ""},
            {"repo": "b", "attribution": "human_only", "static_privacy_candidate": True, "privacy_features": ""},
        ]
        value = repository_balanced_result(rows, "any_privacy_candidate", "test", 100, 7)
        self.assertEqual(value["n_common_repositories"], 2)
        self.assertAlmostEqual(value["effect_repository_balanced"], 0.0)

    def test_lineage_dedup_drops_attribution_conflict(self):
        base = {"repo": "r", "file": "a.py", "line": "2", "statement_redacted": "log.info(x)"}
        rows = [
            {**base, "commit": "1", "attribution": "agent_only"},
            {**base, "commit": "2", "attribution": "human_only"},
            {**base, "file": "b.py", "commit": "3", "attribution": "agent_only"},
            {**base, "file": "b.py", "commit": "4", "attribution": "agent_only"},
        ]
        output, summary = lineage_deduplicate(rows)
        self.assertEqual(len(output), 1)
        self.assertEqual(summary["attribution_conflicted_fingerprints_excluded"], 1)


if __name__ == "__main__":
    unittest.main()
