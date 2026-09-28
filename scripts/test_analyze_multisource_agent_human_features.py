import unittest

from analyze_multisource_agent_human_features import (
    FEATURES,
    extract_features,
    paired_statistics,
    severity,
    sign_flip_p,
)


class MultisourceFeatureRetryTest(unittest.TestCase):
    def test_extracts_logger_shape_without_using_source_identity(self):
        features = extract_features(
            'logger.info("user_id=%s", user_id)', "identity_session_data;whole_object_dump"
        )
        self.assertEqual(features["structured_logger_sink"], 1)
        self.assertEqual(features["severity_info"], 1)
        self.assertEqual(features["dynamic_value"], 1)
        self.assertEqual(features["key_value_message"], 1)
        self.assertEqual(features["identity_session_data"], 1)

    def test_console_object_is_unstructured_dynamic_metadata(self):
        features = extract_features('console.error("failed", { error })', "error_diagnostic_data")
        self.assertEqual(features["unstructured_stdio"], 1)
        self.assertEqual(features["severity_error"], 1)
        self.assertEqual(features["structured_metadata_argument"], 1)
        self.assertEqual(features["dynamic_value"], 1)

    def test_literal_print_is_neutral_and_literal_only(self):
        features = extract_features('print("ok")')
        self.assertEqual(features["severity_neutral"], 1)
        self.assertEqual(features["literal_only"], 1)
        self.assertEqual(features["dynamic_value"], 0)

    def test_severity_priority_is_deterministic(self):
        self.assertEqual(severity('logger.critical("debug failed")'), "fatal")

    def test_template_and_concatenation_are_dynamic(self):
        self.assertEqual(extract_features('console.log(`user=${user}`)')["dynamic_value"], 1)
        self.assertEqual(extract_features('logger.info("user=" + user)')["dynamic_value"], 1)

    def test_exact_sign_flip(self):
        self.assertEqual(sign_flip_p([1.0, 1.0], 100, 1), 0.5)

    def test_github_primary_analysis_excludes_sensitivity_only_pair(self):
        rows = []
        for provenance in ("agent", "human"):
            rows.append({
                "dataset": "GitHub-matched-PR", "provenance": provenance,
                "analysis_pair_id": "pair", "match_tier": "same_repository", "repo": "acme/repo",
                "analysis_eligibility": "sensitivity_only",
                **{feature: 0.0 for feature in FEATURES},
            })
        primary = paired_statistics(rows, "GitHub-matched-PR", 10, 1, primary_only=True)
        sensitivity = paired_statistics(rows, "GitHub-matched-PR", 10, 1)
        self.assertEqual(primary[FEATURES[0]]["n_pairs"], 0)
        self.assertEqual(sensitivity[FEATURES[0]]["n_pairs"], 1)


if __name__ == "__main__":
    unittest.main()
