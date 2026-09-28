import unittest

from scripts.analyze_aidev_log_privacy_semantics import (
    dynamic_values,
    log_statements,
    semantic_features,
)


class ValueAwarePrivacyTest(unittest.TestCase):
    def test_multiline_log_statement_is_joined(self):
        diff = """diff --git a/src/app.ts b/src/app.ts
--- a/src/app.ts
+++ b/src/app.ts
@@ -1,1 +1,5 @@
+console.error("Response:", {
+  body: response.data,
+  headers: response.headers,
+});
 keep();
"""
        rows = log_statements(diff)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["statement_lines"], 4)
        features = semantic_features(rows[0]["statement"], rows[0]["context"])
        self.assertIn("raw_request_response", features["privacy_features"])
        self.assertIn("whole_object_dump", features["privacy_features"])
        self.assertIn("multiline_statement", features["mechanism_features"])

    def test_example_path_is_excluded_from_production_analysis(self):
        diff = """diff --git a/examples/demo.py b/examples/demo.py
--- a/examples/demo.py
+++ b/examples/demo.py
@@ -0,0 +1 @@
+logger.info("token=%s", token)
"""
        self.assertEqual(log_statements(diff), [])

    def test_alias_from_response_body_is_resolved(self):
        diff = """diff --git a/src/app.ts b/src/app.ts
--- a/src/app.ts
+++ b/src/app.ts
@@ -1,1 +1,4 @@
+const errText = await res.text();
+if (!res.ok) {
+  console.error("Response body:", errText);
+}
 keep();
"""
        row = log_statements(diff)[0]
        features = semantic_features(row["statement"], row["context"])
        self.assertIn("raw_request_response", features["privacy_features"])
        self.assertIn("whole_object_dump", features["privacy_features"])
        self.assertIn("alias_derived_sensitive_value", features["mechanism_features"])
        self.assertIn("error_or_exception_branch", features["mechanism_features"])

    def test_status_only_and_static_secret_label_are_not_privacy_values(self):
        status = semantic_features(
            "console.error(`GitHub API request failed: ${res.status} ${res.statusText}`);",
            "const res = await fetch(url, { headers: HEADERS });",
        )
        label = semantic_features('logger.error("API token is missing")', "")
        self.assertFalse(status["static_privacy_candidate"])
        self.assertFalse(label["static_privacy_candidate"])

    def test_safe_counts_and_boolean_presence_do_not_expose_contents(self):
        features = semantic_features(
            "console.log('Request summary', { messageCount: req.body.messages.length, hasAuth: !!req.headers.authorization });",
            "",
        )
        self.assertNotIn("credential_auth_value", features["privacy_features"])
        self.assertNotIn("agent_tool_context_value", features["privacy_features"])
        self.assertNotIn("raw_request_response", features["privacy_features"])

    def test_error_message_is_exception_but_not_agent_message(self):
        features = semantic_features("console.error(error.message)", "")
        self.assertIn("exception_stack_value", features["privacy_features"])
        self.assertNotIn("agent_tool_context_value", features["privacy_features"])

    def test_dynamic_credential_is_detected(self):
        values = dynamic_values('logger.info("token=%s", access_token)')
        self.assertIn("access_token", values)
        features = semantic_features('logger.info("token=%s", access_token)', "")
        self.assertIn("credential_auth_value", features["privacy_features"])

    def test_direct_identifier_and_secret_literals_are_candidates(self):
        email = semantic_features('logger.info("contact=user@example.com")', "")
        secret = semantic_features('logger.info("key=sk-abcdefghijklmnopqrstuvwxyz1234")', "")
        redacted_ip = semantic_features('logger.info("host=[REDACTED_IP]")', "")
        self.assertIn("direct_identifier_literal", email["privacy_features"])
        self.assertIn("personal_session_value", email["privacy_features"])
        self.assertIn("credential_auth_value", secret["privacy_features"])
        self.assertIn("configuration_infrastructure_value", redacted_ip["privacy_features"])

    def test_generic_repository_path_is_not_sensitive_configuration(self):
        features = semantic_features("console.error(`${path}: ${info.version}`)", "")
        self.assertNotIn("configuration_infrastructure_value", features["privacy_features"])

    def test_nonsensitive_metric_object_is_not_a_whole_object_dump(self):
        features = semantic_features(
            'console.log("Scroll metrics", { scrollTop, scrollHeight, hasMoreMessages });', ""
        )
        self.assertFalse(features["static_privacy_candidate"])

    def test_request_summary_fields_are_not_raw_request_body(self):
        features = semantic_features(
            "console.log('Request', { model: req.body.model, stream: req.body.stream, requestId });",
            "",
        )
        self.assertNotIn("raw_request_response", features["privacy_features"])
        self.assertNotIn("whole_object_dump", features["privacy_features"])

    def test_unknown_transform_does_not_propagate_raw_source(self):
        features = semantic_features(
            "console.log(summary)",
            "const summary = extractReleaseNotesSummary(prDetails.body)",
        )
        self.assertFalse(features["static_privacy_candidate"])


if __name__ == "__main__":
    unittest.main()
