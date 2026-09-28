import unittest

from scripts.extract_swe_chat_full_log_evidence import classify_path, classify_sink, reconstruct_statement, redact


class SWEChatEvidenceExtractionTest(unittest.TestCase):
    def test_reconstructs_multiline_statement_at_new_file_line(self):
        source = """before();
console.error(
  "Response body:",
  response.data,
);
after();
"""
        value = reconstruct_statement(source, 2, "console.error(")
        self.assertEqual(value["statement_lines"], 4)
        self.assertTrue(value["statement_complete"])
        self.assertTrue(value["line_matches_original"])
        self.assertIn("response.data", value["statement"])
        self.assertEqual(value["context"], "before();")

    def test_out_of_range_line_falls_back_without_claiming_match(self):
        value = reconstruct_statement("one();", 9, "logger.info(")
        self.assertEqual(value["statement_source"], "single_line_fallback")
        self.assertFalse(value["line_matches_original"])
        self.assertFalse(value["statement_complete"])

    def test_redaction_keeps_type_marker(self):
        value = redact("user@example.com 10.2.3.4 sk-abcdefghijklmnopqrstuvwxyz1234")
        self.assertIn("[REDACTED_EMAIL]", value)
        self.assertIn("[REDACTED_IP]", value)
        self.assertIn("[REDACTED_SECRET]", value)

    def test_comment_and_embedded_sink_are_not_executable_logs(self):
        self.assertFalse(classify_sink("# do not echo the payload", "app.py")[1])
        self.assertFalse(classify_sink('API_KEY=$(node -e "console.log(data.apiKey)")', "setup.sh")[1])
        self.assertTrue(classify_sink('console.log("ready", port)', "server.ts")[1])

    def test_agent_tooling_and_docs_are_separate_from_production(self):
        self.assertEqual(classify_path(".claude/hooks/session.py"), "agent_tooling")
        self.assertEqual(classify_path("docs/bundle.js"), "nonproduction")
        self.assertEqual(classify_path("src/server.ts"), "production")


if __name__ == "__main__":
    unittest.main()
