import unittest

import pandas as pd

from scripts.mine_agent_unique_log_features import (
    feature_hits,
    filter_devgpt_candidates,
    is_explicit_logging_prompt,
    is_sensitive_tool_probe,
    matched_provenance_units,
    normalized_code,
    sensitive_concepts,
)
from scripts.analyze_devgpt_logs import is_executable_log_line


class AgentFeatureRulesTest(unittest.TestCase):
    def test_agent_control_object_is_distinguished_from_normal_identifier_log(self):
        self.assertEqual(
            feature_hits('logger.info("tool result: %s", tool_result)'),
            {"agent_control_data", "tool_io_data", "whole_object_dump"},
        )
        self.assertEqual(feature_hits('logger.info("job completed: %s", job_id)'), set())
        self.assertEqual(
            feature_hits('logger.info("prompt=%s", prompt)'),
            {"agent_context_data_broad", "whole_object_dump"},
        )
        self.assertEqual(
            feature_hits('logger.info("system prompt=%s", system_prompt)'),
            {"agent_control_data", "agent_context_data_broad", "whole_object_dump"},
        )
        self.assertNotIn("agent_control_data", feature_hits("console.log(response.message)"))

    def test_shared_privacy_features_remain_separate_from_agent_control_data(self):
        self.assertEqual(
            feature_hits('print("DEBUG payload=%s" % payload)'),
            {"request_response_data", "whole_object_dump", "unstructured_stdio", "debug_residue_marker"},
        )
        self.assertEqual(
            feature_hits('logger.info("session=%s user=%s", session_id, user_id)'),
            {"identity_session_data", "whole_object_dump"},
        )
        self.assertEqual(
            feature_hits('logger.exception("request failed", exc)'),
            {"request_response_data", "error_diagnostic_data"},
        )

    def test_sensitive_concepts_are_shared_across_prompt_and_log_text(self):
        prompt = "Please diagnose the request headers without printing the token."
        log = 'logger.debug("headers=%s", request.headers)'
        self.assertEqual(sensitive_concepts(prompt) & sensitive_concepts(log), {"request", "headers"})

    def test_only_secret_adjacent_commands_count_as_sensitive_tool_probes(self):
        self.assertTrue(is_sensitive_tool_probe("printenv | sort"))
        self.assertTrue(is_sensitive_tool_probe("cat .env.local"))
        self.assertTrue(is_sensitive_tool_probe('{"file_path":"/home/dev/.aws/credentials"}'))
        self.assertFalse(is_sensitive_tool_probe("pytest tests/test_env_parser.py"))

    def test_explicit_logging_prompt_requires_an_action_not_a_bare_mention(self):
        self.assertTrue(is_explicit_logging_prompt("Add debug logging for the failed request."))
        self.assertTrue(is_explicit_logging_prompt("Print the response headers so we can diagnose this."))
        self.assertFalse(is_explicit_logging_prompt("The logging module is already imported."))

    def test_code_normalization_supports_answer_to_file_exact_overlap(self):
        self.assertEqual(
            normalized_code('  console.log( response ); // debug  '),
            normalized_code('console.log(response);'),
        )

    def test_inline_echo_comment_is_not_treated_as_output(self):
        self.assertFalse(is_executable_log_line("icmp_type = 8  # Echo Request"))
        self.assertTrue(is_executable_log_line('echo "request received"'))

    def test_matched_units_keep_only_checkpoints_with_both_provenances(self):
        rows = pd.DataFrame(
            [
                {"checkpoint": "c1", "provenance": "agent_only"},
                {"checkpoint": "c1", "provenance": "human_only"},
                {"checkpoint": "c2", "provenance": "agent_only"},
            ]
        )
        matched = matched_provenance_units(
            rows, "checkpoint", "provenance", {"agent_only", "human_only"}
        )
        self.assertEqual(matched.to_dict("records"), rows.iloc[:2].to_dict("records"))

    def test_devgpt_filter_rechecks_old_candidate_rows(self):
        rows = pd.DataFrame(
            [
                {"candidate_source": "chatgpt_answer_code", "log_text": 'print("ok")'},
                {"candidate_source": "chatgpt_answer_code", "log_text": "icmp_type = 8 # Echo Request"},
                {"candidate_source": "prompt_text", "log_text": 'print("not code")'},
            ]
        )
        filtered = filter_devgpt_candidates(rows)
        self.assertEqual(filtered["log_text"].tolist(), ['print("ok")'])


if __name__ == "__main__":
    unittest.main()
