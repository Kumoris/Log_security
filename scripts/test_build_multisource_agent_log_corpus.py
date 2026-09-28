import csv
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from build_multisource_agent_log_corpus import github_rows, ordered_features, parse_added_logs


class MultisourceCorpusTest(unittest.TestCase):
    def test_patch_parser_keeps_only_executable_added_logs(self):
        patch = "\n".join(
            [
                "+++ b/app.py",
                "+logger.info('token=%s', token)",
                "-logger.info('old')",
                "+# print('example')",
                "+value = 1",
            ]
        )
        self.assertEqual(list(parse_added_logs(patch)), [(2, "logger.info('token=%s', token)")])

    def test_feature_order_is_stable(self):
        self.assertEqual(
            ordered_features('print("DEBUG payload=%s" % payload)'),
            ["request_response_data", "whole_object_dump", "unstructured_stdio", "debug_residue_marker"],
        )

    def test_github_binding_promotes_only_a_or_b_to_primary(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "lineage.csv"
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=[
                    "provenance", "pr_key", "repo", "file", "line", "path_scope",
                    "risk_features", "log_text_redacted", "lineage_status",
                ])
                writer.writeheader()
                writer.writerow({
                    "provenance": "AGENT_SOURCE_CANDIDATE", "pr_key": "acme/repo#1",
                    "repo": "acme/repo", "file": "src/app.py", "line": "2",
                    "path_scope": "production", "risk_features": "auth_config_data",
                    "log_text_redacted": "logger.info(token)", "lineage_status": "PRESENT",
                })
            binding = {
                "pr_key": "acme/repo#1", "binding_id": "binding", "provenance_grade": "B",
                "binding_status": "high_confidence_exact_patch", "hard_anchor": "canonical_patch",
                "line_authorship_proof": True, "generation_stage": "agent_session_final",
                "analysis_eligibility": "provenance_primary",
                "pr_base_sha": "base", "pr_head_sha": "head", "pr_patch_sha256": "a" * 64,
                "github_evidence_chain_status": "complete_github_snapshot",
            }
            row = next(github_rows(path, {"acme/repo#1": binding}))
            self.assertEqual(row["provenance_grade"], "B")
            self.assertEqual(row["analysis_eligibility"], "provenance_primary")
            self.assertEqual(row["line_authorship_proof"], "true")
            self.assertEqual(row["binding_id"], "binding")

    def test_open_a_or_b_binding_is_not_promoted_to_primary(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "lineage.csv"
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=[
                    "provenance", "pr_key", "repo", "file", "line", "path_scope",
                    "risk_features", "log_text_redacted", "lineage_status",
                ])
                writer.writeheader()
                writer.writerow({
                    "provenance": "AGENT_SOURCE_CANDIDATE", "pr_key": "acme/repo#1",
                    "repo": "acme/repo", "file": "src/app.py", "line": "2",
                    "path_scope": "production", "risk_features": "", "log_text_redacted": "print('ok')",
                })
            binding = {
                "pr_key": "acme/repo#1", "provenance_grade": "A", "line_authorship_proof": True,
                "analysis_eligibility": "provenance_validation_only",
            }
            row = next(github_rows(path, {"acme/repo#1": binding}))
            self.assertEqual(row["analysis_eligibility"], "provenance_validation_only")


if __name__ == "__main__":
    unittest.main()
