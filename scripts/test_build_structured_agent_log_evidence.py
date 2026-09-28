import csv
import json
import tempfile
import unittest
from pathlib import Path

from build_structured_agent_log_evidence import build


class StructuredEvidenceTests(unittest.TestCase):
    def test_static_risk_is_not_promoted_to_sensitive_or_runtime_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (root / "inventory.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=("session_id", "pr_url", "candidate_status"))
                writer.writeheader()
                writer.writerow({"session_id": "s1", "pr_url": "https://github.com/o/r/pull/1", "candidate_status": "READY_FOR_LIVE_BINDING"})
            binding = {
                "binding_id": "b1", "session_id": "s1", "pr_key": "o/r#1",
                "pr_url": "https://github.com/o/r/pull/1", "repo": "o/r", "provenance_grade": "A",
                "hard_anchor": "session_commit_equals_pr_head_commit", "line_authorship_proof": True,
                "generation_stage": "agent_session_final", "pr_state": "OPEN",
                "analysis_eligibility": "provenance_validation_only", "same_base": True,
                "commit_match": True, "tree_match": True, "patch_content_match": True,
                "full_patch_accounted": True, "changed_path_coverage": 1.0,
                "github_evidence_chain_status": "complete",
            }
            (root / "bindings.jsonl").write_text(json.dumps(binding) + "\n", encoding="utf-8")
            fields = ("pr_key", "pr_url", "repo", "file", "line", "path_scope", "static_risk_candidate", "risk_features", "log_concepts", "log_text_redacted")
            with (root / "logs.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow({"pr_key": "o/r#1", "pr_url": binding["pr_url"], "repo": "o/r", "file": "a.py", "line": 1, "path_scope": "production", "static_risk_candidate": True, "risk_features": "unstructured_stdio", "log_concepts": "", "log_text_redacted": "print(x)"})
            summary = build(root / "inventory.csv", root / "bindings.jsonl", root / "logs.csv", root / "out")
            with (root / "out/log_evidence.csv").open(encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(summary["n_static_risk_candidates"], 1)
            self.assertEqual(summary["n_sensitive_content_candidates"], 0)
            self.assertEqual(summary["n_runtime_confirmed_leaks"], 0)
            self.assertEqual(row["runtime_leak_status"], "NOT_EXECUTED_NOT_RUNTIME_CONFIRMED")


if __name__ == "__main__":
    unittest.main()
