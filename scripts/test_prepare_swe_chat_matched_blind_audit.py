import unittest

from scripts.prepare_swe_chat_matched_blind_audit import build_pairs, prepare_review
from scripts.prepare_swe_chat_blind_privacy_audit import source_hash


def row(side, repo, file, sink, commit):
    return {
        "attribution": side, "repo": repo, "file": file, "sink_family": sink,
        "commit": commit, "line": "1", "statement_redacted": f"log({commit})",
        "path_scope": "production", "static_privacy_candidate": "true",
        "evidence_grade": "A", "statement_lines": "1", "checkpoint_pk": "1",
        "privacy_features": "whole_object_dump", "mechanism_features": "",
        "context_redacted": "ctx",
    }


class SWEChatMatchedBlindAuditTest(unittest.TestCase):
    def test_exact_matching_cap_and_prior_exclusion(self):
        rows = [
            row(side, "r", "a.ts", "console_stdio", f"{side}-{i}")
            for side in ("agent_only", "human_only") for i in range(3)
        ]
        excluded = {source_hash(rows[0])}
        pairs = build_pairs(rows, excluded, 7, repo_cap=2)
        self.assertEqual(len(pairs), 2)
        for agent, human in pairs:
            self.assertEqual(agent["repo"], human["repo"])
            self.assertEqual(agent["sink_family"], human["sink_family"])
            self.assertNotIn(source_hash(agent), excluded)

    def test_blind_review_hides_pair_and_provenance(self):
        pair = (row("agent_only", "r", "a.py", "print_stdio", "a"), row("human_only", "r", "b.py", "print_stdio", "h"))
        review, key = prepare_review([pair], 7)
        self.assertEqual(len(review), 2)
        self.assertEqual(len(key), 2)
        self.assertNotIn("pair_id", review[0])
        self.assertNotIn("attribution", review[0])
        self.assertEqual({value["pair_side"] for value in key}, {"A", "B"})


if __name__ == "__main__":
    unittest.main()
