import unittest

from scripts.verify_session_pr_binding import bind_prs, evaluate_binding, verify_bindings


def pr(**changes):
    row = {
        "provenance": "AGENT_SOURCE_CANDIDATE",
        "source_app_slug": "claude",
        "repo": "acme/repo",
        "pr_key": "acme/repo#1",
        "pr_url": "https://github.com/acme/repo/pull/1",
        "base_sha": "base",
        "head_sha": "head",
        "head_tree_sha": "tree",
        "head_committed_at": "2026-08-01T01:00:00Z",
        "canonical_patch_sha256": "a" * 64,
        "patch_content_sha256": "b" * 64,
        "evidence_chain_status": "complete_github_snapshot",
        "state": "MERGED",
    }
    row.update(changes)
    return row


def session(**changes):
    row = {
        "session_id": "session-1",
        "repo": "acme/repo",
        "pr_key": "acme/repo#1",
        "base_sha": "base",
        "commit_sha": "head",
        "tree_sha": "tree",
        "artifact_created_at": "2026-08-01T00:30:00Z",
        "canonical_patch_sha256": "a" * 64,
        "patch_content_sha256": "b" * 64,
        "known_clean_base": True,
        "commit_created_in_session": True,
        "full_pr_commit_chain_created_in_session": True,
        "full_patch_accounted": True,
        "changed_path_coverage": 1.0,
        "unaccounted_pre_session_worktree_changes": False,
    }
    row.update(changes)
    return row


class SessionPrBindingTest(unittest.TestCase):
    def test_exact_session_commit_is_grade_a(self):
        row = evaluate_binding(session(), pr())
        self.assertEqual(row["provenance_grade"], "A")
        self.assertEqual(row["hard_anchor"], "session_commit_equals_pr_head_commit")
        self.assertTrue(row["line_authorship_proof"])
        self.assertEqual(row["analysis_eligibility"], "provenance_primary")

    def test_tree_and_base_match_is_grade_a_without_commit_match(self):
        row = evaluate_binding(session(commit_sha="other", commit_created_in_session=False), pr())
        self.assertEqual(row["provenance_grade"], "A")
        self.assertEqual(row["hard_anchor"], "session_tree_and_base_equal_pr_tree_and_base")

    def test_matching_head_without_full_commit_chain_is_rejected(self):
        row = evaluate_binding(session(full_pr_commit_chain_created_in_session=False), pr())
        self.assertEqual(row["provenance_grade"], "C")
        self.assertIn("incomplete_pr_commit_chain", row["hard_failures"])

    def test_tree_match_without_full_path_coverage_is_rejected(self):
        row = evaluate_binding(
            session(commit_sha="other", commit_created_in_session=False, full_patch_accounted=False,
                    changed_path_coverage=0.5, patch_content_sha256="other"),
            pr(),
        )
        self.assertEqual(row["provenance_grade"], "C")
        self.assertIn("incomplete_changed_path_coverage", row["hard_failures"])

    def test_exact_patch_is_grade_b(self):
        row = evaluate_binding(
            session(commit_sha="other", tree_sha="other-tree", patch_content_sha256="other",
                    commit_created_in_session=False),
            pr(),
        )
        self.assertEqual(row["provenance_grade"], "B")
        self.assertEqual(row["hard_anchor"], "canonical_full_patch_bidirectional_exact")

    def test_patch_content_match_is_grade_b(self):
        row = evaluate_binding(
            session(commit_sha="other", tree_sha="other-tree", canonical_patch_sha256="other",
                    commit_created_in_session=False),
            pr(),
        )
        self.assertEqual(row["provenance_grade"], "B")
        self.assertEqual(row["hard_anchor"], "patch_content_bidirectional_exact")

    def test_open_strong_binding_is_validation_only(self):
        row = evaluate_binding(session(), pr(state="OPEN"))
        self.assertEqual(row["provenance_grade"], "A")
        self.assertEqual(row["analysis_eligibility"], "provenance_validation_only")

    def test_hash_mismatch_claim_is_hard_failure(self):
        row = evaluate_binding(
            session(
                commit_sha="other", tree_sha="other-tree", canonical_patch_sha256="b" * 64,
                commit_created_in_session=False, claims_exact_binding=True,
            ),
            pr(),
        )
        self.assertEqual(row["provenance_grade"], "C")
        self.assertEqual(row["binding_status"], "hard_failure")
        self.assertIn("hash_or_patch_mismatch", row["hard_failures"])
        self.assertFalse(row["line_authorship_proof"])

    def test_session_after_pr_head_is_not_strong_evidence(self):
        row = evaluate_binding(session(artifact_created_at="2026-08-01T02:00:00Z"), pr())
        self.assertEqual(row["provenance_grade"], "C")
        self.assertIn("session_artifact_created_after_pr_head", row["hard_failures"])

    def test_missing_session_keeps_app_pr_at_grade_c(self):
        row = evaluate_binding({}, pr())
        self.assertEqual(row["provenance_grade"], "C")
        self.assertFalse(row["line_authorship_proof"])

    def test_bind_prs_emits_one_best_binding_per_pr(self):
        weak = session(session_id="weak", known_clean_base=False)
        strong = session(session_id="strong")
        rows = bind_prs([weak, strong], [pr()])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["session_id"], "strong")
        self.assertEqual(rows[0]["session_candidate_count"], 2)
        self.assertEqual(verify_bindings(rows), [])

    def test_verifier_rejects_primary_open_pr(self):
        row = evaluate_binding(session(), pr(state="OPEN"))
        row["analysis_eligibility"] = "provenance_primary"
        self.assertIn("analysis eligibility disagrees", verify_bindings([row])[0])


if __name__ == "__main__":
    unittest.main()
