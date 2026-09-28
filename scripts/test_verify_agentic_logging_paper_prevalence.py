import unittest

from scripts.verify_agentic_logging_paper_prevalence import build_rows, summarize


class PaperPrevalenceVerificationTest(unittest.TestCase):
    def test_distinguishes_both_zero_from_human_only_zero_filter(self):
        agent_prs = [{"id": i, "repo_id": 1} for i in range(1, 4)] + [{"id": i, "repo_id": 2} for i in range(4, 7)]
        human_prs = [{"id": i, "repo_id": 1} for i in range(11, 14)] + [{"id": i, "repo_id": 2} for i in range(14, 17)]
        agent_changes = [
            {"pr_id": 1, "has_logging_changes": True},
            {"pr_id": 2, "has_logging_changes": False},
            {"pr_id": 3, "has_logging_changes": False},
            {"pr_id": 4, "has_logging_changes": False},
            {"pr_id": 5, "has_logging_changes": False},
            {"pr_id": 6, "has_logging_changes": False},
        ]
        human_changes = [{"pr_id": i, "has_logging_changes": False} for i in range(11, 17)]
        rows = build_rows(agent_changes, human_changes, agent_prs, human_prs, {})
        value = summarize(rows)
        self.assertEqual(value["paper_denominator_recalculation"]["repositories"], 1)
        self.assertEqual(value["current_plot_script_recalculation"]["repositories"], 0)
        self.assertEqual(value["both_sides_zero_repositories"], 1)


if __name__ == "__main__":
    unittest.main()
