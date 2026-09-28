import unittest
from datetime import date

from scripts.extract_historical_human_controls import select_candidates


class HistoricalHumanControlsTest(unittest.TestCase):
    def test_selects_latest_pre_cutoff_rows_per_repository(self):
        rows = [
            {"repo": "a/r", "pr_key": "a/r#1", "created_at": "2019-01-01T00:00:00Z", "merged_at": "2019-01-02T00:00:00Z"},
            {"repo": "a/r", "pr_key": "a/r#2", "created_at": "2019-12-31T00:00:00Z", "merged_at": "2020-01-02T00:00:00Z"},
            {"repo": "a/r", "pr_key": "a/r#3", "created_at": "2019-12-01T00:00:00Z", "merged_at": "2019-12-02T00:00:00Z"},
            {"repo": "b/r", "pr_key": "b/r#1", "created_at": "2019-06-01T00:00:00Z", "merged_at": "2019-06-02T00:00:00Z"},
        ]
        selected = select_candidates(rows, date(2020, 1, 1), per_repo=1)
        self.assertEqual([row["pr_key"] for row in selected], ["a/r#3", "b/r#1"])


if __name__ == "__main__":
    unittest.main()
