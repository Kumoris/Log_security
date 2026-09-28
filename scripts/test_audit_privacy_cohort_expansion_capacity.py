import unittest

from audit_privacy_cohort_expansion_capacity import exact_temporal_matching


def row(pr_id, kind, created, task="fix"):
    value = {
        "pr_id": str(pr_id), "repo": "o/r", "task_type": task, "language": "Python",
        "created_at": created,
    }
    value["human_actor" if kind == "human" else "agent_product"] = kind
    return value


class ExpansionCapacityTests(unittest.TestCase):
    def test_matching_is_one_to_one_and_respects_caliper(self):
        humans = [
            row(1, "human", "2025-01-01T00:00:00Z"),
            row(2, "human", "2025-01-03T00:00:00Z"),
        ]
        agents = [
            row(10, "agent", "2025-01-02T00:00:00Z"),
            row(11, "agent", "2025-01-04T00:00:00Z"),
        ]
        matches = exact_temporal_matching(humans, agents, 2)
        self.assertEqual(len(matches), 2)
        self.assertEqual(len({item[0]["pr_id"] for item in matches}), 2)
        self.assertEqual(len({item[1]["pr_id"] for item in matches}), 2)
        self.assertTrue(all(item[2] <= 2 for item in matches))

    def test_exact_task_stratum_is_required(self):
        humans = [row(1, "human", "2025-01-01T00:00:00Z", "fix")]
        agents = [row(10, "agent", "2025-01-01T00:00:00Z", "feat")]
        self.assertEqual(exact_temporal_matching(humans, agents, 30), [])

    def test_maximum_cardinality_recovers_reassignment(self):
        humans = [
            row(1, "human", "2025-01-02T00:00:00Z"),
            row(2, "human", "2025-01-04T00:00:00Z"),
        ]
        agents = [
            row(10, "agent", "2025-01-01T00:00:00Z"),
            row(11, "agent", "2025-01-03T00:00:00Z"),
        ]
        self.assertEqual(len(exact_temporal_matching(humans, agents, 2)), 2)


if __name__ == "__main__":
    unittest.main()
