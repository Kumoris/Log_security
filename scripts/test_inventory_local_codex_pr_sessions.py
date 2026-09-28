import json
import tempfile
import unittest
from pathlib import Path

from inventory_local_codex_pr_sessions import completed_events


class LocalSessionInventoryTests(unittest.TestCase):
    def test_only_successful_structured_events_are_returned(self):
        values = [
            {"type": "event_msg", "ordinal": 1, "payload": {"thread_id": "s1", "type": "item_completed", "item": {"type": "FileChange", "status": "completed", "changes": {}}}},
            {"type": "event_msg", "ordinal": 2, "payload": {"type": "item_completed", "item": {"type": "CommandExecution", "status": "completed", "exit_code": 0, "command": ["gh pr create"], "stdout": "https://github.com/o/r/pull/1"}}},
            {"type": "event_msg", "ordinal": 3, "payload": {"type": "item_completed", "item": {"type": "CommandExecution", "status": "failed", "exit_code": 1}}},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.jsonl"
            path.write_text("\n".join(json.dumps(value) for value in values), encoding="utf-8")
            session_id, events, malformed = completed_events(path)
        self.assertEqual(session_id, "s1")
        self.assertEqual([event["ordinal"] for event in events], [1, 2])
        self.assertEqual(malformed, 0)


if __name__ == "__main__":
    unittest.main()
