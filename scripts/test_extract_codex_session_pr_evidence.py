import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote

from scripts.extract_codex_session_pr_evidence import fetch_pr, parse_session


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.strip()


class SessionEvidenceExtractionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo with space"
        self.root.mkdir()
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Test")
        git(self.root, "config", "user.email", "test@example.invalid")
        (self.root / "app.py").write_text("old\n", encoding="utf-8")
        git(self.root, "add", "app.py")
        git(self.root, "commit", "-qm", "base")
        self.base = git(self.root, "rev-parse", "HEAD")

    def tearDown(self):
        self.temporary.cleanup()

    def write_session(self, events):
        path = Path(self.temporary.name) / "session.jsonl"
        path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        return path

    def event(self, ordinal, item, event_type="item_completed"):
        return {
            "timestamp": f"2026-09-01T00:00:{ordinal:02d}Z", "ordinal": ordinal,
            "type": "event_msg", "payload": {"type": event_type, "thread_id": "session-1", "item": item},
        }

    def test_only_successful_items_count_and_file_uri_is_decoded(self):
        uri = "file://" + quote(str(self.root))
        events = [
            self.event(1, {"type": "Message", "text": "git commit; https://github.com/acme/repo/pull/9"}),
            self.event(2, {"type": "CommandExecution", "status": "completed", "exit_code": 0,
                           "cwd": uri, "command": ["zsh", "-lc", "git status --porcelain"], "stdout": self.base + "\n"}),
            self.event(3, {"type": "FileChange", "status": "failed",
                           "changes": {str(self.root / "ignored.py"): {"type": "add"}}}),
            self.event(4, {"type": "FileChange", "status": "completed",
                           "changes": {str(self.root / "app.py"): {"type": "update"}}}),
            self.event(5, {"type": "CommandExecution", "status": "completed", "exit_code": 1,
                           "cwd": uri, "command": ["zsh", "-lc", "git commit -m bad"], "stdout": "[x deadbee] bad"}),
            self.event(6, {"type": "CommandExecution", "status": "completed", "exit_code": 0,
                           "cwd": uri, "command": ["zsh", "-lc", "gh pr create"],
                           "stdout": "https://github.com/acme/repo/pull/9\n"}),
        ]
        row, rejection = parse_session(self.write_session(events), self.root, "acme/repo")
        self.assertIsNone(rejection)
        self.assertEqual(row["file_change_final_paths"], ["app.py"])
        self.assertEqual(row["created_commit_shas"], [])
        self.assertTrue(row["known_clean_base"])
        self.assertEqual(row["clean_base_head_sha"], self.base)

    def test_fetch_marks_an_unobserved_changed_path_as_incomplete(self):
        (self.root / "app.py").write_text("new\n", encoding="utf-8")
        git(self.root, "add", "app.py")
        git(self.root, "commit", "-qm", "agent")
        head = git(self.root, "rev-parse", "HEAD")
        session = {
            "pr_key": "acme/repo#9", "pr_url": "https://github.com/acme/repo/pull/9",
            "created_commit_shas": [head], "file_change_final_paths": [],
            "command_generated_final_paths": [], "known_clean_base": True,
            "clean_base_head_sha": self.base,
        }

        class Client:
            base_url = "https://api.github.com"

            @staticmethod
            def get_json(url):
                return ({
                    "number": 9, "html_url": session["pr_url"], "state": "open", "title": "x",
                    "created_at": "2026-09-01T00:00:00Z", "merged_at": None,
                    "head": {"sha": head}, "base": {"sha": self.base}, "user": {"login": "alice"},
                    "changed_files": 1, "additions": 1, "deletions": 1, "merge_commit_sha": "",
                }, {})

            @staticmethod
            def paginate(url, item_key, max_pages):
                return ([{"sha": head}], {})

            @staticmethod
            def get_text(url):
                return ("diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n", {})

        pr, _ = fetch_pr(session, self.root, Client())
        self.assertEqual(pr["state"], "OPEN")
        self.assertEqual(session["changed_path_coverage"], 0.0)
        self.assertFalse(session["full_patch_accounted"])
        self.assertEqual(session["unaccounted_changed_paths"], ["app.py"])

    def test_dirty_pre_mutation_status_is_not_a_clean_base(self):
        uri = "file://" + quote(str(self.root))
        events = [
            self.event(1, {"type": "CommandExecution", "status": "completed", "exit_code": 0,
                           "cwd": uri, "command": ["zsh", "-lc", "git status --porcelain"],
                           "stdout": " M app.py\n"}),
            self.event(2, {"type": "FileChange", "status": "completed",
                           "changes": {str(self.root / "app.py"): {"type": "update"}}}),
            self.event(3, {"type": "CommandExecution", "status": "completed", "exit_code": 0,
                           "cwd": uri, "command": ["zsh", "-lc", "gh pr create"],
                           "stdout": "https://github.com/acme/repo/pull/9\n"}),
        ]
        row, rejection = parse_session(self.write_session(events), self.root, "acme/repo")
        self.assertIsNone(rejection)
        self.assertFalse(row["known_clean_base"])
        self.assertTrue(row["unaccounted_pre_session_worktree_changes"])


if __name__ == "__main__":
    unittest.main()
