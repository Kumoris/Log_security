import unittest

from scripts.analyze_aidev_paper_estimand_bridge import (
    paper_file_changed_lines,
    paper_language,
    paper_match,
    repository_rows,
)


class PaperEstimandBridgeTest(unittest.TestCase):
    def test_paper_table_two_path_filters(self):
        self.assertEqual(paper_language("src/app.py"), "python")
        self.assertEqual(paper_language("src/App.java"), "java")
        self.assertEqual(paper_language("src/app.tsx"), "javascript_typescript")
        self.assertIsNone(paper_language("tests/test_app.py"))
        self.assertIsNone(paper_language("src/AppTest.java"))
        self.assertIsNone(paper_language("public/app.js"))
        self.assertIsNone(paper_language("src/app.min.js"))
        self.assertIsNone(paper_language("src/main.go"))

    def test_paper_regex_excludes_generic_prints(self):
        self.assertIsNotNone(paper_match("python", 'logger.info("ready")'))
        self.assertIsNotNone(paper_match("java", 'LOGGER.error("failed", error);'))
        self.assertIsNotNone(paper_match("javascript_typescript", "console.warn(message);"))
        self.assertIsNone(paper_match("java", 'System.out.println("ready");'))
        self.assertIsNone(paper_match("python", "print(response)"))
        self.assertIsNone(
            paper_match("javascript_typescript", "x=" + "a" * 1_001 + ";console.error(error)")
        )

    def test_changed_lines_include_deleted_file_and_preserve_sides(self):
        diff = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -10,2 +10,2 @@
-logger.error("old")
+logger.info("new")
 context()
diff --git a/src/old.ts b/src/old.ts
deleted file mode 100644
--- a/src/old.ts
+++ /dev/null
@@ -2,1 +0,0 @@
-console.log(secret)
"""
        rows = paper_file_changed_lines(diff)
        self.assertEqual(
            [(row["file"], row["change_type"], row["line"]) for row in rows],
            [
                ("src/app.py", "deleted", 10),
                ("src/app.py", "added", 10),
                ("src/old.ts", "deleted", 2),
            ],
        )

    def test_repository_summary_uses_paper_normalized_score(self):
        rows = [
            {"repo": "a", "agent_hit": True, "human_hit": False},
            {"repo": "a", "agent_hit": False, "human_hit": True},
            {"repo": "b", "agent_hit": False, "human_hit": True},
            {"repo": "c", "agent_hit": False, "human_hit": False},
        ]
        details, summary = repository_rows(rows, ["hit"])
        self.assertEqual(len(details), 2)
        self.assertEqual(summary["hit"]["equal"], 1)
        self.assertEqual(summary["hit"]["human_higher"], 1)
        self.assertEqual(summary["hit"]["agent_higher"], 0)
        self.assertEqual(summary["hit"]["median_normalized_agent_score"], 0.25)


if __name__ == "__main__":
    unittest.main()
