import unittest
from datetime import date
import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlparse

from scripts.screen_github_agent_logs import (
    GitHubClient,
    added_lines,
    canonical_patch_sha256,
    classify_log,
    date_windows,
    is_production_path,
    is_source_file,
    patch_content_sha256,
    redact_excerpt,
    run_screening,
    verify_outputs,
)


class GitHubAgentLogRuleTest(unittest.TestCase):
    def test_date_windows_are_inclusive_without_overlap(self):
        self.assertEqual(
            date_windows(date(2026, 8, 1), date(2026, 8, 5), 2),
            [
                (date(2026, 8, 1), date(2026, 8, 2)),
                (date(2026, 8, 3), date(2026, 8, 4)),
                (date(2026, 8, 5), date(2026, 8, 5)),
            ],
        )

    def test_added_lines_preserve_new_file_line_numbers(self):
        patch = """@@ -10,2 +10,4 @@ function run() {
 context();
+logger.info("token=%s", token);
+console.log(response);
 return value;
"""
        self.assertEqual(
            added_lines(patch),
            [
                (11, 'logger.info("token=%s", token);'),
                (12, "console.log(response);"),
            ],
        )

    def test_canonical_patch_hash_normalizes_only_line_endings(self):
        self.assertEqual(canonical_patch_sha256("+x\r\n"), canonical_patch_sha256("+x\n"))
        self.assertNotEqual(canonical_patch_sha256("+x \n"), canonical_patch_sha256("+x\n"))

    def test_patch_content_hash_ignores_only_hunk_display_suffix(self):
        left = "@@ -1 +1 @@ old_name\n-old\n+new\n"
        right = "@@ -1 +1 @@ new_name\r\n-old\r\n+new\r\n"
        changed = "@@ -1 +1 @@ new_name\n-old\n+different\n"
        self.assertEqual(patch_content_sha256(left), patch_content_sha256(right))
        self.assertNotEqual(patch_content_sha256(left), patch_content_sha256(changed))

    def test_comment_text_is_not_an_executable_log(self):
        self.assertEqual(classify_log("src/network.py", "icmp_type = 8  # Echo Request"), (False, (), ()))
        self.assertEqual(classify_log("src/main.py", "# print(token)"), (False, (), ()))

    def test_dynamic_sensitive_values_and_agent_control_are_separate_features(self):
        executable, features, concepts = classify_log(
            "src/agent.py", 'logger.info("tool output token=%s", tool_output.token)'
        )
        self.assertTrue(executable)
        self.assertEqual(
            features,
            ("agent_control_data", "auth_config_data", "tool_io_data", "whole_object_dump"),
        )
        self.assertEqual(concepts, ("token", "tool_output"))

    def test_literal_label_is_not_treated_as_a_printed_secret_value(self):
        self.assertEqual(
            classify_log("src/jobs.py", 'logger.info("token refresh started")'),
            (True, (), ("token",)),
        )

    def test_log_method_name_is_not_treated_as_a_dumped_error_object(self):
        self.assertEqual(
            classify_log(
                "src/jobs.py",
                'logger.error("CRITICAL: GEMINI_API_KEY environment variable is missing.")',
            ),
            (True, ("error_diagnostic_data",), ("api_key", "environment", "error")),
        )

    def test_unrelated_object_print_method_is_not_a_log_call(self):
        self.assertEqual(
            classify_log("src/Renderer.java", "printer.print(parameters);"),
            (False, (), ()),
        )

    def test_source_and_production_paths_are_filtered_independently(self):
        self.assertTrue(is_source_file("src/server.ts"))
        self.assertFalse(is_source_file("docs/example.md"))
        self.assertTrue(is_production_path("src/server.ts"))
        self.assertFalse(is_production_path("tests/test_server.py"))
        self.assertFalse(is_production_path("examples/server.py"))
        self.assertFalse(is_production_path("e2e/seed/notifications.ts"))
        self.assertFalse(is_production_path("scripts/test-publish-media.js"))

    def test_output_excerpt_redacts_common_secret_and_identifier_shapes(self):
        raw = 'logger.info("user=%s token=%s", "alice@example.com", "ghp_abcdefghijklmnopqrstuvwxyz123456")'
        self.assertEqual(
            redact_excerpt(raw),
            'logger.info("user=%s token=%s", "[REDACTED_EMAIL]", "[REDACTED_SECRET]")',
        )


class GitHubAgentLogIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.sleeps = []
        self.base_url = "https://api.test.invalid"

    def fetch(self, url, headers, timeout):
        self.requests.append(url)
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        base = self.base_url
        response_headers = {"x-ratelimit-limit": "5000", "x-ratelimit-remaining": "4999"}
        if parsed.path == "/cached":
            return {"value": 7}, response_headers
        if parsed.path == "/search/issues":
            page = int(query.get("page", ["1"])[0])
            number = page
            item = {
                "id": 100 + number,
                "number": number,
                "html_url": f"https://github.com/acme/repo/pull/{number}",
                "repository_url": f"{base}/repos/acme/repo",
                "created_at": f"2026-08-0{number}T00:00:00Z",
                "user": {
                    "login": "claude[bot]",
                    "type": "Bot",
                    "html_url": "https://github.com/apps/claude",
                },
                "performed_via_github_app": {"slug": "claude"},
                "pull_request": {
                    "url": f"{base}/repos/acme/repo/pulls/{number}",
                    "diff_url": f"https://github.com/acme/repo/pull/{number}.diff",
                    "merged_at": f"2026-08-0{number}T01:00:00Z",
                },
            }
            if page == 1:
                response_headers["link"] = f'<{base}/search/issues?page=2>; rel="next"'
            return {"total_count": 2, "incomplete_results": False, "items": [item]}, response_headers
        if parsed.path in {"/repos/acme/repo/pulls/1", "/repos/acme/repo/pulls/2"}:
            number = int(parsed.path.rsplit("/", 1)[1])
            return {
                "number": number,
                "html_url": f"https://github.com/acme/repo/pull/{number}",
                "merged_at": f"2026-08-0{number}T01:00:00Z",
                "merge_commit_sha": f"merge{number}",
                "head": {"sha": f"head{number}"},
                "base": {"sha": f"base{number}"},
                "changed_files": 2 if number == 1 else 1,
            }, response_headers
        if parsed.path in {"/repos/acme/repo/pulls/1/commits", "/repos/acme/repo/pulls/2/commits"}:
            number = int(parsed.path.split("/")[-2])
            return [{
                "sha": f"head{number}",
                "commit": {
                    "tree": {"sha": f"tree{number}"},
                    "committer": {"date": f"2026-08-0{number}T00:30:00Z"},
                },
            }], response_headers
        if parsed.path == "/repos/acme/repo/pulls/1/files":
            page = int(query.get("page", ["1"])[0])
            if page == 1:
                response_headers["link"] = f'<{base}/repos/acme/repo/pulls/1/files?page=2>; rel="next"'
                return [{
                    "filename": "src/app.py",
                    "status": "modified",
                    "blob_url": "https://github.com/acme/repo/blob/head1/src/app.py",
                    "patch": '@@ -1,1 +1,2 @@\n pass\n+logger.info("token=%s", token)',
                }], response_headers
            return [{
                "filename": "src/large.py",
                "status": "modified",
                "blob_url": "https://github.com/acme/repo/blob/head1/src/large.py",
            }], response_headers
        if parsed.path == "/repos/acme/repo/pulls/2/files":
            return [{
                "filename": "tests/test_app.py",
                "status": "modified",
                "blob_url": "https://github.com/acme/repo/blob/head2/tests/test_app.py",
                "patch": '@@ -1,1 +1,2 @@\n pass\n+logger.info("token refresh started")',
            }], response_headers
        if parsed.netloc == "github.com" and parsed.path == "/acme/repo/pull/1.diff":
            return (
                'diff --git a/src/raw.py b/src/raw.py\n'
                'index 1111111..2222222 100644\n'
                '--- a/src/raw.py\n'
                '+++ b/src/raw.py\n'
                '@@ -1,1 +1,2 @@\n'
                ' pass\n'
                '+logger.info("session=%s", session_id)\n'
            ), {"content-type": "text/plain"}
        if parsed.netloc == "github.com" and parsed.path == "/acme/repo/pull/2.diff":
            return (
                'diff --git a/tests/test_app.py b/tests/test_app.py\n'
                '--- a/tests/test_app.py\n'
                '+++ b/tests/test_app.py\n'
                '@@ -1,1 +1,2 @@\n'
                ' pass\n'
                '+logger.info("token refresh started")\n'
            ), {"content-type": "text/plain"}
        raise AssertionError("unexpected URL: " + url)

    def test_client_cache_can_be_replayed_offline(self):
        with TemporaryDirectory() as directory:
            client = GitHubClient(self.base_url, "", Path(directory), offline=False, transport=self.fetch)
            self.assertEqual(client.get_json(f"{self.base_url}/cached")[0], {"value": 7})
            count = len(self.requests)
            offline = GitHubClient(self.base_url, "", Path(directory), offline=True, transport=self.fetch)
            self.assertEqual(offline.get_json(f"{self.base_url}/cached")[0], {"value": 7})
            self.assertEqual(len(self.requests), count)

    def test_client_applies_configured_delay_before_public_diff_fetch(self):
        with TemporaryDirectory() as directory:
            client = GitHubClient(
                self.base_url,
                "",
                Path(directory),
                transport=self.fetch,
                diff_delay=0.25,
                sleep=self.sleeps.append,
            )
            client.get_text("https://github.com/acme/repo/pull/1.diff")
            self.assertEqual(self.sleeps, [0.25])

    def test_screening_follows_pagination_and_marks_missing_patch(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "out"
            cache = root / "cache"
            summary = run_screening(
                start=date(2026, 8, 1),
                end=date(2026, 8, 1),
                window_days=1,
                max_prs=2,
                output_dir=output,
                cache_dir=cache,
                agent_ids=("claude",),
                base_url=self.base_url,
                token="",
                transport=self.fetch,
            )
            self.assertEqual(summary["n_prs"], 2)
            self.assertEqual(summary["n_logs"], 2)
            self.assertEqual(summary["n_static_risk_candidates"], 1)
            self.assertEqual(summary["production_candidate_rate"], 1.0)
            self.assertEqual(summary["n_agent_native_sensitive_candidates"], 0)
            self.assertEqual(summary["n_shared_sensitive_candidates"], 1)
            self.assertEqual(summary["patch_missing_files"], 1)
            self.assertEqual(summary["api_incomplete_prs"], 1)
            self.assertEqual(verify_outputs(output), [])

            evidence = [json.loads(line) for line in (output / "github_agent_pr_evidence.jsonl").read_text().splitlines()]
            self.assertEqual([row["source_app_slug"] for row in evidence], ["claude", "claude"])
            self.assertTrue(all(row["pr_diff_sha256"] for row in evidence))
            self.assertTrue(all(row["commit_list_sha256"] for row in evidence))
            self.assertEqual([row["head_tree_sha"] for row in evidence], ["tree1", "tree2"])
            self.assertEqual([row["provenance_grade"] for row in evidence], ["C", "C"])
            self.assertEqual(
                [row["evidence_chain_status"] for row in evidence],
                ["partial_api_snapshot", "complete_github_snapshot"],
            )
            with (output / "github_agent_log_candidates.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["risk_features"], "auth_config_data;whole_object_dump")
            self.assertEqual(rows[1]["path_scope"], "non_production")
            self.assertIn(
                "生产路径候选率",
                (output / "github_agent_log_screening_report.md").read_text(encoding="utf-8"),
            )

            replay = root / "replay"
            replay_summary = run_screening(
                start=date(2026, 8, 1),
                end=date(2026, 8, 1),
                window_days=1,
                max_prs=2,
                output_dir=replay,
                cache_dir=cache,
                agent_ids=("claude",),
                base_url=self.base_url,
                token="",
                offline=True,
                transport=self.fetch,
            )
            self.assertEqual(replay_summary, summary)
            for name in (
                "github_agent_pr_evidence.jsonl",
                "github_agent_log_candidates.csv",
                "github_agent_log_screening_summary.json",
                "github_agent_log_screening_report.md",
            ):
                self.assertEqual((output / name).read_bytes(), (replay / name).read_bytes())

    def test_search_metadata_mode_uses_raw_diff_without_core_requests(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            summary = run_screening(
                start=date(2026, 8, 1),
                end=date(2026, 8, 1),
                window_days=1,
                max_prs=1,
                output_dir=root / "out",
                cache_dir=root / "cache",
                agent_ids=("claude",),
                base_url=self.base_url,
                token="",
                transport=self.fetch,
                metadata_mode="search",
            )
            self.assertEqual(summary["n_prs"], 1)
            self.assertEqual(summary["n_logs"], 1)
            self.assertEqual(summary["api_incomplete_prs"], 1)
            self.assertFalse(any("/repos/acme/repo/pulls/1" in url for url in self.requests))
            evidence = json.loads((root / "out/github_agent_pr_evidence.jsonl").read_text().splitlines()[0])
            self.assertEqual(evidence["detail_source"], "search_result+raw_diff")
            self.assertEqual(evidence["diff_completeness"], "unknown_github_raw_diff_limits")
            self.assertTrue(evidence["pr_diff_sha256"])
            self.assertEqual(evidence["commit_list_sha256"], "")
            self.assertEqual(evidence["evidence_chain_status"], "partial_search_snapshot")


if __name__ == "__main__":
    unittest.main()
