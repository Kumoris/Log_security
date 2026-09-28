import csv
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.analyze_github_agent_human_log_features import (
    SCORE_FEATURES,
    analyze_feature_rows,
    build_pr_features,
    classification_performance,
    fit_stump,
    leave_one_repository_out,
    mcnemar_exact,
    normalize_log_template,
    paired_feature_statistics,
    read_cached_diff,
    run_analysis,
    verify_outputs,
)
from scripts.mine_github_log_lineage import diff_profile


class FeatureExtractionTest(unittest.TestCase):
    def test_template_normalization_detects_repeated_log_shapes(self):
        self.assertEqual(
            normalize_log_template('logger.error("request failed for %s", user)'),
            normalize_log_template('logger.error("request failed for %s", account)'),
        )
        self.assertNotEqual(
            normalize_log_template('logger.info("request started for %s", user)'),
            normalize_log_template('logger.error("request failed for %s", user)'),
        )
        self.assertEqual(
            normalize_log_template('console.log(`user ${user}`)'),
            normalize_log_template('console.log(`user ${account}`)'),
        )
        self.assertNotEqual(
            normalize_log_template('logger.info("request " + "started")'),
            normalize_log_template('logger.info("request " + "failed")'),
        )
        self.assertNotEqual(
            normalize_log_template('if (bad) console.error("request failed")'),
            normalize_log_template('if (bad) console.error("request started")'),
        )
        self.assertEqual(
            normalize_log_template('echo "user=$USER"'),
            normalize_log_template('echo "user=$ACCOUNT"'),
        )
        self.assertNotEqual(
            normalize_log_template('echo "request started"'),
            normalize_log_template('echo "request failed"'),
        )

    def test_cached_diff_reader_checks_url_and_string_payload(self):
        with TemporaryDirectory() as directory:
            cache = Path(directory)
            url = "https://github.com/acme/repo/pull/1.diff"
            self._write_cache(cache, url, "")
            self.assertEqual(read_cached_diff(cache, url), "")
            path = cache / (hashlib.sha256(url.encode("utf-8")).hexdigest() + ".json")
            path.write_text(json.dumps({"url": url, "data": {"not": "text"}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not text"):
                read_cached_diff(cache, url)

    @staticmethod
    def _write_cache(cache: Path, url: str, data) -> None:
        cache.mkdir(parents=True, exist_ok=True)
        path = cache / (hashlib.sha256(url.encode("utf-8")).hexdigest() + ".json")
        path.write_text(json.dumps({"url": url, "headers": {}, "data": data}), encoding="utf-8")

    def test_pr_features_separate_production_logs_and_aggregate_lineage(self):
        diff = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,1 +1,4 @@
 pass
+logger.error("request failed for %s", user)
+logger.error("request failed for %s", account)
+console.log(response)
diff --git a/tests/test_app.py b/tests/test_app.py
--- a/tests/test_app.py
+++ b/tests/test_app.py
@@ -1,1 +1,2 @@
 pass
+print(token)
"""
        profile = diff_profile(diff)
        row = build_pr_features(
            pair_id="p1",
            match_tier="same_repository",
            provenance="agent",
            repo="acme/repo",
            pr_key="acme/repo#1",
            created_at="2026-08-01T00:00:00Z",
            merged_at="2026-08-01T00:10:00Z",
            profile=profile,
            lineage_rows=[
                {"lineage_status": "PRESENT_AT_CURRENT_HEAD"},
                {"lineage_status": "PRESENT_AT_CURRENT_HEAD"},
                {"lineage_status": "MODIFIED_AFTER_MERGE"},
            ],
        )
        self.assertEqual(row["n_production_logs"], 3)
        self.assertEqual(row["n_nonproduction_logs"], 1)
        self.assertEqual(row["merge_latency_minutes"], 10.0)
        self.assertAlmostEqual(row["duplicate_template_share"], 1 / 3)
        self.assertAlmostEqual(row["error_share"], 2 / 3)
        self.assertAlmostEqual(row["unstructured_share"], 1 / 3)
        self.assertAlmostEqual(row["exact_survival_share"], 2 / 3)
        self.assertEqual(row["diff_completeness_qc"], "unknown_raw_diff_limits")


class ScreeningModelTest(unittest.TestCase):
    def test_mcnemar_exact_uses_only_discordant_pairs(self):
        self.assertEqual(mcnemar_exact(0, 4), 0.125)
        self.assertEqual(mcnemar_exact(3, 3), 1.0)

    def test_stump_selects_a_literal_threshold_and_direction(self):
        rows = [
            {"label": 0, "value": 1.0},
            {"label": 0, "value": 2.0},
            {"label": 1, "value": 8.0},
            {"label": 1, "value": 9.0},
        ]
        rule = fit_stump(rows, "value")
        self.assertEqual(rule["direction"], "ge")
        self.assertEqual(rule["threshold"], 5.0)
        self.assertEqual(rule["balanced_accuracy"], 1.0)

    def test_loco_predictions_hold_out_entire_repositories(self):
        rows = [
            {"repo": "r1", "pr_key": "r1#1", "label": 0, "x": 1.0, "y": 1.0},
            {"repo": "r1", "pr_key": "r1#2", "label": 1, "x": 9.0, "y": 8.0},
            {"repo": "r2", "pr_key": "r2#1", "label": 0, "x": 2.0, "y": 2.0},
            {"repo": "r2", "pr_key": "r2#2", "label": 1, "x": 8.0, "y": 9.0},
            {"repo": "r3", "pr_key": "r3#1", "label": 0, "x": 3.0, "y": 3.0},
            {"repo": "r3", "pr_key": "r3#2", "label": 1, "x": 7.0, "y": 7.0},
        ]
        predictions = leave_one_repository_out(rows, ("x", "y"))
        self.assertEqual(len(predictions), 6)
        self.assertEqual({row["held_out_repo"] for row in predictions}, {"r1", "r2", "r3"})
        self.assertTrue(all(row["prediction"] == row["label"] for row in predictions))

    def test_paired_statistics_use_pair_differences(self):
        rows = [
            {"pair_id": "p1", "repo": "r1", "provenance": "agent", "x": 3.0},
            {"pair_id": "p1", "repo": "r1", "provenance": "human", "x": 1.0},
            {"pair_id": "p2", "repo": "r2", "provenance": "agent", "x": 5.0},
            {"pair_id": "p2", "repo": "r2", "provenance": "human", "x": 1.0},
        ]
        result = paired_feature_statistics(rows, ("x",), "fixture", 100, 20260805)[0]
        self.assertEqual(result["n_pairs"], 2)
        self.assertEqual(result["agent_mean"], 4.0)
        self.assertEqual(result["human_mean"], 1.0)
        self.assertEqual(result["mean_difference"], 3.0)
        self.assertEqual(result["permutation_p"], 0.5)

    def test_classification_performance_reports_confusion_and_intervals(self):
        result = classification_performance(
            [
                {"repo": "r1", "label": 1, "prediction": 1},
                {"repo": "r1", "label": 1, "prediction": 0},
                {"repo": "r2", "label": 0, "prediction": 1},
                {"repo": "r2", "label": 0, "prediction": 0},
            ],
            bootstrap_iterations=100,
            seed=20260805,
        )
        self.assertEqual((result["tp"], result["fn"], result["fp"], result["tn"]), (1, 1, 1, 1))
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 0.5)
        self.assertEqual(result["specificity"], 0.5)
        self.assertLess(result["precision_ci_low"], 0.5)
        self.assertGreater(result["precision_ci_high"], 0.5)
        self.assertLess(result["ppv_lower_at_0.01"], result["ppv_at_0.01"])
        self.assertEqual(result["effective_repositories"], 2.0)
        self.assertLessEqual(result["cluster_bootstrap_ba_ci_low"], 0.5)
        self.assertGreaterEqual(result["cluster_bootstrap_ba_ci_high"], 0.5)

    def test_classification_performance_keeps_undefined_precision_missing(self):
        result = classification_performance(
            [{"label": 1, "prediction": 0}, {"label": 0, "prediction": 0}]
        )
        self.assertIsNone(result["precision"])
        self.assertIsNone(result["precision_ci_low"])
        self.assertIsNone(result["precision_ci_high"])

    def test_feature_analysis_uses_same_repo_log_bearing_rows_for_loco(self):
        rows = []
        for index, repo in enumerate(("r1", "r2", "r3"), start=1):
            for provenance, label, value in (("agent", 1, 9.0), ("human", 0, 1.0)):
                row = {
                    "pair_id": f"p{index}", "match_tier": "same_repository",
                    "provenance": provenance, "label": label, "repo": repo,
                    "pr_key": f"{repo}#{label}", "has_production_log": 1,
                    "merge_latency_minutes": value,
                }
                row.update({feature: value for feature in SCORE_FEATURES})
                rows.append(row)
        result = analyze_feature_rows(rows, bootstrap_iterations=100, seed=20260805)
        self.assertEqual(len(result["oof_predictions"]), 6)
        composite = next(row for row in result["threshold_performance"] if row["model"] == "composite")
        self.assertEqual(composite["n"], 6)
        self.assertEqual(composite["balanced_accuracy"], 1.0)
        self.assertTrue(any(row["scope"] == "same_repo_all_pairs" for row in result["feature_statistics"]))

    def test_cross_repo_sensitivity_clusters_connected_repository_graph(self):
        rows = []
        for pair_id, agent_repo, human_repo in (("p1", "a", "shared"), ("p2", "c", "shared")):
            for provenance, label, repo in (
                ("agent", 1, agent_repo), ("human", 0, human_repo)
            ):
                row = {
                    "pair_id": pair_id, "match_tier": "cross_repository",
                    "provenance": provenance, "label": label, "repo": repo,
                    "pr_key": f"{repo}#{pair_id}-{label}", "has_production_log": 0,
                    "batch_log_addition": 0, "merge_latency_minutes": 1.0,
                }
                row.update({feature: 0.0 for feature in SCORE_FEATURES})
                rows.append(row)
        result = analyze_feature_rows(rows, bootstrap_iterations=10, seed=20260805)
        cross = next(
            row for row in result["feature_statistics"]
            if row["scope"] == "cross_repo_sensitivity_only" and row["feature"] == "has_production_log"
        )
        self.assertEqual(cross["n_repositories"], 1)


class AnalysisIntegrationTest(unittest.TestCase):
    @staticmethod
    def _cache_diff(cache_dir: Path, url: str, diff: str) -> None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / (hashlib.sha256(url.encode("utf-8")).hexdigest() + ".json")
        path.write_text(json.dumps({"url": url, "headers": {}, "data": diff}), encoding="utf-8")

    def test_offline_analysis_writes_verifiable_outputs(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            pairs = root / "matched_prs.csv"
            lineage = root / "log_lineage.csv"
            output = root / "out"
            fields = [
                "pair_id", "repo", "human_repo", "match_tier", "agent_pr_key",
                "agent_pr_url", "agent_created_at", "agent_merged_at", "human_pr_key",
                "human_pr_url", "human_created_at", "human_merged_at",
            ]
            with pairs.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow({
                    "pair_id": "p1", "repo": "acme/repo", "human_repo": "acme/repo",
                    "match_tier": "same_repository", "agent_pr_key": "acme/repo#1",
                    "agent_pr_url": "https://github.com/acme/repo/pull/1",
                    "agent_created_at": "2026-08-01T00:00:00Z",
                    "agent_merged_at": "2026-08-01T00:01:00Z",
                    "human_pr_key": "acme/repo#2",
                    "human_pr_url": "https://github.com/acme/repo/pull/2",
                    "human_created_at": "2026-08-02T00:00:00Z",
                    "human_merged_at": "2026-08-02T01:00:00Z",
                })
            with lineage.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["pr_key", "lineage_status", "path_scope"])
                writer.writeheader()
                writer.writerow({
                    "pr_key": "acme/repo#1", "lineage_status": "PRESENT_AT_CURRENT_HEAD",
                    "path_scope": "production",
                })
                writer.writerow({
                    "pr_key": "acme/repo#1", "lineage_status": "DELETED_AFTER_MERGE",
                    "path_scope": "test",
                })
                writer.writerow({
                    "pr_key": "acme/repo#2", "lineage_status": "DELETED_AFTER_MERGE",
                    "path_scope": "production",
                })

            agent_url = "https://github.com/acme/repo/pull/1.diff"
            human_url = "https://github.com/acme/repo/pull/2.diff"
            self._cache_diff(
                root / "agent-cache", agent_url,
                "diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1,3 @@\n pass\n+logger.error(\"failed\", err)\n+logger.info(\"done\")\n",
            )
            self._cache_diff(
                root / "human-cache", human_url,
                "diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1,2 @@\n pass\n+print(\"ok\")\n",
            )

            summary = run_analysis(
                pairs_path=pairs,
                lineage_path=lineage,
                agent_cache=root / "agent-cache",
                human_cache=root / "human-cache",
                output_dir=output,
                expected_pairs=1,
                bootstrap_iterations=100,
                seed=20260805,
            )
            self.assertEqual(summary["n_pairs"], 1)
            self.assertEqual(summary["n_pr_rows"], 2)
            self.assertEqual(summary["agent_log_bearing_prs"], 1)
            self.assertEqual(summary["human_log_bearing_prs"], 1)
            self.assertEqual(summary["score_status"], "exploratory_not_calibrated")
            with (output / "feature_statistics.csv").open(newline="", encoding="utf-8") as handle:
                self.assertGreater(len(list(csv.DictReader(handle))), 0)
            report = (output / "report.md").read_text(encoding="utf-8")
            self.assertIn("Fallacy Scan", report)
            self.assertIn("会话补丁→PR 新增行", report)
            self.assertEqual(summary["attribution_score_spec"]["hard_anchor_required"], True)
            signal_ids = {
                signal["id"] for signal in summary["attribution_score_spec"]["supporting_signals"]
            }
            self.assertNotIn("exploratory_content_screen", signal_ids)
            tool_anchor = next(
                anchor for anchor in summary["attribution_score_spec"]["hard_anchors"]
                if anchor["id"] == "tool_write_full_added_line_coverage"
            )
            self.assertIn("session_pr_binding", tool_anchor["requires"])
            self.assertEqual(summary["diff_completeness_qc"], "unknown_raw_diff_limits")
            with (output / "pr_features.csv").open(newline="", encoding="utf-8") as handle:
                feature_rows = list(csv.DictReader(handle))
            agent_features = next(row for row in feature_rows if row["provenance"] == "agent")
            self.assertEqual(agent_features["lineage_rows"], "1")
            self.assertEqual(verify_outputs(output, expected_pairs=1), [])
            report_path = output / "report.md"
            original_report = report_path.read_text(encoding="utf-8")
            report_path.write_text(original_report.replace("## 结论", "## 结论\nTAMPERED"), encoding="utf-8")
            self.assertIn("report does not match recomputation", verify_outputs(output, expected_pairs=1))
            report_path.write_text(original_report, encoding="utf-8")

            agent_cache_path = root / "agent-cache" / (
                hashlib.sha256(agent_url.encode("utf-8")).hexdigest() + ".json"
            )
            original_cache = agent_cache_path.read_text(encoding="utf-8")
            cache_record = json.loads(original_cache)
            cache_record["data"] += "+logger.info(\"late cache mutation\")\n"
            agent_cache_path.write_text(json.dumps(cache_record), encoding="utf-8")
            self.assertIn(
                "PR features do not match source recomputation",
                verify_outputs(
                    output,
                    expected_pairs=1,
                    pairs_path=pairs,
                    lineage_path=lineage,
                    agent_cache=root / "agent-cache",
                    human_cache=root / "human-cache",
                ),
            )
            agent_cache_path.write_text(original_cache, encoding="utf-8")

            statistics_path = output / "feature_statistics.csv"
            with statistics_path.open(newline="", encoding="utf-8") as handle:
                statistics_rows = list(csv.DictReader(handle))
                statistics_fields = list(statistics_rows[0])
            statistics_rows[0]["agent_mean"] = "999"
            with statistics_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=statistics_fields)
                writer.writeheader()
                writer.writerows(statistics_rows)
            self.assertIn(
                "feature statistics do not match recomputation",
                verify_outputs(output, expected_pairs=1),
            )


if __name__ == "__main__":
    unittest.main()
