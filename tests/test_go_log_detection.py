"""Go lexical evidence, with real Git/PyDriller reads and no Go execution."""
import json

import pytest

from agentlog_unified import batch_mine as batch
from agentlog_unified.detector import _mask_lexical, detect_snapshot
from synthetic_histories import commit, init


def detect(source):
    return detect_snapshot({"main.go": "package main\n" + source})


@pytest.mark.parametrize("statement", [
    'log.Print("fixed", user.Password)',
    'log.Printf("fixed %v", user.Password)',
    'log.Println("fixed", user.Password)',
    'log.Fatal("fixed", user.Password)',
    'logger.Infof("fixed %v", user.Password)',
    'this.log.Error("fixed", user.Password)',
    's.Logger.Errorf("fixed %v", user.Password)',
    'cclog.Warnf("fixed %v", user.Password)',
])
def test_common_go_calls_keep_weak_sensitive_evidence(statement):
    entity = detect('import "log"\nfunc run() { ' + statement + ' }')["entities"][0]
    assert entity["statement"] == statement
    assert any(label["subtype"] == "password" for label in entity["taxonomy_labels"])
    assert entity["parser_status"] == "lexical_only"
    assert entity["log_detection_status"] == entity["privacy_assessment"] == "possible"
    assert entity["unknown_type_review"]["needs_review"]
    assert "go_semantics_unparsed" in entity["missing_evidence"]
    assert all(label["confidence"] == "low" and not label["runtime_confirmed"] for label in entity["taxonomy_labels"])


@pytest.mark.parametrize("imports,statement,subtype", [
    ('import alias "log/slog"', 'alias.Info("fixed", "email", value)', "email"),
    ('import (\n audit "log/slog"\n)', 'audit.InfoContext(ctx, "fixed", "phone", value)', "phone"),
    ('import "log/slog"', 'slog.Log(ctx, slog.LevelInfo, "fixed", "user_id", value)', "user_identifier"),
    ('import "log/slog"', 'slog.LogAttrs(ctx, slog.LevelInfo, "fixed", slog.String("api_key", value))', "api_key"),
    ('import "go.uber.org/zap"', 'logger.Info("fixed", zap.String("email", value))', "email"),
    ('import "go.uber.org/zap"', 'zap.L().Info("fixed", zap.Any("medical_record", value))', "medical"),
    ('import "go.uber.org/zap"', 'logger.Infow("fixed", "email", value)', "email"),
    ('import "github.com/sirupsen/logrus"', 'logrus.WithField("access_token", value).Info("fixed")', "access_token"),
    ('import "github.com/sirupsen/logrus"', 'logrus.WithFields(logrus.Fields{"phone": value}).Info("fixed")', "phone"),
    ('import "github.com/rs/zerolog/log"', 'log.Info().Str("email", value).Msg("fixed")', "email"),
    ('import "github.com/rs/zerolog/log"', 'log.Info().Str("session_id", value).Send()', "session_identifier"),
])
def test_structured_fields_belong_to_complete_emission(imports, statement, subtype):
    entity = detect(imports + '\nfunc run() { ' + statement + ' }')["entities"][0]
    assert entity["statement"] == statement
    assert any(label["subtype"] == subtype for label in entity["taxonomy_labels"])


def test_raw_strings_runes_and_comments_are_masked_without_offset_changes():
    source = '''import "log"
func run() {
    text := `log.Println("password", user.Password)
        // "email": value`
    quote := '\\''
    // log.Fatal("password", user.Password)
    /* logger.Info("secret", credentials) */
    log.Println(
        "password and email are fixed prose",
        mystery,
    )
}
'''
    masked = _mask_lexical(source, "go")
    assert len(masked) == len(source)
    assert [i for i, char in enumerate(masked) if char == "\n"] == [i for i, char in enumerate(source) if char == "\n"]
    entities = detect(source)["entities"]
    assert len(entities) == 1
    assert entities[0]["end_line"] - entities[0]["start_line"] == 3
    assert entities[0]["taxonomy_labels"] == []
    assert entities[0]["privacy_assessment"] == "unknown"
    assert entities[0]["unknown_type_review"]["needs_review"]


def test_constructors_test_calls_and_incomplete_builders_are_not_emissions():
    result = detect('''import (
    "go.uber.org/zap"
    "github.com/rs/zerolog/log"
)
func run() {
    zap.Error(err)
    t.Log("test")
    t.Errorf("test")
    http.Error(w, "test", 500)
    log.With().Str("email", value).Logger()
    log.Info().Str("token", value)
}
''')
    assert result["entities"] == []
    assert "go_log_builder_without_terminal" in {gap["reason"] for gap in result["gaps"]}


def test_empty_go_file_and_unbalanced_calls_have_semantic_gaps():
    assert detect('func run() {}')["gaps"][0]["reason"] == "lexical_fallback_without_ast"
    result = detect('import "log"\nfunc run() { log.Println(')
    assert result["entities"] == []
    assert "unbalanced_log_call" in {gap["reason"] for gap in result["gaps"]}


def test_context_and_level_arguments_are_not_output_value_hints():
    entity = detect('import "log/slog"\nfunc run() { slog.Log(context, slog.LevelInfo, "fixed") }')["entities"][0]
    assert entity["taxonomy_labels"] == []
    assert entity["source_to_sink"] == []
    entity = detect('func run() { logger.Log("fixed", password) }')["entities"][0]
    assert any(label["subtype"] == "password" for label in entity["taxonomy_labels"])


def test_unrelated_receivers_and_masked_map_fields_do_not_produce_types():
    assert detect('func run() { catalog.Info(user); analogy.Log(password) }')["entities"] == []
    entity = detect('import "log/slog"\nfunc run() { slog.Info("fixed", "data", map[string]string{"password": "[REDACTED]"}) }')["entities"][0]
    assert entity["taxonomy_labels"] == []
    assert entity["privacy_assessment"] == "unknown"


def test_single_line_assignment_is_a_lexical_dependency():
    entity = detect('import "log"\nfunc run() { value := user.Password; log.Println(value) }')["entities"][0]
    assert any(label["subtype"] == "password" for label in entity["taxonomy_labels"])
    assert entity["dependencies"][0]["code"].strip() == "value := user.Password"


def test_one_assignment_hop_preserves_source_and_does_not_cross_closed_scope():
    source = '''import "log"
func unrelated() {
    value := user.Password
}
func run() {
    log.Println("unresolved", value)
    value := user.Email
    log.Println("resolved", value)
}
'''
    before, after = detect(source)["entities"]
    assert before["taxonomy_labels"] == []
    assert before["dependencies"] == []
    assert any(label["subtype"] == "email" for label in after["taxonomy_labels"])
    assert after["dependencies"][0]["code"].strip() == 'value := user.Email'
    assert "go_one_hop_lexical_only" in after["missing_evidence"]
    assert "go_cross_file_dependencies_unresolved" in after["missing_evidence"]


def test_known_logger_constructor_and_masked_field_are_conservative():
    result = detect('''import audit "log/slog"
func run() {
    out := audit.New(handler)
    out.Info("fixed", "phone", value)
    audit.Info("fixed", "password", "***")
}
''')["entities"]
    assert any(label["subtype"] == "phone" for label in result[0]["taxonomy_labels"])
    assert any(dep["kind"] == "logger_binding" for dep in result[0]["dependencies"])
    assert result[1]["taxonomy_labels"] == []
    assert result[1]["privacy_assessment"] == "unknown"


def test_real_git_pydriller_multiline_deletion_and_unknown_export(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    old = commit(repo, {"app.go": '''package main
import "log/slog"
func run() {
    value := user.Email
    slog.Info(
        "fixed",
        slog.String("email", value),
    )
    slog.Info("unclassified", mystery)
}
'''}, "add Go logs")
    (repo / "app.go").unlink()
    deleted = commit(repo, {"README.md": "Synthetic Go deletion calibration.\n"}, "delete Go logs", actor="human", day=3)
    contexts, output = tmp_path / "contexts.jsonl", tmp_path / "batch"
    contexts.write_text("".join(json.dumps({"dataset": "synthetic", "repository": "fixture/go", "sha": sha,
                                             "local_repo_path": str(repo)}) + "\n" for sha in (old, deleted)))
    batch.ingest_commit_contexts(contexts, output)
    result = batch.run_batch(output, tmp_path / "cache", offline=True)
    metrics = result["actual_extraction_metrics"]
    assert metrics["pydriller_repository_traversals"] == metrics["pydriller_commits"] == 2
    assert metrics["pydriller_diff_parsed_calls"] == 3
    assert metrics["pydriller_source_reads"] >= 2
    logs = [json.loads(line) for line in (output / "exports/log_observations.jsonl").read_text().splitlines()]
    assert len(logs) == 4
    assert {log["side"] for log in logs if log["sha"] == deleted} == {"before"}
    assert any(log["entity"]["end_line"] > log["entity"]["start_line"] for log in logs)
    assert any(log["entity"]["taxonomy_labels"] for log in logs)
    assert all(log["entity"]["unknown_type_review"]["needs_review"] for log in logs)
    assert all("pydriller" in log["diff_backend"].lower() for log in logs)
    assert result["commit_status_counts"] == {"partial": 2}
    assert result["full_history_tracing_completed"] is False
    assert (output / "exports/unknown_type_review_queue.csv").is_file()
