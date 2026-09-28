"""Bounded C# lexical candidates; target C# code is never compiled or run."""
import json

import pytest

from agentlog_unified import batch_mine as batch
from agentlog_unified.detector import _mask_lexical, detect_snapshot
from synthetic_histories import commit, init


def detect(body):
    return detect_snapshot({"App.cs": body})


@pytest.mark.parametrize("receiver,method", [
    ("_logger", "LogTrace"), ("_logger", "LogDebug"), ("logger", "LogInformation"),
    ("Logger", "LogWarning"), ("this._logger", "LogError"), ("logger", "LogCritical"),
    ("Log", "Information"), ("Log", "Warning"), ("Log", "Error"), ("Log", "Fatal"),
    ("Log", "Verbose"), ("logger", "Info"), ("logger", "Warn"), ("logger", "Debug"),
    ("logger", "Trace"), ("auditLogger", "Error"), ("application_logger", "Info"),
])
def test_microsoft_serilog_nlog_receivers_keep_weak_value_evidence(receiver, method):
    statement = receiver + '.' + method + '("fixed", user.Password)'
    entity = detect('class App { void Run() { ' + statement + '; } }')["entities"][0]
    assert entity["statement"] == statement
    assert entity["parser_status"] == "lexical_only"
    assert entity["log_detection_status"] == entity["privacy_assessment"] == "possible"
    assert any(label["subtype"] == "password" for label in entity["taxonomy_labels"])
    assert all(label["confidence"] == "low" and not label["runtime_confirmed"] for label in entity["taxonomy_labels"])
    assert entity["unknown_type_review"]["needs_review"]


def test_generic_and_non_generic_ilogger_type_declarations():
    source = '''class App {
    readonly ILogger<App> audit;
    readonly ILogger output;
    void Run() {
        audit.LogInformation("fixed", user.Email);
        output.LogError(exception, "fixed", user.Password);
        catalog.Info(user.Password);
        Test.LogInformation(user.Password);
        analogy.Log(user.Password);
    }
}'''
    entities = detect(source)["entities"]
    assert [entity["callee"] for entity in entities] == ["audit.LogInformation", "output.LogError"]
    assert any(label["subtype"] == "email" for label in entities[0]["taxonomy_labels"])


@pytest.mark.parametrize("statement,subtype", [
    ('logger.LogInformation("Account {Email}", value)', "email"),
    ('logger.LogInformation(eventId, "Account {Phone}", value)', "phone"),
    ('logger.LogError(exception, "Account {AccessToken}", value)', "access_token"),
    ('logger.LogError(eventId, exception, "Account {UserId}", value)', "user_identifier"),
    ('Log.Information("Value {@MedicalRecord}", value)', "medical"),
    ('logger.Log(LogLevel.Information, "Value {Password}", value)', "password"),
    ('logger.LogInformation("Value {Email,10}", value)', "email"),
])
def test_structured_placeholders_map_only_to_present_output_arguments(statement, subtype):
    entity = detect('class App { void Run() { ' + statement + '; } }')["entities"][0]
    assert any(label["subtype"] == subtype for label in entity["taxonomy_labels"])


@pytest.mark.parametrize("statement", [
    'logger.LogInformation("password and email are fixed prose")',
    'logger.LogInformation("Value {{Password}}", value)',
    'logger.LogInformation("Value {Password}", "[REDACTED]")',
    'logger.LogInformation("Value {Email}")',
])
def test_fixed_prose_escaped_or_missing_or_masked_fields_are_not_sensitive(statement):
    entity = detect('class App { void Run() { ' + statement + '; } }')["entities"][0]
    assert entity["taxonomy_labels"] == []
    assert entity["privacy_assessment"] == "unknown"
    assert entity["unknown_type_review"]["needs_review"]


@pytest.mark.parametrize("literal", [
    '$"Account {user.Email}"',
    '$@"Account {user.Email}"',
    '@$"Account {user.Email}"',
    '$"Account {user?.Email,10}"',
    '$"Account {user.Email:whatever}"',
])
def test_simple_interpolation_retains_identifier_evidence(literal):
    entity = detect('class App { void Run() { logger.LogInformation(' + literal + '); } }')["entities"][0]
    assert any(label["subtype"] == "email" for label in entity["taxonomy_labels"])
    assert entity["source_to_sink"][0]["source"] == "user.Email"


def test_complex_nested_interpolation_is_bounded_and_explicitly_unparsed():
    statement = 'logger.LogInformation($"Value {map["email"] ?? "logger.LogError(fake)"}")'
    entity = detect('class App { void Run() { ' + statement + '; } }')["entities"][0]
    assert entity["statement"] == statement
    assert entity["taxonomy_labels"] == []
    assert "csharp_complex_interpolation_unparsed" in entity["missing_evidence"]


def test_comments_verbatim_raw_text_and_attributes_cannot_create_fake_sinks():
    source = '''[Description("logger.LogError(password)")]
class App {
    string text = @"Log.Error(""password"", secret)";
    string raw = """"quote """ logger.LogError(password) more"""";
    string interpolation = $"fixed {{Password}} fake logger.LogError(password)";
    char quote = '\\'';
    // _logger.LogInformation("password", password)
    /* logger.LogError(exception, "password", secret); */
    void Run() {
        logger.LogInformation(
            "fixed",
            mystery
        );
    }
}
// logger.LogError(password)'''
    masked = _mask_lexical(source, "csharp")
    assert len(masked) == len(source)
    assert [i for i, char in enumerate(masked) if char in "\r\n"] == [i for i, char in enumerate(source) if char in "\r\n"]
    entities = detect(source)["entities"]
    assert len(entities) == 1
    assert entities[0]["end_line"] - entities[0]["start_line"] == 3
    assert entities[0]["taxonomy_labels"] == []


def test_raw_interpolation_is_unknown_with_explicit_gap():
    statement = 'logger.LogInformation($$"""Value {{user.Email}} and "logger.LogError(fake)"""")'
    result = detect('class App { void Run() { ' + statement + '; } }')
    assert len(result["entities"]) == 1
    entity = result["entities"][0]
    assert entity["statement"] == statement
    assert entity["taxonomy_labels"] == []
    assert "csharp_raw_interpolation_unparsed" in entity["missing_evidence"]
    assert "csharp_raw_interpolation_unparsed" in {gap["reason"] for gap in result["gaps"]}


def test_one_assignment_hop_respects_closed_scope_and_statement_order():
    entities = detect('''class App {
    void Other() { var value = user.Password; }
    void Run() {
        logger.LogInformation("unknown", value);
        var value = user.Email; logger.LogInformation("known", value);
    }
}''')["entities"]
    assert entities[0]["taxonomy_labels"] == []
    assert entities[0]["dependencies"] == []
    assert any(label["subtype"] == "email" for label in entities[1]["taxonomy_labels"])
    assert entities[1]["dependencies"][0]["code"].strip() == "var value = user.Email"
    assert "csharp_one_hop_lexical_only" in entities[1]["missing_evidence"]
    assert "csharp_cross_file_dependencies_unresolved" in entities[1]["missing_evidence"]


def test_interpolated_assignment_dependency_remains_one_hop():
    entity = detect('class App { void Run() { var value = $"Account {user.Email}"; logger.LogInformation(value); } }')["entities"][0]
    assert any(label["subtype"] == "email" for label in entity["taxonomy_labels"])
    assert len(entity["dependencies"]) == 1


def test_exception_catch_type_is_local_evidence_not_an_ex_name_rule():
    entities = detect('''class App { void Run() {
        logger.LogError(ex, "untyped");
        try { Work(); } catch (Exception ex) {
            logger.LogError(ex, "typed");
        }
        logger.LogError(ex, "outside");
    } }''')["entities"]
    assert entities[0]["taxonomy_labels"] == entities[2]["taxonomy_labels"] == []
    assert any(label["subtype"] == "exception_message" and label["confidence"] == "low" for label in entities[1]["taxonomy_labels"])


def test_dynamic_constant_template_is_explicitly_unresolved():
    entity = detect('class App { void Run() { const string template = "Account {Email}"; logger.LogInformation(template, value); } }')["entities"][0]
    assert entity["taxonomy_labels"] == []
    assert "csharp_dynamic_message_template_unresolved" in entity["missing_evidence"]


def test_unterminated_string_masks_fake_call_and_marks_source_unavailable():
    result = detect('class App { string text = "logger.LogError(password);')
    assert result["entities"] == []
    assert any(gap["reason"] == "csharp_unterminated_string" and gap["source_analysis_unavailable"] for gap in result["gaps"])


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\\\n"])
def test_regular_string_cannot_borrow_closing_quote_across_physical_newline(newline):
    source = 'class App { string text = "unterminated' + newline + 'class App { void Run() { logger.LogInformation("value={Password}", user.Password); } }\n'
    result = detect(source)
    assert result["entities"] == []
    assert any(gap["reason"] == "csharp_unterminated_string" and gap["source_analysis_unavailable"] for gap in result["gaps"])


@pytest.mark.parametrize("literal", ['@"first\nsecond"', '"""first\nsecond"""'])
def test_verbatim_and_raw_strings_keep_legal_newlines(literal):
    result = detect('class App { void Run() { logger.LogInformation(' + literal + '); } }')
    assert len(result["entities"]) == 1
    assert not any(gap.get("source_analysis_unavailable") for gap in result["gaps"])


@pytest.mark.parametrize("prefix", ["\ufeff", "#nullable disable\n", "#nullable enable warnings\n", "\ufeff#nullable restore annotations\n"])
def test_bom_and_nullable_directives_do_not_make_valid_source_unavailable(prefix):
    result = detect(prefix + 'class App { void Run() { logger.LogInformation("Account {Email}", value); } }')
    assert len(result["entities"]) == 1
    assert any(label["subtype"] == "email" for label in result["entities"][0]["taxonomy_labels"])
    assert not any(gap.get("source_analysis_unavailable") for gap in result["gaps"])


@pytest.mark.parametrize("attribute", [
    '[Route("api/[controller]")]',
    '[Route(@"api/[controller]")]',
    '[Route("""api/[controller]""")]',
    '[Route("api/[controller]"), Description("logger.LogError(password)")]',
    '[Route(/* ] is comment text */ "api/[controller]")]',
    "[Marker('[')]",
    "[Marker(']')]",
])
@pytest.mark.parametrize("separator", ["\n", " "])
def test_attribute_string_brackets_cannot_break_later_executable_source(attribute, separator):
    result = detect(attribute + separator + 'class App { void Run() { logger.LogInformation("Account {Email}", value); } }')
    assert len(result["entities"]) == 1
    assert result["entities"][0]["callee"] == "logger.LogInformation"
    assert any(label["subtype"] == "email" for label in result["entities"][0]["taxonomy_labels"])
    assert not any(gap.get("source_analysis_unavailable") for gap in result["gaps"])


def test_collection_and_indexing_continuations_are_not_attributes():
    result = detect('''class App { void Run() {
        var values =
            [logger.Log("fixed", user.Email)];
        var value = source
            [logger.Log("fixed", user.Password)];
    } }''')
    assert len(result["entities"]) == 2
    assert any(label["subtype"] == "email" for label in result["entities"][0]["taxonomy_labels"])
    assert any(label["subtype"] == "password" for label in result["entities"][1]["taxonomy_labels"])


@pytest.mark.parametrize("attribute", ['[Route("api/[controller]")', '[Route("no closing bracket")'])
def test_unterminated_attribute_is_still_explicitly_unavailable(attribute):
    result = detect(attribute + '\nclass App {}')
    assert any(gap["reason"] == "csharp_unterminated_attribute" and gap["source_analysis_unavailable"] for gap in result["gaps"])


def test_complex_interpolation_does_not_desynchronize_later_call_tokens():
    result = detect('class App { void Run() { logger.LogInformation($"Account {map["email"]}"); logger.LogInformation("next", user.Password); } }')
    assert len(result["entities"]) == 2
    assert "csharp_complex_interpolation_unparsed" in result["entities"][0]["missing_evidence"]
    assert any(label["subtype"] == "password" for label in result["entities"][1]["taxonomy_labels"])
    assert not any(gap.get("source_analysis_unavailable") for gap in result["gaps"])


def test_empty_and_broken_csharp_files_never_establish_safe_negative():
    assert detect("class App {}")["gaps"][0]["reason"] == "lexical_fallback_without_ast"
    result = detect('class App { void Run() { logger.LogInformation("unterminated')
    assert result["entities"] == []
    assert any(gap["reason"] == "unbalanced_log_call" and gap["source_analysis_unavailable"] for gap in result["gaps"])
    assert detect_snapshot({"App.CS": 'class App { void Run() { logger.LogError(error); } }'})["entities"]
    assert detect_snapshot({"App.cs": 'class App { void Run() { logger.LogError(error); } }'}, ["python"])["entities"] == []


def test_real_git_pydriller_multiline_deletion_and_unknown_queue(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    old = commit(repo, {"App.cs": '''class App {
    ILogger<App> _logger;
    void Run() {
        var value = user.Email;
        _logger.LogInformation(
            "Account {Email}",
            value
        );
        _logger.LogInformation("unknown", mystery);
    }
}
'''}, "add C# logs")
    (repo / "App.cs").unlink()
    deleted = commit(repo, {"README.md": "Synthetic C# removal.\n"}, "remove C# logs", actor="human", day=3)
    input_path, output = tmp_path / "contexts.jsonl", tmp_path / "batch"
    input_path.write_text("".join(json.dumps({"dataset": "synthetic", "repository": "fixture/csharp", "sha": sha,
                                               "local_repo_path": str(repo)}) + "\n" for sha in (old, deleted)))
    batch.ingest_commit_contexts(input_path, output)
    result = batch.run_batch(output, tmp_path / "cache", offline=True)
    metrics = result["actual_extraction_metrics"]
    assert metrics["pydriller_repository_traversals"] == metrics["pydriller_commits"] == 2
    assert metrics["pydriller_diff_parsed_calls"] == 3
    assert metrics["pydriller_source_reads"] >= 2
    logs = [json.loads(line) for line in (output / "exports/log_observations.jsonl").read_text().splitlines()]
    assert len(logs) == 4
    assert {log["side"] for log in logs if log["sha"] == deleted} == {"before"}
    assert all(log["entity"]["parser_status"] == "lexical_only" for log in logs)
    assert all(log["human_review_status"] == "pending" and log["entity"]["unknown_type_review"]["needs_review"] for log in logs)
    assert any(log["entity"]["taxonomy_labels"] for log in logs)
    assert result["commit_status_counts"] == {"partial": 2}
    assert (output / "exports/unknown_type_review_queue.csv").is_file()
