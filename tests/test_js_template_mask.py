"""Template-expression hints remain lexical candidates, including Git deletions."""
import json

import pytest

from agentlog_unified import batch_mine as batch
from agentlog_unified.detector import _mask_lexical, detect_snapshot
from synthetic_histories import commit, git, init


SOURCE = '''// console.log(secret)
const literal = "console.error(api_key)";
const pattern = /console.log(password)(?:[()])/;
const templateNoise = `console.warn(token)`;
console.info(
    `account ${format(user.email, `nested ${account_id}`)} literal ) password`,
    {requestId: request_id},
);
'''


@pytest.mark.parametrize("extension", ["js", "ts", "tsx", "mjs", "cjs"])
def test_template_identifiers_preserve_offsets_and_weak_evidence(extension):
    source = SOURCE.replace("account ${", "账户 ${").replace("\n", "\r\n")
    language = "typescript" if extension in {"ts", "tsx"} else "javascript"
    masked = _mask_lexical(source, language)
    assert len(masked) == len(source)
    assert [i for i, c in enumerate(masked) if c in "\r\n"] == [
        i for i, c in enumerate(source) if c in "\r\n"]
    assert "user.email" in masked and "account_id" in masked
    assert all(word not in masked for word in ("password", "secret", "api_key", "token"))
    result = detect_snapshot({"app." + extension: source}, ["javascript", "typescript", "tsx"])
    assert len(result["entities"]) == 1
    entity = result["entities"][0]
    assert entity["start_line"] == 5 and entity["end_line"] == 8
    assert entity["statement"].startswith("console.info(\r\n")
    assert entity["statement"].endswith("\r\n)")
    labels = {(label["category"], label["subtype"]) for label in entity["taxonomy_labels"]}
    assert {("PII", "email"), ("QID", "user_identifier"), ("QID", "request_identifier")} <= labels
    assert all(category != "AUTH" for category, _ in labels)
    assert all(label["confidence"] == "low" for label in entity["taxonomy_labels"])
    assert entity["parser_status"] == "lexical_only"
    assert entity["privacy_assessment"] == "possible"
    assert entity["unknown_type_review"]["needs_review"]
    assert "semantic_parser_unavailable" in entity["unknown_type_review"]["reasons"]


def test_real_git_template_addition_and_deletion_use_pydriller(tmp_path):
    repo = tmp_path / "repo"
    init(repo)
    added = commit(repo, {"app.ts": SOURCE}, "synthetic template log")
    git(repo, "rm", "app.ts")
    removed = commit(repo, {}, "remove synthetic log", actor="human", day=3)
    source = tmp_path / "contexts.jsonl"
    source.write_text("".join(json.dumps({"dataset": "synthetic", "repository": "fixture/template",
        "sha": sha, "local_repo_path": str(repo)}) + "\n" for sha in (added, removed)))
    output = tmp_path / "batch"
    batch.ingest_commit_contexts(source, output)
    result = batch.run_batch(output, tmp_path / "cache", offline=True)
    metrics = result["actual_extraction_metrics"]
    assert metrics["pydriller_commits"] == metrics["pydriller_diff_parsed_calls"] == 2
    assert metrics["pydriller_source_reads"] == 2
    logs = [json.loads(line) for line in (output / "exports/log_observations.jsonl").read_text().splitlines()]
    assert len(logs) == 2
    assert {(log["sha"], log["side"]) for log in logs} == {(added, "after"), (removed, "before")}
    assert all(log["snapshot_sha"] == added for log in logs)
    assert all(log["diff_backend"] == "pydriller.Commit.modified_files" for log in logs)
    for log in logs:
        entity = log["entity"]
        assert any(label["subtype"] == "email" for label in entity["taxonomy_labels"])
        assert entity["parser_status"] == "lexical_only"
        assert entity["unknown_type_review"]["needs_review"]
    assert result["type_audit"]["distinct_observed_log_versions"] == 1
    assert result["type_audit"]["unknown_type_review_count"] == 1


def test_invalid_python_retains_its_existing_regex_fallback():
    source = 'broken = (\nlogger.info("email", mystery)\n'
    result = detect_snapshot({"broken.py": source})
    assert len(result["entities"]) == 1
    assert any(gap["reason"] == "python_ast_parse_failed" for gap in result["gaps"])
    assert result["entities"][0]["parser_status"] == "lexical_only"
