import json
from urllib.error import HTTPError

from agentlog_unified.github_client import GitHubClient, enrich_pr
from agentlog_unified.ingest import ingest_records
from agentlog_unified.provenance import classify_actor


def test_csv_dotted_mapping_duplicates_and_original_label(tmp_path):
    path = tmp_path / "export.csv"
    path.write_text('location,identity,attribution,revision\norg/repo,7,Agent,aaa\norg/repo,7,human,bbb\n', encoding="utf-8")
    result = ingest_records(path, {"repository": "location", "pr_number": "identity", "pr_actor_type": "attribution", "commit_shas": "revision"})
    assert len(result["prs"]) == 1
    pr = result["prs"][0]
    assert pr["commit_shas"] == ["aaa", "bbb"]
    assert pr["provided_label"] == "Agent" and pr["verified_actor_type"] == "unknown"
    assert len(pr["raw_records"]) == 2 and result["source_schema"]["rows_read"] == 2


def test_nested_aidev_and_global_id(tmp_path):
    path = tmp_path / "aidev.json"
    path.write_text(json.dumps({"rows": [{"row": {"project": {"name": "org/repo"}, "pr_id": 900000, "html_url": "https://github.com/org/repo/pull/4", "commits": [{"sha": "abcdef"}]}}]}))
    result = ingest_records(path, {"repository": "project.name"}, format="aidev")
    assert result["prs"][0]["pr_number"] == 4
    assert result["prs"][0]["commit_shas"] == ["abcdef"]


def test_fixture_and_missing_pr_are_not_fabricated(tmp_path):
    path = tmp_path / "local.jsonl"
    rows = [{"is_synthetic": True, "fixture_id": "fixture-one", "local_repo_path": "repo", "initial_commit_shas": ["aaa"]}, {"local_repo_path": "real", "initial_commit_shas": ["bbb"]}]
    path.write_text("\n".join(json.dumps(r) for r in rows))
    result = ingest_records(path)
    assert len(result["prs"]) == 2
    fixture, real = result["prs"]
    assert fixture["repository"] is None and fixture["pr_url"] is None
    assert fixture["cohort"] == "calibration_only"
    assert real["pr_metadata_status"] == "missing" and real["pr_number"] is None


def test_malformed_jsonl_is_gap_and_limit_stops_read(tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_text('bad json\n{"repo":"org/repo","number":1}\n{"repo":"org/repo","number":2}\n')
    result = ingest_records(path, limit=1)
    assert len(result["prs"]) == 1 and len(result["gaps"]) == 1
    assert result["source_schema"]["rows_read"] == 2


def test_names_pr_labels_and_coauthors_do_not_prove_authorship():
    result = classify_actor({"hash": "aaa", "author_name": "Codex Agent", "message": "Co-authored-by: Human <human@example.invalid>"}, {"provided_label": "agent"})
    assert result["actor_type"] == "unknown"
    assert classify_actor({"hash": "a", "author_name": "Ordinary Developer"})["actor_type"] == "unknown"
    assert classify_actor({"hash": "a", "author_name": "dependabot[bot]"})["actor_type"] == "unknown"


def test_only_exact_binding_or_explicit_fixture_is_high():
    evidence = [{"kind": "local_session_commit_binding", "actor_type": "agent", "commit_sha": "aaa", "verified": True, "evidence_ref": "/local/binding.json"}]
    assert classify_actor({"hash": "aaa"}, evidence=evidence)["confidence"] == "high"
    assert classify_actor({"hash": "bbb"}, evidence=evidence)["actor_type"] == "unknown"
    fixture = {"is_synthetic": True, "synthetic_author_mapping": {"agent@fixture.invalid": "agent"}}
    assert classify_actor({"hash": "aaa", "author_email": "agent@fixture.invalid"}, fixture)["actor_type"] == "agent"
    fixture["is_synthetic"] = False
    assert classify_actor({"hash": "aaa", "author_email": "agent@fixture.invalid"}, fixture)["actor_type"] == "unknown"


def test_non_agent_bot_needs_platform_evidence():
    result = classify_actor({"sha": "aaa", "github_author": {"login": "dependabot[bot]", "type": "Bot", "html_url": "https://github.com/apps/dependabot"}})
    assert result["actor_type"] == "automation_non_agent"


def test_offline_miss_and_failure_retried_next_get(tmp_path, monkeypatch):
    from agentlog_unified import github_client as module
    client = GitHubClient(tmp_path, offline=True)
    assert client.get("repos/org/repo/pulls/1") is None
    assert client.failures[-1]["error_type"] == "offline_cache_miss"
    client.offline = False
    monkeypatch.setattr(module, "_token", lambda: None)
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(1)
        raise HTTPError("https://api.github.com/repos/org/repo/pulls/1", 404, "not found", {}, None)
    monkeypatch.setattr(module, "urlopen", unavailable)
    assert client.get("repos/org/repo/pulls/1") is None
    assert client.get("repos/org/repo/pulls/1") is None
    assert len(calls) == 2 and client.failures[-1]["error_type"] == "HTTP_404"


def test_pagination_cap_and_count_discrepancy(tmp_path, monkeypatch):
    client = GitHubClient(tmp_path, offline=True)
    def response(path):
        client.last_headers = {"link": '<https://api.github.com/repos/org/repo/pulls/1/commits?page=2>; rel="next"'}
        return [{"sha": str(i)} for i in range(100)]
    monkeypatch.setattr(client, "get", response)
    assert len(client.paginate("repos/org/repo/pulls/1/commits", max_items=50)) == 50
    assert client.failures[-1]["error_type"] == "endpoint_or_budget_cap"
    result = enrich_pr({"repository": "org/repo", "pr_number": 1, "head_sha": "h", "base_sha": "b", "base_ref": "main", "merged_at": None, "merge_commit_sha": None, "github_reported_commit_count": 3, "commit_shas": ["a"]}, client)
    assert result["commit_list_status"] == "potentially_incomplete"


def test_rate_limit_long_wait_is_recorded_without_bypassing(tmp_path, monkeypatch):
    from agentlog_unified import github_client as module
    monkeypatch.setattr(module, "_token", lambda: None)
    def limited(*args, **kwargs):
        raise HTTPError("https://api.github.com/repos/org/repo/pulls/1", 429, "slow", {"Retry-After": "3600"}, None)
    monkeypatch.setattr(module, "urlopen", limited)
    client = GitHubClient(tmp_path)
    assert client.get("repos/org/repo/pulls/1") is None
    assert client.requests == 1
    assert client.failures[-1]["retry_after_seconds"] == 3600


def test_streaming_json_crosses_buffer_and_rejects_truncation(tmp_path):
    import pytest
    path = tmp_path / "large.json"
    path.write_text(json.dumps([{"repo": "org/repo", "number": i, "detail": "x" * 40000} for i in range(1, 5)]))
    assert len(ingest_records(path)["prs"]) == 4
    path.write_text('[{"repo":"org/repo","number":1},')
    with pytest.raises(ValueError, match="Truncated"):
        ingest_records(path)


def test_get_success_cache_preserves_capture_time_and_no_credential(tmp_path, monkeypatch):
    from agentlog_unified import github_client as module
    class Response:
        headers = {"X-RateLimit-Remaining": "99", "Authorization": "must-not-persist"}
        def __enter__(self): return self
        def __exit__(self, *_): return None
        def read(self): return b'{"number": 1}'
    monkeypatch.setattr(module, "_token", lambda: "synthetic-test-credential")
    monkeypatch.setattr(module, "urlopen", lambda *args, **kwargs: Response())
    client = GitHubClient(tmp_path)
    assert client.get("repos/org/repo/pulls/1") == {"number": 1}
    captured = client.last_collected_at
    client.offline = True
    assert client.get("repos/org/repo/pulls/1") == {"number": 1}
    assert client.last_collected_at == captured and client.last_source == "cache"
    cached = next(tmp_path.glob("*.json")).read_text()
    assert "synthetic-test-credential" not in cached and "must-not-persist" not in cached


def test_ingest_then_offline_collect_reports_gaps(tmp_path):
    path = tmp_path / "pr.jsonl"
    path.write_text('{"repo":"org/repo","number":1}\n')
    pr = ingest_records(path)["prs"][0]
    result = enrich_pr(pr, GitHubClient(tmp_path / "cache", offline=True))
    assert result["pr_metadata_status"] == "partial"
    assert len(result["collection_gaps"]) == 2
