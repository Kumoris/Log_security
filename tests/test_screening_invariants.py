"""Bounded runner invariants over real isolated Git/PyDriller histories.

Only TimeoutError is injected for failure-path tests. Fixtures never execute
application code. These checks are independent of engineering/holdout data.
"""
from copy import deepcopy
import sqlite3

import pytest

from agentlog_unified import screening as s
from agentlog_unified import screening_evidence as adapter
from agentlog_unified.screening_history import extract_commit
from synthetic_histories import init, commit, HEADER


def frozen(tmp_path, expression='"password=FICTIONAL_INVALID_TEST_ONLY"', crlf=False):
    repo = tmp_path / 'repo'
    init(repo)
    source = HEADER + 'logger.info(' + expression + ')\n'
    if crlf: source = source.replace('\n', '\r\n')
    sha = commit(repo, {'app.py': source}, 'synthetic invariant fixture')
    out = tmp_path / 'run'
    mined = extract_commit(repo, 'fixture/invariants', sha, out / 'mining')
    records = [{**r, 'commit_id': 'fixture-commit', 'repo_path': str(repo), 'scope': 'test',
                'input_record_ids': ['fixture-input'], 'old_stratum': 'not_hit', 'old_log_ids': []}
               for r in mined['file_versions']]
    s.write_rows(out / 'population/file_versions.jsonl', records)
    cfg = s.config()
    cfg.update(sample_size=1, evaluation_size=0, batch_case_limit=1)
    s.discover(out, cfg)
    s.freeze(out, cfg)
    return out


def results(out, label='main'):
    with sqlite3.connect(out / 'analyses' / label / 'checkpoint.sqlite') as db:
        import json
        return [json.loads(r[0]) for r in db.execute('SELECT data FROM results ORDER BY variant')]


def timeout(*args, **kwargs):
    raise TimeoutError('injected_case_time_budget_exceeded')


def test_real_pipeline_dfg_timeout_preserves_independent_literal_A(tmp_path, monkeypatch):
    out = frozen(tmp_path)
    monkeypatch.setattr(adapter, 'analyze_dfg', timeout)
    executed = s.execute_batches(out)
    rs = results(out)
    assert executed['processed_this_invocation'] == 2
    assert {r['queue'] for r in rs} == {'A'}
    augmented = next(r for r in rs if r['variant'] == 'dfg_augmented')
    assert augmented['processing_status'] == 'blocked'
    assert 'TimeoutError' in augmented['failure_reason']
    assert augmented['assessment']['dimensions']['critical_unknowns'] == []
    assert augmented['assessment']['dimensions']['noncritical_unknowns']
    assert all(r['runtime_confirmed'] is False for r in rs)
    assert 'FICTIONAL_INVALID_TEST_ONLY' not in s.canonical(rs)


@pytest.mark.parametrize('filename', ['engineering.jsonl', 'evaluation.jsonl', 'groups.jsonl', 'batches.jsonl'])
def test_selected_lists_reject_byte_changes(tmp_path, filename):
    out = frozen(tmp_path)
    path = out / 'selection' / filename
    path.write_text(path.read_text() + '\n')
    with pytest.raises(ValueError, match='frozen_manifest_hash_mismatch'):
        s.load_selected(out)


def test_resume_refuses_analysis_signature_change(tmp_path, monkeypatch):
    out = frozen(tmp_path)
    s.execute_batches(out)
    version = deepcopy(s.code_version())
    version['sources']['src/agentlog_unified/screening.py'] = '0' * 64
    monkeypatch.setattr(s, 'code_version', lambda: version)
    with pytest.raises(ValueError, match='analysis_code_config_or_selection_changed'):
        s.execute_batches(out, resume=True)


def test_snapshot_hash_failure_cannot_preserve_A_or_make_C(tmp_path):
    out = frozen(tmp_path)
    cases, _, _ = s.load_selected(out)
    path = s.Path(cases[0]['snapshot_ref'])
    path.write_text(path.read_text() + '\n')
    s.execute_batches(out)
    rs = results(out)
    assert all(r['processing_status'] == 'blocked' for r in rs)
    assert all(r['queue'] not in {'A', 'C'} for r in rs)
    assert all('snapshot_hash_mismatch' in r['failure_reason'] for r in rs)


def test_full_freeze_groups_versions_fields_and_cross_repository_near_duplicates(tmp_path):
    out = tmp_path / 'run'
    prepared = []
    for i, repository in enumerate(['fixture/a', 'fixture/b', 'fixture/c']):
        source = 'print({"value": "one", "ok": True})\n' if i < 2 else 'print(False)\nprint(True)\n'
        path = tmp_path / ('source' + str(i) + '.py')
        path.write_text(source)
        for side, sha in [('before', 'b' * 40), ('after', 'a' * 40)]:
            found = adapter.discover_outputs(repository, 'a' * 40, 'b' * 40, sha, side, 'app.py', source)
            for c in found:
                c.update(near_duplicate_key=s.near_key(c, source), source_path=str(path),
                         repo_path=str(tmp_path), scope='test', old_path='app.py', new_path='app.py',
                         legacy_stratum='not_hit', input_record_ids=['synthetic'])
            prepared.extend(found)
    s.write_rows(out / 'discovery/output_units.jsonl', prepared)
    s.write_rows(out / 'population/file_versions.jsonl', [])
    cfg = s.config()
    cfg.update(sample_size=100, evaluation_size=100, holdout_fraction=0.5)
    manifest = s.freeze(out, cfg)
    groups = list(s.rows(out / 'selection/groups.jsonl'))
    by_repo = {}
    for row in groups:
        by_repo.setdefault(row['repository'], set()).add((row['group_id'], row['split']))
    assert all(len(v) == 1 for v in by_repo.values())
    assert by_repo['fixture/a'] == by_repo['fixture/b']
    assert by_repo['fixture/a'] != by_repo['fixture/c']
    assert manifest['groups'] == 2 and manifest['holdout_groups'] == 1
    dev = {c['case_id'] for c in s.rows(out / 'selection/engineering.jsonl')}
    evaluation = {c['case_id'] for c in s.rows(out / 'selection/evaluation.jsonl')}
    assert dev.isdisjoint(evaluation)
    assert dev | evaluation == {c['case_id'] for c in prepared}


def test_export_rejects_corrupted_graph_without_needing_resume(tmp_path):
    out = frozen(tmp_path)
    s.execute_batches(out)
    graph = next((out / 'analyses/main/graphs').rglob('*.json'))
    changed = s.read(graph)
    changed['nodes'] = []
    s.write(graph, changed)
    with pytest.raises(ValueError, match='hash|integrity|artifact'):
        s.export(out)


def test_unresolved_identifier_to_sink_edge_is_not_DFG_applicability(tmp_path):
    out = frozen(tmp_path, expression='missing_value')
    s.execute_batches(out)
    report = s.export(out)
    assert report['graphs'] == 1
    assert report['acceptance']['real_DFG_applicability'] is False


def test_retry_failed_preserves_original_attempt_and_reuses_only_success(tmp_path, monkeypatch):
    out = frozen(tmp_path)
    with monkeypatch.context() as injected:
        injected.setattr(adapter, 'analyze_dfg', timeout)
        s.execute_batches(out)
    before = {r['variant']: r for r in results(out)}
    retried = s.execute_batches(out, resume=True, retry_failed=True)
    after = {r['variant']: r for r in results(out)}
    assert retried['processed_this_invocation'] == 1 and retried['cache_hits'] == 1
    assert after['baseline']['attempt_id'] == before['baseline']['attempt_id']
    assert after['dfg_augmented']['analysis_id'] == before['dfg_augmented']['analysis_id']
    assert after['dfg_augmented']['attempt_id'] != before['dfg_augmented']['attempt_id']
    assert after['dfg_augmented']['processing_status'] != 'blocked'
    assert all((out / 'analyses/main' / path).exists() for path in before['dfg_augmented']['artifact_hashes'])
    with sqlite3.connect(out / 'analyses/main/checkpoint.sqlite') as db:
        assert db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0] == 3
        assert db.execute('SELECT COUNT(*) FROM results').fetchone()[0] == 2


def test_retry_failed_retries_transient_mining_stage(tmp_path, monkeypatch):
    from agentlog_unified import screening_history
    out = frozen(tmp_path)
    with monkeypatch.context() as injected:
        injected.setattr(screening_history, 'extract_commit', timeout)
        s.execute_batches(out)
    assert all(r['processing_status'] == 'blocked' for r in results(out))
    s.execute_batches(out, resume=True, retry_failed=True)
    assert all(r['processing_status'] != 'blocked' for r in results(out))


def test_crlf_historical_source_is_not_silently_normalized(tmp_path):
    out = frozen(tmp_path, crlf=True)
    s.execute_batches(out)
    assert all(r['processing_status'] != 'blocked' for r in results(out))
