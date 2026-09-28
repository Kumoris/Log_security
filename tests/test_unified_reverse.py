import pytest

from agentlog_unified.reverse import scan_reverse
from synthetic_histories import init, commit


def test_szz_multiline_argument_only_and_no_unrelated_file_attribution(tmp_path):
    repo = tmp_path / 'repo'; init(repo)
    intro = commit(repo, {'app.py': 'import logging\ndef f(user):\n    logging.info(\n        "value",\n        user.password,\n    )\n'}, 'introduce log', actor='human')
    commit(repo, {'app.py': (repo/'app.py').read_text()+'\ndef unrelated():\n    return 1\n'}, 'agent changes unrelated function', actor='agent', day=3)
    tip = commit(repo, {'app.py': (repo/'app.py').read_text().replace('user.password,', '"[redacted]",').replace('return 1', 'return 2')}, 'redact log and cleanup', actor='human', day=4)
    # Build the same metadata used by the forward pipeline; reverse does not promote names.
    from agentlog_unified.miner import mine_repository
    mined = mine_repository(str(repo), tip, [intro]); mined['repository_id'] = 'r'
    repository = {'id': 'r', 'repository': None, 'local_repo_path': str(repo), 'pr_ids': [], 'is_synthetic': True}
    out = scan_reverse([repository], [mined], [], {'max_commits': 100})
    assert out['metrics']['pydriller_szz_calls'] == 1
    assert len(out['reverse_candidates']) == 1
    c = out['reverse_candidates'][0]
    assert c['deleted_line_numbers'] == [5]
    assert [o['sha'] for o in c['introducing_commit_candidates']] == [intro]
    assert c['introducing_commit_candidates'][0]['attribution']['actor_type'] == 'unknown'
    assert c['agent_introduction_confirmed'] is False
    assert c['cohort'] == 'repair_enriched' and not out['gaps']


@pytest.mark.parametrize("extension,source", [
    ("go", 'package main\nimport "log"\nfunc run(password string) {\n log.Printf(\n  "value=%s",\n  password,\n )\n}\n'),
    ("cs", 'using Microsoft.Extensions.Logging;\nclass App {\n void Run(ILogger logger, string password) {\n logger.LogInformation(\n  "value={Password}",\n  password\n );\n }\n}\n'),
])
def test_lexical_history_snapshot_and_reverse_deleted_log_span(tmp_path, extension, source):
    from agentlog_unified.analysis import detect_history
    from agentlog_unified.config import load_config, PROJECT
    from agentlog_unified.miner import mine_repository

    repo = tmp_path / 'repo'
    init(repo)
    path = 'main.' + extension
    intro = commit(repo, {path: source}, 'introduce log')
    tip = commit(repo, {path: source.replace('  password', '  "[redacted]"')},
                 'redact log argument', actor='human', day=3)
    mined = mine_repository(str(repo), tip, [intro])
    mined['repository_id'] = 'r'
    repository = {'id': 'r', 'repository_id': 'synthetic-' + extension, 'repository': None,
                  'local_repo_path': str(repo), 'pr_ids': [], 'is_synthetic': True}
    detected = detect_history(repository, mined, load_config(str(PROJECT / 'config.example.yaml')))
    assert any(event['sha'] == intro and event.get('after', {}).get('path') == path
               for event in detected['events'])
    assert any(gap.get('path') == path for gap in detected['gaps'])
    assert all(snapshot['reverse_dependency_coverage'] == 'partial'
               for snapshot in detected['snapshots'] if snapshot['sha'] in {intro, tip})
    reverse = scan_reverse([repository], [mined], [], {'max_commits': 100})
    assert reverse['metrics']['pydriller_szz_calls'] == 1
    candidate, = reverse['reverse_candidates']
    assert candidate['deleted_line_numbers'] == [6]
    assert [row['sha'] for row in candidate['introducing_commit_candidates']] == [intro]
    assert candidate['privacy_repair_confirmed'] is False
