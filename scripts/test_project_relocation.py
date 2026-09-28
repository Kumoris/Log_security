"""Relocation checks using synthetic folders only."""
import json
from pathlib import Path

from audit_swechat_motivation_inputs import followup_files
import run_swechat_followups as followups


def test_audit_scans_legacy_once_and_excludes_private_trees(tmp_path):
    included = ['outputs/runs/legacy-privacy/demo/data/followups.jsonl',
                'research/development/demo/followups.jsonl']
    excluded = ['data/cache/demo/followups.jsonl',
                'research/sealed/demo/followups.jsonl',
                'research/development/evidence/demo/followups.jsonl',
                'archive/old-demo/followups.jsonl']
    for name in included + excluded:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{}\n')
    result = list(followup_files(tmp_path))
    assert sorted(str(p.relative_to(tmp_path)) for p in result) == sorted(included)
    assert len(result) == len(set(result))


def test_git_alternates_are_resolved_without_rewriting_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(followups, 'PROJECT', tmp_path)
    repo = tmp_path / 'data/cache/repo'
    alternates = repo / '.git/objects/info/alternates'
    alternates.parent.mkdir(parents=True)
    target = tmp_path / 'data/cache/shared/objects'
    target.mkdir(parents=True)
    alternates.write_text('/missing/agentlog_unified/cache/shared/objects\n')
    before = alternates.read_bytes()
    env = followups.environment(repo)
    assert str(target) in env['GIT_ALTERNATE_OBJECT_DIRECTORIES']
    assert alternates.read_bytes() == before


def test_selected_attempt_resolves_old_workspace_path(tmp_path, monkeypatch):
    monkeypatch.setattr(followups, 'PROJECT', tmp_path)
    out = tmp_path / 'outputs/demo'
    monkeypatch.setattr(followups, 'OUT', out)
    attempt = out / 'additional-attempts/accepted'
    attempt.mkdir(parents=True)
    (out / 'selected_repository_attempts.json').write_text(json.dumps({'fixture/repo': {
        'directory': '/missing/agentlog/workspace/outputs/demo/additional-attempts/accepted',
        'validation_status': 'PASS'}}))
    assert followups.repository_output_directory('fixture/repo') == attempt
