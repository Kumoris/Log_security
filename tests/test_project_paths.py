"""Synthetic relocation checks; no real research records are opened."""
import json
from pathlib import Path

import pytest

from agentlog_unified import config, ingest, paths
from agentlog_unified.paths import project_path, resolve_path


@pytest.mark.parametrize('old,new', [
    ('cache/repos/demo', 'data/cache/repos/demo'),
    ('inputs/demo.jsonl', 'data/inputs/demo.jsonl'),
    ('semantic-inputs/demo', 'data/semantic-inputs/demo'),
    ('runs/demo/run_manifest.json', 'outputs/runs/demo/run_manifest.json'),
    ('batches/demo', 'outputs/batches/demo'),
    ('semantic-runs/demo', 'outputs/semantic-runs/demo'),
    ('reports/demo.csv', 'outputs/tool-reports/demo.csv'),
    ('src/agentlog_unified/config.py', 'src/agentlog_unified/config.py'),
])
def test_known_project_paths_are_canonical_even_before_creation(tmp_path, old, new):
    assert project_path(old, tmp_path) == tmp_path / new


@pytest.mark.parametrize('prefix', [
    '/Users/previous/Log 研究/agentlog_unified/',
    'C:\\Users\\previous\\Log 研究\\agentlog\\workspace\\agentlog_unified\\',
    '/mnt/c/Users/previous/Log 研究/agentlog/workspace/agentlog_unified/',
    '/Users/previous/Log 研究/agentlog/',
])
def test_frozen_absolute_cache_paths_relocate(tmp_path, prefix):
    target = tmp_path / 'data/cache/repos/demo'
    target.mkdir(parents=True)
    assert resolve_path(prefix + 'cache/repos/demo', project=tmp_path) == target


def test_existing_explicit_path_is_not_replaced(tmp_path):
    old = tmp_path / 'cache/demo'
    old.mkdir(parents=True)
    (tmp_path / 'data/cache/demo').mkdir(parents=True)
    assert resolve_path(old, project=tmp_path) == old


def test_unknown_external_path_is_not_guessed(tmp_path):
    old = tmp_path.parent / 'unrelated/cache/demo'
    (tmp_path / 'data/cache/demo').mkdir(parents=True)
    assert resolve_path(old, project=tmp_path) == old


def test_legacy_privacy_cache_is_separate(tmp_path):
    assert resolve_path('/missing/agent_log_privacy/cache/demo', project=tmp_path) == tmp_path / 'data/cache/legacy-privacy/demo'


def test_relocation_cannot_escape_project(tmp_path):
    with pytest.raises(ValueError, match='traversal'):
        resolve_path('/missing/agentlog_unified/cache/../../outside', project=tmp_path)


def test_ingest_resolves_old_relative_cache_without_editing_input(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, 'PROJECT', tmp_path)
    repo = tmp_path / 'data/cache/legacy-privacy/demo'
    repo.mkdir(parents=True)
    source = tmp_path / 'examples/relocated/prs.jsonl'
    source.parent.mkdir(parents=True)
    source.write_text(json.dumps({'repository': 'fixture/demo', 'pr_number': 1,
        'local_repo_path': '../../cache/legacy-privacy/demo'}) + '\n')
    before = source.read_bytes()
    result = ingest.ingest_records(source)
    assert result['prs'][0]['local_repo_path'] == str(repo)
    assert result['prs'][0]['raw_records'][0]['local_repo_path'] == '../../cache/legacy-privacy/demo'
    assert source.read_bytes() == before


def test_config_moves_project_cache_but_keeps_run_database_relative(tmp_path, monkeypatch):
    defaults = config.PROJECT / 'config.example.yaml'
    (tmp_path / 'config.example.yaml').write_bytes(defaults.read_bytes())
    custom = tmp_path / 'custom.yaml'
    custom.write_text('mining:\n  repository_cache: cache/new\ninput:\n  prs_path: inputs/prs.jsonl\n')
    monkeypatch.setattr(config, 'PROJECT', tmp_path)
    result = config.load_config(str(custom))
    assert result['mining']['repository_cache'] == str(tmp_path / 'data/cache/new')
    assert result['input']['prs_path'] == str(tmp_path / 'data/inputs/prs.jsonl')
    assert result['storage']['index_database'] == 'data/index.sqlite'


def test_original_research_workspace_output_path(tmp_path):
    assert resolve_path('/Users/previous/Downloads/Log 研究/outputs/demo/manifest.json', project=tmp_path) == tmp_path / 'outputs/demo/manifest.json'
