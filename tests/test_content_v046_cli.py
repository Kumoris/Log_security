"""Real synthetic CLI flows and new-run input validation."""
import json

import pytest

from agentlog_unified import content_advance
from agentlog_unified.cli import main
from test_content_advance import fixture_parent
from test_content_reconcile import fixture


def test_advance_cli_dry_run_export_and_resume(tmp_path, capsys):
    parent, _, _ = fixture_parent(tmp_path)
    output = tmp_path / 'compressed'
    args = ['content-advance', '--input', str(parent), '--output', str(output), '--offline']
    assert main(args + ['--dry-run']) == 0
    assert not output.exists() and not json.loads(capsys.readouterr().out)['files_written']
    assert main(args + ['--max-rows', '0']) == 2
    before = json.loads(capsys.readouterr().out)['processed_rows']
    assert main(args + ['--max-rows', '2', '--resume']) == 2
    result = json.loads(capsys.readouterr().out)
    assert result['processed_rows'] == before + 2
    assert result['stop_reason'] == 'source_row_budget'
    assert (output / 'content_type_occurrences.jsonl.gz').is_file()


def test_reconcile_cli_real_gzip_and_fixed_resume(tmp_path, capsys):
    parent, repair, _ = fixture(tmp_path)
    output = tmp_path / 'merged'
    args = ['content-reconcile', '--input', str(parent), '--repair-run', str(repair),
            '--output', str(output), '--offline']
    assert main(args + ['--dry-run']) == 0
    assert not output.exists()
    capsys.readouterr()
    assert main(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert result['candidate_identities'] == 3 and not result['runtime_confirmed']
    manifest = json.loads((output / 'manifest.json').read_text())
    assert manifest['files_written'] is True and manifest['exit_code'] == 2
    before = (output / 'merged_type_occurrences.jsonl.gz').read_bytes()
    assert main(args + ['--resume']) == 2
    capsys.readouterr()
    assert (output / 'merged_type_occurrences.jsonl.gz').read_bytes() == before


@pytest.mark.parametrize('budgets', [{'max_seconds': float('nan')}, {'max_seconds': float('inf')},
                                    {'max_seconds': True}, {'min_free_bytes': float('nan')},
                                    {'batch_size': True}])
def test_advance_rejects_invalid_budgets_before_io(tmp_path, budgets):
    with pytest.raises(ValueError, match='budgets'):
        content_advance.advance_content(tmp_path/'absent', tmp_path/'out', **budgets)
    assert not (tmp_path/'out').exists()


def test_checkpoint_uri_escapes_path_delimiters(tmp_path):
    nested = tmp_path / 'space ? # unicode中文'; nested.mkdir()
    parent, _, _ = fixture_parent(nested)
    result = content_advance.advance_content(parent, nested/'advance', max_rows=0)
    assert result['before_cursors'] == result['after_cursors']


@pytest.mark.parametrize('dependency', ['storage.py', 'content_repair.py'])
def test_reconcile_resume_rejects_changed_execution_helper(tmp_path, monkeypatch, dependency):
    from agentlog_unified import content_reconcile as reconcile
    parent, fixed, _ = fixture(tmp_path)
    output = tmp_path / 'merged'
    reconcile.reconcile_content(parent, fixed, output)
    before = (output / 'manifest.json').read_bytes()
    digest = reconcile.repair._digest
    monkeypatch.setattr(reconcile.repair, '_digest', lambda path, *args, **kwargs:
                        '0' * 64 if getattr(path, 'name', '') == dependency else digest(path, *args, **kwargs))
    with pytest.raises(ValueError):
        reconcile.reconcile_content(parent, fixed, output, resume=True)
    assert (output / 'manifest.json').read_bytes() == before


@pytest.mark.parametrize('command,module,function,extra', [
    ('content-advance', 'content_advance', 'advance_content', []),
    ('content-reconcile', 'content_reconcile', 'reconcile_content', ['--repair-run', 'repair']),
])
def test_new_cli_error_does_not_echo_input(command, module, function, extra, monkeypatch, capsys):
    import importlib
    def fail(*args, **kwargs):
        raise ValueError('SOURCE_SENTINEL_MUST_NOT_BE_PRINTED')
    monkeypatch.setattr(importlib.import_module('agentlog_unified.'+module), function, fail)
    assert main([command, '--input', 'source', '--output', 'out', '--offline'] + extra) == 1
    printed = capsys.readouterr()
    assert 'SOURCE_SENTINEL' not in printed.out + printed.err
    assert json.loads(printed.err)['error_type'] == 'ValueError'
