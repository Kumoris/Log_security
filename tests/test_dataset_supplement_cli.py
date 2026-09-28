"""CLI entry points exercise real frozen Parquet and private checkpoints."""
import json

import pyarrow as pa
import pytest

from agentlog_unified.cli import main
from test_content_repair import parent_run
from test_schema_scan import frozen


def test_schema_cli_dry_run_execute_resume(tmp_path, capsys):
    imported, _ = frozen(tmp_path, {'all_user': pa.table({'id': [1.0, None, 2.5],
                                                        'login': ['synthetic_actor', '', 'second_actor']})})
    output = tmp_path / 'schema'
    args = ['schema-scan', '--input', str(imported), '--output', str(output), '--offline']
    assert main(args + ['--dry-run']) == 0
    assert json.loads(capsys.readouterr().out)['selected_fields'] == 2
    assert not output.exists()
    assert main(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert result['all_selected_fields_visited'] and result['counts']['cells_decoded'] == 6
    before = (output / 'schema_context_candidates.jsonl').read_bytes()
    assert main(args + ['--resume']) == 2
    assert 'synthetic_actor' not in capsys.readouterr().out
    assert before == (output / 'schema_context_candidates.jsonl').read_bytes()


def test_repair_cli_fixed_selection_and_page_resume(tmp_path, capsys):
    parent, _ = parent_run(tmp_path, ['padding ' * 20 + 'email="fixture@sample.invalid"'])
    output = tmp_path / 'repair'
    args = ['content-repair', '--input', str(parent), '--output', str(output), '--offline']
    assert main(args + ['--dry-run']) == 0
    assert json.loads(capsys.readouterr().out)['selected_cells'] == 1
    assert not output.exists()
    assert main(args + ['--max-pages', '0']) == 2
    assert not json.loads(capsys.readouterr().out)['all_selected_cells_all_rules_finished']
    assert main(args + ['--resume']) == 2
    printed = capsys.readouterr().out
    result = json.loads(printed)
    assert result['all_selected_cells_all_rules_finished'] and result['excluded_occurrences'] == 1
    assert result['unknown_type_review_cells'] == 1 and 'fixture@sample.invalid' not in printed


@pytest.mark.parametrize('command,module,function', [
    ('schema-scan', 'agentlog_unified.schema_scan', 'scan_schema_context'),
    ('content-repair', 'agentlog_unified.content_repair', 'run_content_repair'),
])
def test_decoder_exception_does_not_echo_source(command, module, function, monkeypatch, capsys):
    import importlib
    def fail(*args, **kwargs):
        raise ValueError('SYNTHETIC_SOURCE_VALUE_MUST_NOT_BE_PRINTED')
    monkeypatch.setattr(importlib.import_module(module), function, fail)
    assert main([command, '--input', '/private/tmp/example', '--output', '/private/tmp/example-output', '--offline']) == 1
    captured = capsys.readouterr()
    assert 'SYNTHETIC_SOURCE_VALUE' not in captured.err + captured.out
    assert json.loads(captured.err)['error_type'] == 'ValueError'
