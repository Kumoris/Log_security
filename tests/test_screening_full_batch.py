"""Actual CLI materialization/run/export of an explicitly selected full batch.

Uses real isolated Git commits and PyDriller extraction. No target program,
mock scheduler, model endpoint or network request is executed.
"""
import pytest

from agentlog_unified import screening as s
from agentlog_unified.cli import main
from test_screening_runner import fixture_run


def frozen_frame(tmp_path):
    out, cpath, _ = fixture_run(tmp_path, n=15)
    cfg = s.read(cpath)
    cfg.update(sample_size=5, batch_case_limit=25)
    s.write(cpath, cfg)
    assert main(['screening', 'discover', '--output', str(out), '--config', str(cpath)]) == 0
    assert main(['screening', 'freeze', '--output', str(out), '--config', str(cpath)]) == 0
    assert s.read(out / 'discovery/coverage.json')['output_units'] == 30
    assert s.read(out / 'selection/manifest.json')['primary_selected'] == 5
    return out


def test_explicit_full_batch_cli_runs_frame_cases_beyond_engineering_selection(tmp_path):
    out = frozen_frame(tmp_path)
    with pytest.raises(ValueError, match='exactly_one_explicit_full_batch_required'):
        main(['screening', 'prepare-full-batch', '--output', str(out)])
    with pytest.raises(ValueError, match='exactly_one_explicit_full_batch_required'):
        main(['screening', 'prepare-full-batch', '--output', str(out), '--batch', '0', '--batch', '1'])
    with pytest.raises(ValueError, match='full_batch_id_not_found'):
        main(['screening', 'prepare-full-batch', '--output', str(out), '--batch', '999'])
    assert not (out / 'analyses').exists()
    assert main(['screening', 'prepare-full-batch', '--output', str(out), '--batch', '0']) == 0
    child = out / 'full_batches/batch-0'
    child_cases, _, manifest = s.load_selected(child)
    expected = set(next(s.rows(out / 'selection/full_batches.jsonl'))['case_ids'])
    engineering = {c['case_id'] for c in s.rows(out / 'selection/engineering.jsonl')}
    selected = {c['case_id'] for c in child_cases}
    assert len(selected) == 25 and selected == expected
    assert len(selected - engineering) >= 20
    assert manifest['explicit_batch_only'] is True
    assert manifest['full_depth_executed'] is False
    assert manifest['parent_full_batch_id'] == 0
    assert not (child / 'analyses').exists()
    assert not (out / 'full_batches/batch-1').exists()
    with pytest.raises(ValueError, match='full_batch_already_materialized'):
        s.prepare_full_batch(out, 0)
    assert main(['screening', 'run', '--output', str(child)]) == 0
    assert main(['screening', 'export', '--output', str(child)]) == 0
    coverage = s.read(child / 'analyses/main/coverage.json')
    assert coverage['primary_cases'] == 25
    assert coverage['expected_analyses'] == coverage['actual_analyses'] == 50
    assert coverage['missing'] == coverage['unexpected'] == []
    assert coverage['duplicate_results'] == 0
    assert coverage['paired_base_evidence_equal'] is True
    assert coverage['graphs'] == 25
    assert coverage['acceptance']['process_integrity'] is True
    records = list(s.rows(child / 'analyses/main/results.jsonl'))
    assert {r['case_id'] for r in records} == selected
    assert len({r['analysis_id'] for r in records}) == 50
    assert all(r['processing_status'] != 'blocked' for r in records)
    assert all(r['runtime_confirmed'] is False for r in records)
    assert coverage['precision'] is None and coverage['recall'] is None
    assert main(['screening', 'run', '--output', str(child), '--resume']) == 0
    assert not (out / 'full_batches/batch-1').exists()
    assert not (out / 'analyses').exists()


@pytest.mark.parametrize('relative,error', [
    ('selection/full_batches.jsonl', 'full_batch_manifest_hash_mismatch'),
    ('discovery/output_units.jsonl', 'full_frame_hash_mismatch'),
])
def test_full_batch_materialization_refuses_changed_frozen_inputs(tmp_path, relative, error):
    out = frozen_frame(tmp_path)
    path = out / relative
    actual=s.resolved_data_path(path)
    if actual.suffix=='.gz':
        import gzip
        with gzip.open(actual,'rt') as f:content=f.read()
        path.write_text(content+'\n')
    else:path.write_text(path.read_text()+'\n')
    with pytest.raises(ValueError, match=error):
        s.prepare_full_batch(out, 0)
    assert not (out / 'full_batches/batch-0/selection/manifest.json').exists()
