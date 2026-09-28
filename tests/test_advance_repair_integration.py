"""Real synthetic import -> empty seed -> advance -> repair -> reconcile."""
import csv
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from agentlog_unified import aidev, content_advance as advance, content_scan
from agentlog_unified import content_repair as repair, content_reconcile as reconcile


def fixture(tmp_path, *, first_rows=None, values=None):
    raw = tmp_path / 'raw'; raw.mkdir()
    source = raw / 'all_pull_request.parquet'
    values = values or ['192.0.2.1 192.0.2.2 192.0.2.3', 'plain words', 'plain words']
    pq.write_table(pa.table({'body': values}), source, row_group_size=2)
    imported = tmp_path / 'import'
    ingestion = aidev.import_aidev(raw, imported)
    assert ingestion['complete'] and json.loads((imported / 'manifest.json').read_text())['status'] == 'complete'
    seed = tmp_path / 'seed'
    seed_result = content_scan.scan_content(imported, seed, max_seconds=1e-9, max_matches=1)
    assert seed_result['processed_rows'] == 0
    before = exported_bytes(seed)
    parent = tmp_path / 'advance'
    result = advance.advance_content(seed, parent, max_rows=first_rows, min_free_bytes=1)
    assert exported_bytes(seed) == before
    return seed, parent, source, before, ingestion, seed_result, result


def exported_bytes(path):
    return {p.name: p.read_bytes() for p in path.iterdir() if p.suffix in {'.json', '.jsonl', '.csv'}}


def rows(path, stem):
    with gzip.open(path / (stem + '.jsonl.gz'), 'rt') as stream:
        return [json.loads(line) for line in stream]


def test_real_pipeline_resume_and_compressed_exports(tmp_path, monkeypatch):
    seed, parent, source, before, imported, initial, advanced = fixture(tmp_path)
    source_hash = repair._digest(source)
    fixed = tmp_path / 'repair'; merged = tmp_path / 'merged'
    with monkeypatch.context() as patch:
        patch.setattr(repair, '_selected_values', lambda *a: pytest.fail('dry run decoded values'))
        plan = repair.run_content_repair(parent, fixed, dry_run=True)
        assert not fixed.exists() and plan['selected_cells'] == 1 and not plan['source_values_decoded']
    partial = repair.run_content_repair(parent, fixed, max_pages=1, core_chars=32, page_matches=1)
    complete = repair.run_content_repair(parent, fixed, resume=True, core_chars=32, page_matches=1)
    repeated = repair.run_content_repair(parent, fixed, resume=True, core_chars=32, page_matches=1)
    selection = json.loads((fixed / 'selection/selection_manifest.json').read_text())
    assert selection['parent_run'] == str(parent) and selection['parent_ancestor_run'] == str(seed)
    assert selection['parent_queue_name'].endswith('.jsonl.gz') and selection['parent_queue_format'] == 'gzip_jsonl'
    assert selection['parent_checkpoint_path'] == str(seed / 'content.sqlite')
    assert partial['stop_reason'] == 'page_budget' and not partial['all_selected_cells_all_rules_finished']
    assert complete['all_selected_cells_all_rules_finished'] and repeated['pages_this_invocation'] == 0
    assert complete['candidate_occurrences'] == repeated['candidate_occurrences'] == 3
    dry = reconcile.reconcile_content(parent, fixed, merged, dry_run=True)
    assert dry['exit_code'] == 0 and not merged.exists()
    result = reconcile.reconcile_content(parent, fixed, merged)
    assert result['candidate_identities'] == result['candidate_occurrence_variants'] == 3
    assert result['new_repair_identities'] == 2 and result['exact_duplicate'] == 1
    snapshot = {p.name: p.read_bytes() for p in merged.glob('*.gz')}
    repeat_merge = reconcile.reconcile_content(parent, fixed, merged, resume=True)
    assert {p.name: p.read_bytes() for p in merged.glob('*.gz')} == snapshot
    for p in merged.glob('*.jsonl.gz'):
        with gzip.open(p, 'rt') as stream:
            actual = list(stream)
        with gzip.open(p.with_name(p.name.replace('.jsonl.gz', '.csv.gz')), 'rt') as stream:
            assert len(list(csv.DictReader(stream))) == len(actual)
        assert b'192.0.2.1' not in gzip.decompress(p.read_bytes())
    assert exported_bytes(seed) == before and repair._digest(source) == source_hash
    assert not (parent / 'content.sqlite').exists()
    evidence = {
        'import': {'complete': imported['complete'], 'exit_code': imported['exit_code'], 'manifest_genuinely_generated': True},
        'empty_seed': {'processed_rows': initial['processed_rows'], 'exit_code': initial['exit_code']},
        'advance': {k: advanced[k] for k in ('processed_rows', 'candidate_occurrences', 'exit_code')},
        'selection': {'selected_cells': selection['selected_cells'], 'gzip_parent': True, 'ancestor_verified': True},
        'repair_partial': {k: partial[k] for k in ('pages_this_invocation', 'stop_reason', 'exit_code')},
        'repair_complete': {k: complete[k] for k in ('candidate_occurrences', 'all_selected_cells_all_rules_finished', 'exit_code')},
        'repair_repeat_new_pages': repeated['pages_this_invocation'],
        'reconcile': {k: result[k] for k in ('candidate_identities', 'candidate_occurrence_variants', 'new_repair_identities', 'exact_duplicate', 'exit_code')},
        'legacy_seed_exports_unchanged': exported_bytes(seed) == before, 'source_unchanged': repair._digest(source) == source_hash,
        'gzip_csv_jsonl_row_counts_match': True, 'reconcile_resume_gzip_bytes_identical': True,
        'real_data_used': False, 'source_values_exported': False,
    }
    if os.environ.get('ADVANCE_REPAIR_EVIDENCE'):
        Path(os.environ['ADVANCE_REPAIR_EVIDENCE']).write_text(json.dumps(evidence, indent=2) + '\n')


@pytest.mark.parametrize('owner', ['seed', 'advance'])
def test_selection_holds_both_parent_and_ancestor_locks(tmp_path, owner):
    seed, parent, *_ = fixture(tmp_path)
    lock_path = (seed if owner == 'seed' else parent) / '.content.lock'
    with lock_path.open('rb') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match='writer is active'):
            repair.prepare_repair_selection(parent, tmp_path / 'selection', dry_run=True)


def test_completed_export_with_shared_checkpoint_ahead_is_rejected(tmp_path):
    seed, parent, *_ = fixture(tmp_path, first_rows=1)
    advance.advance_content(seed, tmp_path / 'newer', min_free_bytes=1)
    assert json.loads((parent / 'advance_state.json').read_text())['status'] == 'export_complete'
    with pytest.raises(ValueError, match='checkpoint cursors differ'):
        repair.prepare_repair_selection(parent, tmp_path / 'selection')
    assert not (tmp_path / 'selection').exists()


def test_same_count_queue_metadata_tampering_rejected(tmp_path):
    _, parent, *_ = fixture(tmp_path)
    queue = parent / 'content_unknown_type_review_queue.jsonl.gz'
    payload = rows(parent, 'content_unknown_type_review_queue')
    payload[0]['text_hmac_sha256'] = '0' * 64
    with gzip.open(queue, 'wt') as stream:
        stream.writelines(json.dumps(row) + '\n' for row in payload)
    with pytest.raises(ValueError, match='queue metadata differs'):
        repair.prepare_repair_selection(parent, tmp_path / 'selection')
    assert not (tmp_path / 'selection').exists()


def test_incomplete_gzip_rejected_before_writes(tmp_path):
    _, parent, *_ = fixture(tmp_path)
    queue = parent / 'content_unknown_type_review_queue.jsonl.gz'
    queue.write_bytes(queue.read_bytes()[:-6])
    with pytest.raises((EOFError, OSError)):
        repair.prepare_repair_selection(parent, tmp_path / 'selection')
    assert not (tmp_path / 'selection').exists()


def test_shared_ancestor_does_not_authorize_sibling_advance_repair(tmp_path):
    seed, parent, *_ = fixture(tmp_path)
    fixed = tmp_path / 'repair'; repair.run_content_repair(parent, fixed)
    sibling = tmp_path / 'sibling'; advance.advance_content(seed, sibling, max_rows=0, min_free_bytes=1)
    with pytest.raises(ValueError, match='verified parent ancestor'):
        reconcile.reconcile_content(sibling, fixed, tmp_path / 'merged')
    assert not (tmp_path / 'merged').exists()


def test_checkpoint_replacement_is_rejected(tmp_path):
    seed, parent, *_ = fixture(tmp_path)
    checkpoint = seed / 'content.sqlite'; backup = seed / 'old.sqlite'
    checkpoint.rename(backup); checkpoint.write_bytes(backup.read_bytes())
    with pytest.raises(ValueError, match='checkpoint identity changed'):
        repair.prepare_repair_selection(parent, tmp_path / 'selection', dry_run=True)


def test_resume_keeps_fixed_selection_when_valid_parent_export_grows(tmp_path):
    seed, parent, *_ = fixture(tmp_path, first_rows=1, values=['192.0.2.1 192.0.2.2', '192.0.2.3 192.0.2.4'])
    fixed = tmp_path / 'repair'
    repair.run_content_repair(parent, fixed, max_pages=0)
    selection_before = exported_bytes(fixed / 'selection')
    advance.advance_content(seed, parent, resume=True, min_free_bytes=1)
    result = repair.run_content_repair(parent, fixed, resume=True)
    assert result['selected_cells'] == 1 and exported_bytes(fixed / 'selection') == selection_before
    merged = reconcile.reconcile_content(parent, fixed, tmp_path / 'merged')
    assert merged['candidate_identities'] == 3


def test_stale_state_and_ancestor_key_rejected(tmp_path):
    seed, parent, *_ = fixture(tmp_path)
    state = parent / 'advance_state.json'; original = state.read_bytes()
    state.write_text(json.dumps({'status': 'interrupted'}))
    with pytest.raises(ValueError, match='incomplete or stale'):
        repair.prepare_repair_selection(parent, tmp_path / 'selection', dry_run=True)
    state.write_bytes(original)
    (seed / '.fingerprint-key').write_bytes(b'z' * 32)
    with pytest.raises(ValueError, match='key is missing or changed'):
        repair.prepare_repair_selection(parent, tmp_path / 'selection', dry_run=True)
