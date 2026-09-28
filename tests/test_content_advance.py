import fcntl
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from agentlog_unified import content_advance as advance
from agentlog_unified import content_scan, content_types

STEMS = ('content_type_occurrences', 'content_excluded', 'content_unknown_type_review_queue')


def fixture_parent(tmp_path, values=None):
    source = tmp_path/'source'; source.mkdir()
    imported = tmp_path/'import'; imported.mkdir()
    values = values or ['alpha', 'beta', None, '', 'email=demo@example.com',
                        'message="SYNTHETIC_PRIVATE_SENTINEL"', 'gamma', 'delta']
    path = source/'all_pull_request.parquet'
    pq.write_table(pa.table({'body': values, 'author_login': ['untyped synthetic text']*len(values)}), path, row_group_size=3)
    doc = {'status': 'complete', 'source_signature': {'source_dir': str(source), 'inputs': [
        {'path': path.name, 'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}]},
        'outputs': {'aidev.sqlite': 'synthetic'}}
    (imported/'manifest.json').write_text(json.dumps(doc))
    parent = tmp_path/'parent'
    content_scan.scan_content(imported, parent, max_seconds=1e-9, batch_size=2)
    return parent, imported, path


def rows(parent):
    with sqlite3.connect(parent/'content.sqlite') as db:
        return {table: db.execute('SELECT * FROM '+table+' ORDER BY 1').fetchall() for table in advance.SCHEMA}


def old_exports(parent):
    return {p.name: p.read_bytes() for p in parent.iterdir() if p.suffix in {'.json', '.jsonl', '.csv'}}


def test_gzip_decompressed_bytes_equal_legacy_export_and_parent_snapshot_unchanged(tmp_path):
    parent, imported, _ = fixture_parent(tmp_path)
    baseline = old_exports(parent); inode = (parent/'content.sqlite').stat().st_ino
    reference = tmp_path/'reference'; shutil.copytree(parent, reference)
    output = tmp_path/'advance'
    result = advance.advance_content(parent, output, batch_size=2)
    expected = content_scan.scan_content(imported, reference, resume=True, batch_size=2)
    assert result['candidate_occurrences'] == expected['candidate_occurrences']
    assert result['unknown_type_review_cells'] == expected['unknown_type_review_cells']
    assert result['processed_rows'] == expected['processed_rows'] == 8
    assert rows(parent) == rows(reference)
    assert old_exports(parent) == baseline
    assert (parent/'content.sqlite').stat().st_ino == inode and not (output/'content.sqlite').exists()
    for stem in STEMS:
        for extension in ('.jsonl', '.csv'):
            blob = gzip.decompress((output/(stem+extension+'.gz')).read_bytes())
            assert blob == (reference/(stem+extension)).read_bytes()
            assert b'SYNTHETIC_PRIVATE_SENTINEL' not in blob
    assert (output/'content_type_summary.json').read_bytes() == (reference/'content_type_summary.json').read_bytes()
    manifest = json.loads((output/'manifest.json').read_text())
    assert manifest['engine'] == 'content_advance_v1'
    assert manifest['checkpoint_path'] == str(parent/'content.sqlite')
    assert manifest['fingerprint']['implementation_sha256'] == {'content_advance.py': advance._digest(Path(advance.__file__))}
    assert manifest['fingerprint']['frozen_source_sha256'] == json.loads((parent/'manifest.json').read_text())['fingerprint']['source_sha256']
    assert (output/'.fingerprint-key').read_bytes() == (parent/'.fingerprint-key').read_bytes()
    assert json.loads((output/'advance_state.json').read_text())['status'] == 'export_complete'


def test_time_budget_resume_extends_ranges_and_visits_each_committed_row_once(tmp_path, monkeypatch):
    parent, _, _ = fixture_parent(tmp_path, ['alpha', 'beta', 'gamma', 'delta', 'epsilon'])
    clock = [0]; seen = []
    monkeypatch.setattr(advance.time, 'monotonic', lambda: clock[0])
    original = content_types.classify_text
    def timed(text, **kwargs):
        clock[0] += .5; seen.append(text)
        return original(text, **kwargs)
    monkeypatch.setattr(content_types, 'classify_text', timed)
    output = tmp_path/'advance'
    first = advance.advance_content(parent, output, max_seconds=2, batch_size=3)
    assert first['processed_rows'] == 2 and first['stop_reason'] == 'time_budget'
    last = advance.advance_content(parent, output, resume=True, batch_size=2)
    assert last['processed_rows'] == 5 and len(seen) == 10
    snapshot = rows(parent)
    again = advance.advance_content(parent, output, resume=True)
    assert rows(parent) == snapshot and len(seen) == 10
    assert again['before_cursors'] == again['after_cursors']
    queue = [json.loads(line) for line in gzip.decompress((output/'content_unknown_type_review_queue.jsonl.gz').read_bytes()).splitlines()]
    assert all(r['start_row'] == 1 and r['end_row'] == 5 for r in queue)
    assert sum(r['row_count'] for r in queue) == 10


@pytest.mark.parametrize('target', ['source', 'legacy_classifier', 'field_selection', 'key', 'schema'])
def test_invalid_parent_rejected_before_checkpoint_mutation(tmp_path, target):
    parent, _, source = fixture_parent(tmp_path)
    if target == 'source':
        data = bytearray(source.read_bytes()); data[len(data)//2] ^= 1; source.write_bytes(data)
    elif target == 'legacy_classifier':
        path = parent/'manifest.json'; doc = json.loads(path.read_text())
        doc['fingerprint']['source_sha256']['content_types.py'] = 'changed'; path.write_text(json.dumps(doc))
    elif target == 'field_selection':
        path = parent/'manifest.json'; doc = json.loads(path.read_text())
        doc['tables'][0]['columns'][0]['field_scope'] = 'altered'; path.write_text(json.dumps(doc))
    elif target == 'key':
        (parent/'.fingerprint-key').write_bytes(b'x'*32)
    else:
        with sqlite3.connect(parent/'content.sqlite') as db: db.execute('ALTER TABLE matches ADD COLUMN unexpected TEXT')
    before = (parent/'content.sqlite').read_bytes()
    with pytest.raises(ValueError): advance.advance_content(parent, tmp_path/'advance')
    assert (parent/'content.sqlite').read_bytes() == before and not (tmp_path/'advance').exists()


def test_resume_rejects_new_implementation_identity_or_checkpoint_replacement(tmp_path):
    parent, _, _ = fixture_parent(tmp_path); output = tmp_path/'advance'
    advance.advance_content(parent, output)
    path = output/'manifest.json'; original = path.read_bytes(); doc = json.loads(original)
    doc['fingerprint']['implementation_sha256']['content_advance.py'] = 'changed'; path.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match='same parent'): advance.advance_content(parent, output, resume=True)
    path.write_bytes(original)
    temp = parent/'replacement.sqlite'; shutil.copyfile(parent/'content.sqlite', temp); temp.replace(parent/'content.sqlite')
    with pytest.raises(ValueError, match='same parent'): advance.advance_content(parent, output, resume=True)


def test_locks_and_output_overlap_are_rejected(tmp_path):
    parent, imported, _ = fixture_parent(tmp_path)
    with (parent/'.content.lock').open('rb') as locked:
        fcntl.flock(locked, fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match='active'): advance.advance_content(parent, tmp_path/'advance')
    for output in [parent, parent/'nested', imported/'nested']:
        with pytest.raises(ValueError): advance.advance_content(parent, output)


def test_dry_run_does_not_create_output_or_change_database(tmp_path):
    parent, _, _ = fixture_parent(tmp_path); before = (parent/'content.sqlite').read_bytes()
    report = advance.advance_content(parent, tmp_path/'advance', dry_run=True)
    assert not report['files_written'] and not report['source_values_decoded']
    assert not (tmp_path/'advance').exists() and (parent/'content.sqlite').read_bytes() == before


def test_interrupted_batch_rolls_back_and_resume_preserves_previous_commits(tmp_path, monkeypatch):
    parent, _, _ = fixture_parent(tmp_path, ['alpha', 'beta', 'gamma', 'delta'])
    original = content_types.classify_text
    def interrupt(text, **kwargs):
        if text == 'gamma': raise RuntimeError('synthetic')
        return original(text, **kwargs)
    monkeypatch.setattr(content_types, 'classify_text', interrupt)
    output = tmp_path/'advance'
    with pytest.raises(RuntimeError, match='synthetic'): advance.advance_content(parent, output, batch_size=2)
    with sqlite3.connect(parent/'content.sqlite') as db:
        assert db.execute('SELECT next_row FROM tables').fetchone()[0] == 2
    state = json.loads((output/'advance_state.json').read_text())
    assert state['status'] == 'interrupted' and state['exports_may_be_stale']
    monkeypatch.setattr(content_types, 'classify_text', original)
    result = advance.advance_content(parent, output, resume=True, batch_size=2)
    assert result['processed_rows'] == 4


def test_disk_guard_stops_scan_and_export_failure_is_explicit_and_resumable(tmp_path, monkeypatch):
    parent, _, _ = fixture_parent(tmp_path); output = tmp_path/'advance'
    usage = shutil.disk_usage(parent); free = [2*1024**3]
    monkeypatch.setattr(advance.shutil, 'disk_usage', lambda path: usage._replace(free=free[0]))
    first = advance.advance_content(parent, output, min_free_bytes=1700*1024**2)
    assert first['processed_rows'] == 0 and first['stop_reason'] == 'disk_budget'
    before = rows(parent); free[0] = 1
    with pytest.raises(OSError, match='reserve'): advance.advance_content(parent, output, resume=True, min_free_bytes=1700*1024**2)
    assert rows(parent) == before
    assert json.loads((output/'advance_state.json').read_text())['status'] == 'interrupted'
    free[0] = 8*1024**3
    last = advance.advance_content(parent, output, resume=True, min_free_bytes=1700*1024**2)
    assert last['processed_rows'] == 8


def test_exact_new_row_budget_and_output_lock(tmp_path):
    parent, _, _ = fixture_parent(tmp_path); output = tmp_path/'advance'
    first = advance.advance_content(parent, output, max_rows=1)
    assert first['processed_rows'] == 1 and first['stop_reason'] == 'source_row_budget'
    second = advance.advance_content(parent, output, resume=True, max_rows=2)
    assert second['processed_rows'] == 3 and second['execution_budget']['max_rows'] == 2
    with (output/'.content.lock').open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match='active'): advance.advance_content(parent, output, resume=True)


def test_invalid_detector_fields_rollback_without_plaintext_export(tmp_path, monkeypatch):
    parent, _, _ = fixture_parent(tmp_path)
    monkeypatch.setattr(content_types, 'classify_text', lambda text, **kw: {'matches': [{'text': 'SYNTHETIC_SENSITIVE_SENTINEL'}], 'truncated': False})
    with pytest.raises(ValueError, match='unapproved evidence'): advance.advance_content(parent, tmp_path/'advance')
    with sqlite3.connect(parent/'content.sqlite') as db:
        assert db.execute('SELECT next_row FROM tables').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM matches').fetchone()[0] == 0
    for path in (tmp_path/'advance').iterdir():
        if path.is_file(): assert b'SYNTHETIC_SENSITIVE_SENTINEL' not in path.read_bytes()


def test_existing_export_size_increases_peak_reserve(tmp_path):
    output = tmp_path/'output'; output.mkdir()
    (output/'content_type_occurrences.jsonl.gz').write_bytes(b'x'*80)
    (output/'content_coverage.json').write_text(json.dumps({'checkpoint_bytes_at_export': 100}))
    ratio, retained = advance._export_reserve_ratio(output)
    assert ratio == pytest.approx(1.2) and retained == 80


def test_zero_row_budget_reexports_same_checkpoint_without_decoding_source(tmp_path, monkeypatch):
    parent, _, _ = fixture_parent(tmp_path); output = tmp_path/'advance'
    advance.advance_content(parent, output, max_rows=1)
    before = rows(parent)
    exported = {p.name: p.read_bytes() for p in output.glob('*.gz')}
    def must_not_decode(*args, **kwargs): raise AssertionError('zero-row export decoded source')
    monkeypatch.setattr(pq.ParquetFile, 'iter_batches', must_not_decode)
    result = advance.advance_content(parent, output, resume=True, max_rows=0)
    assert result['before_cursors'] == result['after_cursors'] and rows(parent) == before
    assert result['processed_rows'] == 1 and result['stop_reason'] == 'source_row_budget'
    assert {p.name: p.read_bytes() for p in output.glob('*.gz')} == exported
