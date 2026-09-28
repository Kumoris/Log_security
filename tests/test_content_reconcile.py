"""Synthetic Parquet -> genuine parent/repair -> audited compressed merge."""
import csv
import fcntl
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from agentlog_unified import content_scan, content_repair, content_reconcile as reconcile
from agentlog_unified.storage import canonical, stable_id


def fixture(tmp_path, *, values=None, repair_pages=None):
    values = values or ['中文🙂 192.0.2.1 192.0.2.2 192.0.2.3', 'plain words', 'plain words']
    raw = tmp_path / 'raw'; raw.mkdir()
    source = raw / 'all_pull_request.parquet'
    pq.write_table(pa.table({'body': values}), source)
    imported = tmp_path / 'import'; imported.mkdir()
    manifest = {'status': 'complete', 'source_signature': {'source_dir': str(raw), 'inputs': [{'path': source.name, 'bytes': source.stat().st_size, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}]}, 'outputs': {'aidev.sqlite': 'fixture only'}}
    (imported / 'manifest.json').write_text(json.dumps(manifest))
    parent = tmp_path / 'parent'; fixed = tmp_path / 'repair'
    content_scan.scan_content(imported, parent, max_matches=1)
    content_repair.run_content_repair(parent, fixed, max_pages=repair_pages, core_chars=32, page_matches=1)
    return parent, fixed, source


def rows(output, stem):
    with gzip.open(output / (stem + '.jsonl.gz'), 'rt') as stream:
        return [json.loads(line) for line in stream]


def snapshot(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest() for p in path.rglob('*') if p.is_file()}


def refresh_repair(fixed):
    scan = fixed / 'scan'; manifest = json.loads((scan / 'manifest.json').read_text())
    with sqlite3.connect(scan / 'repair.sqlite') as db:
        content_repair._export(db, scan, manifest, None, True)


def test_actual_complete_union_gzip_counts_provenance_and_readonly(tmp_path):
    parent, fixed, source = fixture(tmp_path)
    before = snapshot(parent), snapshot(fixed), source.read_bytes()
    output = tmp_path / 'merged'; result = reconcile.reconcile_content(parent, fixed, output)
    actual = rows(output, 'merged_type_occurrences')
    assert result['candidate_occurrence_variants'] == result['candidate_identities'] == 3
    assert result['new_repair_identities'] == 2 and result['exact_duplicate'] == 1
    assert result['source_verification_complete'] and result['parent_and_repair_counts_additive'] is False
    assert len([r for r in actual if r['origins'] == ['parent', 'repair']]) == 1
    assert all(not r['classification_conflict'] and not r['runtime_confirmed'] and r['human_review_status'] == 'pending' for r in actual)
    assert rows(output, 'repair_overlay')[0]['mode'].startswith('complete_replace')
    assert rows(output, 'merged_unknown_type_review_queue')[1]['row_count'] == 2
    summaries = rows(output, 'merged_type_summary')
    assert sum(r['candidate_variant_count'] for r in summaries) == 3
    assert sum(sum(r['candidate_status_variant_counts'].values()) for r in summaries) == 3
    for path in output.glob('*.jsonl.gz'):
        with gzip.open(path, 'rt') as stream:
            json_rows = list(stream)
        with gzip.open(path.with_name(path.name.replace('.jsonl.gz', '.csv.gz')), 'rt') as stream:
            assert len(list(csv.DictReader(stream))) == len(json_rows)
        assert b'192.0.2.1' not in gzip.decompress(path.read_bytes())
    assert before == (snapshot(parent), snapshot(fixed), source.read_bytes())


def test_partial_empty_repair_keeps_every_parent_row(tmp_path):
    parent, fixed, _ = fixture(tmp_path, repair_pages=1)
    output = tmp_path / 'merge'; result = reconcile.reconcile_content(parent, fixed, output)
    assert result['candidate_occurrence_variants'] == 1
    assert rows(output, 'merged_type_occurrences')[0]['origins'] == ['parent']
    assert rows(output, 'repair_overlay')[0]['mode'] == 'partial_union'


def test_complete_repair_removal_is_explicit_not_silent(tmp_path):
    parent, fixed, _ = fixture(tmp_path)
    with sqlite3.connect(fixed / 'scan' / 'repair.sqlite') as db:
        db.execute("DELETE FROM matches WHERE json_extract(details,'$.start')=(SELECT MIN(json_extract(details,'$.start')) FROM matches)")
    refresh_repair(fixed)
    output = tmp_path / 'merge'; result = reconcile.reconcile_content(parent, fixed, output)
    assert result['candidate_occurrence_variants'] == 2
    assert result['removed_parent_identities'] == 1
    audit = rows(output, 'reconciliation_audit')
    assert len(audit) == 1 and audit[0]['reason'] == 'completed_repair_removed_parent_identity'
    assert audit[0]['parent_occurrence_ids'] and not audit[0]['retained_variant_ids']


def test_same_identity_different_details_remains_conflict_pending(tmp_path):
    parent, fixed, _ = fixture(tmp_path)
    with sqlite3.connect(fixed / 'scan' / 'repair.sqlite') as db:
        row = db.execute("SELECT id,details FROM matches ORDER BY json_extract(details,'$.start') LIMIT 1").fetchone()
        detail = json.loads(row[1]); detail['basis'] = 'identifier_or_unquoted_value'; detail['value_status'] = 'opaque'; detail['candidate_status'] = 'identifier_reference'
        db.execute('UPDATE matches SET details=? WHERE id=?', (canonical(detail), row[0]))
    refresh_repair(fixed)
    output = tmp_path / 'merge'; result = reconcile.reconcile_content(parent, fixed, output)
    assert result['candidate_occurrence_variants'] == 4 and result['candidate_identities'] == 3
    assert result['details_conflict_pending'] == 1
    variants = [r for r in rows(output, 'merged_type_occurrences') if r['classification_conflict']]
    assert len(variants) == 2 and len({r['identity_id'] for r in variants}) == 1
    assert {r['candidate_status'] for r in variants} == {'literal_candidate', 'identifier_reference'}


def test_unknown_and_example_types_stay_distinct(tmp_path):
    parent, fixed, _ = fixture(tmp_path, values=['sensitive="unresolved payload" user@example.test 192.0.2.1'])
    output = tmp_path / 'merge'; result = reconcile.reconcile_content(parent, fixed, output)
    summary = rows(output, 'merged_type_summary')
    assert any(r['category'] is None and r['subtype'] is None for r in summary)
    assert result['excluded_occurrence_variants'] == 1
    assert rows(output, 'merged_excluded')[0]['candidate_status'] == 'placeholder_or_example'


def test_dry_run_no_files_and_resume_deterministic_rebuild(tmp_path):
    parent, fixed, _ = fixture(tmp_path); output = tmp_path / 'merge'
    assert reconcile.reconcile_content(parent, fixed, output, dry_run=True)['status'] == 'dry_run'
    assert not output.exists()
    reconcile.reconcile_content(parent, fixed, output); before = snapshot(output)
    reconcile.reconcile_content(parent, fixed, output, resume=True)
    assert snapshot(output) == before
    with pytest.raises(ValueError, match='identical frozen'):
        reconcile.reconcile_content(parent, fixed, output)
    coverage = fixed / 'scan' / 'repair_coverage.json'; document = json.loads(coverage.read_text()); document['note'] = 'changed snapshot'; coverage.write_text(json.dumps(document))
    with pytest.raises(ValueError, match='identical frozen'):
        reconcile.reconcile_content(parent, fixed, output, resume=True)


@pytest.mark.parametrize('which', ['parent', 'repair'])
def test_active_input_writer_rejected(tmp_path, which):
    parent, fixed, _ = fixture(tmp_path)
    lock_path = parent / '.content.lock' if which == 'parent' else fixed / 'scan' / '.repair.lock'
    with lock_path.open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match='writer is active'):
            reconcile.reconcile_content(parent, fixed, tmp_path / 'merge', dry_run=True)


def test_changed_frozen_parquet_rejected_even_with_completed_repair(tmp_path):
    parent, fixed, source = fixture(tmp_path)
    source.write_bytes(source.read_bytes() + b'changed')
    with pytest.raises(ValueError, match='Parquet changed'):
        reconcile.reconcile_content(parent, fixed, tmp_path / 'merge')
    assert not (tmp_path / 'merge').exists()


@pytest.mark.parametrize('producer', ['parent', 'repair'])
def test_stale_export_counts_rejected(tmp_path, producer):
    parent, fixed, _ = fixture(tmp_path)
    coverage = parent / 'content_coverage.json' if producer == 'parent' else fixed / 'scan' / 'repair_coverage.json'
    document = json.loads(coverage.read_text()); document['candidate_occurrences'] += 1; coverage.write_text(json.dumps(document))
    with pytest.raises(ValueError, match='occurrence counts differ'):
        reconcile.reconcile_content(parent, fixed, tmp_path / 'merge')


def test_advance_verified_ancestry_uses_new_coverage_and_checkpoint(tmp_path):
    from agentlog_unified.content_advance import advance_content
    parent, fixed, _ = fixture(tmp_path); advanced = tmp_path / 'advance'
    advance_content(parent, advanced, max_rows=0, min_free_bytes=1)
    manifest = json.loads((advanced / 'manifest.json').read_text())
    (parent / 'content_coverage.json').write_text('{}')  # Parent plaintext snapshot is intentionally stale.
    result = reconcile.reconcile_content(advanced, fixed, tmp_path / 'merged')
    assert result['candidate_occurrence_variants'] == 3
    manifest['fingerprint']['frozen_source_sha256']['content_types.py'] = 'different'
    (advanced / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='classifier is inconsistent'):
        reconcile.reconcile_content(advanced, fixed, tmp_path / 'other')


def test_invalid_span_or_raw_detail_field_rejected_without_accepted_manifest(tmp_path):
    parent, fixed, _ = fixture(tmp_path)
    with sqlite3.connect(fixed / 'scan' / 'repair.sqlite') as db:
        row = db.execute('SELECT id,details FROM matches LIMIT 1').fetchone(); detail = json.loads(row[1]); detail['body'] = 'do not export'
        db.execute('UPDATE matches SET details=? WHERE id=?', (canonical(detail), row[0]))
    output = tmp_path / 'merge'
    with pytest.raises(ValueError, match='details or character span'):
        reconcile.reconcile_content(parent, fixed, output)
    assert json.loads((output / 'manifest.json').read_text())['status'] == 'building'
    assert not list(output.glob('*.gz'))


def test_type_set_change_is_reviewable_and_rule_types_have_separate_identity(tmp_path):
    parent, fixed, _ = fixture(tmp_path)
    with sqlite3.connect(fixed / 'scan' / 'repair.sqlite') as db:
        row = db.execute("SELECT id,cell_id,details FROM matches ORDER BY json_extract(details,'$.start') LIMIT 1").fetchone()
        detail = json.loads(row[2]); detail['category'] = 'PII'; detail['subtype'] = 'email'
        identifier = stable_id(row[1], detail['start'], detail['end'], detail['category'], detail['subtype'])
        db.execute('UPDATE matches SET id=?,category=?,subtype=?,details=? WHERE id=?', (identifier, detail['category'], detail['subtype'], canonical(detail), row[0]))
    refresh_repair(fixed)
    output = tmp_path / 'merge'; result = reconcile.reconcile_content(parent, fixed, output)
    assert result['candidate_identities'] == 3 and result['type_set_changes_pending'] == 1
    assert result['removed_parent_rows'] == 1
    assert {r['reason'] for r in rows(output, 'reconciliation_audit')} == {'completed_repair_removed_parent_identity', 'type_set_changed_pending'}


def test_repair_gap_preserved_and_prior_verification_budget_does_not_hide_it(tmp_path):
    value = '192.0.2.1 192.0.2.2 -----BEGIN PRIVATE KEY----- unfinished'
    parent, fixed, _ = fixture(tmp_path, values=[value])
    with sqlite3.connect(fixed / 'scan' / 'repair.sqlite') as db:
        db.execute("DELETE FROM matches WHERE json_extract(details,'$.start')=(SELECT MIN(json_extract(details,'$.start')) FROM matches)")
    refresh_repair(fixed)
    path = fixed / 'scan' / 'repair_coverage.json'; coverage = json.loads(path.read_text()); coverage['source_verification_complete'] = False; coverage['all_selected_cells_all_rules_finished'] = False; coverage['status'] = 'partial'; path.write_text(json.dumps(coverage))
    output = tmp_path / 'merge'; result = reconcile.reconcile_content(parent, fixed, output)
    assert result['source_verification_complete'] and result['repair_data_gap_records'] == 1
    assert rows(output, 'repair_data_gaps')[0]['reason'] == 'unclosed_private_key_envelope'
    assert result['candidate_occurrence_variants'] == 2 and result['removed_parent_rows'] == 0
    assert rows(output, 'repair_overlay')[0]['mode'] == 'data_gap_union'


def test_active_checkpoint_or_stale_advance_state_rejected(tmp_path):
    parent, fixed, _ = fixture(tmp_path)
    coverage = parent / 'content_coverage.json'; document = json.loads(coverage.read_text()); document['tables'][0]['next_row'] -= 1; coverage.write_text(json.dumps(document))
    with pytest.raises(ValueError, match='checkpoint cursors differ'):
        reconcile.reconcile_content(parent, fixed, tmp_path / 'merge')


@pytest.mark.parametrize('parent_kind', ['legacy', 'advance'])
@pytest.mark.parametrize('mode', ['new', 'dry_run', 'resume'])
def test_current_classifier_change_rejects_old_matching_producers_without_writes(tmp_path, monkeypatch, parent_kind, mode):
    parent, fixed, source = fixture(tmp_path)
    selected_parent = parent
    if parent_kind == 'advance':
        from agentlog_unified.content_advance import advance_content
        selected_parent = tmp_path / 'advance'
        advance_content(parent, selected_parent, max_rows=0, min_free_bytes=1)
    output = tmp_path / 'merge'
    if mode == 'resume':
        reconcile.reconcile_content(selected_parent, fixed, output)
    parent_manifest = json.loads((parent / 'manifest.json').read_text())
    fixed_manifest = json.loads((fixed / 'scan/manifest.json').read_text())
    assert fixed_manifest['fingerprint']['classifier_sha256'] == {
        k: parent_manifest['fingerprint']['source_sha256'][k]
        for k in ('content_types.py', 'taxonomy.py', 'storage.py')}
    before = snapshot(tmp_path)
    real_digest = content_repair._digest
    classifier_path = Path(content_repair.content_types.__file__).with_name('taxonomy.py').resolve()

    def upgraded_digest(path):
        # Simulate an installed taxonomy upgrade without editing production code
        # or forging the genuine parent/repair provenance created by the fixture.
        return '0' * 64 if Path(path).resolve() == classifier_path else real_digest(path)

    monkeypatch.setattr(content_repair, '_digest', upgraded_digest)
    monkeypatch.setitem(reconcile.SCOPE, 'taxonomy_version', 'synthetic-next-version')
    with pytest.raises(ValueError, match='current finite classifier'):
        reconcile.reconcile_content(selected_parent, fixed / 'scan', output,
                                    dry_run=mode == 'dry_run', resume=mode == 'resume')
    assert snapshot(tmp_path) == before
    assert source.is_file()
