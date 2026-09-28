"""Read-only, fixed-input reconciliation; no source text is decoded.

Resume rebuilds compressed exports from the identical snapshot. It never appends
or reclassifies. SQLite temporary indexes contain metadata keys, not copied text.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import ExitStack
import csv
import fcntl
import gzip
import hashlib
import heapq
import io
import itertools
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile

from . import content_repair as repair
from .storage import atomic_write, canonical, csv_cell, stable_id

SCOPE = {**repair.SCOPE, 'observation_scope': 'dataset_text_reconciled'}
MATCH_FIELDS = sorted(repair.MATCH_FIELDS)
SOURCE_FIELDS = ['table_path', 'source_row', 'column_name', 'field_scope']
IDENTITY_SQL = "json_extract(m.details,'$.start'),json_extract(m.details,'$.end'),json_extract(m.details,'$.rule'),COALESCE(m.category,''),COALESCE(m.subtype,'')"
SAFE_LABELS = {
    'rule': {'credential_prefix_shape', 'compact_jwt_shape', 'bearer_scheme_shape', 'email_shape', 'url_userinfo_shape', 'ipv4_shape', 'private_key_envelope_shape', 'named_field_taxonomy', 'unclassified_sensitive_field'},
    'basis': {'literal_shape', 'identifier_or_unquoted_value', 'named_carrier_hint', 'named_value_hint'},
    'confidence': {'low'},
    'value_status': {'unverified', 'opaque', 'placeholder_or_example'},
    'candidate_status': {'literal_candidate', 'named_value_candidate', 'identifier_reference', 'carrier_candidate', 'placeholder_or_example', 'unknown_named_value'},
}
REVIEW_SQL = """SELECT id,table_path,source_row,column_name,field_scope,characters,scanned_characters,text_hmac_sha256,status,'cell' record_kind,source_row start_row,source_row end_row,1 row_count FROM cells
 UNION ALL SELECT id,table_path,NULL,column_name,field_scope,characters,characters,NULL,'unclassified_text','source_row_range',start_row,end_row,end_row-start_row+1 FROM review_ranges"""


def _json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _lock(stack, path):
    handle = stack.enter_context(Path(path).open('rb'))
    try:
        fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('Input writer is active; reconciliation must wait') from None


def _readonly(path):
    db = sqlite3.connect(Path(path).as_uri() + '?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA temp_store=FILE')
    db.execute('PRAGMA cache_size=-8192')
    return db


def _parent_view(parent):
    manifest = _json(parent / 'manifest.json')
    if manifest.get('engine') == 'content_advance_v1':
        ancestor = Path(manifest['parent_run']).resolve()
        if repair._digest(ancestor / 'manifest.json') != manifest['parent_manifest_sha256']:
            raise ValueError('Advance ancestor manifest changed')
        original = _json(ancestor / 'manifest.json')
        for field in ('dataset', 'source_import', 'source_manifest_sha256', 'tables', 'fingerprint_key_sha256'):
            if manifest[field] != original[field]:
                raise ValueError('Advance source ancestry is inconsistent')
        if manifest['fingerprint']['frozen_source_sha256'] != original['fingerprint']['source_sha256']:
            raise ValueError('Advance original classifier is inconsistent')
        checkpoint = Path(manifest['checkpoint_path']).resolve()
        checkpoint_lock = Path(manifest['checkpoint_lock_path']).resolve()
        if checkpoint != ancestor / 'content.sqlite' or checkpoint_lock != ancestor / '.content.lock':
            raise ValueError('Advance checkpoint escapes its verified ancestor')
        checkpoint_stat = checkpoint.stat()
        if manifest.get('checkpoint_identity') != {'device': checkpoint_stat.st_dev, 'inode': checkpoint_stat.st_ino}:
            raise ValueError('Advance checkpoint identity changed')
        return manifest, original, ancestor, checkpoint, [parent / '.content.lock', checkpoint_lock]
    if manifest.get('engine') is not None:
        raise ValueError('Unsupported parent engine')
    return manifest, manifest, parent, parent / 'content.sqlite', [parent / '.content.lock']


def _snapshot_files(paths):
    result = {}
    for path in sorted(set(Path(p).resolve() for p in paths)):
        before = repair._stat(path)
        digest = repair._digest(path)
        if before != repair._stat(path):
            raise ValueError('Input changed during fingerprinting')
        result[str(path)] = {'sha256': digest, 'stat': list(before)}
    return result


def _check_unchanged(snapshot):
    for path, item in snapshot.items():
        if list(repair._stat(path)) != item['stat']:
            raise ValueError('Input changed during reconciliation')


def _counts(db, prefix=''):
    return {int(r[0]): r[1] for r in db.execute(f'SELECT excluded,COUNT(*) FROM {prefix}matches GROUP BY excluded')}


def _validate_parent(db, coverage, manifest):
    if coverage.get('source_manifest_sha256') != manifest['source_manifest_sha256']:
        raise ValueError('Parent coverage source differs')
    tables = [dict(r) for r in db.execute('SELECT * FROM tables ORDER BY path')]
    for row in tables:
        row['stats'] = json.loads(row['stats'])
    if tables != sorted(coverage['tables'], key=lambda r: r['path']):
        raise ValueError('Parent coverage is stale: checkpoint cursors differ')
    counts = _counts(db)
    if counts.get(0, 0) != coverage['candidate_occurrences'] or counts.get(1, 0) != coverage['excluded_occurrences']:
        raise ValueError('Parent coverage occurrence counts differ')
    cells = dict(db.execute('SELECT status,COUNT(*) FROM cells GROUP BY status'))
    ranges, expanded = db.execute('SELECT COUNT(*),COALESCE(SUM(end_row-start_row+1),0) FROM review_ranges').fetchone()
    if cells != coverage['cell_status_counts'] or sum(cells.values()) + ranges != coverage['unknown_type_review_export_records'] or sum(cells.values()) + expanded != coverage['unknown_type_review_cells']:
        raise ValueError('Parent coverage review counts differ')
    if db.execute('SELECT COUNT(*) FROM matches m LEFT JOIN cells c ON m.cell_id=c.id WHERE c.id IS NULL').fetchone()[0]:
        raise ValueError('Parent has orphan occurrences')
    inventory = {t['path']: t for t in manifest['tables']}
    fields = {path: {c['column']: c['field_scope'] for c in table['columns'] if c['selected']} for path, table in inventory.items()}
    previous = None
    for row in db.execute('SELECT * FROM (' + REVIEW_SQL + ') ORDER BY table_path,column_name,start_row'):
        table = inventory.get(row['table_path'])
        if table is None or row['column_name'] not in fields[row['table_path']] or row['field_scope'] != fields[row['table_path']][row['column_name']]:
            raise ValueError('Parent review source column is invalid')
        if any(type(row[k]) is not int for k in ('start_row', 'end_row', 'characters', 'scanned_characters')) or not 1 <= row['start_row'] <= row['end_row'] <= table['rows'] or not 0 < row['scanned_characters'] <= row['characters']:
            raise ValueError('Parent review source range is invalid')
        key = row['table_path'], row['column_name']
        if previous is not None and key == previous[:2] and row['start_row'] <= previous[2]:
            raise ValueError('Parent review source ranges overlap')
        previous = (*key, row['end_row'])
        if row['id'] != stable_id('content-cell', manifest['source_manifest_sha256'], row['table_path'], row['start_row'], row['column_name']):
            raise ValueError('Parent review source identity differs')


def _validate_repair(db, coverage, manifest, selection_dir, selected, parent_original, ancestor, parent):
    selection_path = selection_dir / 'selection_manifest.json'
    selection = _json(selection_path)
    if repair._digest(selection_path) != manifest['fingerprint']['selection_manifest_sha256'] or repair._digest(selection_dir / 'selection.jsonl') != selection['selection_sha256'] or selection['selection_sha256'] != manifest['fingerprint']['selection_sha256']:
        raise ValueError('Repair selection fingerprint changed')
    selection_parent = Path(selection['parent_run']).resolve()
    if selection_parent not in {ancestor, parent} or Path(manifest['parent_run']).resolve() != selection_parent:
        raise ValueError('Repair does not share the verified parent ancestor')
    selection_parent_hash = repair._digest(selection_parent / 'manifest.json')
    if selection['parent_manifest_sha256'] != selection_parent_hash or manifest['parent_manifest_sha256'] != selection_parent_hash:
        raise ValueError('Repair parent manifest changed')
    if ('parent_ancestor_run' in selection and
        (Path(selection['parent_ancestor_run']).resolve() != ancestor or selection['parent_ancestor_manifest_sha256'] != repair._digest(ancestor / 'manifest.json'))):
        raise ValueError('Repair selection ancestor differs')
    if selection['source_manifest_sha256'] != parent_original['source_manifest_sha256'] or selection['parent_fingerprint_key_sha256'] != parent_original['fingerprint_key_sha256']:
        raise ValueError('Repair source or HMAC-key ancestry differs')
    original_classifier = parent_original['fingerprint']['source_sha256']
    if manifest['fingerprint']['classifier_sha256'] != {k: original_classifier[k] for k in ('content_types.py', 'taxonomy.py', 'storage.py')}:
        raise ValueError('Parent and repair classifiers differ')
    db.execute('CREATE TEMP TABLE selected(id TEXT PRIMARY KEY,source TEXT)')
    count = characters = 0
    with (selection_dir / 'selection.jsonl').open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if set(row) != repair.SOURCE_FIELDS:
                raise ValueError('Repair selection has unexpected fields')
            db.execute('INSERT INTO selected VALUES(?,?)', (row['id'], canonical(row)))
            count += 1; characters += row['characters']
    if count != selected or count != selection['selected_cells'] or characters != selection['selected_characters']:
        raise ValueError('Repair selected-cell counts differ')
    statuses = dict(db.execute('SELECT status,COUNT(*) FROM fix.cells GROUP BY status'))
    if sum(statuses.values()) != selected or statuses != coverage['cell_status_counts']:
        raise ValueError('Repair coverage cell counts differ')
    if set(statuses) - {'pending', 'partial', 'complete_with_semantic_gaps'}:
        raise ValueError('Unknown repair status')
    counts = _counts(db, 'fix.')
    if counts.get(0, 0) != coverage['candidate_occurrences'] or counts.get(1, 0) != coverage['excluded_occurrences']:
        raise ValueError('Repair coverage occurrence counts differ')
    if db.execute('SELECT COUNT(*) FROM fix.matches m LEFT JOIN fix.cells c ON m.cell_id=c.id WHERE c.id IS NULL').fetchone()[0]:
        raise ValueError('Repair has orphan occurrences')
    if db.execute('SELECT COUNT(*) FROM fix.cells c LEFT JOIN selected s ON c.id=s.id WHERE s.id IS NULL').fetchone()[0]:
        raise ValueError('Repair has unselected cells')
    for row in db.execute('SELECT s.id,s.source,f.source,f.cursor,f.status,f.pages FROM selected s LEFT JOIN fix.cells f ON f.id=s.id'):
        if row[2] is None or json.loads(row[1]) != json.loads(row[2]):
            raise ValueError('Repair source differs from fixed selection')
        source = json.loads(row[1]); cursor = json.loads(row[3])
        parent = db.execute('SELECT * FROM cells WHERE id=?', (row[0],)).fetchone()
        if parent is None or any(parent[k] != source[k] for k in repair.SOURCE_FIELDS):
            raise ValueError('Repair source-cell identity or HMAC differs from parent')
        if row[4] == 'complete_with_semantic_gaps' and cursor != {'rule_index': 13, 'search_offset': 0}:
            raise ValueError('Completed repair cursor is unfinished')
        if row[4] != 'complete_with_semantic_gaps' and not (type(cursor.get('rule_index')) is int and 0 <= cursor['rule_index'] < 13 and type(cursor.get('search_offset')) is int and 0 <= cursor['search_offset'] <= source['characters']):
            raise ValueError('Repair cursor is out of bounds')
    if db.execute('SELECT COALESCE(SUM(pages),0) FROM fix.cells').fetchone()[0] != coverage['committed_pages'] or db.execute('SELECT COUNT(*) FROM fix.gaps').fetchone()[0] != coverage['data_gap_records']:
        raise ValueError('Repair page or gap counts differ')


class _GzipRows:
    """Two streaming formats, deterministic gzip, files private by default."""
    def __init__(self, stack, directory, stem, fields):
        self.fields = fields; self.count = 0
        handles = []
        for suffix in ('.jsonl.gz', '.csv.gz'):
            path = directory / (stem + suffix)
            raw = stack.enter_context(path.open('wb')); os.chmod(path, 0o600)
            zipped = stack.enter_context(gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0))
            handles.append(stack.enter_context(io.TextIOWrapper(zipped, encoding='utf-8', newline='')))
        self.jsonl, stream = handles
        self.csv = csv.DictWriter(stream, fieldnames=fields)
        self.csv.writeheader()

    def write(self, row):
        if set(row) != set(self.fields):
            raise ValueError('Unexpected reconciliation export fields')
        self.jsonl.write(canonical(row) + '\n')
        self.csv.writerow({k: csv_cell(row[k]) for k in self.fields})
        self.count += 1


def _identity(detail):
    return (detail['start'], detail['end'], detail['rule'], detail['category'] or '', detail['subtype'] or '')


def _records(db, source, origin):
    if origin == 'parent':
        query = f'SELECT m.* FROM matches m WHERE cell_id=? ORDER BY {IDENTITY_SQL},m.id'
    else:
        query = 'SELECT m.* FROM repair_keys k CROSS JOIN fix.matches m ON m.rowid=k.rid WHERE k.cell_id=? ORDER BY k.start,k.end,k.rule,k.category,k.subtype,k.rid'
    for row in db.execute(query, (source['id'],)):
        detail = json.loads(row['details'])
        if set(detail) != repair.MATCH_FIELDS or (detail['category'], detail['subtype']) not in repair.TYPE_KEYS or any(type(detail[k]) is not int for k in ('start', 'end')) or not 0 <= detail['start'] < detail['end'] <= source['characters']:
            raise ValueError('Occurrence details or character span is invalid')
        if row['category'] != detail['category'] or row['subtype'] != detail['subtype'] or row['excluded'] != int(detail['value_status'] == 'placeholder_or_example'):
            raise ValueError('Occurrence label columns disagree with details')
        if any(detail[k] not in allowed for k, allowed in SAFE_LABELS.items()):
            raise ValueError('Occurrence rule metadata is invalid')
        expected = stable_id(source['id'], detail) if origin == 'parent' else stable_id(source['id'], detail['start'], detail['end'], detail['category'], detail['subtype'])
        if row['id'] != expected:
            raise ValueError('Producer occurrence identity is inconsistent')
        yield _identity(detail), {'detail': detail, 'origin': origin, 'source_id': row['id'], 'excluded': bool(row['excluded'])}


def _export(db, directory, parent, repair_coverage, source_manifest):
    totals = Counter(); types = defaultdict(Counter); status_counts = defaultdict(Counter)
    scope_fields = list(SCOPE)
    occurrence_fields = ['id', 'identity_id', 'cell_id', *SOURCE_FIELDS, 'text_hmac_sha256', *MATCH_FIELDS, 'excluded', 'origins', 'source_occurrence_ids', 'classification_conflict', *scope_fields]
    audit_fields = ['cell_id', 'identity_id', 'reason', 'parent_occurrence_ids', 'repair_occurrence_ids', 'retained_variant_ids', *scope_fields]
    overlay_fields = ['cell_id', *SOURCE_FIELDS, 'status', 'cursor', 'pages', 'data_gap_records', 'mode', 'parent_rows', 'repair_rows', 'shared_identities', 'new_identities', 'removed_parent_identities', 'removed_parent_rows', 'conflicting_identities', 'type_set_changes', *scope_fields]
    with ExitStack() as stack:
        candidates = _GzipRows(stack, directory, 'merged_type_occurrences', occurrence_fields)
        examples = _GzipRows(stack, directory, 'merged_excluded', occurrence_fields)
        audits = _GzipRows(stack, directory, 'reconciliation_audit', audit_fields)
        overlay = _GzipRows(stack, directory, 'repair_overlay', overlay_fields)
        for cell in db.execute('SELECT * FROM cells ORDER BY id'):
            source = dict(cell); cid = source['id']; stats = Counter(); touched = set()
            expected = stable_id('content-cell', source_manifest, source['table_path'], source['source_row'], source['column_name'])
            if cid != expected or not re.fullmatch('[0-9a-f]{64}', source['text_hmac_sha256']):
                raise ValueError('Parent source identity is inconsistent')
            fix = db.execute('SELECT * FROM fix.cells WHERE id=?', (cid,)).fetchone()
            gap_count = db.execute('SELECT COUNT(*) FROM fix.gaps WHERE cell_id=?', (cid,)).fetchone()[0] if fix is not None else 0
            complete = fix is not None and fix['status'] == 'complete_with_semantic_gaps' and not gap_count
            streams = [_records(db, source, 'parent')]
            if fix is not None:
                streams.append(_records(db, source, 'repair'))
            last_base = None; base_types = {'parent': set(), 'repair': set()}; base_ids = {'parent': [], 'repair': []}
            def type_change_audit():
                if base_types['parent'] and base_types['repair'] and base_types['parent'] != base_types['repair']:
                    totals['type_set_changes_pending'] += 1; stats['type_set_changes'] += 1
                    audits.write({'cell_id': cid, 'identity_id': stable_id('reconciled-span-rule', source_manifest, cid, last_base),
                                  'reason': 'type_set_changed_pending', 'parent_occurrence_ids': sorted(base_ids['parent']),
                                  'repair_occurrence_ids': sorted(base_ids['repair']), 'retained_variant_ids': [], **SCOPE})
            for key, group in itertools.groupby(heapq.merge(*streams, key=lambda item: item[0]), key=lambda item: item[0]):
                if last_base is not None and last_base != key[:3]:
                    type_change_audit(); base_types = {'parent': set(), 'repair': set()}; base_ids = {'parent': [], 'repair': []}
                last_base = key[:3]
                records = []
                for _, record in group:
                    records.append(record)
                    if len(records) > 10000:
                        raise ValueError('Excessive variants at one identity')
                parents = [r for r in records if r['origin'] == 'parent']; fixes = [r for r in records if r['origin'] == 'repair']
                stats['parent_rows'] += len(parents); stats['repair_rows'] += len(fixes)
                for record in records:
                    base_types[record['origin']].add(key[3:]); base_ids[record['origin']].append(record['source_id'])
                identity_id = stable_id('reconciled-identity', source_manifest, cid, key)
                reason = None
                if parents and fixes:
                    stats['shared_identities'] += 1
                elif fixes:
                    stats['new_identities'] += 1
                elif complete:
                    stats['removed_parent_identities'] += 1
                    stats['removed_parent_rows'] += len(parents)
                    reason = 'completed_repair_removed_parent_identity'
                variants = defaultdict(list)
                if reason is None:
                    for record in records:
                        variants[canonical([record['detail'], record['excluded']])].append(record)
                conflict = len(variants) > 1
                if conflict:
                    stats['conflicting_identities'] += 1; reason = 'details_conflict_pending'
                elif parents and fixes:
                    reason = 'exact_duplicate'
                accepted = []
                candidate_identity = excluded_identity = False
                for metadata, members in sorted(variants.items()):
                    record = members[0]; detail = record['detail']; excluded = record['excluded']
                    variant_id = stable_id('reconciled-variant', identity_id, metadata)
                    row = {'id': variant_id, 'identity_id': identity_id, 'cell_id': cid, **{k: source[k] for k in SOURCE_FIELDS},
                           'text_hmac_sha256': source['text_hmac_sha256'], **detail, 'excluded': excluded,
                           'origins': sorted({r['origin'] for r in members}),
                           'source_occurrence_ids': {o: sorted({r['source_id'] for r in members if r['origin'] == o}) for o in ('parent', 'repair')},
                           'classification_conflict': conflict, **SCOPE}
                    (examples if excluded else candidates).write(row); accepted.append(variant_id)
                    typekey = detail['category'], detail['subtype']
                    if excluded:
                        excluded_identity = True; types[typekey]['excluded_variant_count'] += 1
                    else:
                        candidate_identity = True; types[typekey]['candidate_variant_count'] += 1
                        status_counts[typekey][detail['candidate_status']] += 1; touched.add(typekey)
                if variants:
                    totals['logical_identities'] += 1
                    typekey = key[3] or None, key[4] or None
                    if candidate_identity:
                        totals['candidate_identities'] += 1; types[typekey]['candidate_identity_count'] += 1
                    if excluded_identity:
                        totals['excluded_identities'] += 1; types[typekey]['excluded_identity_count'] += 1
                if reason:
                    totals[reason] += 1
                    audits.write({'cell_id': cid, 'identity_id': identity_id, 'reason': reason,
                                  'parent_occurrence_ids': sorted(r['source_id'] for r in parents),
                                  'repair_occurrence_ids': sorted(r['source_id'] for r in fixes),
                                  'retained_variant_ids': accepted, **SCOPE})
            type_change_audit()
            for typekey in touched:
                types[typekey]['distinct_candidate_cells'] += 1
            if fix is not None:
                overlay.write({'cell_id': cid, **{k: source[k] for k in SOURCE_FIELDS}, 'status': fix['status'], 'cursor': json.loads(fix['cursor']), 'pages': fix['pages'],
                               'data_gap_records': gap_count,
                               'mode': 'complete_replace_with_conflicts_retained' if complete else 'data_gap_union' if gap_count else 'partial_union',
                               **{k: stats[k] for k in ('parent_rows', 'repair_rows', 'shared_identities', 'new_identities', 'removed_parent_identities', 'removed_parent_rows', 'conflicting_identities', 'type_set_changes')}, **SCOPE})
                totals.update({'replaced_parent_rows': stats['parent_rows'] if complete else 0,
                               'removed_parent_identities': stats['removed_parent_identities'], 'removed_parent_rows': stats['removed_parent_rows'], 'new_repair_identities': stats['new_identities']})
        review_fields = ['id', *SOURCE_FIELDS, 'characters', 'scanned_characters', 'text_hmac_sha256', 'status', 'record_kind', 'start_row', 'end_row', 'row_count', 'reason', *scope_fields]
        reviews = _GzipRows(stack, directory, 'merged_unknown_type_review_queue', review_fields)
        expanded = 0
        for row in db.execute(REVIEW_SQL):
            reviews.write({**dict(row), 'reason': 'text_semantics_and_sensitive_type_completeness_unresolved', **SCOPE}); expanded += row['row_count']
        gaps = _GzipRows(stack, directory, 'repair_data_gaps', ['cell_id', 'start', 'end', 'reason', *scope_fields])
        for row in db.execute('SELECT g.cell_id,g.details,c.source FROM fix.gaps g LEFT JOIN fix.cells c ON c.id=g.cell_id ORDER BY g.id'):
            detail = json.loads(row['details'])
            if row['source'] is None or set(detail) != {'start', 'end', 'reason'} or detail['reason'] != 'unclosed_private_key_envelope' or any(type(detail[k]) is not int for k in ('start', 'end')) or not 0 <= detail['start'] < detail['end'] <= json.loads(row['source'])['characters']:
                raise ValueError('Repair gap metadata is invalid')
            gaps.write({'cell_id': row['cell_id'], **detail, **SCOPE})
        summary_fields = ['category', 'subtype', 'candidate_variant_count', 'candidate_identity_count', 'excluded_variant_count', 'excluded_identity_count', 'distinct_candidate_cells', 'candidate_status_variant_counts', *scope_fields]
        summaries = _GzipRows(stack, directory, 'merged_type_summary', summary_fields)
        for key, counts in sorted(types.items(), key=lambda item: (item[0][0] or '', item[0][1] or '')):
            summaries.write({'category': key[0], 'subtype': key[1], **{k: counts[k] for k in summary_fields[2:7]}, 'candidate_status_variant_counts': dict(status_counts[key]), **SCOPE})
        result = {'status': 'reconciled_with_semantic_gaps', 'candidate_occurrence_variants': candidates.count,
                  'excluded_occurrence_variants': examples.count, **dict(totals), 'audit_records': audits.count,
                  'repair_overlay_cells': overlay.count, 'unknown_type_review_export_records': reviews.count,
                  'repair_data_gap_records': gaps.count,
                  'unknown_type_review_cells': expanded, 'type_summary_records': summaries.count,
                  'parent_candidate_occurrences': parent['candidate_occurrences'], 'parent_excluded_occurrences': parent['excluded_occurrences'],
                  'repair_candidate_occurrences': repair_coverage['candidate_occurrences'], 'repair_excluded_occurrences': repair_coverage['excluded_occurrences'],
                  'parent_all_selected_text_rows_visited': parent['all_selected_text_rows_visited'],
                  'repair_cell_status_counts': repair_coverage['cell_status_counts'],
                  'source_verification_complete': True, 'parent_and_repair_counts_additive': False,
                  'identity_unit': 'frozen source cell + Unicode span + rule + category + subtype',
                  'variant_unit': 'logical identity + complete classifier details and exclusion state',
                  'candidate_status_counts_unit': 'candidate evidence variants, not unique identities, values, or people',
                  'unknown_parent_ranges_preserved': True, 'repair_status_is_overlay': True,
                  'network_accessed': False, 'source_text_decoded': False, 'target_code_executed': False,
                  'exit_code': 2, **SCOPE}
    return result


def reconcile_content(parent_run, repair_run, output_dir, *, offline=True, dry_run=False, resume=False):
    """Validate sources and merge immutable producer snapshots into gzip exports."""
    if not offline:
        raise ValueError('Reconciliation is offline only')
    parent = Path(parent_run).resolve(); fixed = Path(repair_run).resolve(); output = Path(output_dir).resolve()
    if fixed.name == 'scan' and (fixed / 'repair.sqlite').is_file():
        fixed = fixed.parent
    manifest, original, ancestor, checkpoint, locks = _parent_view(parent)
    scan = fixed / 'scan'; selection_dir = fixed / 'selection'
    protected = [parent, ancestor, fixed, Path(manifest['source_import']).resolve()]
    repair._safe_output(output, protected)
    with ExitStack() as stack:
        for path in sorted(set([*locks, scan / '.repair.lock'])):
            _lock(stack, path)
        if _parent_view(parent) != (manifest, original, ancestor, checkpoint, locks):
            raise ValueError('Parent changed while acquiring locks')
        fixed_manifest = _json(scan / 'manifest.json')
        current_classifier = {name: repair._digest(Path(repair.content_types.__file__).with_name(name))
                              for name in ('content_types.py', 'taxonomy.py', 'storage.py')}
        # Export labels and SCOPE come from this installation. Two mutually
        # consistent old producers must not be relabelled as the current taxonomy.
        if (any(original['fingerprint']['source_sha256'].get(name) != digest
                for name, digest in current_classifier.items())
                or fixed_manifest['fingerprint'].get('classifier_sha256') != current_classifier):
            raise ValueError('Parent and repair must match the current finite classifier; '
                             'reclassify in new runs and preserve historical outputs')
        tables = repair._parent_sources(parent, manifest); repair._key(ancestor, original)
        repair._safe_output(output, [Path(t['absolute_path']).parent for t in tables.values()])
        parent_coverage = _json(parent / 'content_coverage.json')
        fixed_coverage = _json(scan / 'repair_coverage.json')
        if Path(fixed_manifest['selection_dir']).resolve() != selection_dir:
            raise ValueError('Repair selection directory differs')
        paths = [parent / 'manifest.json', parent / 'content_coverage.json', ancestor / 'manifest.json', ancestor / '.fingerprint-key', checkpoint,
                 scan / 'manifest.json', scan / 'repair_coverage.json', scan / 'repair.sqlite', selection_dir / 'selection_manifest.json', selection_dir / 'selection.jsonl', Path(manifest['source_import']) / 'manifest.json']
        if manifest.get('engine') == 'content_advance_v1':
            state_path = parent / 'advance_state.json'; state = _json(state_path)
            if state.get('status') != 'export_complete' or state.get('coverage_sha256') != repair._digest(parent / 'content_coverage.json'):
                raise ValueError('Advance export is incomplete or stale')
            paths.append(state_path)
        paths += [Path(str(p) + '-wal') for p in (checkpoint, scan / 'repair.sqlite') if Path(str(p) + '-wal').exists()]
        snapshot = _snapshot_files(paths)
        db = _readonly(checkpoint); stack.callback(db.close)
        db.execute('ATTACH DATABASE ? AS fix', ((scan / 'repair.sqlite').as_uri() + '?mode=ro',))
        _validate_parent(db, parent_coverage, manifest)
        _validate_repair(db, fixed_coverage, fixed_manifest, selection_dir, fixed_manifest['selected_cells'], original, ancestor, parent)
        verified_sources = {}
        for relative, table in sorted(tables.items()):
            path = Path(table['absolute_path']); before = repair._stat(path)
            if before[2] != table['bytes'] or repair._digest(path) != table['sha256'] or before != repair._stat(path):
                raise ValueError('Frozen source Parquet changed')
            verified_sources[str(path)] = {'sha256': table['sha256'], 'stat': list(before)}
        fingerprint = {'input_files': {p: v['sha256'] for p, v in snapshot.items()},
                       'source_manifest_sha256': manifest['source_manifest_sha256'],
                       'verified_source_files': {p: v['sha256'] for p, v in verified_sources.items()},
                       'implementation_sha256': repair._digest(Path(__file__)),
                       'execution_dependency_sha256': {name: repair._digest(Path(repair.__file__).with_name(name))
                           for name in ('content_repair.py', 'content_cursor.py', 'content_types.py', 'storage.py', 'taxonomy.py')},
                       'original_classifier_sha256': original['fingerprint']['source_sha256']}
        plan = {'status': 'dry_run', 'parent_run': str(parent), 'repair_run': str(fixed), 'output_dir': str(output),
                'source_verification_complete': True, 'selected_repair_cells': fixed_manifest['selected_cells'],
                'resume_policy': 'rebuild_from_identical_frozen_inputs', 'fingerprint': fingerprint,
                'source_text_decoded': False, **SCOPE}
        if dry_run:
            _check_unchanged(snapshot); _check_unchanged(verified_sources)
            return {**plan, 'files_written': False, 'exit_code': 0}
        output.mkdir(parents=True, exist_ok=True)
        output_lock = stack.enter_context((output / '.reconcile.lock').open('a'))
        try:
            fcntl.flock(output_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Reconciliation output writer is active') from None
        manifest_path = output / 'manifest.json'
        if manifest_path.exists():
            if not resume or _json(manifest_path)['fingerprint'] != fingerprint:
                raise ValueError('Resume requires identical frozen inputs and implementation')
        elif resume or any(p.name != '.reconcile.lock' for p in output.iterdir()):
            raise ValueError('New reconciliation requires an empty independent output')
        document = {**plan, 'status': 'building', 'engine': 'content_reconcile_v1', 'fingerprint': fingerprint}
        atomic_write(manifest_path, canonical(document) + '\n')
        # Only keys/rowids are copied. Full producer details stay in their read-only DBs.
        db.execute('CREATE TEMP TABLE repair_keys(cell_id TEXT,rid INTEGER,start INTEGER,end INTEGER,rule TEXT,category TEXT,subtype TEXT)')
        db.execute("INSERT INTO repair_keys SELECT cell_id,rowid,json_extract(details,'$.start'),json_extract(details,'$.end'),json_extract(details,'$.rule'),COALESCE(category,''),COALESCE(subtype,'') FROM fix.matches")
        db.execute('CREATE INDEX repair_lookup ON repair_keys(cell_id,start,end,rule,category,subtype,rid)')
        with tempfile.TemporaryDirectory(prefix='.reconcile-build-', dir=output) as temporary:
            build = Path(temporary)
            coverage = _export(db, build, parent_coverage, fixed_coverage, manifest['source_manifest_sha256'])
            _check_unchanged(snapshot); _check_unchanged(verified_sources)
            outputs = {path.name: {'sha256': repair._digest(path), 'bytes': path.stat().st_size} for path in build.iterdir()}
            for path in build.iterdir():
                os.replace(path, output / path.name)
            coverage['fingerprint'] = fingerprint
            atomic_write(output / 'merged_coverage.json', canonical(coverage) + '\n')
            atomic_write(manifest_path, canonical({**document, 'status': 'complete', 'outputs': outputs,
                                                  'files_written': True, 'exit_code': coverage['exit_code']}) + '\n')
        return coverage
