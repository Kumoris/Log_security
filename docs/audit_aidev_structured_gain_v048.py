"""Compare controlled source-cell/type sets; never export text, keys or HMACs."""
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
import csv
import fcntl
import gzip
import hashlib
import io
import json
import sqlite3
import tempfile
import sys

from agentlog_unified import structured_scan, structured_types
from agentlog_unified.storage import canonical, csv_cell
from agentlog_unified.taxonomy import taxonomy_catalog

ROOT = Path(__file__).resolve().parents[1]
TYPE_ROWS = [(c['category'], s['subtype'], s['label']) for c in taxonomy_catalog()['categories'] for s in c['subtypes']]
TYPE_KEYS = {(c, s) for c, s, _ in TYPE_ROWS}
KEY_FIELDS = ('table_path', 'source_row', 'column_name', 'category', 'subtype')
SCOPE = {'observation_scope': 'structured_vs_plaintext_cell_type_gain', 'human_review_status': 'pending',
         'runtime_confirmed': False, 'new_sensitive_type_established': False, 'full_dataset_coverage_claim': False,
         'application_log_evidence': False}


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()


def stat(path):
    s = Path(path).stat()
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def lock(stack, path):
    stream = stack.enter_context(Path(path).open('rb'))
    fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)


def connect(path):
    return sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro&immutable=1', uri=True)


def create_keys(db):
    columns = 'table_path TEXT,source_row INTEGER,column_name TEXT,category TEXT,subtype TEXT,PRIMARY KEY(table_path,source_row,column_name,category,subtype)'
    db.execute('CREATE TABLE baseline(' + columns + ') WITHOUT ROWID')
    db.execute('CREATE TABLE new_types(' + columns + ') WITHOUT ROWID')
    db.execute('CREATE TABLE catalog(category TEXT,subtype TEXT,PRIMARY KEY(category,subtype)) WITHOUT ROWID')
    db.executemany('INSERT INTO catalog VALUES(?,?)', sorted(TYPE_KEYS)); db.commit()


def add_database_union(db, parent_db, repair_db):
    db.execute('ATTACH DATABASE ? AS old', (Path(parent_db).resolve().as_uri() + '?mode=ro&immutable=1',))
    db.execute('ATTACH DATABASE ? AS fix', (Path(repair_db).resolve().as_uri() + '?mode=ro&immutable=1',))
    with db:
        db.execute('''INSERT OR IGNORE INTO baseline SELECT c.table_path,c.source_row,c.column_name,m.category,m.subtype
                      FROM old.matches m JOIN old.cells c ON c.id=m.cell_id
                      JOIN catalog t ON t.category=m.category AND t.subtype=m.subtype WHERE m.excluded=0''')
        db.execute('''INSERT OR IGNORE INTO baseline SELECT json_extract(c.source,'$.table_path'),json_extract(c.source,'$.source_row'),
                      json_extract(c.source,'$.column_name'),m.category,m.subtype FROM fix.matches m JOIN fix.cells c ON c.id=m.cell_id
                      JOIN catalog t ON t.category=m.category AND t.subtype=m.subtype WHERE m.excluded=0''')
    db.execute('DETACH DATABASE old'); db.execute('DETACH DATABASE fix')


def baseline_proof(parent, repair, merged):
    pm = read(parent / 'manifest.json'); rm = read(repair / 'scan/manifest.json')
    mm = read(merged / 'manifest.json'); coverage = read(merged / 'merged_coverage.json')
    sm = read(repair / 'selection/selection_manifest.json'); fp = mm['fingerprint']
    conditions = {
        'reconcile_complete': mm['status'] == 'complete' and mm['source_verification_complete'],
        'coverage_same_fingerprint': coverage['fingerprint'] == fp and coverage['source_verification_complete'],
        'no_parent_identity_or_row_removed': coverage.get('removed_parent_identities') == 0 and coverage.get('removed_parent_rows') == 0,
        'exact_run_ancestry': Path(mm['parent_run']).resolve() == parent and Path(mm['repair_run']).resolve() == repair and Path(rm['parent_run']).resolve() == parent and Path(sm['parent_run']).resolve() == parent,
        'parent_manifest_frozen_in_repair': rm['parent_manifest_sha256'] == sm['parent_manifest_sha256'] == sha(parent / 'manifest.json'),
        'shared_source_manifest': fp['source_manifest_sha256'] == pm['source_manifest_sha256'] == sm['source_manifest_sha256'] == sha(Path(pm['source_import']) / 'manifest.json'),
        'selection_frozen': sha(repair / 'selection/selection_manifest.json') == rm['fingerprint']['selection_manifest_sha256'] and sha(repair / 'selection/selection.jsonl') == sm['selection_sha256'] == rm['fingerprint']['selection_sha256'],
        'reconcile_implementation_matches_reviewed_code': fp['implementation_sha256'] == sha(ROOT / 'src/agentlog_unified/content_reconcile.py'),
        'legacy_classifier_shared': rm['fingerprint']['classifier_sha256'] == {k: pm['fingerprint']['source_sha256'][k] for k in ('content_types.py', 'taxonomy.py', 'storage.py')},
    }
    checked = 0
    for path, expected in fp['input_files'].items():
        p = Path(path)
        if not p.is_file() or sha(p) != expected:
            conditions['reconcile_input_files_identical'] = False
            break
        checked += 1
    else: conditions['reconcile_input_files_identical'] = True
    # Fingerprint/key files are checked in memory; individual key hashes never leave this helper.
    return pm, mm, coverage, {'conditions': conditions, 'input_files_checked': checked,
        'database_union_proven': all(conditions.values()),
        'removed_parent_identities': coverage.get('removed_parent_identities'),
        'removed_parent_rows': coverage.get('removed_parent_rows'),
        'shared_exact_duplicate_occurrences': coverage.get('exact_duplicate', 0),
        'new_repair_identities': coverage.get('new_repair_identities', 0),
        'proof_rule': 'With zero removed parent identities, reconciliation retains every parent/repair classification variant; duplicate removal does not alter source-cell/type set membership.'}


def add_merged_export(db, path, metadata):
    assert sha(path) == metadata['sha256'] and path.stat().st_size == metadata['bytes']
    pending = []
    with gzip.open(path, 'rt') as stream:
        for line in stream:
            row = json.loads(line)
            assert not row['excluded']
            if (row['category'], row['subtype']) not in TYPE_KEYS: continue
            pending.append(tuple(row[k] for k in KEY_FIELDS))
            if len(pending) >= 4096:
                with db: db.executemany('INSERT OR IGNORE INTO baseline VALUES(?,?,?,?,?)', pending)
                pending.clear()
    with db: db.executemany('INSERT OR IGNORE INTO baseline VALUES(?,?,?,?,?)', pending)


def validate_source_keys(db, table, inventory):
    for path, column, lo, hi in db.execute('SELECT table_path,column_name,MIN(source_row),MAX(source_row) FROM ' + table + ' GROUP BY table_path,column_name'):
        assert path in inventory and column in inventory[path]['columns'] and type(lo) is int and 1 <= lo <= hi <= inventory[path]['rows']


def self_test():
    with tempfile.TemporaryDirectory(prefix='structured_gain_test_') as temporary:
        root = Path(temporary); parent = root / 'parent.sqlite'; repair = root / 'repair.sqlite'
        with sqlite3.connect(parent) as db:
            db.executescript('CREATE TABLE cells(id,table_path,source_row,column_name); CREATE TABLE matches(cell_id,category,subtype,excluded);')
            db.execute('INSERT INTO cells VALUES(?,?,?,?)', ('c', 'table.parquet', 1, 'body'))
            db.executemany('INSERT INTO matches VALUES(?,?,?,?)', [('c', 'PII', 'email', 0), ('c', 'PII', 'email', 0), ('c', 'AUTH', 'password', 1)])
        with sqlite3.connect(repair) as db:
            db.executescript('CREATE TABLE cells(id,source); CREATE TABLE matches(cell_id,category,subtype,excluded);')
            db.execute('INSERT INTO cells VALUES(?,?)', ('c', canonical({'table_path': 'table.parquet', 'source_row': 1, 'column_name': 'body'})))
            db.executemany('INSERT INTO matches VALUES(?,?,?,?)', [('c', 'PII', 'email', 0), ('c', 'QID', 'user_identifier', 0)])
        with sqlite3.connect(':memory:', uri=True) as db:
            create_keys(db); add_database_union(db, parent, repair)
            assert db.execute('SELECT COUNT(*) FROM baseline').fetchone()[0] == 2
            db.executemany('INSERT INTO new_types VALUES(?,?,?,?,?)', [('table.parquet', 1, 'body', 'PII', 'email'), ('table.parquet', 2, 'body', 'PII', 'email')])
            assert db.execute('SELECT COUNT(*) FROM new_types n WHERE NOT EXISTS(SELECT 1 FROM baseline b WHERE b.table_path=n.table_path AND b.source_row=n.source_row AND b.column_name=n.column_name AND b.category=n.category AND b.subtype=n.subtype)').fetchone()[0] == 1
    print(json.dumps({'synthetic_cell_type_union_and_gain_checks_passed': True, 'real_outputs_read': False}))


def main():
    started = datetime.now(timezone.utc).isoformat()
    parent = ROOT / 'content-runs/aidev-v044'; repair = ROOT / 'repair-runs/aidev-v045-final'
    merged = ROOT / 'reconciled-runs/aidev-v046'; new = ROOT / 'structured-runs/aidev-v048'
    report_path = ROOT / 'docs/aidev_structured_gain_v048.json'
    evidence_paths = [ROOT / 'docs'/('aidev_structured_gain_v048_evidence.' + suffix + '.gz') for suffix in ('jsonl', 'csv')]
    with ExitStack() as stack:
        for path in (parent / '.content.lock', repair / 'scan/.repair.lock', merged / '.reconcile.lock', new / '.structured.lock'):
            lock(stack, path)
        nm = read(new / 'manifest.json'); nc = read(new / 'structured_coverage.json'); state = read(new / 'export_state.json')
        assert state['status'] == 'complete' and state['fingerprint'] == nm['fingerprint']
        assert nc['all_source_rows_visited'] and nm['dataset'] == nc['dataset'] == 'aidev'
        assert nm['fingerprint']['source_sha256'] == structured_scan._sources()
        for name, item in state['outputs'].items():
            assert sha(new / name) == item['sha256']
        pm, mm, mc, proof = baseline_proof(parent, repair, merged)
        assert nm['source_manifest_sha256'] == pm['source_manifest_sha256'] == mm['fingerprint']['source_manifest_sha256']
        assert nm['fingerprint']['inputs'] == pm['fingerprint']['inputs']
        inventory = {t['path']: {'rows': t['rows'], 'columns': {f['column'] for f in t['columns'] if f['selected']}} for t in nm['tables']}
        observed_paths = [parent / 'manifest.json', parent / 'content.sqlite', repair / 'scan/manifest.json', repair / 'scan/repair.sqlite',
                          merged / 'manifest.json', merged / 'merged_coverage.json', new / 'manifest.json', new / 'structured.sqlite', new / 'structured_coverage.json', new / 'export_state.json']
        before = {str(p.relative_to(ROOT)): {'stat': stat(p), 'sha256': sha(p)} for p in observed_paths}
        with tempfile.TemporaryDirectory(prefix='aidev_structured_gain_') as temporary:
            db = stack.enter_context(sqlite3.connect(str(Path(temporary) / 'sets.sqlite'), uri=True))
            db.execute('PRAGMA cache_size=-16384'); create_keys(db)
            if proof['database_union_proven']:
                add_database_union(db, parent / 'content.sqlite', repair / 'scan/repair.sqlite'); method = 'verified_parent_repair_nonexcluded_cell_type_union'
            else:
                name = 'merged_type_occurrences.jsonl.gz'; add_merged_export(db, merged / name, mm['outputs'][name]); method = 'verified_reconciled_export_stream'
            validate_source_keys(db, 'baseline', inventory)
            new_db = stack.enter_context(connect(new / 'structured.sqlite')); new_db.row_factory = sqlite3.Row
            assert new_db.execute('SELECT COUNT(*) FROM matches m LEFT JOIN documents d ON d.id=m.document_id WHERE d.id IS NULL').fetchone()[0] == 0
            query = '''SELECT m.id,m.document_id,m.category,m.subtype,m.details,d.table_path,d.source_row,d.column_name,
                       d.document_index,d.source_start,d.source_end,d.format FROM matches m JOIN documents d ON d.id=m.document_id
                       WHERE m.excluded=0 ORDER BY d.table_path,d.source_row,d.column_name,m.category,m.subtype,m.id'''
            columns = ['structured_occurrence_id', 'structured_document_id', *KEY_FIELDS, 'document_index', 'source_start', 'source_end', 'format',
                       'node_path', 'node_kind', 'rule', 'basis', 'candidate_status', 'value_status', 'confidence', 'decoded_start', 'decoded_end', *SCOPE]
            streams = []; raw_streams = []
            for path in evidence_paths:
                raw = stack.enter_context(path.open('wb')); raw_streams.append(raw)
                gz = stack.enter_context(gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0))
                streams.append(stack.enter_context(io.TextIOWrapper(gz, encoding='utf-8', newline='')))
            writer = csv.DictWriter(streams[1], fieldnames=columns); writer.writeheader()
            evidence_count = outside_catalog = controlled_occurrences = 0
            for row in new_db.execute(query):
                if (row['category'], row['subtype']) not in TYPE_KEYS:
                    outside_catalog += 1; continue
                controlled_occurrences += 1; item = json.loads(row['details'])
                assert set(item) == structured_types.MATCH_FIELDS and item['document_index'] == row['document_index']
                assert all(item[k] in valid for k, valid in structured_types.MATCH_LABELS.items())
                assert isinstance(item['node_path'], list) and all(type(x) is int and x >= -1 for x in item['node_path'])
                assert (item['category'], item['subtype']) == (row['category'], row['subtype'])
                assert item['candidate_status'] != 'placeholder_or_example' and item['value_status'] != 'placeholder_or_example'
                assert type(row['source_start']) is int and type(row['source_end']) is int and 0 <= row['source_start'] <= row['source_end']
                assert row['format'] in {'whole_json', 'fenced_json'}
                key = tuple(row[k] for k in KEY_FIELDS)
                db.execute('INSERT OR IGNORE INTO new_types VALUES(?,?,?,?,?)', key)
                if db.execute('SELECT 1 FROM baseline WHERE table_path=? AND source_row=? AND column_name=? AND category=? AND subtype=?', key).fetchone(): continue
                record = {'structured_occurrence_id': row['id'], 'structured_document_id': row['document_id'],
                          **{k: row[k] for k in KEY_FIELDS + ('document_index','source_start','source_end','format')},
                          **{k: item[k] for k in ('node_path','node_kind','rule','basis','candidate_status','value_status','confidence','decoded_start','decoded_end')}, **SCOPE}
                streams[0].write(canonical(record) + '\n'); writer.writerow({k: csv_cell(record[k]) for k in columns}); evidence_count += 1
            assert controlled_occurrences + outside_catalog == nc['candidate_occurrences']
            db.commit(); validate_source_keys(db, 'new_types', inventory)
            for stream in streams: stream.close()
            for raw in raw_streams: raw.close()
            baseline_counts = {(c,s):n for c,s,n in db.execute('SELECT category,subtype,COUNT(*) FROM baseline GROUP BY category,subtype')}
            new_counts = {(c,s):n for c,s,n in db.execute('SELECT category,subtype,COUNT(*) FROM new_types GROUP BY category,subtype')}
            gains = {(c,s):n for c,s,n in db.execute('''SELECT n.category,n.subtype,COUNT(*) FROM new_types n WHERE NOT EXISTS(
                     SELECT 1 FROM baseline b WHERE b.table_path=n.table_path AND b.source_row=n.source_row AND b.column_name=n.column_name AND b.category=n.category AND b.subtype=n.subtype) GROUP BY n.category,n.subtype''')}
            type_rows = [{'category':c,'subtype':s,'label':label,'baseline_cell_type_pairs':baseline_counts.get((c,s),0),
                          'structured_cell_type_pairs':new_counts.get((c,s),0),'shared_cell_type_pairs':new_counts.get((c,s),0)-gains.get((c,s),0),
                          'gained_cell_type_pairs':gains.get((c,s),0)} for c,s,label in TYPE_ROWS]
        assert all(stat(p) == before[str(p.relative_to(ROOT))]['stat'] and sha(p) == before[str(p.relative_to(ROOT))]['sha256'] for p in observed_paths)
        assert structured_scan._sources() == nm['fingerprint']['source_sha256']
        report = {'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'command':[sys.executable,str(Path(__file__).resolve())],
                  'helper_sha256':sha(Path(__file__)),'dataset':'aidev','source_manifest_sha256':nm['source_manifest_sha256'],
                  'baseline_method':method,'baseline_proof':proof,'baseline_controlled_cell_type_pairs':sum(baseline_counts.values()),
                  'structured_controlled_cell_type_pairs':sum(new_counts.values()),'shared_cell_type_pairs':sum(new_counts.values())-sum(gains.values()),
                  'gained_cell_type_pairs':sum(gains.values()),'controlled_labels_with_gain':sum(n>0 for n in gains.values()),
                  'labels_observed_only_in_structured':sum(n>0 and baseline_counts.get(key,0)==0 for key,n in new_counts.items()),
                  'structured_controlled_occurrences':controlled_occurrences,'structured_candidates_outside_catalog':outside_catalog,
                  'novel_cell_type_occurrence_evidence_records':evidence_count,'type_summary':type_rows,
                  'evidence_outputs':{p.name:{'bytes':p.stat().st_size,'sha256':sha(p)} for p in evidence_paths},
                  'input_snapshot':before,'inputs_unchanged':True,'structured_source_fingerprint':nm['fingerprint']['source_sha256'],
                  'source_values_decoded':False,'original_values_dynamic_keys_or_hmac_exported':False,'network_accessed':False,'target_code_executed':False,
                  'count_unit':'Distinct (source table, column, row, controlled category, subtype); occurrence coordinates are not comparable across parsers.',
                  'evidence_boundary':'A gain is a new cell/type relationship relative to the frozen non-excluded plaintext baseline, not a new real secret, person, leak or sensitive type. Prior and structured occurrence counts are not additive. Zero-gain labels remain visible.', **SCOPE}
        report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('baseline_method','baseline_controlled_cell_type_pairs','structured_controlled_cell_type_pairs','shared_cell_type_pairs','gained_cell_type_pairs','controlled_labels_with_gain','labels_observed_only_in_structured','novel_cell_type_occurrence_evidence_records')},ensure_ascii=False))


if __name__ == '__main__':
    self_test() if sys.argv[1:] == ['--self-test'] else main()
