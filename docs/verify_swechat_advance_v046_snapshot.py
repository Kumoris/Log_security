"""Compare a terminal zero-row gzip snapshot with preserved legacy exports."""
from pathlib import Path
from datetime import datetime, timezone
from contextlib import ExitStack
import argparse
import fcntl
import gzip
import hashlib
import json
import sqlite3

BASE = Path(__file__).resolve().parent.parent
PARENT = BASE/'content-runs/swechat-v044'
OUTPUT = BASE/'content-runs/swechat-v046'
STEMS = ('content_type_occurrences', 'content_excluded', 'content_unknown_type_review_queue')


def stat(path):
    value = path.stat()
    return {'device': value.st_dev, 'inode': value.st_ino, 'bytes': value.st_size,
            'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024*1024): h.update(chunk)
    return h.hexdigest()


def document(path):
    return json.loads(path.read_text())


def verify():
    baseline_path = BASE/'docs/swechat_advance_v046_snapshot_baseline.json'
    baseline = document(baseline_path)
    before = {row['path']: row for row in baseline['files']}
    checks = {'baseline_stat_hash_stat_stable': baseline['all_stat_hash_stat_stable'],
              'baseline_parent_manifest_matches_pre_execution': baseline['parent_manifest_matches_pre_execution']}
    start = datetime.now(timezone.utc).isoformat()
    with ExitStack() as stack:
        for lock_path in sorted({PARENT/'.content.lock', OUTPUT/'.content.lock'}):
            lock = stack.enter_context(lock_path.open('rb'))
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        parent = document(PARENT/'manifest.json'); old_coverage = document(PARENT/'content_coverage.json')
        new = document(OUTPUT/'manifest.json'); coverage = document(OUTPUT/'content_coverage.json')
        state = document(OUTPUT/'advance_state.json')
        pairs = []; old_hashes = {}
        for stem in STEMS:
            for extension in ('.jsonl', '.csv'):
                raw = PARENT/(stem+extension); compressed = OUTPUT/(stem+extension+'.gz')
                raw_before, gzip_before = stat(raw), stat(compressed)
                h_raw, h_gzip = hashlib.sha256(), hashlib.sha256(); identical = True; size = lines = 0
                with raw.open('rb') as left, gzip.open(compressed, 'rb') as right:
                    while True:
                        a, b = left.read(1024*1024), right.read(1024*1024)
                        if not a and not b: break
                        identical &= a == b; h_raw.update(a); h_gzip.update(b)
                        size += len(b); lines += b.count(b'\n')
                raw_sha, decompressed_sha = h_raw.hexdigest(), h_gzip.hexdigest()
                old_hashes[str(raw)] = raw_sha
                key = stem+extension
                checks[key+'_decompressed_bytes_equal'] = identical and raw_sha == decompressed_sha
                checks[key+'_files_stable'] = raw_before == stat(raw) and gzip_before == stat(compressed)
                checks[key+'_legacy_sha_unchanged'] = raw_sha == before[str(raw)]['sha256']
                checks[key+'_legacy_stat_unchanged'] = raw_before == before[str(raw)]['stat_after']
                pair = {'legacy': str(raw), 'gzip': str(compressed), 'legacy_sha256': raw_sha,
                        'decompressed_sha256': decompressed_sha, 'bytewise_equal': identical,
                        'decompressed_bytes': size, 'gzip_bytes': gzip_before['bytes'],
                        'gzip_sha256': digest(compressed)}
                if extension == '.jsonl':
                    count_key = {'content_type_occurrences':'candidate_occurrences', 'content_excluded':'excluded_occurrences',
                                 'content_unknown_type_review_queue':'unknown_type_review_export_records'}[stem]
                    checks[key+'_records_match_coverage'] = lines == coverage[count_key] == old_coverage[count_key]
                    pair['records'] = lines
                pairs.append(pair)
        for name in ('manifest.json', 'content_coverage.json'):
            path = PARENT/name
            checks['legacy_'+name+'_sha_unchanged'] = digest(path) == before[str(path)]['sha256']
            checks['legacy_'+name+'_stat_unchanged'] = stat(path) == before[str(path)]['stat_after']
        checks['parent_manifest_matches_pre_execution'] = digest(PARENT/'manifest.json') == new['parent_manifest_sha256'] == document(Path(baseline['pre_execution_dry_run']))['parent_manifest_sha256']
        checks['advance_state_complete'] = state.get('status') == 'export_complete'
        checks['coverage_state_sha_valid'] = state.get('coverage_sha256') == digest(OUTPUT/'content_coverage.json')
        checks['new_engine_explicit'] = new.get('engine') == coverage.get('engine') == 'content_advance_v1'
        checks['zero_row_budget'] = coverage['execution_budget']['max_rows'] == 0
        checks['cursors_equal_pre_execution'] = coverage['before_cursors'] == coverage['after_cursors'] == baseline['expected_cursors']
        db_path = PARENT/'content.sqlite'
        db = sqlite3.connect(db_path.as_uri()+'?mode=ro', uri=True); stack.callback(db.close); db.row_factory = sqlite3.Row
        tables = [dict(row) for row in db.execute('SELECT * FROM tables ORDER BY path')]
        for row in tables: row['stats'] = json.loads(row['stats'])
        checks['database_table_metadata_unchanged'] = tables == old_coverage['tables'] == coverage['tables']
        cursors = {row['path']: row['next_row'] for row in tables}
        checks['database_cursors_equal'] = cursors == baseline['expected_cursors']
        counts = dict(db.execute('SELECT excluded,COUNT(*) FROM matches GROUP BY excluded'))
        statuses = dict(db.execute('SELECT status,COUNT(*) FROM cells GROUP BY status'))
        range_count, expanded = db.execute('SELECT COUNT(*),COALESCE(SUM(end_row-start_row+1),0) FROM review_ranges').fetchone()
        checks['database_occurrence_counts_unchanged'] = counts.get(0,0) == coverage['candidate_occurrences'] == old_coverage['candidate_occurrences'] and counts.get(1,0) == coverage['excluded_occurrences'] == old_coverage['excluded_occurrences']
        checks['database_review_metadata_unchanged'] = statuses == coverage['cell_status_counts'] == old_coverage['cell_status_counts'] and sum(statuses.values())+range_count == coverage['unknown_type_review_export_records'] == old_coverage['unknown_type_review_export_records'] and sum(statuses.values())+expanded == coverage['unknown_type_review_cells'] == old_coverage['unknown_type_review_cells']
        checks['shared_checkpoint_location'] = Path(new['checkpoint_path']).resolve() == db_path and not (OUTPUT/'content.sqlite').exists()
        identity = {'device': db_path.stat().st_dev, 'inode': db_path.stat().st_ino}
        checks['shared_checkpoint_identity_unchanged'] = identity == baseline['expected_checkpoint_identity'] == new['checkpoint_identity']
        checks['source_metadata_stat_unchanged'] = all(stat(Path(row['path'])) == row['stat'] for row in baseline['source_parquet_stats'])
        checks['key_digest_only_matches'] = digest(PARENT/'.fingerprint-key') == digest(OUTPUT/'.fingerprint-key') == parent['fingerprint_key_sha256'] == new['fingerprint_key_sha256']
        checks['original_four_hashes_match'] = new['fingerprint']['frozen_source_sha256'] == parent['fingerprint']['source_sha256']
        for field in ('frozen_source_sha256', 'implementation_sha256', 'inventory_dependency_sha256'):
            checks[field+'_current_match'] = all(digest(BASE/'src/agentlog_unified'/name)==expected for name,expected in new['fingerprint'][field].items())
        report = {'started_utc': start, 'completed_utc': datetime.now(timezone.utc).isoformat(),
                  'all_checks_passed': all(checks.values()), 'checks': checks, 'passed': sum(checks.values()), 'total': len(checks),
                  'pairs': pairs, 'baseline_path': str(baseline_path), 'baseline_sha256': digest(baseline_path),
                  'legacy_baseline_timing': baseline['basis'], 'processed_rows': sum(cursors.values()),
                  'candidate_occurrences': counts.get(0,0), 'excluded_occurrences': counts.get(1,0),
                  'same_snapshot': all(checks.values()), 'source_values_decoded': False,
                  'source_values_printed': False, 'target_code_executed': False, 'remote_accessed': False,
                  'limits': ['Metadata and export bytes were verified. The entire raw Parquet corpus was not rehashed; its captured stat metadata was unchanged. Original export SHA baseline was captured during the zero-row export; the parent manifest SHA and cursors also match the independently saved pre-execution dry run.']}
        result = BASE/'docs/swechat_advance_v046_snapshot_verification.json'
        if result.exists(): raise RuntimeError('Verification already exists; refusing overwrite')
        result.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps({'report':str(result),'all_checks_passed':report['all_checks_passed'],'passed':report['passed'],'total':report['total'],'failed':[k for k,v in checks.items() if not v]},ensure_ascii=False))
        return 0 if report['all_checks_passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runs-confirmed-terminal', action='store_true', required=True)
    parser.parse_args()
    raise SystemExit(verify())
