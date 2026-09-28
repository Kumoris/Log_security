"""Terminal-only metadata preservation audit after the bounded advance run."""
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
import argparse
import csv
import fcntl
import gzip
import hashlib
import json
import sqlite3

from agentlog_unified.storage import canonical, csv_cell
from verify_swechat_advance_v046_snapshot import BASE, PARENT, OUTPUT, STEMS, stat, digest, document


def projection(row):
    return hashlib.sha256(canonical(row).encode()).hexdigest()


def json_rows(path, compressed, metrics):
    h = hashlib.sha256(); count = 0
    opener = gzip.open if compressed else open
    with opener(path, 'rb') as stream:
        for line in stream:
            h.update(line); count += 1
            yield json.loads(line)
    metrics.update(sha256=h.hexdigest(), records=count)


def new_rows(stem, checks, metrics):
    with (PARENT/(stem+'.csv')).open(newline='') as raw:
        fields = next(csv.reader(raw))
    with gzip.open(OUTPUT/(stem+'.csv.gz'), 'rt', newline='') as stream:
        reader = csv.DictReader(stream); same = reader.fieldnames == fields; count = 0
        for row in json_rows(OUTPUT/(stem+'.jsonl.gz'), True, metrics):
            count += 1; actual = next(reader, None)
            same &= actual == {key: csv_cell(row.get(key)) for key in fields}
            yield row
        same &= next(reader, None) is None
    checks[stem+'_csv_jsonl_projection_equal'] = same
    metrics['csv_records'] = count


def verify():
    started = datetime.now(timezone.utc).isoformat()
    zero_path = BASE/'docs/swechat_advance_v046_snapshot_verification.json'
    zero = document(zero_path)
    baseline = document(BASE/'docs/swechat_advance_v046_snapshot_baseline.json')
    old_cursors = baseline['expected_cursors']; old_files = {p['legacy']:p for p in zero['pairs']}
    checks = {'zero_snapshot_previously_verified': zero['all_checks_passed']}; match_results = {}
    with ExitStack() as stack:
        for path in sorted({PARENT/'.content.lock', OUTPUT/'.content.lock'}):
            lock = stack.enter_context(path.open('rb')); fcntl.flock(lock, fcntl.LOCK_SH|fcntl.LOCK_NB)
        manifest = document(OUTPUT/'manifest.json'); parent_manifest = document(PARENT/'manifest.json')
        coverage = document(OUTPUT/'content_coverage.json'); state = document(OUTPUT/'advance_state.json')
        new_cursors = coverage['after_cursors']; expected_rows = {t['path']:t['rows'] for t in parent_manifest['tables']}
        checks['export_state_complete'] = state['status'] == 'export_complete' and state['coverage_sha256'] == digest(OUTPUT/'content_coverage.json')
        checks['before_cursors_equal_zero_snapshot'] = coverage['before_cursors'] == old_cursors
        checks['cursors_monotone'] = set(new_cursors) == set(old_cursors) and all(old_cursors[k] <= new_cursors[k] <= expected_rows[k] for k in old_cursors)
        source_valid = lambda row: row['table_path'] in new_cursors and type(row['source_row']) is int and old_cursors[row['table_path']] < row['source_row'] <= new_cursors[row['table_path']]
        for stem in STEMS[:2]:
            old_metrics = {}; new_metrics = {}; previous_old = previous_new = None
            old_iter = iter(json_rows(PARENT/(stem+'.jsonl'),False,old_metrics))
            old = next(old_iter,None); matched = added = missing = changed = 0; sorted_ok = True; additions_valid = True
            for row in new_rows(stem, checks, new_metrics):
                identifier = row['id']; sorted_ok &= previous_new is None or previous_new < identifier; previous_new = identifier
                while old is not None and old['id'] < identifier:
                    sorted_ok &= previous_old is None or previous_old < old['id']; previous_old = old['id']
                    missing += 1; old = next(old_iter,None)
                if old is not None and old['id'] == identifier:
                    matched += 1; changed += old != row
                    sorted_ok &= previous_old is None or previous_old < old['id']; previous_old = old['id']
                    old = next(old_iter,None)
                else:
                    added += 1; additions_valid &= source_valid(row)
            while old is not None:
                missing += 1; old = next(old_iter,None)
            checks[stem+'_old_ids_and_all_fields_preserved'] = not missing and not changed
            checks[stem+'_ids_strictly_sorted_unique'] = sorted_ok
            checks[stem+'_new_records_only_after_old_cursors'] = additions_valid
            checks[stem+'_old_plaintext_sha_matches_zero_snapshot'] = old_metrics['sha256'] == old_files[str(PARENT/(stem+'.jsonl'))]['legacy_sha256']
            key = 'candidate_occurrences' if stem == 'content_type_occurrences' else 'excluded_occurrences'
            checks[stem+'_records_match_coverage'] = new_metrics['records'] == matched+added == coverage[key]
            match_results[stem] = {'matched_old_ids':matched,'new_ids':added,'missing_old_ids':missing,'changed_old_records':changed,'old':old_metrics,'new':new_metrics}
        stem = STEMS[2]; old_metrics = {}; new_metrics = {}; old = {}; tails = {}; duplicate_old = False
        for row in json_rows(PARENT/(stem+'.jsonl'),False,old_metrics):
            identifier = row['id']; duplicate_old |= identifier in old; old[identifier] = projection(row)
            if row['record_kind'] == 'source_row_range' and row['end_row'] == old_cursors[row['table_path']] < expected_rows[row['table_path']]: tails[identifier] = row
        seen_old = set(); exact = extended = changed = duplicate = added = expanded = characters = 0; additions_valid = True
        max_chars = manifest['fingerprint']['max_source_chars']; tail_projection_drop = {'end_row','row_count','characters','scanned_characters'}
        for row in new_rows(stem, checks, new_metrics):
            identifier = row['id']; expanded += row['row_count']; characters += row['characters']
            if identifier in old:
                duplicate += identifier in seen_old; seen_old.add(identifier)
                if projection(row) == old[identifier]: exact += 1
                elif identifier in tails:
                    prior = tails[identifier]; delta_rows = row['end_row']-prior['end_row']; delta_chars = row['characters']-prior['characters']
                    valid = ({k:v for k,v in row.items() if k not in tail_projection_drop} == {k:v for k,v in prior.items() if k not in tail_projection_drop}
                        and 0 < delta_rows and row['end_row'] <= new_cursors[row['table_path']]
                        and row['row_count'] == row['end_row']-row['start_row']+1
                        and row['scanned_characters'] == row['characters'] and delta_rows <= delta_chars <= delta_rows*max_chars)
                    extended += bool(valid); changed += not valid
                else: changed += 1
            else:
                added += 1
                additions_valid &= (row['table_path'] in new_cursors and old_cursors[row['table_path']] < row['start_row'] <= row['end_row'] <= new_cursors[row['table_path']]
                    and row['row_count'] == row['end_row']-row['start_row']+1)
        missing = len(old)-len(seen_old)
        checks['review_old_records_preserved_with_legal_tail_extension'] = not (missing or changed or duplicate or duplicate_old)
        checks['review_new_records_only_after_old_cursors'] = additions_valid
        checks['review_old_plaintext_sha_matches_zero_snapshot'] = old_metrics['sha256'] == old_files[str(PARENT/(stem+'.jsonl'))]['legacy_sha256']
        checks['review_counts_and_characters_match_coverage'] = (new_metrics['records'] == coverage['unknown_type_review_export_records'] and expanded == coverage['unknown_type_review_cells'] and characters == coverage['counts']['characters_seen'])
        review_result = {'old_records':len(old),'exact_preserved':exact,'legal_tail_extensions':extended,'eligible_old_tails':len(tails),'new_records':added,'missing_old_ids':missing,'changed_nonpermitted_records':changed,'duplicate_old_ids_in_new':duplicate,'expanded_cells':expanded,'old':old_metrics,'new':new_metrics}
        del old
        for item in baseline['files']:
            path = Path(item['path'])
            checks['legacy_'+path.name+'_stat_unchanged'] = stat(path) == item['stat_after']
            if path.suffix != '.jsonl': checks['legacy_'+path.name+'_sha_unchanged'] = digest(path) == item['sha256']
        db_path = PARENT/'content.sqlite'; db=sqlite3.connect(db_path.as_uri()+'?mode=ro',uri=True); stack.callback(db.close);db.row_factory=sqlite3.Row
        tables=[dict(r) for r in db.execute('SELECT * FROM tables ORDER BY path')]
        for t in tables:t['stats']=json.loads(t['stats'])
        counts=dict(db.execute('SELECT excluded,COUNT(*) FROM matches GROUP BY excluded'))
        statuses=dict(db.execute('SELECT status,COUNT(*) FROM cells GROUP BY status'))
        ranges,expanded_db=db.execute('SELECT COUNT(*),COALESCE(SUM(end_row-start_row+1),0) FROM review_ranges').fetchone()
        checks['database_tables_match_current_coverage'] = tables == coverage['tables']
        checks['database_counters_match_current_coverage'] = counts.get(0,0)==coverage['candidate_occurrences'] and counts.get(1,0)==coverage['excluded_occurrences'] and statuses==coverage['cell_status_counts'] and sum(statuses.values())+ranges==coverage['unknown_type_review_export_records'] and sum(statuses.values())+expanded_db==coverage['unknown_type_review_cells']
        checks['checkpoint_original_identity_preserved'] = {'device':db_path.stat().st_dev,'inode':db_path.stat().st_ino} == baseline['expected_checkpoint_identity']
        checks['parent_manifest_and_source_lineage_preserved'] = digest(PARENT/'manifest.json') == manifest['parent_manifest_sha256'] and manifest['source_manifest_sha256']==parent_manifest['source_manifest_sha256']
        checks['source_parquet_stats_unchanged'] = all(stat(Path(row['path']))==row['stat'] for row in baseline['source_parquet_stats'])
        for field in ('frozen_source_sha256','implementation_sha256','inventory_dependency_sha256'):
            checks[field+'_matches_current'] = all(digest(BASE/'src/agentlog_unified'/name)==h for name,h in manifest['fingerprint'][field].items())
        report={'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'all_checks_passed':all(checks.values()),'checks':checks,'passed':sum(checks.values()),'total':len(checks),
            'zero_snapshot_report':str(zero_path),'zero_snapshot_report_sha256':digest(zero_path),'before_cursors':old_cursors,'after_cursors':new_cursors,
            'previous_processed_rows':zero['processed_rows'],'processed_rows':coverage['processed_rows'],'new_processed_rows':coverage['processed_rows']-zero['processed_rows'],
            'candidate_occurrences':coverage['candidate_occurrences'],'excluded_occurrences':coverage['excluded_occurrences'],'matches':match_results,'review_preservation':review_result,
            'source_values_decoded':False,'source_values_printed':False,'target_code_executed':False,'remote_accessed':False,
            'limits':['Full Parquet bytes were not rehashed; source stats and frozen fingerprints were checked. Newly emitted sensitive-shape metadata remains unverified and pending. Continuous no-match review tails may grow while all fixed fields remain identical.']}
        result=BASE/'docs/swechat_advance_v046_resume_verification.json'
        if result.exists():raise RuntimeError('Verification already exists; refusing overwrite')
        result.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps({'report':str(result),'all_checks_passed':report['all_checks_passed'],'passed':report['passed'],'total':report['total'],'new_processed_rows':report['new_processed_rows'],'failed':[k for k,v in checks.items() if not v]},ensure_ascii=False))
        return 0 if report['all_checks_passed'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--runs-confirmed-terminal',action='store_true',required=True);parser.parse_args()
    raise SystemExit(verify())
