#!/usr/bin/env python3
"""Terminal-only AIDev v050 gzip content snapshot audit; metadata and hashes only.

Reuses the existing v048 verifier's digest/stat/CSV projection helpers. Never
loads Parquet values, modifies checkpoints, or treats finite scans as semantics.
"""
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
from itertools import zip_longest
from pathlib import Path
import argparse, csv, fcntl, gzip, hashlib, importlib.metadata, json, re, sqlite3, time
from agentlog_unified.content_scan import SCOPE, MATCH_FIELDS
from agentlog_unified.content_reconcile import SAFE_LABELS
from agentlog_unified.content_types import detector_catalog
from agentlog_unified.storage import stable_id
from agentlog_unified.taxonomy import TAXONOMY_VERSION, taxonomy_catalog
from verify_aidev_structured_v048 import digest, stat, cv, integer

BASE = Path(__file__).resolve().parents[1]
STEMS = ('content_type_occurrences', 'content_excluded', 'content_unknown_type_review_queue')
HEX = re.compile(r'[0-9a-f]{24}\Z')
HMAC = re.compile(r'[0-9a-f]{64}\Z')
OCCURRENCE_COLUMNS = ['id','cell_id','table_path','source_row','column_name','field_scope','start','end','category','subtype','rule','basis','confidence','value_status','candidate_status','observation_scope','human_review_status','runtime_confirmed']
REVIEW_COLUMNS = ['id','table_path','source_row','column_name','field_scope','characters','scanned_characters','text_hmac_sha256','status','reason','observation_scope','human_review_status','record_kind','start_row','end_row','row_count']
REVIEW_SQL = """SELECT id,table_path,source_row,column_name,field_scope,characters,scanned_characters,text_hmac_sha256,status,'cell' record_kind,source_row start_row,source_row end_row,1 row_count FROM cells
UNION ALL SELECT id,table_path,NULL,column_name,field_scope,characters,characters,NULL,'unclassified_text','source_row_range',start_row,end_row,end_row-start_row+1 FROM review_ranges"""


def intervals_valid(rows):
    """Require a source-sorted metadata stream with disjoint cell/range coverage."""
    previous = None
    last_end = 0
    for table, column, start, end in rows:
        key = table, column
        if previous is not None and key < previous:
            return False
        if key != previous:
            last_end = 0
        if not integer(start, 1) or not integer(end, 1) or not last_end < start <= end:
            return False
        previous, last_end = key, end
    return True


def self_test():
    assert intervals_valid([('table','a',1,2),('table','a',4,4),('table','b',1,5)])
    assert not intervals_valid([('table','a',1,3),('table','a',3,4)])
    assert not intervals_valid([('table','b',1,1),('table','a',3,4)])
    assert not intervals_valid([('table','a',True,2)])
    assert not intervals_valid([('table','a',3,2)])
    assert cv(None)=='' and cv(False)=='False' and cv({'n':2})=='{"n":2}'
    assert cv('=synthetic')=="'=synthetic"
    assert len(stable_id('content-cell','synthetic-source','table',1,'column'))==24
    print(json.dumps({'self_test':'passed','assertions':8,'real_snapshot_read':False}))


def verify(run, seed, report_path):
    if report_path.exists():
        raise FileExistsError('Preserve prior verification report')
    started = datetime.now(timezone.utc).isoformat(); timer = time.monotonic()
    checks = {}; evidence = {}; pairs = []; source_records = []
    def check(name, value):
        checks[name] = bool(value)
    def read(path):
        raw = path.read_bytes()
        evidence[str(path)] = {'sha256': hashlib.sha256(raw).hexdigest(), 'stat': stat(path)}
        return json.loads(raw)
    def capture(path):
        before = stat(path); sha = digest(path)
        evidence[str(path)] = {'sha256': sha, 'stat': before}
        check('hash_stat_stable_' + path.name, before == stat(path))
        return sha
    with ExitStack() as stack:
        for path in sorted({seed/'.content.lock', run/'.content.lock'}):
            handle = stack.enter_context(path.open('rb'))
            fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
        parent = read(seed/'manifest.json'); manifest = read(run/'manifest.json')
        coverage = read(run/'content_coverage.json'); state = read(run/'advance_state.json')
        fingerprint = manifest['fingerprint']; dbpath = seed/'content.sqlite'
        imported = read(Path(manifest['source_import'])/'manifest.json')
        catalog = {(c['category'], s['subtype']):s['label'] for c in taxonomy_catalog()['categories'] for s in c['subtypes']}
        check('installed_v050_taxonomy_v120_and_49_catalog_types', importlib.metadata.version('agentlog-unified')=='0.5.0' and TAXONOMY_VERSION=='1.2.0' and len(catalog)==49)
        check('terminal_export_state_and_coverage_sha', state['status']=='export_complete' and state['engine']=='content_advance_v1' and state['coverage_sha256']==evidence[str(run/'content_coverage.json')]['sha256'])
        check('aidev_finite_pending_scope', all(item.get('dataset')=='aidev' and all(item.get(k)==v for k,v in SCOPE.items()) for item in (parent,manifest,coverage)))
        check('coverage_detector_matches_current_catalog', coverage['detector']==detector_catalog())
        check('shared_seed_checkpoint_path_and_identity', Path(manifest['checkpoint_path']).resolve()==dbpath and Path(manifest['parent_run']).resolve()==seed and Path(manifest['checkpoint_lock_path']).resolve()==seed/'.content.lock' and manifest['checkpoint_identity']=={'device':dbpath.stat().st_dev,'inode':dbpath.stat().st_ino} and not (run/'content.sqlite').exists())
        ancestor = {k:manifest[k] for k in ('parent_run','parent_manifest_sha256','checkpoint_path','checkpoint_lock_path','checkpoint_identity')}
        check('ancestor_lineage_consistent', all(manifest['parent_shared_checkpoint']==coverage['parent_shared_checkpoint']==ancestor and coverage[k]==v and fingerprint[k]==v for k,v in ancestor.items()) and manifest['parent_manifest_sha256']==evidence[str(seed/'manifest.json')]['sha256'])
        check('source_import_complete_and_sha_consistent', imported['status']=='complete' and len({manifest['source_manifest_sha256'],parent['source_manifest_sha256'],coverage['source_manifest_sha256'],fingerprint['source_manifest_sha256'],evidence[str(Path(manifest['source_import'])/'manifest.json')]['sha256']})==1)
        check('source_import_and_tables_equal_seed', manifest['source_import']==parent['source_import'] and manifest['tables']==parent['tables'])
        check('fingerprint_keys_match_without_exposing_key', digest(seed/'.fingerprint-key')==digest(run/'.fingerprint-key')==parent['fingerprint_key_sha256']==manifest['fingerprint_key_sha256']==fingerprint['fingerprint_key_sha256'])
        check('seed_and_advance_finite_classifier_hashes_match', parent['fingerprint']['source_sha256']==fingerprint['frozen_source_sha256'])
        for group in ('frozen_source_sha256','implementation_sha256','inventory_dependency_sha256'):
            matches = []
            for name, expected in fingerprint[group].items():
                path = BASE/'src/agentlog_unified'/name
                matches.append(capture(path)==expected)
            check(group+'_matches_current_source', all(matches))
        check('frozen_limits_same_as_seed', all(fingerprint[k]==parent['fingerprint'][k] for k in ('max_source_chars','max_matches','pyarrow_version')) and fingerprint['pyarrow_version']==importlib.metadata.version('pyarrow'))
        check('exact_expected_compressed_export_names', manifest['export_files']=={s:{'jsonl':s+'.jsonl.gz','csv':s+'.csv.gz'} for s in STEMS})
        check('no_temporary_exports', not list(run.glob('*.tmp')))
        for stem in STEMS:
            for ext in ('.jsonl.gz','.csv.gz'):
                capture(run/(stem+ext))
        tables = {t['path']:t for t in manifest['tables']}
        signature = imported['source_signature']; root = Path(signature['source_dir']).resolve()
        check('frozen_source_inputs_equal_manifest', [{'path':t['path'],'bytes':t['bytes'],'sha256':t['sha256']} for t in manifest['tables']]==signature['inputs']==parent['fingerprint']['inputs'])
        for name, table in tables.items():
            path = Path(table['absolute_path']).resolve(); before = stat(path)
            valid_path = path==(root/name).resolve() and path.is_relative_to(root) and path.suffix=='.parquet'
            source_sha = digest(path) if valid_path else None
            valid = valid_path and before==stat(path)==tuple(table['source_stat']) and path.stat().st_size==table['bytes'] and source_sha==table['sha256']
            source_records.append({'table_path':name,'bytes':before[2],'sha256':source_sha,'expected_sha256':table['sha256'],'stat_stable_and_matches':valid})
        check('all_frozen_parquet_byte_hashes_and_stats_match', all(r['stat_stable_and_matches'] for r in source_records))
        print(json.dumps({'stage':'source_lineage_and_byte_hashes','tables':len(tables)}),flush=True)
        before_db = stat(dbpath)
        db = sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True); stack.callback(db.close); db.row_factory=sqlite3.Row
        db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        progress = [dict(r) for r in db.execute('SELECT * FROM tables ORDER BY path')]
        for item in progress: item['stats']=json.loads(item['stats'])
        totals = Counter(); selected = {name:{f['column']:f['field_scope'] for f in t['columns'] if f['selected']} for name,t in tables.items()}
        cursors = {p['path']:p['next_row'] for p in progress}; rows_ok = set(cursors)==set(tables)
        for p in progress:
            s=p['stats']; totals.update(s); n=p['next_row']; t=tables[p['path']]
            rows_ok &= integer(n) and n<=p['expected_rows']==t['rows'] and (p['status']=='complete')==(n==t['rows'])
            rows_ok &= s.get('text_cells_visited',0)==n*len(selected[p['path']]) and sum(s.get(k,0) for k in ('null_cells','empty_cells','nonempty_cells'))==s.get('text_cells_visited',0)
        check('18_tables_2456073_rows_and_17362345_nonempty_cells', len(tables)==18 and sum(t['rows'] for t in tables.values())==coverage['source_rows']==sum(cursors.values())==2456073 and totals.get('nonempty_cells')==17362345)
        check('progress_tables_and_cumulative_stats_equal_coverage', progress==coverage['tables'] and dict(totals)==coverage['counts'] and rows_ok)
        check('all_rows_visited_with_honest_truncation_boundary', coverage['all_selected_text_rows_visited'] is True and all(p['status']=='complete' for p in progress) and coverage['status']=='complete_with_semantic_gaps' and coverage['all_available_text_characters_scanned']==(not totals.get('truncated_cells',0)))
        check('cursor_state_and_checkpoint_export_size_consistent', cursors==coverage['after_cursors']==state['after_cursors'] and coverage['before_cursors']==state['before_cursors'] and all(0<=manifest['initial_cursors'][k]<=coverage['before_cursors'][k]<=v for k,v in cursors.items()) and coverage['checkpoint_bytes_at_export']==before_db[2])
        dbcounts = dict(db.execute('SELECT excluded,COUNT(*) FROM matches GROUP BY excluded'))
        statuses = dict(db.execute('SELECT status,COUNT(*) FROM cells GROUP BY status'))
        range_count, expanded = db.execute('SELECT COUNT(*),COALESCE(SUM(end_row-start_row+1),0) FROM review_ranges').fetchone()
        check('database_occurrence_counts_equal_coverage', dbcounts.get(0,0)==coverage['candidate_occurrences'] and dbcounts.get(1,0)==coverage['excluded_occurrences'])
        check('review_export_record_and_expanded_cell_denominators', statuses==coverage['cell_status_counts'] and sum(statuses.values())+range_count==coverage['unknown_type_review_export_records'] and sum(statuses.values())+expanded==coverage['unknown_type_review_cells']==totals['nonempty_cells'])
        check('truncated_cell_count_exact_and_present_in_unknown_queue', statuses.get('truncated',0)==totals.get('truncated_cells',0))
        check('all_match_cell_references_exist', db.execute('SELECT COUNT(*) FROM matches m LEFT JOIN cells c ON c.id=m.cell_id WHERE c.id IS NULL').fetchone()[0]==0)
        match_query = 'SELECT m.*,c.table_path,c.source_row,c.column_name,c.field_scope,c.scanned_characters,c.characters FROM matches m JOIN cells c ON c.id=m.cell_id'
        def expected(stem):
            if stem==STEMS[2]:
                for r in db.execute(REVIEW_SQL):
                    yield {**dict(r),**SCOPE,'reason':'text_semantics_and_sensitive_type_completeness_unresolved'},None
            else:
                excluded = int(stem==STEMS[1])
                for r in db.execute(match_query+' WHERE m.excluded=? ORDER BY m.id',(excluded,)):
                    row=dict(r); bounds=(row.pop('scanned_characters'),row.pop('characters')); detail=json.loads(row.pop('details'))
                    yield {**row,**detail,**SCOPE},bounds
        allowed_matches=set(OCCURRENCE_COLUMNS)|set(SCOPE)|{'excluded'}
        allowed_review=set(REVIEW_COLUMNS)|set(SCOPE)
        status_total = Counter(); label_total = Counter(); candidate_status = Counter(); review_status = Counter(); review_table=Counter()
        review_expanded=review_chars=review_scanned=0
        for stem in STEMS:
            count=0;csv_ok=db_ok=fields_ok=identities_ok=True;last_id=None;headers=REVIEW_COLUMNS if stem==STEMS[2] else OCCURRENCE_COLUMNS
            with gzip.open(run/(stem+'.jsonl.gz'),'rt',encoding='utf-8') as js,gzip.open(run/(stem+'.csv.gz'),'rt',encoding='utf-8',newline='') as cs:
                csvrows=csv.DictReader(cs)
                check(stem+'_csv_schema',csvrows.fieldnames==headers)
                for line,crow,pair in zip_longest(js,csvrows,expected(stem)):
                    count+=1
                    if line is None or crow is None or pair is None: csv_ok=db_ok=False;continue
                    row=json.loads(line);erow,bounds=pair
                    csv_ok &= crow=={k:cv(row.get(k)) for k in headers};db_ok &= row==erow
                    try:
                        fields_ok &= set(row)==(allowed_review if stem==STEMS[2] else allowed_matches) and all(row[k]==v for k,v in SCOPE.items()) and bool(HEX.fullmatch(row['id']))
                        table,column=row['table_path'],row['column_name'];fields_ok &= table in selected and column in selected[table] and selected[table][column]==row['field_scope']
                        if stem==STEMS[2]:
                            a,b=row['start_row'],row['end_row'];kind=row['record_kind']
                            fields_ok &= integer(a,1) and integer(b,1) and a<=b<=cursors[table] and row['row_count']==b-a+1 and integer(row['characters'],1) and integer(row['scanned_characters'],1) and row['scanned_characters']<=row['characters']
                            identities_ok &= row['id']==stable_id('content-cell',manifest['source_manifest_sha256'],table,a,column)
                            if kind=='cell':
                                fields_ok &= a==b==row['source_row'] and row['status'] in {'scanned_with_semantic_gaps','truncated'} and bool(HMAC.fullmatch(row['text_hmac_sha256'])) and row['scanned_characters']<=fingerprint['max_source_chars']
                            elif kind=='source_row_range':
                                fields_ok &= row['source_row'] is None and row['text_hmac_sha256'] is None and row['status']=='unclassified_text' and row['scanned_characters']==row['characters']
                            else: fields_ok=False
                            review_status[row['status']]+=row['row_count'];review_table[table]+=row['row_count'];review_expanded+=row['row_count'];review_chars+=row['characters'];review_scanned+=row['scanned_characters']
                        else:
                            detail={k:row[k] for k in MATCH_FIELDS};key=row['category'],row['subtype']
                            fields_ok &= bool(HEX.fullmatch(row['cell_id'])) and integer(row['source_row'],1) and row['source_row']<=cursors[table] and key in set(catalog)|{(None,None)} and all(row[k] in values for k,values in SAFE_LABELS.items())
                            fields_ok &= integer(row['start']) and integer(row['end'],1) and 0<=row['start']<row['end']<=bounds[0]<=bounds[1] and row['excluded']==int(stem==STEMS[1]) and (row['value_status']=='placeholder_or_example')==(stem==STEMS[1])
                            identities_ok &= row['id']==stable_id(row['cell_id'],detail) and (last_id is None or last_id<row['id'])
                            last_id=row['id']
                            if stem==STEMS[0]: label_total[key]+=1;candidate_status[row['candidate_status']]+=1;status_total[(key,row['candidate_status'])]+=1
                    except (KeyError,TypeError,ValueError): fields_ok=False
            check(stem+'_csv_jsonl_projection_exact',csv_ok);check(stem+'_database_all_fields_equal',db_ok);check(stem+'_safe_metadata_and_span_bounds',fields_ok);check(stem+'_stable_identity_and_unique_matches',identities_ok)
            target=coverage['unknown_type_review_export_records' if stem==STEMS[2] else 'excluded_occurrences' if stem==STEMS[1] else 'candidate_occurrences']
            check(stem+'_records_match_coverage',count==target)
            pairs.append({'stem':stem,'records':count,'csv_jsonl_projection_exact':bool(csv_ok),'database_all_fields_equal':bool(db_ok)})
            print(json.dumps({'verified_export_group':stem,'records':count}),flush=True)
        check('review_character_and_per_table_cell_totals', review_expanded==totals['nonempty_cells'] and review_chars==totals['characters_seen'] and review_scanned==totals['characters_scanned'] and all(review_table[p['path']]==p['stats'].get('nonempty_cells',0) for p in progress))
        check('review_truncation_status_exact',review_status['truncated']==totals.get('truncated_cells',0))
        intervals = db.execute('SELECT table_path,column_name,start_row,end_row FROM ('+REVIEW_SQL+') ORDER BY table_path,column_name,start_row')
        check('unknown_cell_ranges_disjoint_including_single_cells',intervals_valid(intervals))
        summary=read(run/'content_type_summary.json');summary_rows=summary['summary'];capture(run/'content_type_summary.csv')
        check('type_summary_taxonomy_and_scope',summary['taxonomy_version']==TAXONOMY_VERSION and all(summary[k]==v for k,v in SCOPE.items()))
        sql_labels={(r[0],r[1]):(r[2],r[3]) for r in db.execute('SELECT category,subtype,COUNT(*),COUNT(DISTINCT cell_id) FROM matches WHERE excluded=0 GROUP BY category,subtype')}
        sql_categories={r[0]:(r[1],r[2]) for r in db.execute('SELECT category,COUNT(*),COUNT(DISTINCT cell_id) FROM matches WHERE excluded=0 AND category IS NOT NULL GROUP BY category')}
        seen_subtypes=set();seen_categories=set();summary_ok=True
        for row in summary_rows:
            key=row['category'],row['subtype'];level=row['summary_level']
            if level=='subtype':
                summary_ok &= key in catalog and key not in seen_subtypes and row['label']==catalog.get(key)
                seen_subtypes.add(key);count,cells=sql_labels.get(key,(0,0));states={s:n for (k,s),n in status_total.items() if k==key}
            elif level=='category':
                summary_ok &= row['category'] in {c[0] for c in catalog} and row['category'] not in seen_categories and row['subtype'] is None
                seen_categories.add(row['category']);count,cells=sql_categories.get(row['category'],(0,0));acc=Counter()
                for (k,s),n in status_total.items():
                    if k[0]==row['category']:acc[s]+=n
                states=dict(acc)
            else: summary_ok=False;continue
            summary_ok &= row['occurrence_count']==count and row['distinct_cell_count']==cells and row['evidence_status_counts']==states and row['cell_denominator']==totals['nonempty_cells'] and all(row[k]==v for k,v in SCOPE.items())
        check('type_summary_all_49_including_zero_and_six_categories',seen_subtypes==set(catalog) and len(seen_subtypes)==49 and len(seen_categories)==6 and len(summary_rows)==55)
        check('type_summary_counts_distinct_cells_and_evidence_status_exact',summary_ok)
        with (run/'content_type_summary.csv').open(newline='',encoding='utf-8') as f:
            reader=csv.DictReader(f);summary_csv_ok=set(reader.fieldnames or [])==set(summary_rows[0])
            for actual,expected in zip_longest(reader,summary_rows):
                summary_csv_ok &= actual is not None and expected is not None and actual=={k:cv(v) for k,v in expected.items()}
        check('type_summary_csv_json_exact',summary_csv_ok)
        check('type_summary_plus_unknown_equals_all_candidates',sum(n for k,n in label_total.items() if k in catalog)+label_total[(None,None)]==coverage['candidate_occurrences'] and sum(n>0 for k,n in label_total.items() if k in catalog)==coverage['observed_subtypes'])
        check('sqlite_snapshot_unchanged',before_db==stat(dbpath))
        check('all_verified_files_unchanged',all(tuple(item['stat'])==stat(Path(path)) and (Path(path).suffix not in {'.py','.json'} or digest(Path(path))==item['sha256']) for path,item in evidence.items()))
        check('exit2_and_no_runtime_network_claims',coverage['exit_code']==2 and coverage['network_accessed'] is False and coverage['target_code_executed'] is False)
        report={'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':round(time.monotonic()-timer,3),'all_checks_passed':all(checks.values()),'passed':sum(checks.values()),'total':len(checks),'checks':checks,'run':str(run),'seed':str(seed),'checkpoint':str(dbpath),'tables':len(tables),'source_rows':coverage['source_rows'],'processed_rows':coverage['processed_rows'],'nonempty_cells':totals['nonempty_cells'],'candidate_occurrences':coverage['candidate_occurrences'],'excluded_occurrences':coverage['excluded_occurrences'],'unknown_type_review_cells':coverage['unknown_type_review_cells'],'unknown_type_review_export_records':coverage['unknown_type_review_export_records'],'truncated_cells':totals.get('truncated_cells',0),'candidate_status_counts':dict(candidate_status),'catalog_subtypes':len(catalog),'observed_controlled_subtypes':sum(n>0 for k,n in label_total.items() if k in catalog),'zero_count_catalog_subtypes':[{'category':k[0],'subtype':k[1]} for k in sorted(catalog) if not label_total[k]],'outside_catalog_candidates':label_total[(None,None)],'pairs':pairs,'files':evidence,'frozen_source_files':source_records,'source_values_decoded':False,'source_values_exported':False,'target_code_executed':False,'network_accessed':False,'finite_rules_all_cells_complete':not totals.get('truncated_cells',0),'semantic_complete':False,'limits':['All Parquet bytes were hashed; source values were not decoded. HMAC metadata links were checked, not recomputed from text.','JSONL is checked against its complete metadata projection; CSV intentionally exports the established subset of fields.','Every nonempty cell remains in unknown review. Visited rows do not establish semantic completeness, credential validity, or confirmed disclosure.','Truncated cells require same-version repair; all text rows visited does not mean all finite rules finished for every cell.']}
        report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps({'report':str(report_path),'all_checks_passed':report['all_checks_passed'],'passed':report['passed'],'total':report['total'],'failed':[k for k,v in checks.items() if not v]},ensure_ascii=False))
        return 0 if report['all_checks_passed'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--runs-confirmed-terminal',action='store_true')
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--run',type=Path,default=BASE/'content-runs/aidev-v050')
    parser.add_argument('--seed',type=Path,default=BASE/'content-runs/aidev-v050-seed')
    parser.add_argument('--report',type=Path,default=BASE/'docs/aidev_content_v050_verification.json')
    args=parser.parse_args()
    if args.self_test:self_test()
    elif args.runs_confirmed_terminal:raise SystemExit(verify(args.run.resolve(),args.seed.resolve(),args.report.resolve()))
    else:parser.error('--runs-confirmed-terminal is required before reading any real output')
