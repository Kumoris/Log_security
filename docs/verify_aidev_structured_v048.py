#!/usr/bin/env python3
"""Read-only structured snapshot verification; run only after its writer stops.

Never read source text. Shared locking rejects an active writer. Six gzip pairs
are streamed against CSV and the SQLite snapshot; smoke evidence is immutable.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import zip_longest
from pathlib import Path
import argparse, csv, fcntl, gzip, hashlib, json, re, sqlite3, time
from agentlog_unified import structured_types as parser
from agentlog_unified.taxonomy import taxonomy_catalog

BASE=Path(__file__).resolve().parents[1]
SCOPE={'observation_scope':'dataset_structured_text','human_review_status':'pending','runtime_confirmed':False,'new_type_status':'not_established','application_log_evidence':False,'full_dataset_coverage_claim':False}
STEMS=('structured_documents','structured_type_occurrences','structured_excluded','structured_data_gaps','structured_unknown_type_review_queue','structured_type_summary')
HEX=re.compile(r'[0-9a-f]{24}\Z')

def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for part in iter(lambda:f.read(1048576),b''):h.update(part)
 return h.hexdigest()
def stat(path):
 s=Path(path).stat();return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def cv(value):
 if value is None:return ''
 if isinstance(value,(dict,list)):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
 if isinstance(value,str) and value.lstrip().startswith(('=','+','-','@','\t','\r')):return "'"+value
 return str(value)
def integer(v,minimum=0):return type(v) is int and v>=minimum
def node_path(v):return isinstance(v,list) and all(integer(n,-1) for n in v)
def preserved_range(old,new,cursor):
 return new is not None and all(new.get(k)==v for k,v in old.items() if k!='end_row') and new['end_row']>=old['end_row'] and (new['end_row']==old['end_row'] or old['end_row']==cursor)
def self_test():
 old={'id':'synthetic','start_row':4,'end_row':9,'status':'partial'}
 assert preserved_range(old,{**old,'end_row':12},9)
 assert not preserved_range(old,{**old,'end_row':12},10)
 assert not preserved_range(old,{**old,'end_row':8},9)
 assert not preserved_range(old,{**old,'start_row':3},9)
 assert cv([0,-1,2])=='[0,-1,2]' and cv(None)=='' and cv(False)=='False'
 assert node_path([0,-1,2]) and not node_path([True]) and not node_path([-2])
 print(json.dumps({'self_test':'passed','checks':6,'real_snapshot_read':False}))


def verify(run,report_path):
 started=datetime.now(timezone.utc).isoformat();clock=time.monotonic();checks={};evidence={};pairs=[]
 def check(name,value):checks[name]=bool(value)
 def read(path):
  raw=path.read_bytes();evidence[str(path)]={'sha256':hashlib.sha256(raw).hexdigest(),'stat':stat(path)};return json.loads(raw)
 smoke_path=BASE/'docs/aidev_structured_v048_smoke_checkpoint.json'
 old_coverage_path=BASE/'content-runs/aidev-v044/content_coverage.json'
 smoke=read(smoke_path);old_coverage=read(old_coverage_path)
 with (run/'.structured.lock').open('rb') as lock:
  fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
  manifest=read(run/'manifest.json');coverage=read(run/'structured_coverage.json');state=read(run/'export_state.json')
  fingerprint=manifest['fingerprint'];limits=fingerprint['limits'];source_manifest=Path(fingerprint['source_import'])/'manifest.json'
  imported=read(source_manifest)
  check('export_state_complete',state['status']=='complete')
  check('snapshot_fingerprint_consistent',state['fingerprint']==fingerprint and coverage['limits']==limits)
  check('source_manifest_consistent',digest(source_manifest)==manifest['source_manifest_sha256']==coverage['source_manifest_sha256']==old_coverage['source_manifest_sha256']==fingerprint['source_manifest_sha256'])
  check('source_file_signature_consistent',fingerprint['inputs']==imported['source_signature']['inputs'])
  check('smoke_manifest_unchanged',digest(run/'manifest.json')==smoke['manifest_sha256'])
  check('source_implementation_hashes_match',all(digest(BASE/'src/agentlog_unified'/name)==sha for name,sha in fingerprint['source_sha256'].items()))
  check('aidev_scope_and_pending_boundaries',all(x.get('dataset')=='aidev' and all(x.get(k)==v for k,v in SCOPE.items()) for x in (manifest,coverage)))
  expected_names={s+ext+'.gz' for s in STEMS for ext in ('.jsonl','.csv')}|{'structured_coverage.json'}
  check('complete_export_name_set',set(state['outputs'])==expected_names)
  for name,meta in state['outputs'].items():
   path=run/name;evidence[str(path)]={'sha256':digest(path),'stat':stat(path)}
   check('snapshot_hash_'+name,evidence[str(path)]['sha256']==meta['sha256'] and ('bytes' not in meta or path.stat().st_size==meta['bytes']))
  dbpath=run/'structured.sqlite';db_before=stat(dbpath)
  db=sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
  try:
   db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
   progress={r['table_path']:{**dict(r),'stats':json.loads(r['stats'])} for r in db.execute('SELECT * FROM progress')}
   tables={t['path']:t for t in manifest['tables']};selected={name:{f['column'] for f in t['columns'] if f['selected']} for name,t in tables.items()}
   check('18_frozen_tables_and_2456073_rows',len(tables)==18 and sum(t['rows'] for t in tables.values())==2456073==coverage['source_rows'])
   check('progress_matches_coverage',sorted(progress.values(),key=lambda x:x['table_path'])==coverage['tables'] and set(progress)==set(tables))
   stats=Counter();progress_valid=True
   for name,p in progress.items():
    stats.update(p['stats']);n=p['next_row'];s=p['stats']
    progress_valid &= integer(n) and n<=tables[name]['rows']==p['expected_rows'] and (p['status']=='complete')==(n==p['expected_rows'])
    progress_valid &= s.get('text_cells_visited',0)==n*len(selected[name]) and sum(s.get(k,0) for k in ('null_cells','empty_cells','nonempty_cells'))==s.get('text_cells_visited',0)
    progress_valid &= sum(s.get('cells_'+k,0) for k in parser.STATUSES)==s.get('nonempty_cells',0)
   check('progress_row_and_cell_arithmetic',progress_valid)
   complete=all(p['status']=='complete' for p in progress.values())
   check('coverage_status_honest',coverage['all_source_rows_visited'] is complete and coverage['status']==('complete_with_semantic_gaps' if complete else 'partial'))
   check('coverage_cumulative_counts_match',dict(stats)==coverage['counts'] and sum(p['next_row'] for p in progress.values())==coverage['processed_rows'])
   denominator_keys=('rows_decoded','text_cells_visited','nonempty_cells','null_cells','empty_cells','characters_seen')
   check('complete_or_partial_denominators',all(stats.get(k,0)==old_coverage['counts'].get(k,0) if complete else stats.get(k,0)<=old_coverage['counts'].get(k,0) for k in denominator_keys))
   check('historical_nonempty_denominator_verified',old_coverage['counts']['nonempty_cells']==17362345 and old_coverage['source_rows']==2456073 and old_coverage['all_selected_text_rows_visited'] is True)
   catalog={(c['category'],s['subtype']):s['label'] for c in taxonomy_catalog()['categories'] for s in c['subtypes']}
   category_counts={(r[0],r[1]):r[2] for r in db.execute('SELECT category,subtype,COUNT(*) FROM matches WHERE excluded=0 GROUP BY category,subtype')}
   summary=[{'category':c,'subtype':s,'label':label,'candidate_occurrences':category_counts.get((c,s),0),**SCOPE} for (c,s),label in sorted(catalog.items())]
   summary.insert(0,{'category':None,'subtype':None,'label':'Unclassified named JSON values','candidate_occurrences':category_counts.get((None,None),0),**SCOPE})
   dbcounts={'documents':db.execute('SELECT COUNT(*) FROM documents').fetchone()[0],'candidate_occurrences':db.execute('SELECT COUNT(*) FROM matches WHERE excluded=0').fetchone()[0],'excluded_occurrences':db.execute('SELECT COUNT(*) FROM matches WHERE excluded=1').fetchone()[0],'data_gap_records':db.execute('SELECT COUNT(*) FROM gaps').fetchone()[0],'unknown_review_range_records':db.execute('SELECT COUNT(*) FROM review_ranges').fetchone()[0],'unknown_review_source_cells':db.execute('SELECT COALESCE(SUM(end_row-start_row+1),0) FROM review_ranges').fetchone()[0]}
   check('coverage_database_record_counts_match',all(coverage[k]==v for k,v in dbcounts.items()))
   check('parser_emission_counts_match_database',stats.get('parser_documents_selected',0)==dbcounts['documents'] and stats.get('parser_matches_emitted',0)==dbcounts['candidate_occurrences']+dbcounts['excluded_occurrences'] and stats.get('parser_gap_records',0)==dbcounts['data_gap_records'])
   check('summary43_including_unknown_and_zero_labels',len(summary)==43 and len(catalog)==42 and sum(r['candidate_occurrences'] for r in summary)==dbcounts['candidate_occurrences'])
   check('controlled_label_count_matches',sum(n>0 for k,n in category_counts.items() if k in catalog)==coverage['observed_controlled_labels'])
   document_status=dict(db.execute('SELECT status,COUNT(*) FROM documents GROUP BY status').fetchall())
   candidate_status=dict(db.execute("SELECT json_extract(details,'$.candidate_status'),COUNT(*) FROM matches WHERE excluded=0 GROUP BY 1").fetchall())
   check('document_and_candidate_status_counts',document_status==coverage['document_status_counts'] and candidate_status==coverage['candidate_status_counts'])
   check('all_match_references_exist',db.execute('SELECT COUNT(*) FROM matches m LEFT JOIN documents d ON d.id=m.document_id WHERE d.id IS NULL').fetchone()[0]==0)
   check('all_gap_references_consistent',db.execute('SELECT COUNT(*) FROM gaps g LEFT JOIN documents d ON d.id=g.document_id WHERE (g.document_id IS NULL AND g.document_index IS NOT NULL) OR (g.document_id IS NOT NULL AND (d.id IS NULL OR d.table_path!=g.table_path OR d.source_row!=g.source_row OR d.column_name!=g.column_name OR d.document_index!=g.document_index))').fetchone()[0]==0)
   # Stream DB rows in the exact producer order. No full export is loaded.
   def expected(stem):
    if stem=='structured_type_summary':yield from summary;return
    if stem=='structured_documents':query='SELECT * FROM documents ORDER BY id'
    elif stem=='structured_data_gaps':query='SELECT * FROM gaps ORDER BY id'
    elif stem=='structured_unknown_type_review_queue':query='SELECT *,end_row-start_row+1 row_count FROM review_ranges ORDER BY table_path,column_name,start_row'
    else:query='SELECT m.id,m.document_id,m.details,d.table_path,d.source_row,d.column_name,d.source_start,d.source_end,d.format FROM matches m JOIN documents d ON d.id=m.document_id WHERE m.excluded='+('1' if stem=='structured_excluded' else '0')+' ORDER BY m.id'
    for item in db.execute(query):
     row=dict(item)
     if 'details' in row:row.update(json.loads(row.pop('details')))
     if stem=='structured_data_gaps':row['node_path']=json.loads(row['node_path'])
     yield {**row,**SCOPE}
   locations={'id','table_path','source_row','column_name'}
   allowed={
    'structured_documents':locations|parser.DOCUMENT_FIELDS,
    'structured_type_occurrences':{'id','document_id','table_path','source_row','column_name','source_start','source_end','format'}|parser.MATCH_FIELDS,
    'structured_data_gaps':locations|{'document_id'}|parser.GAP_FIELDS,
    'structured_unknown_type_review_queue':{'id','table_path','column_name','start_row','end_row','row_count','status'},
    'structured_type_summary':{'category','subtype','label','candidate_occurrences'}}
   allowed['structured_excluded']=allowed['structured_type_occurrences']
   ranges_total=0;range_status=Counter();range_tables=Counter();last_end={};ranges_ok=True
   def valid(stem,row):
    if set(row)!=allowed[stem]|set(SCOPE) or any(row[k]!=v for k,v in SCOPE.items()):return False
    if stem=='structured_type_summary':return (row['category'],row['subtype']) in set(catalog)|{(None,None)} and integer(row['candidate_occurrences'])
    if not isinstance(row['id'],str) or not HEX.fullmatch(row['id']):return False
    table,column=row['table_path'],row['column_name']
    if table not in selected or column not in selected[table]:return False
    if 'source_row' in row and not (integer(row['source_row'],1) and row['source_row']<=progress[table]['next_row']):return False
    if stem=='structured_documents':return row['format'] in {'whole_json','fenced_json'} and row['status'] in parser.DOCUMENT_STATUSES and integer(row['document_index']) and row['document_index']<limits['max_documents'] and integer(row['source_start']) and integer(row['source_end']) and row['source_start']<=row['source_end']<=limits['max_source_chars']
    if stem in ('structured_type_occurrences','structured_excluded'):
     if not HEX.fullmatch(row['document_id']) or not node_path(row['node_path']) or (row['category'],row['subtype']) not in set(catalog)|{(None,None)} or any(row[k] not in values for k,values in parser.MATCH_LABELS.items()):return False
     a,b=row['decoded_start'],row['decoded_end'];good=(a is None and b is None) or (integer(a) and integer(b) and a<=b<=limits['max_source_chars'])
     return good and (row['candidate_status']=='placeholder_or_example')==(stem=='structured_excluded') and row['format'] in {'whole_json','fenced_json'} and integer(row['document_index']) and row['document_index']<limits['max_documents'] and integer(row['source_start']) and integer(row['source_end']) and row['source_start']<=row['source_end']<=limits['max_source_chars']
    if stem=='structured_data_gaps':return node_path(row['node_path']) and row['reason'] in parser.GAP_REASONS and (row['document_index'] is None or integer(row['document_index']))
    return row['status'] in parser.STATUSES and integer(row['start_row'],1) and integer(row['end_row'],1) and row['start_row']<=row['end_row']<=progress[table]['next_row'] and row['row_count']==row['end_row']-row['start_row']+1
   for stem in STEMS:
    n=0;csv_ok=db_ok=fields_ok=True
    with gzip.open(run/(stem+'.jsonl.gz'),'rt',encoding='utf-8') as js,gzip.open(run/(stem+'.csv.gz'),'rt',encoding='utf-8',newline='') as cs:
     csvrows=csv.DictReader(cs);check(stem+'_csv_header',set(csvrows.fieldnames or [])==allowed[stem]|set(SCOPE))
     for line,crow,erow in zip_longest(js,csvrows,expected(stem)):
      n+=1
      if line is None or crow is None or erow is None:csv_ok=db_ok=False;continue
      row=json.loads(line);csv_ok &= {k:cv(v) for k,v in row.items()}==crow;db_ok &= row==erow
      try:fields_ok &= valid(stem,row)
      except (KeyError,TypeError,ValueError):fields_ok=False
      if stem=='structured_unknown_type_review_queue':
       key=row['table_path'],row['column_name'];ranges_ok &= row['start_row']>last_end.get(key,0);last_end[key]=row['end_row']
       ranges_total+=row['row_count'];range_tables[row['table_path']]+=row['row_count'];range_status[(row['table_path'],row['status'])]+=row['row_count']
    check(stem+'_csv_jsonl_exact_fields',csv_ok);check(stem+'_database_exact_records',db_ok);check(stem+'_finite_fields_and_coordinates',fields_ok)
    pairs.append({'stem':stem,'rows':n,'csv_jsonl_equal':csv_ok,'database_equal':db_ok,'allowed_fields_and_coordinates':fields_ok})
    print(json.dumps({'verified_export_group':stem,'rows':n}),flush=True)
   check('review_ranges_nonoverlapping',ranges_ok)
   check('review_ranges_exact_processed_nonempty_total',ranges_total==dbcounts['unknown_review_source_cells']==stats.get('nonempty_cells',0) and all(range_tables[t]==p['stats'].get('nonempty_cells',0) for t,p in progress.items()))
   check('review_range_status_totals_match_parser',all(range_status[(t,status)]==p['stats'].get('cells_'+status,0) for t,p in progress.items() for status in parser.STATUSES))
   old_progress={r['table_path']:r for r in smoke['progress']};preserved={};prefix_ok=True
   for table in ('documents','matches','gaps'):
    ok=True
    for old in smoke[table]:
     new=db.execute('SELECT * FROM '+table+' WHERE id=?',(old['id'],)).fetchone();ok &= new is not None and dict(new)==old
    preserved[table]={'old_records':len(smoke[table]),'all_exactly_preserved':bool(ok)};check('smoke_'+table+'_exact_preservation',ok)
    for t,p in old_progress.items():
     if table=='matches':count=db.execute('SELECT COUNT(*) FROM matches m JOIN documents d ON d.id=m.document_id WHERE d.table_path=? AND d.source_row<=?',(t,p['next_row'])).fetchone()[0];old_docids={r['id'] for r in smoke['documents'] if r['table_path']==t};oldcount=sum(r['document_id'] in old_docids for r in smoke['matches'])
     else:count=db.execute('SELECT COUNT(*) FROM '+table+' WHERE table_path=? AND source_row<=?',(t,p['next_row'])).fetchone()[0];oldcount=sum(r['table_path']==t for r in smoke[table])
     prefix_ok &= count==oldcount
   check('no_new_records_inserted_into_old_processed_prefix',prefix_ok)
   extended=0;range_preserved=True
   for old in smoke['review_ranges']:
    new=db.execute('SELECT * FROM review_ranges WHERE id=?',(old['id'],)).fetchone();new=dict(new) if new else None
    range_preserved &= preserved_range(old,new,old_progress[old['table_path']]['next_row']);extended+=int(new is not None and new['end_row']>old['end_row'])
   check('smoke_review_ranges_preserved_or_tail_extended',range_preserved)
   check('smoke_review_prefix_has_no_insertions',all(db.execute('SELECT COUNT(*) FROM review_ranges WHERE table_path=? AND start_row<=?',(t,p['next_row'])).fetchone()[0]==sum(r['table_path']==t for r in smoke['review_ranges']) for t,p in old_progress.items()))
   check('smoke_progress_and_counters_monotonic',all(progress[t]['next_row']>=p['next_row'] and all(progress[t]['stats'].get(k,0)>=v for k,v in json.loads(p['stats']).items()) for t,p in old_progress.items()))
   check('database_stat_unchanged',stat(dbpath)==db_before)
   check('all_checked_snapshot_files_unchanged',all(digest(path)==record['sha256'] and stat(path)==record['stat'] for path,record in evidence.items()))
   result={'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-clock,'run_dir':str(run),'checks':checks,'passed':sum(checks.values()),'total':len(checks),'all_checks_passed':all(checks.values()),'all_source_rows_visited':complete,'source_rows':coverage['source_rows'],'processed_rows':coverage['processed_rows'],'expected_full_nonempty_cells':17362345,'processed_nonempty_cells':stats.get('nonempty_cells',0),'database_counts':dbcounts,'export_pairs':pairs,'type_summary_rows':len(summary),'observed_controlled_labels':coverage['observed_controlled_labels'],'unknown_type_summary_count':category_counts.get((None,None),0),'document_status_counts':document_status,'candidate_status_counts':candidate_status,'smoke_preservation':preserved,'smoke_review_ranges':len(smoke['review_ranges']),'smoke_review_tail_extensions':extended,'evidence_sha256':{p:r['sha256'] for p,r in evidence.items()},'helper_sha256':digest(Path(__file__)),'source_bodies_read':False,'raw_source_bytes_rehashed':False,'swe_sources_read':False,'database_modified':False,'count_totals_added_to_plaintext':False,'human_review_status':'pending','runtime_confirmed':False,'new_sensitive_type_confirmed':False,'limitations':['Checks prove snapshot, export/DB arithmetic, references and finite-coordinate consistency; original source text was not reread to validate exact document/leaf text positions.','All-source-row completion means selected text cells were visited, not that every value/type/encoding was classified.','Raw source-file hashes are linked through producer/import manifests; this verifier only rehashes metadata, gzip exports and implementation files.','Structured occurrences overlap old plaintext observations and cannot be reported as their incremental total.']}
  finally:db.close()
 if report_path.exists():raise FileExistsError('Preserve the existing verification report')
 report_path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'report':str(report_path),'passed':result['passed'],'total':result['total'],'all_source_rows_visited':complete,'processed_rows':coverage['processed_rows'],'processed_nonempty_cells':stats.get('nonempty_cells',0)}))
 return 0 if result['all_checks_passed'] else 1


def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--run-dir',type=Path,default=BASE/'structured-runs/aidev-v048');ap.add_argument('--report',type=Path,default=BASE/'docs/aidev_structured_v048_verification.json');ap.add_argument('--self-test',action='store_true');args=ap.parse_args()
 if args.self_test:self_test();return
 raise SystemExit(verify(args.run_dir.resolve(),args.report.resolve()))
if __name__=='__main__':main()
