#!/usr/bin/env python3
"""Read-only structured snapshot verification; run only after its writer stops.

Never read source text. Shared locking rejects an active writer. Six gzip pairs
are streamed against CSV and SQLite. Old v049 results are compared, not inherited smoke evidence.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import zip_longest
from pathlib import Path
import argparse, csv, fcntl, gzip, hashlib, json, re, sqlite3, time
from agentlog_unified import structured_types as parser
from agentlog_unified.taxonomy import TAXONOMY_VERSION, taxonomy_catalog

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
def comparison_key(row):
 return (row['table_path'],row['source_row'],row['column_name'],row['source_start'],row['source_end'],row['format'],row['document_index'],tuple(row['node_path']),row['node_kind'],row['decoded_start'],row['decoded_end'],row['category'],row['subtype'],row['rule'])

def position_key(row):
 return (row['table_path'],row['source_row'],row['column_name'],row['document_index'],tuple(row['node_path']),row['category'],row['subtype'])

def context_review_rows(after,probe_rows,replay_rows):
 # Only the finite public metadata already verified above is inspected here.
 positions=defaultdict(list);context_counts=Counter()
 quality=('category','subtype','candidate_status','value_status','confidence','node_kind','basis')
 for value in after.values():
  row=json.loads(value[5]);positions[position_key(row)].append(row)
  if row['basis']=='json_parent_key_hint':
   context_counts[tuple(row[k] for k in quality)+(value[3],)]+=1
 replay={position_key(r):r for r in replay_rows}
 if len(replay)!=len(replay_rows) or len({position_key(r) for r in probe_rows})!=len(probe_rows):raise ValueError('Frozen context position identities are ambiguous')
 groups=defaultdict(list)
 for old in probe_rows:
  key=position_key(old);prior=replay[key]
  if old['disposition']!=prior['prior_disposition']:raise ValueError('Frozen context disposition changed between probe and replay')
  group='supported_pair_pending' if old['disposition']=='supported_pair_pending' else ('replay_accepted_unresolved_pending' if prior['accepted'] else 'replay_rejected_unresolved_pending')
  current=positions.get(key,[])
  fields=tuple(sorted(parser.MATCH_FIELDS))
  current_details=sorted(json.dumps({k:r[k] for k in fields},sort_keys=True) for r in current)
  prior_details=sorted(json.dumps({k:r[k] for k in fields},sort_keys=True) for r in prior['new_matches'])
  groups[group].append({'table_path':key[0],'source_row':key[1],'column_name':key[2],'document_index':key[3],'node_path':list(key[4]),'category':key[5],'subtype':key[6],'current_matches':len(current),'matches_equal_fixed_replay':current_details==prior_details,'current_quality':[{k:r[k] for k in ('basis','candidate_status','value_status','confidence','node_kind')} for r in current],'human_review_status':'pending'})
 return {'all_context_basis_quality_counts':[{**dict(zip(quality,key[:-1])),'excluded':key[-1],'count':n} for key,n in sorted(context_counts.items(),key=lambda x:json.dumps(x[0]))],
         'fixed_position_groups':{group:{'positions':len(rows),'positions_currently_present':sum(r['current_matches']>0 for r in rows),'positions_equal_fixed_replay':sum(r['matches_equal_fixed_replay'] for r in rows),'rows':rows} for group,rows in sorted(groups.items())},
         'unknown_observations_all_bases':sum(json.loads(v[5])['category'] is None for v in after.values()),
         'unresolved_positions_promoted_to_supported':False,'human_review_status':'pending','runtime_confirmed':False,
         'limitation':'Fixed positions are a bounded regression cohort. Accepted unresolved compositions remain a separate pending group; all context hints and unclassified nodes still need review.'}

def compare_context_positions(after,coverage,read,check,current_manifest):
 docs=BASE/'docs';probe=read(docs/'aidev_structured_parent_context_v050_probe.json');replay=read(docs/'aidev_structured_parent_context_v050_replay.json')
 check('fixed_context_probe_report_hash',digest(docs/'aidev_structured_parent_context_v050_probe.json')==replay['prior_probe_sha256'])
 source_run=Path(probe['source_run']).resolve()
 if source_run!=(BASE/'structured-runs/aidev-v049').resolve():raise ValueError('Frozen probe does not reference the expected prior structured run')
 source_manifest_path=source_run/'manifest.json';source_manifest=read(source_manifest_path)
 check('fixed_context_prior_structured_manifest_hash',digest(source_manifest_path)==probe['source_manifest_sha256'])
 check('fixed_context_same_frozen_import',source_manifest['source_manifest_sha256']==source_manifest['fingerprint']['source_manifest_sha256']==coverage['source_manifest_sha256'])
 check('fixed_context_same_parquet_metadata',source_manifest['fingerprint']['inputs']==current_manifest['fingerprint']['inputs'] and source_manifest['tables']==current_manifest['tables'])
 loaded=[];artifacts={}
 for name,sha in (('aidev_structured_parent_context_v050_evidence.jsonl',probe['evidence_sha256']),('aidev_structured_parent_context_v050_replay_evidence.jsonl',replay['new_evidence_sha256'])):
  path=docs/name
  if path.stat().st_size>1048576:raise ValueError('Frozen context metadata exceeds its bounded input size')
  raw=path.read_bytes();actual=hashlib.sha256(raw).hexdigest()
  check('fixed_context_hash_'+name,actual==sha)
  rows=[json.loads(line) for line in raw.splitlines()]
  if len(rows)>100:raise ValueError('Frozen context metadata exceeds its bounded row budget')
  loaded.append(rows);artifacts[str(path)]=actual
 check('fixed_context_prior_evidence_chain',replay['prior_evidence_sha256']==probe['evidence_sha256'])
 result=context_review_rows(after,*loaded);groups=result['fixed_position_groups']
 check('fixed_context_cohort_16_supported_5_pending_25_rejected',len(loaded[0])==len(loaded[1])==46 and {k:g['positions'] for k,g in groups.items()}=={'supported_pair_pending':16,'replay_accepted_unresolved_pending':5,'replay_rejected_unresolved_pending':25})
 if coverage['all_source_rows_visited']:
  check('fixed_supported_context_positions_preserved',groups['supported_pair_pending']['positions_currently_present']==16 and groups['supported_pair_pending']['positions_equal_fixed_replay']==16)
 check('fixed_context_evidence_files_unchanged',all(digest(path)==sha for path,sha in artifacts.items()))
 result['evidence_sha256']=artifacts
 return result

def compare_previous(run,coverage,read,check):
 old=BASE/'structured-runs/aidev-v049'
 with (old/'.structured.lock').open('rb') as lock:
  fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
  old_manifest=read(old/'manifest.json');old_coverage=read(old/'structured_coverage.json');old_state=read(old/'export_state.json')
  check('comparison_same_frozen_source',old_manifest['source_manifest_sha256']==coverage['source_manifest_sha256'])
  check('comparison_old_snapshot_complete',old_state['status']=='complete' and old_state['fingerprint']==old_manifest['fingerprint'])
  snapshots=[]
  for folder,state in ((old,old_state),(run,read(run/'export_state.json'))):
   records={}
   for stem in ('structured_type_occurrences','structured_excluded'):
    path=folder/(stem+'.jsonl.gz')
    check('comparison_hash_'+folder.name+'_'+stem,digest(path)==state['outputs'][path.name]['sha256'])
    with gzip.open(path,'rt',encoding='utf-8') as stream:
     for line in stream:
      row=json.loads(line);key=comparison_key(row)
      if key in records:raise ValueError('Comparison coordinate identity is ambiguous')
      records[key]=(row['candidate_status'],row['value_status'],row['basis'],stem=='structured_excluded',row['confidence'],json.dumps(row,sort_keys=True,separators=(',',':')))
      if len(records)>200000:raise ValueError('Structured comparison exceeds the 200000-record metadata memory budget')
   snapshots.append(records)
  before,after=snapshots;common=before.keys()&after.keys();transitions=Counter((before[k][0],after[k][0],before[k][1],after[k][1],before[k][2],after[k][2]) for k in common if before[k][:5]!=after[k][:5])
  old_ids={json.loads(v[5])['id'] for v in before.values()};new_ids={json.loads(v[5])['id'] for v in after.values()}
  context_review=compare_context_positions(after,coverage,read,check,read(run/'manifest.json'))
  type_counts=[]
  for folder,state in ((old,old_state),(run,read(run/'export_state.json'))):
   path=folder/'structured_type_summary.jsonl.gz'
   check('comparison_summary_hash_'+folder.name,digest(path)==state['outputs'][path.name]['sha256'])
   with gzip.open(path,'rt',encoding='utf-8') as stream:type_counts.append({(r['category'],r['subtype']):r['candidate_occurrences'] for r in map(json.loads,stream)})
  old_counts,new_counts=type_counts
  delta=[{'category':k[0],'subtype':k[1],'v049_count':old_counts.get(k),'v050_count':new_counts.get(k),'count_delta':new_counts[k]-old_counts[k] if k in old_counts else None,'newly_evaluated_type':k not in old_counts} for k in sorted(new_counts,key=lambda k:((k[0] or ''),(k[1] or '')))]
  return {'v049_taxonomy_version':old_manifest['fingerprint']['taxonomy_version'],'v050_taxonomy_version':coverage['taxonomy_version'],'both_all_rows_visited':old_coverage['all_source_rows_visited'] and coverage['all_source_rows_visited'],'common_coordinate_type_rule_records':len(common),'added_coordinate_type_rule_records':len(after.keys()-before.keys()),'removed_coordinate_type_rule_records':len(before.keys()-after.keys()),'unchanged_full_export_rows':sum(before[k]==after[k] for k in common),'unchanged_quality_details':sum(before[k][:5]==after[k][:5] for k in common),'status_transitions':[{'old_status':k[0],'new_status':k[1],'old_value_status':k[2],'new_value_status':k[3],'old_basis':k[4],'new_basis':k[5],'count':v} for k,v in sorted(transitions.items())],'per_type_counts':delta,'versioned_record_ids':{'common':len(old_ids&new_ids),'added':len(new_ids-old_ids),'removed':len(old_ids-new_ids)},'context_basis_review':context_review,'comparison_metadata_record_limit_per_version':200000,'comparison_identity_excludes':['versioned_record_id','candidate_status','value_status','basis','confidence'],'full_metadata_row_comparison_includes_id_and_scope':True,'incremental_true_sensitive_values_claim':False,'note':'Differences are classifier observations on matched metadata coordinates; newly evaluated labels have no prior count, and neither differences nor statuses establish real values.'}

def self_test():
 row={'table_path':'t','source_row':1,'column_name':'body','source_start':0,'source_end':9,'format':'whole_json','document_index':0,'node_path':[0],'node_kind':'string','decoded_start':0,'decoded_end':2,'category':'PII','subtype':'email','rule':'json_key_taxonomy'}
 assert comparison_key(row)==comparison_key({**row,'candidate_status':'identifier_reference','id':'different'})
 assert comparison_key(row)!=comparison_key({**row,'decoded_start':1})
 assert comparison_key(row)!=comparison_key({**row,'node_path':[1]})
 assert cv([0,-1,2])=='[0,-1,2]' and cv(None)=='' and cv(False)=='False'
 assert node_path([0,-1,2]) and not node_path([True]) and not node_path([-2])
 probe=[];replay=[];after={}
 for index,(disposition,accepted) in enumerate((('supported_pair_pending',True),('unresolved_composition_pending',True),('unresolved_composition_pending',False))):
  meta={**row,'node_path':[index],'candidate_status':'named_value_candidate','value_status':'unverified','basis':'json_parent_key_hint','confidence':'low'}
  probe.append({**meta,'disposition':disposition});replay.append({**meta,'prior_disposition':disposition,'accepted':accepted,'new_matches':[{k:meta[k] for k in parser.MATCH_FIELDS}] if accepted else []})
  if accepted:after[comparison_key(meta)]=(meta['candidate_status'],meta['value_status'],meta['basis'],False,meta['confidence'],json.dumps(meta))
 review=context_review_rows(after,probe,replay);groups=review['fixed_position_groups']
 assert groups['supported_pair_pending']['positions_equal_fixed_replay']==1
 assert groups['replay_accepted_unresolved_pending']['positions_currently_present']==1
 assert groups['replay_rejected_unresolved_pending']['positions_currently_present']==0
 assert review['unresolved_positions_promoted_to_supported'] is False
 assert review['all_context_basis_quality_counts'][0]['count']==2
 changed=dict(after);first=next(iter(changed));v=changed[first];m=json.loads(v[5]);m['value_status']='opaque';changed[first]=(*v[:5],json.dumps(m))
 assert context_review_rows(changed,probe,replay)['fixed_position_groups']['supported_pair_pending']['positions_equal_fixed_replay']==0
 print(json.dumps({'self_test':'passed','checks':11,'real_snapshot_read':False,'historical_smoke_inherited':False}))


def verify(run,report_path):
 started=datetime.now(timezone.utc).isoformat();clock=time.monotonic();checks={};evidence={};pairs=[]
 def check(name,value):checks[name]=bool(value)
 def read(path):
  raw=path.read_bytes();evidence[str(path)]={'sha256':hashlib.sha256(raw).hexdigest(),'stat':stat(path)};return json.loads(raw)
 old_coverage_path=BASE/'content-runs/aidev-v044/content_coverage.json'
 old_coverage=read(old_coverage_path)
 with (run/'.structured.lock').open('rb') as lock:
  fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
  manifest=read(run/'manifest.json');coverage=read(run/'structured_coverage.json');state=read(run/'export_state.json')
  fingerprint=manifest['fingerprint'];limits=fingerprint['limits'];source_manifest=Path(fingerprint['source_import'])/'manifest.json'
  imported=read(source_manifest)
  check('export_state_complete',state['status']=='complete')
  check('snapshot_fingerprint_consistent',state['fingerprint']==fingerprint and coverage['limits']==limits)
  check('source_manifest_consistent',digest(source_manifest)==manifest['source_manifest_sha256']==coverage['source_manifest_sha256']==old_coverage['source_manifest_sha256']==fingerprint['source_manifest_sha256'])
  check('source_file_signature_consistent',fingerprint['inputs']==imported['source_signature']['inputs'])
  check('taxonomy_version_matches_current',fingerprint['taxonomy_version']==coverage['taxonomy_version']==TAXONOMY_VERSION)
  check('finite_parent_context_basis_supported','json_parent_key_hint' in parser.MATCH_LABELS['basis'])
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
   check('summary50_including_unknown_and_zero_labels',len(summary)==50 and len(catalog)==49 and sum(r['candidate_occurrences'] for r in summary)==dbcounts['candidate_occurrences'])
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
   comparison=compare_previous(run,coverage,read,check)
   check('database_stat_unchanged',stat(dbpath)==db_before)
   check('all_checked_snapshot_files_unchanged',all(digest(path)==record['sha256'] and stat(path)==record['stat'] for path,record in evidence.items()))
   result={'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-clock,'run_dir':str(run),'checks':checks,'passed':sum(checks.values()),'total':len(checks),'all_checks_passed':all(checks.values()),'all_source_rows_visited':complete,'source_rows':coverage['source_rows'],'processed_rows':coverage['processed_rows'],'expected_full_nonempty_cells':17362345,'processed_nonempty_cells':stats.get('nonempty_cells',0),'database_counts':dbcounts,'export_pairs':pairs,'type_summary_rows':len(summary),'observed_controlled_labels':coverage['observed_controlled_labels'],'unknown_type_summary_count':category_counts.get((None,None),0),'document_status_counts':document_status,'candidate_status_counts':candidate_status,'previous_v049_comparison':comparison,'historical_smoke_preservation_claim':False,'evidence_sha256':{p:r['sha256'] for p,r in evidence.items()},'helper_sha256':digest(Path(__file__)),'source_bodies_read':False,'raw_source_bytes_rehashed':False,'swe_sources_read':False,'database_modified':False,'count_totals_added_to_plaintext':False,'human_review_status':'pending','runtime_confirmed':False,'new_sensitive_type_confirmed':False,'limitations':['Checks prove snapshot, export/DB arithmetic, references and finite-coordinate consistency; original source text was not reread to validate exact document/leaf text positions.','All-source-row completion means selected text cells were visited, not that every value/type/encoding was classified.','Raw source-file hashes are linked through producer/import manifests; this verifier only rehashes metadata, gzip exports and implementation files.','Structured occurrences overlap old plaintext observations and cannot be reported as their incremental total.']}
  finally:db.close()
 if report_path.exists():raise FileExistsError('Preserve the existing verification report')
 report_path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'report':str(report_path),'passed':result['passed'],'total':result['total'],'all_source_rows_visited':complete,'processed_rows':coverage['processed_rows'],'processed_nonempty_cells':stats.get('nonempty_cells',0)}))
 return 0 if result['all_checks_passed'] else 1


def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--run-dir',type=Path,default=BASE/'structured-runs/aidev-v050');ap.add_argument('--report',type=Path,default=BASE/'docs/aidev_structured_v050_verification.json');ap.add_argument('--self-test',action='store_true');ap.add_argument('--runs-confirmed-terminal',action='store_true');args=ap.parse_args()
 if args.self_test:self_test();return
 if not args.runs_confirmed_terminal:ap.error('--runs-confirmed-terminal is required before reading real snapshots')
 raise SystemExit(verify(args.run_dir.resolve(),args.report.resolve()))
if __name__=='__main__':main()
