"""Read-only AIDev v0.4.7 export verification; never decode source values."""
from collections import Counter
from datetime import datetime, timezone
from itertools import zip_longest
from pathlib import Path
import csv, fcntl, hashlib, json, sqlite3, sys, time
import pyarrow as pa
import pyarrow.parquet as pq
from agentlog_unified.storage import csv_cell,stable_id
from agentlog_unified.taxonomy import taxonomy_catalog,TAXONOMY_VERSION

ROOT=Path(__file__).resolve().parents[1]
VERSION='schema-context-1'
SCOPE={'observation_scope':'dataset_schema_context','evidence_basis':'schema_context','human_review_status':'pending','confidence':'low','runtime_confirmed':False,'personal_ownership_confirmed':False,'sensitivity_confirmed':False,'application_log_evidence':False,'new_type_status':'not_established'}
ROLE={}
for t in ('all_pull_request','human_pull_request','pr_comments','pull_request'): ROLE['aidev',t,'user_id']=('numeric_account_id','QID','user_identifier')
for t in ('user','all_user'):
 ROLE['aidev',t,'id']=('numeric_account_id','QID','user_identifier');ROLE['aidev',t,'login']=('account_login','QID','user_identifier')
ROLE['swe-chat','commits','author_name']=('author_name','PII','person_name')
ROLE['swe-chat','commits','author_email']=('author_email','PII','email')
ROLE['swe-chat','commits','github_username']=('account_login','QID','user_identifier')
for t in ('checkpoints','commits','conversations','sessions'):ROLE['swe-chat',t,'user_id']=('account_reference','QID','user_identifier')
for t in ('sessions','session_logs','conversations'):ROLE['swe-chat',t,'session_id']=('session_reference','QID','session_identifier')
LEGACY_ROLE=dict(ROLE)
for t in ('all_pull_request','human_pull_request','issue','pr_comments','pr_review_comments','pr_review_comments_v2','pr_reviews','pull_request'):
 ROLE['aidev',t,'user']=('account_reference','QID','user_identifier')
ROLE['aidev','pr_timeline','actor']=('account_reference','QID','user_identifier')
LEGACY_ROLE=dict(ROLE)
JOIN_FIELDS={('aidev',t,c) for t in ('pr_commits','pr_commit_details') for c in ('author','committer')} | {('aidev','pr_timeline','assignee')}
for key in JOIN_FIELDS: ROLE[key]=('account_login_join','QID','user_identifier')
TYPES={(c['category'],s['subtype']) for c in taxonomy_catalog()['categories'] for s in c['subtypes']}
QUALITY={'null','empty','invalid','placeholder_or_example','schema_context_candidate','unresolved'}
REASONS={'null':{'arrow_null'},'empty':{'empty_or_whitespace_text'},'invalid':{'expected_numeric_account_id','nonfinite_numeric_id','nonintegral_numeric_id','floating_id_precision_unverifiable','nonpositive_numeric_id','expected_text_schema_field','control_characters_in_metadata','structured_metadata_requires_interpretation','email_field_shape_unresolved'},'placeholder_or_example':{'example_shaped_metadata_not_validated'},'schema_context_candidate':{'explicit_numeric_account_field','explicit_account_login_field','explicit_account_reference_field','explicit_author_name_field','explicit_author_email_field','explicit_session_reference_field'}}

REASONS['unresolved']={'account_login_not_found_in_frozen_references','account_reference_contains_no_values','account_reference_sources_unavailable_or_incomplete'}
REASONS['schema_context_candidate'].add('exact_frozen_account_login_match')

def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as stream:
  for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
 return h.hexdigest()
def read(path):return json.loads(path.read_text())
def stat(path):
 s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def verify(output):
 started=time.monotonic();fail=Counter()
 def check(name,condition):
  if not condition:fail[name]+=1
 lock=(output/'.schema.lock').open('rb');fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
 before={p.name:stat(p) for p in output.iterdir() if p.is_file()}
 check('no_active_temporary_exports',not any(n.endswith('.tmp') for n in before))
 manifest=read(output/'manifest.json');coverage=read(output/'schema_coverage.json');fp=manifest['fingerprint'];dataset=manifest['dataset']
 imported=Path(fp['source_import']);im=read(imported/'manifest.json');source_root=Path(im['source_signature']['source_dir'])
 check('frozen_import_complete',im['status']=='complete')
 check('source_manifest_fingerprint',sha(imported/'manifest.json')==manifest['source_manifest_sha256']==fp['source_manifest_sha256'])
 check('frozen_input_manifest_list',fp['inputs']==im['source_signature']['inputs'])
 current={name:sha(ROOT/'src/agentlog_unified'/name) for name in fp['source_sha256']}
 check('implementation_frozen',current==fp['source_sha256'])
 check('taxonomy_version',fp['taxonomy_version']==TAXONOMY_VERSION and fp['version']==VERSION and fp['pyarrow_version']==pa.__version__)
 expected={};table_groups={};source_files=[]
 for item in im['source_signature']['inputs']:
  path=(source_root/item['path']).resolve()
  check('source_path_contained',path.is_relative_to(source_root.resolve()))
  source_ok=path.stat().st_size==item['bytes'] and sha(path)==item['sha256']
  source_files.append({'path':item['path'],'bytes':item['bytes'],'hash_matches':source_ok});check('source_table_frozen',source_ok)
  parquet=pq.ParquetFile(path);table=Path(item['path']).stem
  table_groups[item['path']]=[parquet.metadata.row_group(g).num_rows for g in range(parquet.metadata.num_row_groups)]
  for field in parquet.schema_arrow:
   scalar=not pa.types.is_nested(field.type);role=ROLE.get((dataset,table,field.name)) if scalar else None
   chunks=[parquet.metadata.row_group(g).column(i) for g in range(parquet.metadata.num_row_groups) for i in range(parquet.metadata.row_group(g).num_columns) if parquet.metadata.row_group(g).column(i).path_in_schema==field.name]
   known=len(chunks)==parquet.metadata.num_row_groups and all(c.statistics is not None and c.statistics.has_null_count for c in chunks)
   fid=stable_id(VERSION,manifest['source_manifest_sha256'],item['path'],field.name)
   expected[fid]={'field_id':fid,'dataset':dataset,'table_path':item['path'],'table':table,'column_name':field.name,'native_type':str(field.type),'is_scalar':scalar,'source_rows':parquet.metadata.num_rows,'source_table_sha256':item['sha256'],'source_manifest_sha256':manifest['source_manifest_sha256'],'selected_for_value_scan':role is not None,'schema_role':role[0] if role else None,'category':role[1] if role else None,'subtype':role[2] if role else None,'footer_null_count':sum(c.statistics.null_count for c in chunks) if known else None}
 check('all_manifest_fields_exact_schema_and_role',{f['field_id']:f for f in manifest['fields']}==expected and len(manifest['fields'])==len(expected))
 for f in expected.values():check('only_existing_taxonomy_types',(f['category'],f['subtype']) in TYPES|{(None,None)})
 db=sqlite3.connect((output/'schema.sqlite').as_uri()+'?mode=ro&immutable=1',uri=True);db.row_factory=sqlite3.Row
 check('db_field_columns_are_metadata_only',[r[1] for r in db.execute('PRAGMA table_info(fields)')]==['field_id','next_row','next_row_group','state','stats'])
 check('db_range_columns_are_metadata_only',[r[1] for r in db.execute('PRAGMA table_info(ranges)')]==['id','field_id','start_row','end_row','status','reason'])
 check('sqlite_quick_check',db.execute('PRAGMA quick_check').fetchone()[0]=='ok')
 states={r['field_id']:dict(r) for r in db.execute('SELECT * FROM fields')};check('checkpoint_field_partition',set(states)==set(expected))
 totals=Counter();perfield={fid:Counter() for fid in expected};ends=Counter();range_counts=Counter();types=Counter();reasons=Counter()
 for r in db.execute('SELECT * FROM ranges ORDER BY field_id,start_row'):
  fid=r['field_id'];f=expected.get(fid)
  check('range_field_selected',f is not None and f['selected_for_value_scan'])
  check('range_exact_partition',r['start_row']==ends[fid]+1 and r['start_row']<=r['end_row']<=states[fid]['next_row'])
  check('quality_enum_and_finite_reason',r['status'] in QUALITY and r['reason'] in REASONS.get(r['status'],set()))
  check('range_identity',r['id']==stable_id(VERSION,fid,r['start_row'],r['status'],r['reason']))
  n=r['end_row']-r['start_row']+1;perfield[fid][r['status']]+=n;ends[fid]=r['end_row'];range_counts[r['status']]+=1;reasons[(r['status'],r['reason'])]+=n
  if r['status']=='schema_context_candidate':types[f['category'],f['subtype']]+=n
 coverage_expected={}
 for fid,f in expected.items():
  state=dict(states[fid]);stats=json.loads(state.pop('stats'));totals.update(stats);seen=perfield[fid]
  check('finite_stats_keys',set(stats)<=QUALITY|{'cells_decoded'})
  check('field_progress_bounds',0<=state['next_row']<=f['source_rows'])
  if f['selected_for_value_scan']:
   check('decoded_cells_exact_partition',state['next_row']==ends[fid]==sum(seen.values())==stats.get('cells_decoded',0))
   check('quality_counts_exact',{k:v for k,v in stats.items() if k!='cells_decoded'}==dict(seen))
   check('field_completion_state',(state['state']=='complete')==(state['next_row']==f['source_rows']))
   completed_groups=0;group_end=0
   for n in table_groups[f['table_path']]:
    group_end+=n
    if f['source_rows'] and group_end<=state['next_row']:completed_groups+=1
   check('row_group_checkpoint',state['next_row_group']==completed_groups)
   if state['state']=='complete' and f['footer_null_count'] is not None:check('null_count_agrees_with_footer',stats.get('null',0)==f['footer_null_count'])
   types.setdefault((f['category'],f['subtype']),0)
  else:
   check('unselected_not_decoded_or_classified',state['next_row']==0 and stats=={} and ends[fid]==0 and f['category'] is None and f['subtype'] is None and state['state']=='schema_semantics_unresolved')
  coverage_expected[fid]={**f,**state,'counts':stats,'null_count':stats.get('null',0) if f['selected_for_value_scan'] else None,'empty_count':stats.get('empty',0) if f['selected_for_value_scan'] else None,'invalid_count':stats.get('invalid',0) if f['selected_for_value_scan'] else None,'values_decoded':state['next_row']>0,**SCOPE}
 check('coverage_fields_exact',{f['field_id']:f for f in coverage['fields']}==coverage_expected and len(coverage['fields'])==len(expected))
 check('coverage_counts_exact',dict(totals)==coverage['counts'])
 check('cell_not_row_count_name','rows_decoded' not in coverage['counts'] and 'cells_decoded' in coverage['counts'])
 check('selected_all_scalar_field_counts',coverage['all_fields']==len(expected) and coverage['scalar_fields']==sum(f['is_scalar'] for f in expected.values()) and coverage['selected_fields']==sum(f['selected_for_value_scan'] for f in expected.values()))
 done=all(s['state']=='complete' for fid,s in states.items() if expected[fid]['selected_for_value_scan'])
 check('coverage_completion_semantics',coverage['all_selected_fields_visited']==done and coverage['status']==('complete_with_schema_gaps' if done else 'partial') and coverage['all_dataset_values_classified'] is False)
 for document in (manifest,coverage):check('top_level_scope_pending',all(document.get(k)==v for k,v in SCOPE.items()))
 def range_rows(candidate):
  query='SELECT * FROM ranges'+(" WHERE status='schema_context_candidate'" if candidate else '')+' ORDER BY field_id,start_row'
  for raw in db.execute(query):
   row=dict(raw);f=expected[row['field_id']]
   unclassified=f['schema_role']=='account_login_join' and row['status']!='schema_context_candidate'
   yield {**{k:f[k] for k in ('dataset','table_path','column_name','native_type','schema_role','source_manifest_sha256','source_table_sha256','category','subtype')},**row,'row_count':row['end_row']-row['start_row']+1,**({'category':None,'subtype':None} if unclassified else {}),'candidate_status':'schema_context_candidate' if row['status']=='schema_context_candidate' else None,**SCOPE}
 def unresolved_rows():
  for field in manifest['fields']:
   f=expected[field['field_id']]
   if f['selected_for_value_scan']:continue
   yield {**f,'start_row':1 if f['source_rows'] else None,'end_row':f['source_rows'] or None,'row_count':f['source_rows'],'record_kind':'unread_source_field_range','values_decoded':False,'empty_count':None,'invalid_count':None,'status':'schema_semantics_unresolved' if f['is_scalar'] else 'nested_schema_unresolved',**SCOPE}
 results={}
 def compare(stem,rows):
  n=0;represented=0
  with (output/(stem+'.jsonl')).open() as js,(output/(stem+'.csv')).open(newline='') as cs:
   reader=csv.DictReader(cs)
   expected_columns=(['id','field_id','dataset','table_path','column_name','native_type','schema_role','source_manifest_sha256','source_table_sha256','start_row','end_row','row_count','status','reason','category','subtype','candidate_status',*SCOPE] if stem in {'schema_context_candidates','schema_context_review_queue'} else ['field_id','dataset','table_path','column_name','native_type','is_scalar','start_row','end_row','row_count','footer_null_count','empty_count','invalid_count','status','values_decoded','source_manifest_sha256','source_table_sha256',*SCOPE] if stem=='schema_unresolved_fields' else ['category','subtype','candidate_source_cells','candidate_status',*SCOPE])
   check(stem+'_csv_complete_metadata_columns',reader.fieldnames==expected_columns)
   for expected_row,line,csvrow in zip_longest(rows,js,reader):
    if expected_row is None or line is None or csvrow is None:check(stem+'_record_count',False);break
    row=json.loads(line);check(stem+'_exact_jsonl_evidence_fields',row==expected_row)
    check(stem+'_csv_jsonl_equivalence',csvrow=={k:csv_cell(row.get(k)) for k in reader.fieldnames})
    check(stem+'_csv_field_whitelist',set(reader.fieldnames)<=set(expected_row))
    check(stem+'_scope_pending',all(row.get(k)==v for k,v in SCOPE.items()))
    n+=1;represented+=row.get('row_count',row.get('candidate_source_cells',0))
  results[stem]={'records':n,'represented_source_cells':represented}
 compare('schema_context_candidates',range_rows(True));compare('schema_context_review_queue',range_rows(False));compare('schema_unresolved_fields',unresolved_rows())
 check('candidate_range_count',results['schema_context_candidates']['records']==range_counts.get('schema_context_candidate',0)==coverage['candidate_range_records'])
 check('review_range_count',results['schema_context_review_queue']['records']==sum(range_counts.values())==coverage['review_range_records'])
 check('unresolved_field_record_count',results['schema_unresolved_fields']['records']==sum(not f['selected_for_value_scan'] for f in expected.values())==coverage['unresolved_field_records'])
 check('decoded_cells_review_coverage',results['schema_context_review_queue']['represented_source_cells']==totals.get('cells_decoded',0))
 check('candidates_only_schema_cells',results['schema_context_candidates']['represented_source_cells']==totals.get('schema_context_candidate',0))
 summary=[{'category':c,'subtype':s,'candidate_source_cells':n,'candidate_status':'schema_context_candidate',**SCOPE} for (c,s),n in sorted(types.items())]
 summary_doc=read(output/'schema_type_summary.json')
 check('summary_json_complete',summary_doc=={'taxonomy_version':TAXONOMY_VERSION,'summary':summary,**SCOPE})
 compare('schema_type_summary',iter(summary))
 check('summary_cells_exact',sum(r['candidate_source_cells'] for r in summary)==totals.get('schema_context_candidate',0))
 check('source_code_stable_during_verification',current=={name:sha(ROOT/'src/agentlog_unified'/name) for name in current})
 check('output_files_stable_during_verification',before=={p.name:stat(p) for p in output.iterdir() if p.is_file()})
 db.close();lock.close()
 return {'output':str(output),'dataset':dataset,'status':coverage['status'],'all_checks_passed':not fail,'failed_check_counts':dict(fail),'elapsed_seconds':round(time.monotonic()-started,3),'source_manifest_sha256':manifest['source_manifest_sha256'],'source_code_sha256':current,'frozen_source_inputs':source_files,'all_fields':len(expected),'scalar_fields':coverage['scalar_fields'],'selected_fields':coverage['selected_fields'],'counts':dict(totals),'range_counts_by_quality':dict(range_counts),'quality_reason_source_cells':[{'status':s,'reason':r,'source_cells':n} for (s,r),n in sorted(reasons.items())],'type_summary':summary,'exports':results,'selected_field_coverage':[{k:f[k] for k in ('field_id','dataset','table_path','column_name','native_type','schema_role','category','subtype','source_rows','next_row','next_row_group','counts','state')} for f in coverage_expected.values() if f['selected_for_value_scan']],
  'verified':['Every manifest field equals frozen native schema, finite role registry and existing taxonomy; all scalar columns included.','Selected field ranges exactly partition one-based rows 1..next_row with no overlap/gap; status/quality counts and row-group checkpoints recomputed.','JSONL matches DB/manifest evidence, CSV matches JSONL, coverage/summary source-cell counts match independently recomputed ranges.','Null counts equal source footer for fully scanned fields; unselected fields stay unresolved with no decoded/empty/invalid claims.','Current source hashes and implementation fingerprints match frozen manifests; shared lock and file-stat stability protect terminal snapshot.','Only finite quality/type labels and source references are exported; pending status and non-confirmation flags remain explicit.'],
  'limitations':['The unit cells_decoded is a source table/column/row observation, not unique rows, people, identities, or confirmed sensitive records.','This verification does not decode or reclassify source values; quality-label counts are checked, not the truth of a real identity or sensitivity.','Schema-context and text/log observations remain separate evidence scopes and must not be blindly summed.']}


def records(folder, stem, suffix='jsonl'):
 with (folder/(stem+'.'+suffix)).open(newline='') as stream:
  return list(csv.DictReader(stream)) if suffix=='csv' else [json.loads(line) for line in stream if line.strip()]


def compare_legacy(old, new):
 old_cov,new_cov=read(old/'schema_coverage.json'),read(new/'schema_coverage.json')
 old_fields={f['field_id']:f for f in old_cov['fields']};new_fields={f['field_id']:f for f in new_cov['fields']}
 old_selected={fid:f for fid,f in old_fields.items() if f['selected_for_value_scan']}
 added={fid:f for fid,f in new_fields.items() if f['selected_for_value_scan'] and fid not in old_selected}
 assert len(old_selected)==17 and set(old_fields)==set(new_fields)
 assert {(f['dataset'],f['table'],f['column_name']) for f in old_selected.values()}=={k for k in LEGACY_ROLE if k[0]=='aidev'}
 assert {(f['dataset'],f['table'],f['column_name']) for f in added.values()}==JOIN_FIELDS
 comparisons=[]
 with sqlite3.connect((old/'schema.sqlite').as_uri()+'?mode=ro&immutable=1',uri=True) as a,sqlite3.connect((new/'schema.sqlite').as_uri()+'?mode=ro&immutable=1',uri=True) as b:
  for fid,f in old_selected.items():
   old_ranges=a.execute('SELECT * FROM ranges WHERE field_id=? ORDER BY start_row',(fid,)).fetchall()
   new_ranges=b.execute('SELECT * FROM ranges WHERE field_id=? ORDER BY start_row',(fid,)).fetchall()
   assert old_ranges==new_ranges and f==new_fields[fid]
   assert a.execute('SELECT * FROM fields WHERE field_id=?',(fid,)).fetchone()==b.execute('SELECT * FROM fields WHERE field_id=?',(fid,)).fetchone()
   comparisons.append({'field_id':fid,'table_path':f['table_path'],'column_name':f['column_name'],'source_cells':f['source_rows'],'counts':f['counts'],'ranges':len(old_ranges),'coverage_and_db_equal':True,'range_metadata_sha256':hashlib.sha256(json.dumps(old_ranges,separators=(',',':')).encode()).hexdigest()})
 projected=[]
 for stem in ('schema_context_candidates','schema_context_review_queue'):
  for suffix in ('jsonl','csv'):
   before=records(old,stem,suffix);after=[r for r in records(new,stem,suffix) if r['field_id'] in old_selected]
   assert before==after
   projected.append({'export':stem+'.'+suffix,'legacy_records':len(before),'all_evidence_fields_equal':True})
 for suffix in ('jsonl','csv'):
  old_unresolved={r['field_id']:r for r in records(old,'schema_unresolved_fields',suffix)}
  new_unresolved={r['field_id']:r for r in records(new,'schema_unresolved_fields',suffix)}
  assert set(old_unresolved)-set(new_unresolved)==set(added)
  assert all(old_unresolved[fid]==r for fid,r in new_unresolved.items())
 old_summary=read(old/'schema_type_summary.json')['summary']
 assert old_summary==records(old,'schema_type_summary')
 for row,cr in zip(old_summary,records(old,'schema_type_summary','csv'),strict=True):
  assert cr=={k:csv_cell(v) for k,v in row.items()}
 assert sum(r['candidate_source_cells'] for r in old_summary)==sum(f['counts'].get('schema_context_candidate',0) for f in old_selected.values())
 delta=Counter(new_cov['counts']);delta.subtract(old_cov['counts']);delta={k:v for k,v in delta.items() if v}
 added_stats=Counter()
 for f in added.values():added_stats.update(f['counts'])
 assert delta==dict(added_stats) and sum(f['source_rows'] for f in added.values())==added_stats['cells_decoded']
 return {'all_passed':True,'old_selected_fields':17,'legacy_fields':comparisons,'projected_exports':projected,'retained_unmapped_evidence_equal':True,'unmapped_before':len(old_unresolved),'unmapped_after':len(new_unresolved),'new_fields':[{k:f[k] for k in ('field_id','table_path','column_name','source_rows','counts')} for f in added.values()],'quality_count_delta':delta}


def compare_probe_evidence(new):
 author_path=ROOT/'docs/aidev_author_account_join_v046.json';assignee_path=ROOT/'docs/aidev_schema_gap_v047_review.json'
 authors=read(author_path);assignee=read(assignee_path);manifest=read(new/'manifest.json');coverage=read(new/'schema_coverage.json')
 inputs={t['path']:t for t in manifest['fingerprint']['inputs']};fields={(f['table_path'],f['column_name']):f for f in coverage['fields']}
 assert authors['all_checks_passed'] and authors['source_manifest_sha256']==manifest['source_manifest_sha256']
 for f in authors['source_files'].values():assert f['source_sha256']==inputs[f['table_path']]['sha256'] and f['source_unchanged_during_probe']
 for f in assignee['source_checks']:assert f['source_sha256']==inputs[f['table_path']]['sha256'] and f['source_unchanged']
 reference=manifest['account_reference_coverage'];assert reference==coverage['account_reference_coverage'] and reference['status']=='complete'
 assert reference['reference_cells_decoded']==authors['total_reference_source_cells_decoded']==73985
 assert reference['distinct_nonempty_reference_strings']==authors['reference_union_distinct_string_keys']==72189
 assert reference['reference_values_or_value_hashes_exported'] is False
 reference_fields={'table','column_name','values_decoded','table_path','source_sha256','source_rows','native_type','status','counts'}
 for src in reference['sources']:
  assert set(src)==reference_fields and src['status']=='complete' and src['values_decoded'] and src['column_name']=='login'
  assert src['source_sha256']==inputs[src['table_path']]['sha256']
  assert set(src['counts'])<={'reference_cells_decoded','null','empty_string','nonempty_string'}
  assert src['counts']['reference_cells_decoded']==sum(v for k,v in src['counts'].items() if k!='reference_cells_decoded')==src['source_rows']
 comparisons=[]
 with sqlite3.connect((new/'schema.sqlite').as_uri()+'?mode=ro&immutable=1',uri=True) as db:
  db.row_factory=sqlite3.Row
  for pf in authors['fields']:
   f=fields[pf['table_path'],pf['column_name']];raw=pf['source_ranges'];actual=[dict(r) for r in db.execute('SELECT * FROM ranges WHERE field_id=? ORDER BY start_row',(f['field_id'],))]
   assert f['source_rows']==pf['source_rows'] and f['counts']['cells_decoded']==pf['source_cells_decoded']
   end=0
   for r in raw:
    assert r['start_row']==end+1 and r['row_count']==r['end_row']-r['start_row']+1
    end=r['end_row']
   assert end==f['source_rows']
   matrix=Counter();i=j=0
   while i<len(raw) and j<len(actual):
    a,b=raw[i],actual[j];lo=max(a['start_row'],b['start_row']);hi=min(a['end_row'],b['end_row'])
    if lo<=hi:matrix[a['status'],b['status']]+=hi-lo+1
    if a['end_row']<=b['end_row']:i+=1
    if b['end_row']<=a['end_row']:j+=1
   assert sum(matrix.values())==f['source_rows']
   for (p,s),n in matrix.items():
    assert s!='schema_context_candidate' or p=='match'
    assert s!='unresolved' or p=='nonmatch'
    assert (s=='null')==(p=='null')
   for p,n in pf['counts'].items():assert sum(v for (s,_),v in matrix.items() if s==p)==n
   for s,n in f['counts'].items():
    if s!='cells_decoded':assert sum(v for (_,st),v in matrix.items() if st==s)==n
   comparisons.append({'table_path':f['table_path'],'column_name':f['column_name'],'comparison_level':'every_source_row_via_range_intersection','source_cells':f['source_rows'],'raw_probe_counts':pf['counts'],'schema_quality_counts':f['counts'],'raw_matches_minus_candidates':pf['counts']['match']-f['counts'].get('schema_context_candidate',0),'quality_transition_cells':[{'probe_status':p,'schema_status':s,'source_cells':n} for (p,s),n in sorted(matrix.items())],'all_passed':True})
 ap=assignee['assignee_full_probe'];f=fields[ap['table_path'],ap['column_name']];ac=ap['counts'];fc=f['counts']
 assert ap['complete'] and ap['source_unchanged'] and f['source_rows']==fc['cells_decoded']==ac['cells_decoded']
 assert fc.get('null',0)==ac['null']
 quality=sum(fc.get(k,0) for k in ('empty','invalid','placeholder_or_example'))
 match_gap=ac['exact_account_reference_match']-fc.get('schema_context_candidate',0)
 unmatched_gap=ac['unmatched_reference_unresolved']-fc.get('unresolved',0)
 assert match_gap>=0 and unmatched_gap>=0 and match_gap+unmatched_gap==quality
 comparisons.append({'table_path':f['table_path'],'column_name':f['column_name'],'comparison_level':'aggregate_probe_only_no_published_probe_row_ranges','source_cells':f['source_rows'],'raw_probe_counts':ac,'schema_quality_counts':fc,'raw_matches_minus_candidates':match_gap,'raw_nonmatches_minus_unresolved':unmatched_gap,'quality_exclusion_cells':quality,'all_passed':True,'limitation':'The assignee probe exposes counts, not row ranges; source-row quality origins are not independently re-decoded.'})
 return {'all_passed':True,'source_probe_sha256':{author_path.name:sha(author_path),assignee_path.name:sha(assignee_path)},'reference_coverage':reference,'fields':comparisons,'candidate_count_is_not_raw_match_count':True,'reference_count_note':'Reference distinct nonempty strings is not a count of quality-qualified, valid, or personally owned accounts.'}


def main():
 from contextlib import ExitStack
 from agentlog_unified import schema_scan
 started=datetime.now(timezone.utc).isoformat();old=ROOT/'schema-runs/aidev-v046';new=ROOT/'schema-runs/aidev-v047'
 assert schema_scan.ROLES==ROLE and len(ROLE)==32 and sum(k[0]=='aidev' for k in ROLE)==22
 with ExitStack() as stack:
  for folder in (old,new):
   lock=stack.enter_context((folder/'.schema.lock').open('rb'));fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
  paths=[p for folder in (old,new) for p in folder.iterdir() if p.suffix in {'.json','.jsonl','.csv','.sqlite'}]
  paths += [ROOT/'docs'/name for name in ('schema_exports_v046_verification.json','aidev_author_account_join_v046.json','aidev_schema_gap_v047_review.json')]
  before={str(p.relative_to(ROOT)):sha(p) for p in paths}
  result=verify(new);legacy=compare_legacy(old,new);probes=compare_probe_evidence(new)
  assert result['all_checks_passed'] and result['selected_fields']==22 and result['all_fields']==160
  assert result['status']=='complete_with_schema_gaps' and legacy['unmapped_after']==138
  assert result['counts']['cells_decoded']==4504029 and legacy['quality_count_delta']['cells_decoded']==1926498
  executions=[];cli_results=[]
  for suffix in ('','_resume'):
   execution_path=ROOT/'docs'/('aidev_v047_schema'+suffix+'_execution.json');execution=read(execution_path)
   stdout_path=Path(execution['stdout_path']);stderr_path=Path(execution['stderr_path']);command=read(stdout_path)
   assert execution['exit_code']==2 and execution['source_unchanged'] is True and execution['source_before']==execution['source_after']
   assert sha(stdout_path)==execution['stdout_sha256'] and sha(stderr_path)==execution['stderr_sha256']
   assert command['counts']==result['counts'] and command['all_selected_fields_visited'] is True
   assert command['resumed']==bool(suffix)
   executions.append({'path':execution_path.name,'sha256':sha(execution_path),'stdout_sha256':sha(stdout_path),'stderr_sha256':sha(stderr_path),'exit_code':execution['exit_code'],'source_unchanged':True})
   cli_results.append(command)
  for key in ('counts','selected_fields','all_fields','scalar_fields','candidate_range_records','review_range_records','unresolved_field_records','account_reference_coverage'):
   assert cli_results[0][key]==cli_results[1][key]
  prior=read(ROOT/'docs/schema_exports_v046_verification.json')
  prior_hashes=prior['real_v045_to_v046_comparison'][0]['old_and_new_run_file_sha256']
  assert all(sha(p)==prior_hashes[str(p)] for p in old.iterdir() if p.suffix in {'.json','.jsonl','.csv','.sqlite'})
  after={str(p.relative_to(ROOT)):sha(p) for p in paths};assert before==after
  report={'schema_version':'aidev_schema_exports_independent_verification_v047','started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'all_checks_passed':True,'command':[sys.executable,str(Path(__file__).resolve())],'verifier_sha256':sha(Path(__file__)),'source_values_read':False,'source_bytes_rehashed_without_value_decode':True,'source_min_max_values_read':False,'raw_values_or_value_hashes_exported':False,'remote_accessed':False,'target_code_executed':False,'formal_source_modified':False,'swechat_output_accessed':False,'result':result,'v046_legacy_comparison':legacy,'new_field_probe_comparison':probes,'input_output_fingerprints_before':before,'input_output_fingerprints_after':after,'input_output_files_unchanged':True,'real_cli_executions':executions,'full_and_resume_cli_counts_and_range_record_counts_identical':True,'resume_evidence_limit':'CLI omits field details and no pre-resume database snapshot was supplied; final field/range partitions are fully verified, while full-versus-resume equality is checked at exported CLI aggregate level.','old_v046_artifacts_match_prior_verification_sha256':True,'count_unit':'Source table/column/row cells; not distinct rows, people, accounts, secrets or leaks.','evidence_boundary':'All 22 selected AIDev fields visited; 138 AIDev fields remain semantically unresolved. Exact join candidates remain low-confidence and pending. This metadata-only verification does not establish actual identity, sensitivity, or runtime disclosure.'}
 out=ROOT/'docs/aidev_schema_v047_verification.json';out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'report':str(out),'all_checks_passed':True,'counts':result['counts'],'selected_fields':22,'unmapped_fields':138,'legacy_fields_equal':17,'new_field_count':5,'new_field_counts':legacy['quality_count_delta'],'probe_quality_differences':[{'table_path':f['table_path'],'column_name':f['column_name'],'raw_matches_minus_candidates':f['raw_matches_minus_candidates']} for f in probes['fields']]},ensure_ascii=False))


if __name__=='__main__':main()
