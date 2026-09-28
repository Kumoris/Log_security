#!/usr/bin/env python3
"""Terminal-only metadata audit of same-version AIDev repair; no text decode."""
from collections import Counter, defaultdict
from contextlib import ExitStack
from datetime import datetime, timezone
from itertools import zip_longest
from pathlib import Path
import argparse, csv, fcntl, gzip, hashlib, json, re, sqlite3, time
from agentlog_unified import content_cursor, content_repair
from agentlog_unified.content_reconcile import SAFE_LABELS
from agentlog_unified.storage import stable_id
from agentlog_unified.taxonomy import TAXONOMY_VERSION, taxonomy_catalog
from verify_aidev_structured_v048 import digest, stat, cv, integer

BASE=Path(__file__).resolve().parents[1]
FIELDS={'basis','candidate_status','category','confidence','end','rule','start','subtype','value_status'}
SOURCE=('table_path','source_row','column_name','field_scope')
TYPE_KEYS={(c['category'],s['subtype']) for c in taxonomy_catalog()['categories'] for s in c['subtypes']}|{(None,None)}
SELECT_FIELDS={'id',*SOURCE,'characters','scanned_characters','text_hmac_sha256'}
HEX=re.compile(r'[0-9a-f]{24}\Z');HMAC=re.compile(r'[0-9a-f]{64}\Z')
REVIEW_SQL="""SELECT id,table_path,source_row,column_name,field_scope,characters,scanned_characters,text_hmac_sha256,status,'cell' record_kind,source_row start_row,source_row end_row,1 row_count FROM cells UNION ALL SELECT id,table_path,NULL,column_name,field_scope,characters,characters,NULL,'unclassified_text','source_row_range',start_row,end_row,end_row-start_row+1 FROM review_ranges"""

def canonical(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def type_key(d):return d['category'],d['subtype']
def identity(d):return d['start'],d['end'],d['rule'],d['category'] or '',d['subtype'] or ''
def variant(d,excluded):return canonical([d,bool(excluded)])
def lock(stack,path):
 h=stack.enter_context(path.open('rb'));fcntl.flock(h,fcntl.LOCK_SH|fcntl.LOCK_NB)
def readonly(stack,path):
 db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True);stack.callback(db.close);db.row_factory=sqlite3.Row
 db.execute('PRAGMA query_only=ON');db.execute('PRAGMA cache_size=-8192');db.execute('BEGIN');return db

class Audit:
 def __init__(self):self.checks={};self.files={};self.started=datetime.now(timezone.utc).isoformat();self.clock=time.monotonic()
 def check(self,name,value):self.checks[name]=bool(value)
 def capture(self,path):
  path=Path(path);before=stat(path);sha=digest(path);self.check('stable_hash_'+str(path),before==stat(path));self.files[str(path)]={'sha256':sha,'stat':before};return sha
 def read(self,path):self.capture(path);return json.loads(Path(path).read_text())
 def finish(self,report,kind,results):
  self.check('all_observed_files_unchanged',all(stat(Path(p))==tuple(v['stat']) for p,v in self.files.items()))
  data={'audit_kind':kind,'started_utc':self.started,'completed_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':round(time.monotonic()-self.clock,3),'all_checks_passed':all(self.checks.values()),'checks':self.checks,'passed':sum(self.checks.values()),'total':len(self.checks),'results':results,'evidence_files':self.files,'source_values_decoded':False,'source_values_printed':False,'source_files_modified':False,'network_accessed':False,'credentials_validated':False,'evidence_boundary':'Metadata consistency and finite-rule completion do not prove all sensitive semantics, unique people or secrets, validity, disclosure, or application-log execution.'}
  if report.exists():raise FileExistsError('Preserve prior verification report')
  report.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
  print(json.dumps({'report':str(report),'all_checks_passed':data['all_checks_passed'],'passed':data['passed'],'total':data['total'],'failed':[k for k,v in self.checks.items() if not v]},ensure_ascii=False))
  return 0 if data['all_checks_passed'] else 1

class PairReader:
 def __init__(self,stack,audit,directory,stem,compressed):
  self.audit=audit;self.stem=stem;self.n=0;self.parity=True;self.exact=True
  ext='.gz' if compressed else '';opener=gzip.open if compressed else open
  jp=directory/(stem+'.jsonl'+ext);cp=directory/(stem+'.csv'+ext);audit.capture(jp);audit.capture(cp)
  self.js=iter(stack.enter_context(opener(jp,'rt',encoding='utf-8')))
  self.csv=csv.DictReader(stack.enter_context(opener(cp,'rt',encoding='utf-8',newline='')))
 def take(self,expected):
  line=next(self.js,None);crow=next(self.csv,None);self.n+=1
  if line is None or crow is None:self.parity=self.exact=False;return
  row=json.loads(line);self.exact &= row==expected
  self.parity &= set(row)==set(crow) and crow=={k:cv(v) for k,v in row.items()}
 def finish(self):
  self.exact &= next(self.js,None) is None;self.parity &= next(self.csv,None) is None
  self.audit.check(self.stem+'_exact_metadata_against_producers',self.exact)
  self.audit.check(self.stem+'_jsonl_csv_all_field_parity',self.parity)
  return self.n

def parent_view(stack,a,parent):
 m0=json.loads((parent/'manifest.json').read_text());ancestor=Path(m0['parent_run']).resolve() if m0.get('engine')=='content_advance_v1' else parent
 for p in sorted({parent/'.content.lock',ancestor/'.content.lock'}):lock(stack,p)
 m=a.read(parent/'manifest.json');original=a.read(ancestor/'manifest.json');coverage=a.read(parent/'content_coverage.json')
 a.check('parent_unchanged_while_locking',m==m0)
 dbpath=ancestor/'content.sqlite'
 if m.get('engine')=='content_advance_v1':
  state=a.read(parent/'advance_state.json')
  a.check('advance_terminal_state_matches_coverage',state['status']=='export_complete' and state['coverage_sha256']==a.files[str(parent/'content_coverage.json')]['sha256'])
  a.check('advance_exact_ancestor_and_checkpoint',m['parent_manifest_sha256']==a.files[str(ancestor/'manifest.json')]['sha256'] and Path(m['checkpoint_path']).resolve()==dbpath and Path(m['checkpoint_lock_path']).resolve()==ancestor/'.content.lock' and m['checkpoint_identity']=={'device':dbpath.stat().st_dev,'inode':dbpath.stat().st_ino})
  a.check('advance_source_chain',all(m[k]==original[k] for k in ('source_import','source_manifest_sha256','tables','fingerprint_key_sha256','dataset')) and m['fingerprint']['frozen_source_sha256']==original['fingerprint']['source_sha256'])
 a.check('parent_aidev',m['dataset']=='aidev')
 a.check('current_classifier_equals_parent',all(a.capture(BASE/'src/agentlog_unified'/name)==original['fingerprint']['source_sha256'][name] for name in ('content_types.py','taxonomy.py','storage.py')))
 a.check('parent_and_ancestor_keys_consistent',digest(parent/'.fingerprint-key')==digest(ancestor/'.fingerprint-key')==m['fingerprint_key_sha256']==original['fingerprint_key_sha256'])
 a.capture(dbpath);db=readonly(stack,dbpath)
 tables=[dict(r) for r in db.execute('SELECT * FROM tables ORDER BY path')]
 for t in tables:t['stats']=json.loads(t['stats'])
 a.check('parent_snapshot_current_db_tables',tables==coverage['tables'])
 counts=dict(db.execute('SELECT excluded,COUNT(*) FROM matches GROUP BY excluded'))
 a.check('parent_db_counts_equal_coverage',counts.get(0,0)==coverage['candidate_occurrences'] and counts.get(1,0)==coverage['excluded_occurrences'])
 statuses=dict(db.execute('SELECT status,COUNT(*) FROM cells GROUP BY status'));ranges,expanded=db.execute('SELECT COUNT(*),COALESCE(SUM(end_row-start_row+1),0) FROM review_ranges').fetchone()
 a.check('parent_review_counts_equal_coverage',statuses==coverage['cell_status_counts'] and sum(statuses.values())+ranges==coverage['unknown_type_review_export_records'] and sum(statuses.values())+expanded==coverage['unknown_type_review_cells'])
 return m,original,ancestor,coverage,db

def repair_view(stack,a,run,parent=None):
 scan=run/'scan';selection=run/'selection';lock(stack,scan/'.repair.lock')
 sm=a.read(selection/'selection_manifest.json');fm=a.read(scan/'manifest.json');fc=a.read(scan/'repair_coverage.json')
 actual_parent=Path(sm['parent_run']).resolve();parent=parent or actual_parent
 pm,original,ancestor,pc,pdb=parent_view(stack,a,parent)
 a.check('repair_exact_current_or_ancestor_parent',actual_parent in {parent,ancestor} and Path(fm['parent_run']).resolve()==actual_parent and digest(actual_parent/'manifest.json')==sm['parent_manifest_sha256']==fm['parent_manifest_sha256'])
 a.check('selection_fingerprint_consistent',a.capture(selection/'selection.jsonl')==sm['selection_sha256']==fm['fingerprint']['selection_sha256'] and a.files[str(selection/'selection_manifest.json')]['sha256']==fm['fingerprint']['selection_manifest_sha256'])
 a.check('selection_source_and_key_chain',sm['source_manifest_sha256']==pm['source_manifest_sha256'] and sm['parent_fingerprint_key_sha256']==pm['fingerprint_key_sha256'])
 rows=[json.loads(line) for line in (selection/'selection.jsonl').read_text().splitlines()];selected={r['id']:r for r in rows}
 a.check('selection_unique_count_and_characters',len(selected)==len(rows)==sm['selected_cells']==fm['selected_cells']==fc['selected_cells'] and sum(r['characters'] for r in rows)==sm['selected_characters']==fm['selected_characters'])
 a.check('selection_safe_metadata_and_ids',all(set(r)==SELECT_FIELDS and r['id']==stable_id('content-cell',pm['source_manifest_sha256'],r['table_path'],r['source_row'],r['column_name']) and bool(HMAC.fullmatch(r['text_hmac_sha256'])) for r in rows))
 for group in ('source_sha256','classifier_sha256'):
  a.check('repair_'+group+'_current',all(a.capture(BASE/'src/agentlog_unified'/name)==value for name,value in fm['fingerprint'][group].items()))
 a.check('repair_taxonomy_current_pending',fc['taxonomy_version']==fm['taxonomy_version']==TAXONOMY_VERSION and fc['human_review_status']=='pending' and fc['runtime_confirmed'] is False)
 a.capture(scan/'repair.sqlite');db=readonly(stack,scan/'repair.sqlite')
 cells={r['id']:{**dict(r),'source':json.loads(r['source']),'cursor':json.loads(r['cursor'])} for r in db.execute('SELECT * FROM cells')}
 status=Counter(c['status'] for c in cells.values());rules=len(content_cursor.SPECS)
 ok=set(cells)==set(selected)
 for cid,c in cells.items():
  pr=pdb.execute('SELECT * FROM cells WHERE id=?',(cid,)).fetchone();cur=c['cursor']
  ok &= c['source']==selected[cid] and pr is not None and all(pr[k]==selected[cid][k] for k in SELECT_FIELDS)
  ok &= (cur=={'rule_index':rules,'search_offset':0}) if c['status']=='complete_with_semantic_gaps' else c['status'] in {'pending','partial'} and integer(cur.get('rule_index')) and cur['rule_index']<rules and integer(cur.get('search_offset')) and cur['search_offset']<=selected[cid]['characters']
 a.check('repair_cell_sources_hmac_cursors_and_selection_exact',ok)
 a.check('repair_cell_status_and_page_totals',dict(status)==fc['cell_status_counts'] and sum(c['pages'] for c in cells.values())==fc['committed_pages'] and status['complete_with_semantic_gaps']==fc['recorded_completed_cells'])
 complete=all(c['status']=='complete_with_semantic_gaps' for c in cells.values()) and fc['source_verification_complete']
 a.check('completion_requires_all_rules_and_verified_sources',fc['all_selected_cells_all_rules_finished']==complete and fc['status']==('complete_with_semantic_gaps' if complete else 'partial'))
 imported=a.read(Path(pm['source_import'])/'manifest.json');a.check('frozen_import_manifest',imported['status']=='complete' and a.files[str(Path(pm['source_import'])/'manifest.json')]['sha256']==pm['source_manifest_sha256'])
 tables={t['path']:t for t in pm['tables']}
 a.check('selected_source_byte_sha_and_size',all(a.capture(Path(tables[name]['absolute_path']))==tables[name]['sha256'] and Path(tables[name]['absolute_path']).stat().st_size==tables[name]['bytes'] for name in {r['table_path'] for r in rows}))
 return {'scan':scan,'selection':sm,'manifest':fm,'coverage':fc,'selected':selected,'cells':cells,'db':db,'parent_manifest':pm,'original':original,'ancestor':ancestor,'parent_coverage':pc,'parent_db':pdb,'parent':parent}

def valid_detail(row,detail,source,origin):
 expected=stable_id(source['id'],detail) if origin=='parent' else stable_id(source['id'],detail['start'],detail['end'],detail['category'],detail['subtype'])
 return set(detail)==FIELDS and row['id']==expected and type_key(detail) in TYPE_KEYS and all(detail[k] in choices for k,choices in SAFE_LABELS.items()) and integer(detail['start']) and integer(detail['end'],1) and detail['start']<detail['end']<=source['characters'] and row['category']==detail['category'] and row['subtype']==detail['subtype'] and bool(row['excluded'])==(detail['value_status']=='placeholder_or_example')

def verify(run,report):
 a=Audit()
 with ExitStack() as stack:
  v=repair_view(stack,a,run);db=v['db'];scan=v['scan'];selected=v['selected'];coverage=v['coverage'];scope=content_repair.SCOPE
  readers={s:PairReader(stack,a,scan,s,False) for s in ('repair_type_occurrences','repair_excluded','repair_unknown_type_review_queue','repair_data_gaps','repair_type_summary')}
  counts=Counter();statuses=defaultdict(Counter);good=True;known=set();retained=missing=changed=added=0
  for flag,stem in ((0,'repair_type_occurrences'),(1,'repair_excluded')):
   for r in db.execute('SELECT * FROM matches WHERE excluded=? ORDER BY id',(flag,)):
    d=json.loads(r['details']);source=selected[r['cell_id']];good &= valid_detail(r,d,source,'repair')
    readers[stem].take({'id':r['id'],'cell_id':r['cell_id'],**{k:source[k] for k in SOURCE},**d,**scope})
    if not flag:counts[type_key(d)]+=1;statuses[type_key(d)][d['candidate_status']]+=1
  a.check('repair_occurrences_safe_labels_spans_and_identities',good)
  for cid,c in sorted(v['cells'].items()):
   s=c['source'];readers['repair_unknown_type_review_queue'].take({'cell_id':cid,**{k:s[k] for k in (*SOURCE,'characters','text_hmac_sha256')},'cursor':c['cursor'],'status':c['status'],'pages':c['pages'],'reason':'full_text_semantics_and_finite_named_value_limits_unresolved',**scope})
  for r in db.execute('SELECT * FROM gaps ORDER BY id'):
   d=json.loads(r['details']);a.check('gap_'+r['id']+'_safe',set(d)=={'start','end','reason'} and d['reason']=='unclosed_private_key_envelope' and integer(d['start']) and integer(d['end'],1) and d['start']<d['end']<=selected[r['cell_id']]['characters'])
   readers['repair_data_gaps'].take({'cell_id':r['cell_id'],**d,**scope})
  summaries=[]
  for r in db.execute('SELECT category,subtype,COUNT(*),COUNT(DISTINCT cell_id) FROM matches WHERE excluded=0 GROUP BY category,subtype'):
   key=r[0],r[1];row={'category':r[0],'subtype':r[1],'occurrence_count':r[2],'distinct_cell_count':r[3],'candidate_status_counts':dict(statuses[key]),**scope};summaries.append(row);readers['repair_type_summary'].take(row)
  n={name:reader.finish() for name,reader in readers.items()}
  a.check('repair_coverage_counts_and_embedded_summary',n['repair_type_occurrences']==coverage['candidate_occurrences'] and n['repair_excluded']==coverage['excluded_occurrences'] and n['repair_data_gaps']==coverage['data_gap_records'] and n['repair_unknown_type_review_queue']==coverage['unknown_type_review_cells'] and summaries==coverage['type_summary'])
  # Compare full detail metadata from the currently frozen parent only for selected cells.
  for cid in selected:
   pcount=0;common=0
   for p in v['parent_db'].execute('SELECT * FROM matches WHERE cell_id=?',(cid,)):
    pcount+=1;d=json.loads(p['details']);rid=stable_id(cid,d['start'],d['end'],d['category'],d['subtype']);f=db.execute('SELECT * FROM matches WHERE id=?',(rid,)).fetchone()
    if f is None:missing+=1
    else:
     common+=1
     if json.loads(f['details'])==d and f['excluded']==p['excluded']:retained+=1
     else:changed+=1
   added+=db.execute('SELECT COUNT(*) FROM matches WHERE cell_id=?',(cid,)).fetchone()[0]-common
  a.check('same_version_selected_parent_metadata_delta_accounted',retained+missing+changed==sum(v['parent_db'].execute('SELECT COUNT(*) FROM matches WHERE cell_id=?',(cid,)).fetchone()[0] for cid in selected))
  results={'run':str(run),'parent':str(v['parent']),'selected_cells':len(selected),'selected_characters':sum(r['characters'] for r in selected.values()),'candidate_occurrences':n['repair_type_occurrences'],'excluded_occurrences':n['repair_excluded'],'committed_pages':coverage['committed_pages'],'all_selected_cells_all_rules_finished':coverage['all_selected_cells_all_rules_finished'],'source_verification_complete':coverage['source_verification_complete'],'data_gap_records':n['repair_data_gaps'],'same_version_parent_comparison':{'exact_retained_details':retained,'missing_identities':missing,'changed_details_or_exclusion':changed,'new_repair_identities':added},'semantic_complete':False}
  return a.finish(report,'readonly_same_version_repair_verification',results)

def self_test():
 d={'start':1,'end':5,'category':'PII','subtype':'email','rule':'email_shape','basis':'literal_shape','confidence':'low','value_status':'unverified','candidate_status':'literal_candidate'}
 source={'id':'synthetic','characters':10};row={'id':stable_id('synthetic',1,5,'PII','email'),'category':'PII','subtype':'email','excluded':0}
 assert valid_detail(row,d,source,'repair')
 assert not valid_detail(row,{**d,'end':11},source,'repair')
 assert not valid_detail(row,{**d,'confidence':'human_confirmed'},source,'repair')
 assert identity(d)!=identity({**d,'rule':'named_field_taxonomy'})
 assert variant(d,False)!=variant(d,True)
 print(json.dumps({'self_test':'passed','assertions':5,'real_outputs_read':False}))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runs-confirmed-terminal',action='store_true');p.add_argument('--self-test',action='store_true');p.add_argument('--run',type=Path,default=BASE/'repair-runs/aidev-v049');p.add_argument('--report',type=Path,default=BASE/'docs/aidev_repair_v049_verification.json');args=p.parse_args()
 if args.self_test:self_test()
 elif args.runs_confirmed_terminal:raise SystemExit(verify(args.run.resolve(),args.report.resolve()))
 else:p.error('--runs-confirmed-terminal is required before reading real outputs')
