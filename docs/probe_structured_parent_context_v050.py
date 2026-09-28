#!/usr/bin/env python3
"""Bounded read-only parent/leaf JSON-context probe on the frozen v049 parsed subset.

Visits every node in selected documents before inspecting classifications. Emits
only source coordinates, ordinal paths, fixed type/status labels and counts.
"""
from collections import Counter,defaultdict
from contextlib import ExitStack
from datetime import datetime,timezone
from pathlib import Path
import argparse,fcntl,hashlib,json,re,sqlite3,time
from agentlog_unified import structured_types as parser,content_types,taxonomy
from verify_aidev_structured_v048 import digest,stat

BASE=Path(__file__).resolve().parents[1]
PERSONS={'person','personal','user','patient','employee','customer','member','applicant','candidate','profile','student'}
ATTRS={'name':'person_name','age':'age','race':'ethnicity','education':'education','school':'education','degree':'education','job_title':'employment','employer':'employment','employment':'employment','occupation':'employment'}
ID_PARENTS={'user':'user_identifier','account':'user_identifier','customer':'user_identifier','session':'session_identifier','device':'device_identifier','advertising':'device_identifier','request':'request_identifier','correlation':'request_identifier','trace':'request_identifier','span':'request_identifier','order':'transaction_identifier','transaction':'transaction_identifier','payment':'transaction_identifier','invoice':'transaction_identifier','tenant':'tenant_identifier'}
LIMITS={'max_documents':6000,'max_cells':6000,'max_total_nodes':200000,'max_seconds':300,'arrow_batch_rows':256}

def normalize(s):return re.sub(r'([a-z0-9])([A-Z])',r'\1_\2',s).lower()
def permitted(parent,leaf,category,subtype):
 p,k=normalize(parent),normalize(leaf)
 if k=='id' and ID_PARENTS.get(p)==subtype and category=='QID':return 'scoped_identifier'
 if p in PERSONS and ATTRS.get(k)==subtype and category=='PII':return 'scoped_person_attribute'
 if p in {'request','req','http_request'} and k in {'body','data'} and (category,subtype)==('BIZ','request_body'):return 'request_body_carrier'
 if p in {'response','res','http_response'} and k in {'body','data'} and (category,subtype)==('BIZ','response_body'):return 'response_body_carrier'
 if p in {'request','req','http_request','response','res','http_response'} and k in {'headers','header'} and (category,subtype)==('BIZ','http_headers'):return 'http_header_carrier'
 return None

def children(value,path,depth,name,layers):
 if isinstance(value,parser._Object):
  for i,(key,child) in enumerate(value):yield child,path+[i],depth+1,key,name,layers
 else:
  for i,child in enumerate(value):yield child,path+[i],depth+1,None,None,layers

def inspect_document(value,limits,baseline,counts,remaining):
 result=[];gaps=[];visited=0
 stack=[iter([(value,[],0,None,None,0)])]
 while stack:
  try:value,path,depth,name,parent,layers=next(stack[-1])
  except StopIteration:stack.pop();continue
  if visited>=limits['max_nodes'] or visited>=remaining:gaps.append('node_budget');break
  if depth>limits['max_depth']:gaps.append('depth_budget');continue
  visited+=1;kind=parser._kind(value);counts['nodes_visited']+=1;counts[kind+'_nodes']+=1
  decoded=None;decoded_ok=False
  if kind=='string' and value.strip() and value.lstrip()[0] in '[{"':
   if layers>=limits['max_decode_layers']:gaps.append('decode_layer_budget')
   else:
    decoded,error=parser._parse(value,limits['max_depth']-depth-1)
    if error:gaps.append('encoded_parse_gap')
    else:decoded_ok=True
  container=decoded_ok and parser._kind(decoded) in {'object','array'}
  if name is not None:counts['keyed_nodes']+=1
  if parent is not None and name is not None:
   counts['direct_parent_leaf_pairs']+=1
   if len(parent)>parser.MAX_KEY_CHARS or len(name)>parser.MAX_KEY_CHARS:gaps.append('key_size_budget')
   else:
    old=baseline.get(tuple(path),set())
    for candidate in parser._key_candidates(value,kind,taxonomy._matches(parent+'.'+name),decoded_container=container,decoded_empty=container and not decoded):
     label=candidate['category'],candidate['subtype']
     if label in old:continue
     family=permitted(parent,name,*label)
     row={'node_path':path,'node_kind':kind,'category':label[0],'subtype':label[1],
          'candidate_status':candidate['candidate_status'],'value_status':candidate['value_status'],
          'confidence':candidate['confidence'],'context_rule_family':family or 'unresolved_composed_hint',
          'disposition':'supported_pair_pending' if family else 'unresolved_composition_pending',
          'comparison_unit':'node_and_type','observation_scope':'structured_context_probe','runtime_confirmed':False,'human_review_status':'pending'}
     result.append(row)
  if decoded_ok:
   counts['decode_boundaries_without_context_inheritance']+=1
   stack.append(iter([(decoded,path+[-1],depth+1,None,None,layers+1)]))
  elif kind=='object':
   counts['duplicate_keys']+=len(value)-len({p[0] for p in value})
   stack.append(iter(children(value,path,depth,name,layers)))
  elif kind=='array':
   if name is not None:counts['array_boundaries_without_context_inheritance']+=1
   stack.append(iter(children(value,path,depth,name,layers)))
 return result,gaps,visited

def synthetic():
 cases=[('personal_scope','{"user":{"id":123,"age":25,"name":"Synthetic Example"}}'),
        ('carrier_scope','{"request":{"body":{"x":1},"headers":{"x":2}}}'),
        ('general_scope','{"repository":{"id":123,"age":25,"name":"Project"}}'),
        ('null_bool_empty','{"user":{"id":null,"age":false,"name":""}}'),
        ('no_grandparent','{"user":{"settings":{"age":25}}}'),
        ('array_boundary','{"user":[{"id":123}]}'),
        ('encoded_boundary','{"user":"{\\"id\\":123}"}'),
        ('unsafe_composition','{"request":{"id":123}}')]
 result=[]
 for name,text in cases:
  baseline=parser.classify_structured(text);labels=defaultdict(set)
  for r in baseline['matches']:labels[tuple(r['node_path'])].add((r['category'],r['subtype']))
  value,error=parser._parse(text,32);assert error is None
  rows,gaps,n=inspect_document(value,{'max_nodes':10000,'max_depth':32,'max_decode_layers':2},labels,Counter(),200000)
  result.append({'case':name,'added_labels':[{k:r[k] for k in ('category','subtype','candidate_status','disposition')} for r in rows],'nodes_visited':n})
 by={r['case']:r for r in result}
 assert {r['subtype'] for r in by['personal_scope']['added_labels']}=={'user_identifier','age','person_name'}
 assert any(r['subtype']=='request_body' and r['disposition']=='supported_pair_pending' for r in by['carrier_scope']['added_labels'])
 assert not any(r['disposition']=='supported_pair_pending' for r in by['general_scope']['added_labels'])
 for name in ('null_bool_empty','no_grandparent','array_boundary','encoded_boundary'):assert not any(r['disposition']=='supported_pair_pending' for r in by[name]['added_labels'])
 assert any(r['subtype']=='request_body' and r['disposition']=='unresolved_composition_pending' for r in by['unsafe_composition']['added_labels'])
 return result

def run():
 import pyarrow.parquet as pq
 started=datetime.now(timezone.utc).isoformat();clock=time.monotonic();deadline=clock+LIMITS['max_seconds']
 synthetic_results=synthetic();source=BASE/'structured-runs/aidev-v049';output=BASE/'docs'
 report_path=output/'aidev_structured_parent_context_v050_probe.json';evidence_path=output/'aidev_structured_parent_context_v050_evidence.jsonl';selection_path=output/'aidev_structured_parent_context_v050_selection.jsonl'
 for p in (report_path,evidence_path,selection_path):
  if p.exists():raise FileExistsError('Preserve prior probe evidence')
 codes={p.name:digest(p) for p in (Path(parser.__file__),Path(content_types.__file__),Path(taxonomy.__file__))}
 with ExitStack() as stack:
  handle=stack.enter_context((source/'.structured.lock').open('rb'));fcntl.flock(handle,fcntl.LOCK_SH|fcntl.LOCK_NB)
  manifest=json.loads((source/'manifest.json').read_text());state=json.loads((source/'export_state.json').read_text());coverage=json.loads((source/'structured_coverage.json').read_text())
  assert state['status']=='complete' and state['outputs']['structured_coverage.json']['sha256']==digest(source/'structured_coverage.json')
  assert all(manifest['fingerprint']['source_sha256'][k]==v for k,v in codes.items())
  dbpath=source/'structured.sqlite';dbbefore=stat(dbpath);db=sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True);stack.callback(db.close);db.row_factory=sqlite3.Row;db.execute('BEGIN')
  docs=[dict(r) for r in db.execute("SELECT * FROM documents WHERE status='parsed_with_semantic_gaps' ORDER BY table_path,source_row,column_name,document_index LIMIT ?",(LIMITS['max_documents'],))]
  available=db.execute("SELECT COUNT(*) FROM documents WHERE status='parsed_with_semantic_gaps'").fetchone()[0]
  cells={};cohort=[]
  for d in docs:
   key=d['table_path'],d['source_row'],d['column_name']
   if key not in cells and len(cells)>=LIMITS['max_cells']:continue
   cells.setdefault(key,[]).append(d);cohort.append(d)
  selection_path.write_text(''.join(json.dumps({k:d[k] for k in ('table_path','source_row','column_name','document_index','source_start','source_end','format','status')},sort_keys=True)+'\n' for d in cohort))
  tables={t['path']:t for t in manifest['tables']};groups=defaultdict(dict)
  for (table,row,col),ds in cells.items():groups[table].setdefault(row,{})[col]=ds
  counts=Counter();bytype=Counter();bygroup=Counter();affected=set();supported_doc=set();supported_cell_type=set();evidence=[];gap_counts=Counter();table_counts=[];source_hashes=[];stopped=None;replay_equal=True
  existing_global={(r[0],r[1]) for r in db.execute('SELECT DISTINCT category,subtype FROM matches WHERE excluded=0 AND category IS NOT NULL')}
  for relative,targets in sorted(groups.items()):
   if time.monotonic()>=deadline:stopped='time_budget';break
   table=tables[relative];path=Path(table['absolute_path']);before=stat(path);assert digest(path)==table['sha256'] and before==stat(path)
   source_hashes.append({'table_path':relative,'sha256':table['sha256'],'bytes':table['bytes']})
   pqf=pq.ParquetFile(path);columns=sorted({col for fields in targets.values() for col in fields});positions=sorted(targets);pos=0;base=0;visited=0
   for batch in pqf.iter_batches(batch_size=LIMITS['arrow_batch_rows'],columns=columns):
    upper=base+batch.num_rows
    while pos<len(positions) and positions[pos]<=upper:
     if time.monotonic()>=deadline:stopped='time_budget';break
     n=positions[pos];pos+=1
     for column,ds in targets[n].items():
      text=batch.column(columns.index(column))[n-base-1].as_py();assert isinstance(text,str);counts['source_cells_decoded']+=1;counts['source_characters']+=len(text)
      if len(text)>manifest['fingerprint']['limits']['max_source_chars']:gap_counts['source_size_budget']+=1;continue
      original=parser.classify_structured(text,**manifest['fingerprint']['limits']);discovered=list(parser._documents(text,Counter()))
      for d in ds:
       if counts['nodes_visited']>=LIMITS['max_total_nodes']:stopped='total_node_budget';break
       saved=[json.loads(r[0]) for r in db.execute('SELECT details FROM matches WHERE document_id=? ORDER BY id',(d['id'],))]
       replay=[r for r in original['matches'] if r['document_index']==d['document_index']]
       replay_equal &= sorted(json.dumps(r,sort_keys=True) for r in saved)==sorted(json.dumps(r,sort_keys=True) for r in replay)
       fmt,start,end,raw,error=discovered[d['document_index']];assert error is None and fmt==d['format'] and start==d['source_start'] and end==d['source_end']
       value,error=parser._parse(raw,manifest['fingerprint']['limits']['max_depth']);assert error is None
       baseline=defaultdict(set)
       for r in replay:baseline[tuple(r['node_path'])].add((r['category'],r['subtype']))
       rows,gaps,nodes=inspect_document(value,manifest['fingerprint']['limits'],baseline,counts,LIMITS['max_total_nodes']-counts['nodes_visited'])
       counts['documents_visited']+=1;visited+=1;gap_counts.update(gaps)
       for row in rows:
        safe={'table_path':relative,'column_name':column,'source_row':n,'document_index':d['document_index'],**row}
        evidence.append(safe);bytype[(row['category'],row['subtype'],row['disposition'],row['candidate_status'])]+=1
        bygroup[(relative,column,row['disposition'])]+=1
        if row['disposition']=='supported_pair_pending':
         affected.add((relative,n,column));supported_doc.add((relative,n,column,d['document_index']));supported_cell_type.add((relative,n,column,row['category'],row['subtype']))
       if stopped:break
      if stopped:break
     if stopped:break
    base=upper
    if stopped or pos==len(positions):break
   assert before==stat(path)
   table_counts.append({'table_path':relative,'selected_documents':sum(len(ds) for fields in targets.values() for ds in fields.values()),'visited_documents':visited,'selected_cells':sum(len(fields) for fields in targets.values())})
   print(json.dumps({'table':relative,'documents':visited,'total_nodes':counts['nodes_visited'],'supported_added_node_types':sum(v for k,v in bytype.items() if k[2]=='supported_pair_pending')}),flush=True)
   if stopped:break
  assert codes=={name:digest(Path(parser.__file__).with_name(name)) for name in codes} and dbbefore==stat(dbpath)
  evidence_path.write_text(''.join(json.dumps(r,ensure_ascii=False,sort_keys=True)+'\n' for r in evidence))
  supported={(r['category'],r['subtype']) for r in evidence if r['disposition']=='supported_pair_pending' and r['candidate_status']!='placeholder_or_example'}
  report={'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-clock,'scope':'readonly_parsed_json_parent_context_probe','taxonomy_version':taxonomy.TAXONOMY_VERSION,'source_run':str(source),'source_manifest_sha256':digest(source/'manifest.json'),'source_code_sha256':codes,'source_codes_unchanged':True,'source_database_unchanged':True,'frozen_source_files':source_hashes,'limits':LIMITS,'selection_policy':"All existing status=parsed_with_semantic_gaps documents, ordered by source coordinates, limited independently of keys or sensitive words. Invalid and partial documents outside this cohort remain unresolved.",'available_parsed_documents':available,'selected_documents':len(cohort),'selected_cells':len(cells),'all_selected_documents_visited':counts['documents_visited']==len(cohort),'all_available_parsed_documents_visited':counts['documents_visited']==available,'stop_reason':stopped,'counts':dict(counts),'probe_gaps':dict(gap_counts),'baseline_replay_matches_frozen_per_document':replay_equal,'added_node_type_counts':[{'category':c,'subtype':s,'disposition':d,'candidate_status':st,'count':n} for (c,s,d,st),n in sorted(bytype.items())],'source_groups':[{'table_path':t,'column_name':c,'disposition':d,'count':n} for (t,c,d),n in sorted(bygroup.items())],'supported_added_source_cells':len(affected),'supported_added_documents':len(supported_doc),'supported_added_cell_type_pairs':len(supported_cell_type),'supported_new_labels_vs_existing_structured_global':[{'category':c,'subtype':s} for c,s in sorted(supported-existing_global)],'tables':table_counts,'synthetic_cases':synthetic_results,'selection_file':str(selection_path),'selection_sha256':digest(selection_path),'evidence_file':str(evidence_path),'evidence_sha256':digest(evidence_path),'helper_path':str(Path(__file__).resolve()),'helper_sha256':digest(Path(__file__)),'source_values_read_in_memory':True,'raw_values_dynamic_keys_or_value_hashes_exported':False,'source_or_tests_modified':False,'network_accessed':False,'credentials_validated':False,'human_review_status':'pending','runtime_confirmed':False,'new_sensitive_type_confirmed':False,'boundaries':['Additional rows are finite parent/leaf key hints for known types, not observed real personal attributes or confirmed disclosures.','Immediate object parent only. Context does not propagate through array elements, JSON decode boundaries, or intermediate ancestors.','All nodes of the selected documents are visited; explicit source/document/node/depth budgets remain limitations.','Unrestricted parent+leaf composition is separately marked unresolved: a receiver carrier can otherwise be falsely attached to a leaf id.','Examples and identifier references remain separate from unverified named values. Current literal-shape rules are unchanged.']}
  report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
  print(json.dumps({'report':str(report_path),'documents_visited':counts['documents_visited'],'nodes_visited':counts['nodes_visited'],'added_rows':len(evidence),'supported_cells':len(affected),'baseline_replay_equal':replay_equal,'stop_reason':stopped}),flush=True)
  return 0 if replay_equal and stopped is None else 2

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--run',action='store_true');p.add_argument('--self-test',action='store_true');args=p.parse_args()
 if args.self_test:print(json.dumps({'synthetic_cases':synthetic(),'real_outputs_read':False}))
 elif args.run:raise SystemExit(run())
 else:p.error('Use --self-test or --run')
