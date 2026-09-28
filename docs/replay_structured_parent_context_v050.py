#!/usr/bin/env python3
"""Replay frozen v050 parent-context evidence against the isolated new parser."""
from pathlib import Path
from collections import Counter,defaultdict
from datetime import datetime,timezone
import fcntl,hashlib,json,sqlite3,time
from agentlog_unified import structured_types as parser,content_types,taxonomy
from verify_aidev_structured_v048 import digest,stat

BASE=Path(__file__).resolve().parents[1]
STAGE=Path('/private/tmp/structured_parent_v050_stage/src/agentlog_unified')
SCOPE={'observation_scope':'structured_parent_context_replay','human_review_status':'pending','runtime_confirmed':False,'new_sensitive_type_confirmed':False}


def run():
 import pyarrow.parquet as pq
 assert Path(parser.__file__).resolve()==STAGE/'structured_types.py','Isolated PYTHONPATH required'
 assert digest(Path(taxonomy.__file__))=='8bb74d6b21fe1b776249750b8efb3abfe5b65c476e63c1c34795ca200527269a'
 clock=time.monotonic();started=datetime.now(timezone.utc).isoformat();deadline=clock+300
 docs=BASE/'docs';prior=docs/'aidev_structured_parent_context_v050_probe.json';evidence_path=docs/'aidev_structured_parent_context_v050_evidence.jsonl'
 report_path=docs/'aidev_structured_parent_context_v050_replay.json';out_path=docs/'aidev_structured_parent_context_v050_replay_evidence.jsonl'
 for p in (report_path,out_path):
  if p.exists():raise FileExistsError('Preserve prior replay')
 old=json.loads(prior.read_text());assert digest(evidence_path)==old['evidence_sha256']
 evidence=[json.loads(line) for line in evidence_path.read_text().splitlines()]
 formal={str(p.relative_to(BASE)):digest(p) for p in list((BASE/'src/agentlog_unified').glob('*.py'))+list((BASE/'tests').glob('test_*.py'))}
 stage_before={p.name:digest(p) for p in (Path(parser.__file__),Path(taxonomy.__file__),Path(content_types.__file__))}
 groups=defaultdict(lambda:defaultdict(lambda:defaultdict(list)))
 for e in evidence:groups[e['table_path']][e['source_row']][e['column_name']].append(e)
 source=BASE/'structured-runs/aidev-v049';rows=[];counts=Counter();states=Counter();source_hashes=[];replay_cells=0;visited_nodes=0
 with (source/'.structured.lock').open('rb') as lock:
  fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
  manifest=json.loads((source/'manifest.json').read_text());assert digest(source/'manifest.json')==old['source_manifest_sha256']
  tables={t['path']:t for t in manifest['tables']};limits=manifest['fingerprint']['limits']
  for relative,targets in sorted(groups.items()):
   table=tables[relative];path=Path(table['absolute_path']);before=stat(path)
   assert digest(path)==table['sha256'] and before==stat(path)
   source_hashes.append({'table_path':relative,'sha256':table['sha256'],'bytes':table['bytes']})
   positions=sorted(targets);pos=0;base=0;columns=sorted({c for fields in targets.values() for c in fields})
   for batch in pq.ParquetFile(path).iter_batches(batch_size=256,columns=columns):
    upper=base+batch.num_rows
    while pos<len(positions) and positions[pos]<=upper:
     assert time.monotonic()<deadline,'Replay time budget reached'
     n=positions[pos];pos+=1
     for column,items in targets[n].items():
      text=batch.column(columns.index(column))[n-base-1].as_py();assert isinstance(text,str)
      result=parser.classify_structured(text,**limits);replay_cells+=1;visited_nodes+=result['counts']['nodes_visited']
      index=defaultdict(list)
      for r in result['matches']:index[(r['document_index'],tuple(r['node_path']),r['category'],r['subtype'])].append(r)
      for e in items:
       matches=index.get((e['document_index'],tuple(e['node_path']),e['category'],e['subtype']),[])
       disposition=e['disposition'];accepted=bool(matches)
       counts[(disposition,'accepted' if accepted else 'rejected')]+=1
       for m in matches:states[(disposition,m['basis'],m['candidate_status'])]+=1
       rows.append({'table_path':relative,'column_name':column,'source_row':n,'document_index':e['document_index'],'node_path':e['node_path'],'category':e['category'],'subtype':e['subtype'],'prior_disposition':disposition,'accepted':accepted,'new_matches':matches,**SCOPE})
    base=upper
    if pos==len(positions):break
   assert before==stat(path)
 assert stage_before=={name:digest(STAGE/name) for name in stage_before}
 assert formal=={rel:digest(BASE/rel) for rel in formal}
 assert digest(evidence_path)==old['evidence_sha256'] and digest(Path(old['selection_file']))==old['selection_sha256']
 supported=[r for r in rows if r['prior_disposition']=='supported_pair_pending']
 checks={'frozen16_supported_positions_all_replayed':len(supported)==16,'all_supported_positions_accepted':all(r['accepted'] for r in supported),'supported_hints_remain_low_unverified_named_and_context_based':all(all(m['basis']=='json_parent_key_hint' and m['confidence']=='low' and m['candidate_status']=='named_value_candidate' and m['value_status']=='unverified' for m in r['new_matches']) for r in supported),'all_prior46_positions_replayed':len(rows)==len(evidence)==46,'formal_source_and_tests_unchanged':True,'isolated_sources_unchanged':True,'prior_probe_selection_and_evidence_unchanged':True}
 out_path.write_text(''.join(json.dumps(r,ensure_ascii=False,sort_keys=True)+'\n' for r in rows))
 data={'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-clock,'all_checks_passed':all(checks.values()),'checks':checks,'counts':[{'prior_disposition':d,'acceptance':s,'count':n} for (d,s),n in sorted(counts.items())],'basis_and_quality_counts':[{'prior_disposition':d,'basis':b,'candidate_status':s,'count':n} for (d,b,s),n in sorted(states.items())],'selected_source_cells':replay_cells,'all_nodes_visited_in_selected_cells':visited_nodes,'frozen_evidence_rows':len(evidence),'prior_probe_sha256':digest(prior),'prior_evidence_sha256':digest(evidence_path),'new_evidence_file':str(out_path),'new_evidence_sha256':digest(out_path),'isolated_source_sha256':stage_before,'formal_source_sha256':formal,'frozen_source_files':source_hashes,'time_budget_seconds':300,'raw_values_dynamic_keys_or_value_hashes_exported':False,'source_values_read_in_memory':True,'formal_source_modified':False,'prior_outputs_modified':False,'network_accessed':False,'credentials_validated':False,'bounds':['This is a fixed 16-positive and30-unresolved position replay, not a new whole-corpus census.','Every node in the selected source cells is visited by the bounded parser; arrays/decode boundaries do not inherit outer parent context.','Acceptance means a low-confidence static key-context hint for an existing class, not a real sensitive value or runtime disclosure.'],**SCOPE}
 report_path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'report':str(report_path),'all_checks_passed':data['all_checks_passed'],'counts':data['counts'],'selected_source_cells':replay_cells,'elapsed_seconds':data['elapsed_seconds']}))
 return 0 if data['all_checks_passed'] else 1

if __name__=='__main__':raise SystemExit(run())
