"""Bounded AIDev JSON-format comparison. Original values and dynamic keys never leave memory."""
from pathlib import Path
from collections import Counter
from datetime import datetime,timezone
import argparse,hashlib,json,re,time
import pyarrow.parquet as pq
from agentlog_unified import content_types as ct
ROOT=Path('/Users/lzh/Downloads/Log 研究/agentlog_unified')
TABLES=('issue','pr_comments','pr_reviews')
LIMIT=1048576
MAX_DOCUMENTS=128
MAX_NODES=4096
MAX_DEPTH=12
MAX_LEAF=65536
FENCE=re.compile(r'(?m)^[ \t]{0,8}```(?:json|JSON)[ \t]*\r?\n([\s\S]*?)^[ \t]{0,8}```[ \t]*(?:\n|$)')

def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
 return h.hexdigest()
def stat(p):
 s=p.stat();return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def ordered(values):return [list(k) for k in sorted(values)]
def labels(rows,example=False):
 return {(r['category'],r['subtype']) for r in rows if r['category'] is not None and (r['candidate_status']=='placeholder_or_example')==example}

def decode(document):
 duplicates=0
 def pairs(items):
  nonlocal duplicates
  d={}
  for k,v in items:
   if k in d:duplicates+=1
   d[k]=v
  return d
 def invalid(_):raise ValueError('nonstandard_json_constant')
 try:
  obj=json.loads(document,object_pairs_hook=pairs,parse_constant=invalid);layers=1
  if isinstance(obj,str) and obj.lstrip().startswith(('{','[')):
   obj=json.loads(obj,object_pairs_hook=pairs,parse_constant=invalid);layers=2
 except (ValueError,RecursionError):return {'format':'invalid_strict_json','gaps':['strict_json_parse_failed']},set(),set(),set(),set()
 if duplicates:return {'format':'duplicate_json_keys','duplicate_keys':duplicates,'gaps':['duplicate_keys_semantics_unresolved']},set(),set(),set(),set()
 hints=set();literal=set();hint_examples=set();literal_examples=set();counts=Counter();gaps=set();stack=[(obj,0)]
 while stack and counts['nodes_visited']<MAX_NODES:
  item,depth=stack.pop();counts['nodes_visited']+=1
  if depth>MAX_DEPTH:gaps.add('json_depth_budget');continue
  if isinstance(item,dict):
   for k,v in item.items():
    counts['object_member_occurrences']+=1
    if len(k)>96:gaps.add('key_character_budget')
    else:
     matches=ct._matches(k)
     if matches:
      if v is None or isinstance(v,str) and not v.strip():
       counts['finite_key_null_or_empty_values_unresolved']+=1
       stack.append((v,depth+1));continue
      counts['finite_key_hint_occurrences']+=len(matches)
      target=hint_examples if isinstance(v,str) and ct._example(v,0,len(v)) else hints
      target.update((r[0],r[1]) for r in matches)
     else:counts['unknown_key_occurrences_not_exported']+=1
    stack.append((v,depth+1))
  elif isinstance(item,list):stack.extend((v,depth+1) for v in item)
  elif isinstance(item,str):
   counts['string_leaves']+=1
   if len(item)>MAX_LEAF:gaps.add('string_leaf_character_budget');continue
   observations=list(ct._literal_candidates(item))
   literal.update(labels(observations));literal_examples.update(labels(observations,True))
   counts['literal_shape_observations']+=len(observations)
   if item.lstrip().startswith(('{','[')):counts['nested_encoded_strings_not_recursively_decoded']+=1
 if stack:gaps.add('json_node_budget')
 return {'format':'strict_json_'+('object' if isinstance(obj,dict) else 'array' if isinstance(obj,list) else 'scalar'),'decoded_layers':layers,'counts':dict(counts),'gaps':sorted(gaps)},hints,literal,hint_examples,literal_examples

def documents(text):
 stripped=text.strip()
 if stripped[:1] in ('{','[','"'):
  start=len(text)-len(text.lstrip());yield 'whole_cell_json_candidate',(start,start+len(stripped)),stripped
 for m in FENCE.finditer(text):yield 'explicit_json_fence',m.span(1),m.group(1)

def self_test():
 a,h,l,he,le=decode(r'{"e\u006dail":"fixture\u0040example.invalid"}')
 assert a['format']=='strict_json_object' and ('PII','email') in h|he
 assert ('PII','email') not in labels(ct.classify_text(r'{"e\u006dail":"fixture\u0040example.invalid"}')['matches'])
 assert decode('{"x":1,"x":2}')[0]['format']=='duplicate_json_keys'
 assert decode('{"x":NaN}')[0]['format']=='invalid_strict_json'
 assert 'DYNAMIC_KEY' not in json.dumps(decode('{"DYNAMIC_KEY":"NEVER EXPORT"}')[0])
 assert decode(json.dumps('{"session_id":"fixture"}'))[0]['decoded_layers']==2
 assert list(documents('```json\n{}\n```\n'))[0][1]==(8,11)
 return 7

def main():
 n=self_test()
 if '--self-test' in __import__('sys').argv:
  print(json.dumps({'synthetic_assertions_passed':n,'real_source_read':False}));return
 started=datetime.now(timezone.utc).isoformat();clock=time.monotonic();deadline=clock+120
 manifest_path=ROOT/'inputs/aidev-full-v2/manifest.json';manifest=json.loads(manifest_path.read_text())
 inputs={r['path']:r for r in manifest['source_signature']['inputs']};field_results=[];document_rows=[];gap_rows=[];hashes_before={f.name:digest(f) for f in (Path(ct.__file__),Path(ct.__file__).with_name('taxonomy.py'))}
 allcomplete=True
 for table in TABLES:
  relative=table+'.parquet';path=ROOT/'cache/aidev-frozen'/relative;before=stat(path)
  assert digest(path)==inputs[relative]['sha256'] and before[2]==inputs[relative]['bytes']
  parquet=pq.ParquetFile(path);assert str(parquet.schema_arrow.field('body').type)=='string'
  counts=Counter();byraw=Counter();bykey=Counter();byleaf=Counter();byadded=Counter();byaddedleaf=Counter();end_row=0
  for batch in parquet.iter_batches(columns=['body'],batch_size=64,use_threads=False):
   for text in batch.column(0).to_pylist():
    if time.monotonic()>=deadline:break
    end_row+=1;counts['source_cells_decoded']+=1
    if text is None:counts['null_cells']+=1;continue
    if not isinstance(text,str):counts['non_string_unresolved']+=1;continue
    if not text.strip():counts['empty_cells']+=1;continue
    counts['nonempty_text_cells']+=1;original_chars=len(text);text=text[:LIMIT]
    capped_chars=original_chars>LIMIT
    if capped_chars:
     counts['source_character_capped_cells']+=1;gap_rows.append({'table_path':relative,'column_name':'body','source_row':end_row,'reason':'source_character_budget','characters':original_chars,'characters_processed':len(text)})
    raw=ct.classify_text(text,max_matches=1000);rawlabels=labels(raw['matches']);byraw.update(rawlabels)
    if raw['truncated']:counts['raw_match_cap_cells']+=1
    doc_count=0;cellkey=set();cellleaf=set();celladded=set();celladdedleaf=set()
    for origin,span,payload in documents(text):
     if doc_count>=MAX_DOCUMENTS:
      counts['document_capped_cells']+=1;gap_rows.append({'table_path':relative,'column_name':'body','source_row':end_row,'reason':'document_budget','documents_processed':doc_count});break
     doc_count+=1;counts['documents_attempted']+=1
     meta,hints,literal,hint_examples,literal_examples=decode(payload)
     counts['documents_'+meta['format']]+=1
     added=(hints|literal)-rawlabels;addedleaf=literal-rawlabels
     cellkey.update(hints);cellleaf.update(literal);celladded.update(added);celladdedleaf.update(addedleaf)
     if added:counts['documents_with_added_labels']+=1
     if addedleaf:counts['documents_with_added_literal_shapes']+=1
     document_rows.append({'table_path':relative,'column_name':'body','source_row':end_row,'document_index':doc_count,'document_origin':origin,'document_span':list(span),'offset_unit':'unicode_characters_half_open','raw_text_character_capped':capped_chars,'raw_text_match_capped':raw['truncated'],**meta,'raw_text_finite_labels':ordered(rawlabels),'decoded_key_hint_labels':ordered(hints),'decoded_string_literal_shape_labels':ordered(literal),'decoded_key_example_labels':ordered(hint_examples),'decoded_string_example_shape_labels':ordered(literal_examples),'added_labels_vs_raw_text':ordered(added),'added_literal_shape_labels_vs_raw_text':ordered(addedleaf)})
    if doc_count:counts['cells_with_documents']+=1
    if celladded:counts['cells_with_added_labels']+=1
    if celladdedleaf:counts['cells_with_added_literal_shapes']+=1
    bykey.update(cellkey);byleaf.update(cellleaf);byadded.update(celladded);byaddedleaf.update(celladdedleaf)
   if time.monotonic()>=deadline:break
  complete=end_row==parquet.metadata.num_rows;allcomplete&=complete
  assert before==stat(path)
  field_results.append({'table_path':relative,'column_name':'body','source_rows':parquet.metadata.num_rows,'processed_source_range':[1,end_row] if end_row else None,'all_source_rows_visited':complete,'unprocessed_source_rows':parquet.metadata.num_rows-end_row,'counts':dict(counts),'per_type_source_cell_counts':{kind:[{'category':c,'subtype':s,'source_cells':n} for (c,s),n in sorted(v.items())] for kind,v in [('raw_finite_labels',byraw),('decoded_key_hints',bykey),('decoded_leaf_shapes',byleaf),('added_labels',byadded),('added_leaf_shapes',byaddedleaf)]},'source_sha256_verified':inputs[relative]['sha256'],'source_stat_before':list(before),'source_stat_after':list(stat(path))})
  print(json.dumps({'table':table,'rows_visited':end_row,'all_rows':complete,'documents':counts['documents_attempted'],'added_label_cells':counts['cells_with_added_labels'],'added_shape_cells':counts['cells_with_added_literal_shapes'],'elapsed_seconds':round(time.monotonic()-clock,3)}),flush=True)
 hashes_after={f.name:digest(f) for f in (Path(ct.__file__),Path(ct.__file__).with_name('taxonomy.py'))};assert hashes_before==hashes_after
 report={'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-clock,'time_budget_seconds':120,'all_three_columns_source_rows_visited':allcomplete,'dataset':'aidev','observation_scope':'dataset_structured_text_probe','source_manifest_path':str(manifest_path),'source_manifest_sha256':digest(manifest_path),'fields':field_results,'documents':document_rows,'source_cell_budget_gaps':gap_rows,'limits':{'max_source_characters_per_cell':LIMIT,'max_documents_per_cell':MAX_DOCUMENTS,'raw_match_cap':1000,'max_json_nodes':MAX_NODES,'max_json_depth':MAX_DEPTH,'max_decoded_string_leaf_characters':MAX_LEAF,'max_top_level_json_string_layers':2},'format_definition':'Whole-cell JSON candidates and explicit json/JSON triple-backtick Markdown blocks only. Strict JSON rejects duplicate keys, NaN/Infinity and invalid syntax. Nested encoded strings are counted but not recursively decoded.','comparison_definition':'Per source cell finite label sets; original-text labels are from capped content_types.classify_text. Decoded key hints use its finite taxonomy, decoded string leaves use its literal-shape generator. Example-shaped hints/leaves are retained separately. Added labels mean representation/rule evidence beyond the capped original text, not new true sensitive types.','semantic_boundaries':['Decoded key hints do not establish value type, ownership, credential validity, or leakage.','Code/config location fields and general object carriers remain ambiguous; labels are weak candidates.','No document is selected using sensitive words; all requested source rows enter the pipeline.','Decoded coordinates are not substituted for raw text offsets; evidence points to enclosing raw JSON document span.','Source rows, document counts, per-type source-cell counts and leaf observations are separate units.','Character/match/document/node/depth budgets and unparsed representations remain unresolved.'], 'code_sha256_before':hashes_before,'code_sha256_after':hashes_after,'source_code_unchanged':True,'helper_path':str(Path(__file__)),'helper_sha256':digest(Path(__file__)),'command':['agent_log_privacy/.venv/bin/python',str(Path(__file__))],'synthetic_assertions_passed':n,'raw_values_dynamic_keys_value_hashes_exported':False,'network_accessed':False,'shared_databases_accessed':False,'package_source_modified':False,'existing_outputs_modified':False,'application_log_evidence':False,'human_review_status':'pending','new_sensitive_type_confirmed':False,'runtime_confirmed':False,'exit_code':0 if allcomplete else 2}
 out=ROOT/'docs/aidev_structured_probe_v048.json';assert not out.exists();out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'report':str(out),'all_rows_visited':allcomplete,'documents':len(document_rows),'source_cells':sum(f['counts']['source_cells_decoded'] for f in field_results),'elapsed_seconds':report['elapsed_seconds'],'exit_code':report['exit_code']}));raise SystemExit(report['exit_code'])
if __name__=='__main__':main()
