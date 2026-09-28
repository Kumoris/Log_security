"""Bounded evidence probe of fixed personal-attribute keys; not a classifier change."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import fcntl
import hashlib
import json
import re
import sqlite3
import sys
import time

import pyarrow.parquet as pq
from agentlog_unified import aidev, content_scan, content_repair, content_types, taxonomy

ROOT=Path(__file__).resolve().parents[1]
LABELS=('birth_date','age','sex_gender','ethnicity_race','religion_belief','political_opinion','sexual_orientation','education_history','employment_profile')
# Only these spellings may select a field. Generic age/race/job/class are excluded.
BARE={
 'birth_date':('date_of_birth','birth_date','birthdate','dob','出生日期'),
 'age':('age_in_years','年龄'),
 'sex_gender':('gender','biological_sex','gender_identity','性别'),
 'ethnicity_race':('ethnicity','ethnic_origin','racial_identity','种族','民族'),
 'religion_belief':('religion','religious_belief','religious_affiliation','宗教信仰'),
 'political_opinion':('political_opinion','political_views','political_affiliation','政治观点','政治倾向'),
 'sexual_orientation':('sexual_orientation','性取向'),
 'education_history':('education_level','educational_attainment','education_history','highest_degree','学历','教育经历'),
 'employment_profile':('employment_status','employment_history','employer_name','occupation','就业状况','职业'),
}
PERSON_PREFIX=('person','personal','user','patient','employee','customer','member','applicant','candidate','profile','student')
SCOPED={**BARE,'age':('age',),'ethnicity_race':('race','ethnicity'),'education_history':('education','school','degree','education_level'),
        'employment_profile':('job_title','employer','employment','occupation','employment_status')}
def norm(s):return re.sub(r'[_.-]','',s).lower()
KEYS={norm(k):(label,'explicit_attribute_name') for label,keys in BARE.items() for k in keys}
for label,keys in SCOPED.items():
 for prefix in PERSON_PREFIX:
  for key in keys:KEYS[norm(prefix+key)]=(label,'explicit_person_scoped_attribute')
KEY=re.compile(r'''(?<![\w./-])(?P<quote>["']?)(?P<key>[^\W\d][\w.-]{0,95})(?P=quote)[ \t]{0,16}(?P<operator>[:=])(?![:=>])[ \t]{0,16}(?P<value>"(?:[^"\\\n]|\\.){0,4096}"|'(?:[^'\\\n]|\\.){0,4096}'|[^\s,;"']{1,256})''',re.I)
NUMBER=re.compile(r'-?\d+(?:\.\d+)?\Z')
DATE=re.compile(r'\d{4}[-/]\d{1,2}[-/]\d{1,2}\Z')
TYPE_WORDS={'int','integer','float','double','str','string','number','bool','boolean','date','datetime','any','object','optional'}
MAX_CHARS=1048576
QUALITY={'explicit_literal_value','unquoted_literal_value','unquoted_identifier_ambiguous','reference_or_expression','type_declaration','empty_value','null_value','placeholder_or_example','container_not_scalar'}


def scan_text(text):
 for m in KEY.finditer(text):
  if norm(m['key']) not in KEYS:continue
  label,key_role=KEYS[norm(m['key'])];raw=m['value'];start,end=m.span('value')
  quoted=len(raw)>1 and raw[0] in "\"'" and raw[-1]==raw[0]
  value=raw[1:-1] if quoted else raw.rstrip('}])')
  if quoted:start+=1;end-=1
  else:end=start+len(value)
  if not value.strip():quality='empty_value'
  elif not quoted and value.lower() in {'none','null','nil'}:quality='null_value'
  elif content_types._example(text,start,end) or value.lower() in {'yyyy-mm-dd','yyyy/mm/dd','dd/mm/yyyy','mm/dd/yyyy'}:quality='placeholder_or_example'
  elif value.startswith(('{','[','(','${','$')) or content_types._TEMPLATE.search(value):quality='container_not_scalar' if value.startswith(('{','[')) else 'reference_or_expression'
  elif value.lower() in TYPE_WORDS:quality='type_declaration'
  elif quoted:quality='explicit_literal_value'
  elif NUMBER.fullmatch(value) or DATE.fullmatch(value) or value in {'true','false','True','False'}:quality='unquoted_literal_value'
  elif content_types._REFERENCE.fullmatch(value):quality='unquoted_identifier_ambiguous' if '.' not in value else 'reference_or_expression'
  else:quality='reference_or_expression'
  yield {'semantic_label':label,'key_role':key_role,'evidence_kind':quality,'key_start':m.start('key'),'key_end':m.end('key'),'value_start':start,'value_end':end,
         'existing_taxonomy_key_hint':bool(taxonomy._matches(m['key']))}


def self_test():
 cases=[('dateOfBirth="2001-02-03"','birth_date','explicit_literal_value'),('user.age=27','age','unquoted_literal_value'),
        ('race="human"',None,None),('job="build"',None,None),('class="widget"',None,None),('age=9',None,None),
        ('personRace="placeholder"','ethnicity_race','placeholder_or_example'),('gender: string','sex_gender','type_declaration'),
        ('religion=null','religion_belief','null_value'),('sexual_orientation=""','sexual_orientation','empty_value'),
        ('employmentStatus=user.status','employment_profile','reference_or_expression'),('political_views="redacted"','political_opinion','placeholder_or_example'),
        ('educationLevel="graduate"','education_history','explicit_literal_value'),('Discuss gender and education',None,None),('gender == \"female\"',None,None),('gender => value',None,None),('dob=\"YYYY-MM-DD\"','birth_date','placeholder_or_example'),('gender=\"string\"','sex_gender','type_declaration')]
 for text,label,quality in cases:
  actual=list(scan_text(text));assert bool(actual)==bool(label)
  if label:assert actual[0]['semantic_label']==label and actual[0]['evidence_kind']==quality
 print(json.dumps({'synthetic_checks':len(cases),'all_passed':True}))


def main():
 started=time.monotonic();started_utc=datetime.now(timezone.utc).isoformat();deadline=started+300
 parent=ROOT/'content-runs/aidev-v044';imported=ROOT/'inputs/aidev-full-v2';docs=ROOT/'docs'
 dataset,manifest_sha,tables=content_scan._inventory(imported);assert dataset=='aidev'
 sources={t['path']:t for t in tables};source_stats={t['path']:tuple(t['source_stat']) for t in tables}
 code_paths=[Path(m.__file__) for m in (aidev,content_scan,content_repair,content_types,taxonomy)]
 code_sha={p.name:content_repair._digest(p) for p in code_paths}
 sample_cells=[]
 with (parent/'.content.lock').open('rb') as handle:
  fcntl.flock(handle,fcntl.LOCK_SH|fcntl.LOCK_NB)
  pm=json.loads((parent/'manifest.json').read_text());assert pm['source_manifest_sha256']==manifest_sha
  with sqlite3.connect((parent/'content.sqlite').as_uri()+'?mode=ro&immutable=1',uri=True) as db:
   db.row_factory=sqlite3.Row
   for row in db.execute("SELECT DISTINCT c.id,c.table_path,c.source_row,c.column_name FROM matches m JOIN cells c ON c.id=m.cell_id WHERE m.excluded=0 AND m.category IS NULL AND json_extract(m.details,'$.candidate_status')='unknown_named_value' ORDER BY c.table_path,c.source_row,c.column_name"):
    sample_cells.append(dict(row))
 inventory={(t['path'],f['column']):t['rows'] for t in tables for f in t['columns'] if f['selected'] and f['column'] in aidev.CONTENT_FIELDS}
 stats=Counter();sample_stats=Counter();counts=Counter();sample_counts=Counter();coverage=[];evidence=[]
 def inspect(cell,text,phase):
  target=sample_stats if phase=='unknown_named_sample' else stats
  target['source_cells_examined']+=1;target['characters_seen']+=len(text);target['characters_examined']+=min(len(text),MAX_CHARS)
  target['truncated_source_cells']+=int(len(text)>MAX_CHARS)
  for item in scan_text(text[:MAX_CHARS]):
   target['field_assignments']+=1;(sample_counts if phase=='unknown_named_sample' else counts)[item['semantic_label'],item['evidence_kind']]+=1
   evidence.append({'phase':phase,'table_path':cell['table_path'],'column_name':cell['column_name'],'source_row':cell['source_row'],**item,
    'human_review_status':'pending','personal_ownership_confirmed':False,'sensitivity_confirmed':False,'runtime_confirmed':False,'taxonomy_change_applied':False})
 sample_deadline=min(deadline,started+30);sample_stop=None
 try:
  for cell,value,path,before in content_repair._selected_values(sample_cells[:32],sources,sample_deadline,source_stats):
   inspect(cell,value,'unknown_named_sample')
 except content_repair._BudgetExpired:sample_stop='time_budget'
 print(json.dumps({'phase':'unknown_named_sample','available_source_cells':len(sample_cells),'requested_source_cells':min(32,len(sample_cells)),'stats':dict(sample_stats),'counts':[{'semantic_label':a,'evidence_kind':b,'count':n} for (a,b),n in sorted(sample_counts.items())],'stop_reason':sample_stop}),flush=True)
 stop=None
 for t in tables:
  columns=[f['column'] for f in t['columns'] if f['selected'] and f['column'] in aidev.CONTENT_FIELDS]
  if not columns:continue
  seen=0;table_stats=Counter();path=Path(t['absolute_path']);parquet=pq.ParquetFile(path)
  for batch in parquet.iter_batches(batch_size=256,columns=columns,use_threads=False):
   if time.monotonic()>=deadline:stop='time_budget';break
   for raw in batch.to_pylist():
    if time.monotonic()>=deadline:stop='time_budget';break
    seen+=1
    for column in columns:
     value=raw[column];stats['source_cells_visited']+=1
     if value is None:stats['null_cells']+=1;continue
     if not value.strip():stats['empty_cells']+=1;continue
     inspect({'table_path':t['path'],'column_name':column,'source_row':seen},value,'body_field_scan')
   if stop:break
  assert content_scan._stat(path)==source_stats[t['path']]
  coverage.append({'table_path':t['path'],'columns':columns,'source_rows':t['rows'],'visited_rows':seen,'source_cells_visited':seen*len(columns),'complete':seen==t['rows']})
  print(json.dumps({'phase':'body_field_scan','table_path':t['path'],'visited_rows':seen,'total_rows':t['rows'],'field_assignments':stats['field_assignments'],'elapsed_seconds':round(time.monotonic()-started,2),'by_semantic_label':dict(Counter({label:sum(n for (a,_),n in counts.items() if a==label) for label in LABELS}))}),flush=True)
  if stop:break
 assert all(content_scan._stat(Path(t['absolute_path']))==source_stats[t['path']] for t in tables)
 assert content_repair._digest(imported/'manifest.json')==manifest_sha
 assert code_sha=={p.name:content_repair._digest(p) for p in code_paths}
 all_visited=sum(r['source_cells_visited'] for r in coverage)==sum(inventory.values())
 source_cells_by_label=defaultdict(set)
 for e in evidence:
  if e['phase']=='body_field_scan':source_cells_by_label[e['semantic_label']].add((e['table_path'],e['column_name'],e['source_row']))
 summary=[{'semantic_label':label,'field_assignment_count':sum(n for (a,_),n in counts.items() if a==label),
           'source_cells':len(source_cells_by_label[label]),'quality_counts':{kind:counts.get((label,kind),0) for kind in sorted(QUALITY)}} for label in LABELS]
 evidence_path=docs/'personal_attribute_probe_v049_evidence.jsonl'
 with evidence_path.open('w') as stream:
  for e in evidence:stream.write(json.dumps(e,ensure_ascii=False,sort_keys=True)+'\n')
 report={'started_utc':started_utc,'completed_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':round(time.monotonic()-started,3),
  'command':[sys.executable,str(Path(__file__).resolve())],'helper_sha256':content_repair._digest(Path(__file__)),'time_budget_seconds':300,
  'source_manifest_sha256':manifest_sha,'source_code_sha256':code_sha,'frozen_source_inputs':[{k:t[k] for k in ('path','bytes','sha256')} for t in tables],
  'source_inputs_unchanged':True,'unknown_named_available_cells':len(sample_cells),'unknown_named_sample_requested':min(32,len(sample_cells)),
  'unknown_named_sample_stats':dict(sample_stats),'unknown_named_sample_stop_reason':sample_stop,
  'unknown_named_sample_label_counts':[{'semantic_label':a,'evidence_kind':b,'count':n} for (a,b),n in sorted(sample_counts.items())],
  'full_scan_attempts':1,'selected_body_field_count':len(inventory),'source_cell_denominator':sum(inventory.values()),'scan_stats':dict(stats),'coverage':coverage,
  'all_selected_body_rows_visited':all_visited,'stop_reason':stop,'type_probe_summary':summary,'evidence_records':len(evidence),
  'evidence_path':evidence_path.name,'evidence_sha256':content_repair._digest(evidence_path),'ordinary_prose_mentions_counted':False,
  'source_values_exported':False,'dynamic_keys_exported':False,'value_hashes_exported':False,'source_or_package_modified':False,'network_accessed':False,
  'human_review_status':'pending','new_sensitive_type_established':False,'runtime_confirmed':False,'personal_ownership_confirmed':False,
  'limitations':['Only this fixed spelling set and scalar key:value/key=value forms were probed; no completeness claim about unknown types.',
   'The old unknown_named_value queue only includes generic personal/sensitive keys and cannot represent never-recognized personal attributes.',
   'Quoted/numeric literal assignments are static field-value evidence in code or prose, not confirmed records about real people; fixtures and placeholders remain distinct.',
   'Generic job/race/class/age keys and ordinary mentions do not count as personal-attribute evidence. Chinese and explicit compound/personal-scoped spellings are finite.',
   'Values beyond a 1MiB cell prefix and quoted values beyond the 4096-character recognizer bound remain unexamined; no raw values or dynamic keys are exported.',
   'Unknown sample and body scan phases can revisit the same source cell; phase counts must not be added. Source rows may repeat the same PR across dataset tables.']}
 out=docs/'personal_attribute_probe_v049.json';out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'report':str(out),'all_body_rows_visited':all_visited,'stats':dict(stats),'summary':summary},ensure_ascii=False),flush=True)


if __name__=='__main__':self_test() if sys.argv[1:]==['--self-test'] else main()
