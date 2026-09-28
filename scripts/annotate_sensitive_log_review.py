"""Event-level sensitivity annotations with explicit uncertainty and no raw value export."""
import collections,json,re,sys,copy
import sensitive_log_review as s
from sensitive_review_decisions import GROUP_NOTES,PILOT_APPROVED_QUEUE_INDICES
OUT=s.OUT
QUOTED=re.compile(r'(["\x27`])(?:\\.|(?!\1)[^\\])*?\1',re.S)
DIRECT=re.compile(r'\b(?:console\.(?:log|warn|error|info|debug)|logging\.[A-Za-z]+|(?:\w+\.)?(?:logger|log|slog)\.[A-Za-z]+|print|fmt\.Print[a-z]*)\s*\(')

def code_values(statement):
 # Preserve only interpolation expressions and unquoted expressions for hinting.
 templates=[]
 for m in QUOTED.finditer(statement):
  if m.group(1)=='`' or (m.start()>0 and statement[m.start()-1].lower()=='f'):
   templates+=re.findall(r'\$?\{([^{}]+)\}',m.group())
 text=QUOTED.sub(' STRING_LITERAL ',statement)+' '+' '.join(templates)
 for _ in range(3):text=re.sub(r'\b(?:len|length|count|size|str|int)\s*\([^()]*\)',' AGGREGATE ',text)
 text=re.sub(r'\b(?:file\s*=\s*)?sys\.stderr\b',' OUTPUT_CONTROL ',text)
 text=re.sub(r'\b(?:console|logging|(?:\w+\.)?(?:logger|log|slog)|zap)\.[A-Za-z_][A-Za-z0-9_]*(?=\s*\()',' LOG_CALL ',text)
 text=re.sub(r'\b[\w.]+\.(?:length|size)\b',' AGGREGATE ',text)
 text=re.sub(r'\b\w*(?:Duration|Count|Bytes|Lines|Tokens|Limit|Length|Size|Total|Millis|Ms)\b(?:\.\w+\([^)]*\))?',' AGGREGATE ',text)
 return text

def types_for(e):
 stmt='\n'.join([e['current_observation'].get('before_statement') or '',e['current_observation'].get('after_statement') or ''])
 vals=code_values(stmt);rules=[
 ('QID.session_identifier',r'(?i)\b[\w.]*session_?id\b'),
 ('QID.user_identifier',r'(?i)\buser_?id\b|\.UserID\b'),
 ('CFG.filesystem_path',r'(?i)\b[\w.]*(?:FilePath|TranscriptPath|file_path|transcript_path|working_directory)\b'),
 ('QID.request_identifier',r'(?i)\b[\w.]*(?:request_?id|trace_?id|correlation_?id)\b'),
 ('QID.unspecified_linkable_identifier',r'(?i)\b[\w.]*(?:checkpoint_?id|task_?id|issue_?id|swarm_?id)\b|\b(?:task|entInv|inv)\.ID\b'),
 ('BIZ.unclassified_object',r'(?i)\bjson\.(?:dumps|stringify)\b'),
 ('BIZ.message_content',r'(?i)\b(?:triggerPrompt|resumePrompt|conversation_history)\b|(?<![\w.])message\b|\btask\.output\b'),
 ('CFG.unclassified_internal_resource',r'(?i)\b(?:apiUrl|effectiveCwd|taskDir|folder|outputPath|inputPath)\b'),
 ('PII.email',r'(?i)\b[\w.]*email\b'),
 ('AUTH.access_token',r'(?i)\b[\w.]*(?:access_token|refresh_token|oauth_token|authToken)\b'),
 ('AUTH.api_key',r'(?i)\b[\w.]*(?:api_key|apiKey|secretKey)\b'),
 ('AUTH.password',r'(?i)\b[\w.]*(?:password|passwd)\b'),
 ('BIZ.request_body',r'(?i)\b(?:payload|requestBody|req\.body|request\.body|refusalPayload)\b'),
 ('BIZ.response_body',r'(?i)\b(?:responseBody|response\.body|response\.data)\b'),
 ('BIZ.http_headers',r'(?i)\b[\w.]*headers\b'),
 ('BIZ.document_content',r'(?i)\b(?:transcript|file_content|document_content|sessionData\.Transcript)\b'),
 ('DIAG.exception_message',r'(?i)\b(?:err|error|exception|exc|[A-Za-z_]+Err|errMsg|error_msg|preflight_error)\b|\b(?:error|err)\.message\b')]
 result=[]
 for typ,pat in rules:
  match=re.search(pat,vals)
  if match:result.append({'baseline_type':typ,'certainty':'potential_static_type','basis':'unquoted output/call expression; concrete value and runtime sensitivity unverified','expression_hint':s.redact(match.group(),True)})
 return result,vals,bool(DIRECT.search(stmt))

def safe_excerpt(source,start,end):
 text=source['text'];start=text.rfind('\n',0,start)+1;endpos=text.find('\n',end);end=len(text) if endpos<0 else endpos
 return {'original_start':start,'original_end':end,'quote_redacted':s.redact(text[start:end],True),'original_source_sha256':source['content_sha256'],'redaction':'conservative literals, credentials, URLs, contact values and opaque tokens; never raw values'}

def note_for(e):
 return next((v for k,v in GROUP_NOTES.items() if e['modification_sha'].startswith(k)),'仅对已读目标表达式和直接关联的有限材料判读；未闭合运行时值、序列化和实际写入边。')

def annotate(e,q,sources,links,batch):
 types,vals,direct=types_for(e);obs=e['current_observation'];stmt=(obs.get('before_statement') or '')+'\n'+(obs.get('after_statement') or '')
 scrub=bool(re.search(r'\b(?:scrubSecrets|redact\w*|sanitize\w*|mask\w*)\s*\(',vals,re.I))
 sensitive_types=[t for t in types if t['baseline_type'].split('.')[0] in {'AUTH','PII','QID','CFG'}]
 ids={l['evidence_id'] for l in links};material=[]
 if 'cd368fde85d16f311fc4c66a' in ids:material.append({'evidence_id':'cd368fde85d16f311fc4c66a','value_kind':'concrete_credential_like_value_in_prompt','baseline_types':['AUTH.password','PII.email'],'authenticity':'unverified','enters_target_log':'not_established','role':'session_context_not_value_flow'})
 for eid in ['aff0490286349ad8b81c922f','66bed92b082619b20d9b23a3']:
  if eid in ids:material.append({'evidence_id':eid,'value_kind':'placeholder_or_pre_redacted','baseline_types':['AUTH.api_key','AUTH.credential_bundle'],'authenticity':'underlying_value_not_available','enters_target_log':'not_established','role':'session_context_not_value_flow'})
 if not direct:assessment='output_sink_unresolved'
 elif scrub:assessment='sanitizer_call_present_effect_unverified'
 elif sensitive_types:assessment='potential_type_in_static_output'
 elif types:assessment='carrier_only_sensitive_contents_unverified'
 elif q['target_match']:assessment='concept_or_keyword_without_sensitive_value_flow'
 else:assessment='related_material_only_no_target_sensitive_value_established'
 refs=[];seen=set()
 # Preserve all relationships separately; citations are selected, scoped excerpts.
 for l in sorted(links,key=lambda l:({'prompt':0,'commit_message':1,'pr_description':2,'review_comment':3,'issue':4}[l['source_type']],l['evidence_id'])):
  eid=l['evidence_id'];source=sources[eid];eq=source['equivalence_group']
  if eq in seen:continue
  seen.add(eq);text=source['text'];hit=s.PURPOSE.search(text)
  if source['source_type']=='commit_message':start,end=0,min(len(text),450)
  elif hit:start,end=max(0,hit.start()-80),min(len(text),hit.end()+220)
  elif source['source_type'] in ('pr_description','prompt'):start,end=0,min(len(text),300)
  else:continue
  refs.append({'evidence_id':eid,'role':'context_only_not_direct_privacy_purpose',**safe_excerpt(source,start,end)})
 return {'modification_id':e['modification_id'],'queue_index':q['queue_index'],'repository':e['repository'],'modification_sha':e['modification_sha'],'parent_sha':e['parent_sha'],'file_path':e['file_path'],
  'association_event_ids':e['association_event_ids'],'stage1_log_ids':e['stage1_log_ids'],'review_state':'assistant_reviewed','reviewed_at':s.now(),'batch_id':batch,
  'prior_motive_status':e['motive_status'],'prior_motive_labels':e['motive_labels'],'sensitivity_assessment':assessment,'potential_types':types,'confirmed_actual_sensitive_value_in_target_log':False,
  'actual_runtime':'unverified','actual_exposure':'unverified','concrete_values_in_related_material':material,'source_value_authenticity':'unverified',
  'log_entry_evidence':'static_log_argument_expression' if direct else 'call_present_final_sink_unresolved',
  'sensitivity_motive_status':'unknown','observed_code_change':{'classification':obs['classification'],'before_redacted':s.redact(obs.get('before_statement'),True),'after_redacted':s.redact(obs.get('after_statement'),True),'before_lines':e['observed_change']['before_lines'],'after_lines':e['observed_change']['after_lines'],'span_corrections':e['span_corrections']},
  'explicit_sensitive_purpose':None,'contextual_inference':note_for(e),'unknown_reason':'No directly corresponding evidence establishing this target log change as sensitive-value removal or disclosure; static names/context do not establish actual values.',
  'novelty':'no_new_type_established','taxonomy_baseline':'1.2.0','sanitizer_seen':scrub,'sanitizer_effectiveness':'unverified' if scrub else 'not_assessed',
  'source_conflict_scope':'storage_redaction_claims_and_rebuttals_not_this_log' if e['modification_sha'].startswith('f446dcfc') else 'no_opposed_target_log_purpose_established_in_read_material',
  'citations':refs,'evidence_ids':sorted(ids),'source_coverage':sorted({l['source_type'] for l in links}),
  'review_scope':'assistant conservative static review of guarded target expressions, diff observations and selected associated excerpts; not independent evaluation, not runtime confirmation'}

def validate(rows,events,sources,edges):
 catalog=json.loads((OUT/'taxonomy_baseline.json').read_text());allowed={x['category']+'.'+x['subtype'] for x in catalog['subtypes']}
 assert len({r['modification_id'] for r in rows})==len(rows)
 for r in rows:
  e=events[r['modification_id']];assert all(r[k]==e[k] for k in ('repository','modification_sha','file_path','association_event_ids','stage1_log_ids'))
  assert all(t['baseline_type'] in allowed for t in r['potential_types'])
  for c in r['citations']:
   assert any(l['evidence_id']==c['evidence_id'] for l in edges[r['modification_id']]);v=sources[c['evidence_id']]
   assert c['quote_redacted']==s.redact(v['text'][c['original_start']:c['original_end']],True)
  assert r['actual_runtime']=='unverified' and r['actual_exposure']=='unverified'
  assert r['review_state']=='assistant_reviewed'
 # Observed sensitive-looking literal is checked in memory without exporting it.
 v=sources.get('cd368fde85d16f311fc4c66a',{}).get('text','');tail=v.strip().split()[-1] if v else ''
 if len(tail)>8:assert tail not in json.dumps(rows,ensure_ascii=False),'redaction_leak_detected'
 return {'status':'PASS','events':len(rows),'at':s.now(),'checks':['unique_event_ids','unchanged_event_and_candidate_links','baseline_types_only','redacted_excerpt_replay','evidence_links','no_claimed_runtime_exposure','known_concrete_value_not_exported'],'independent_evaluation':False}

def pilot(revision=False):
 ev,sources,edges,contexts=s.load();events={e['modification_id']:e for e in ev};q=s.read(OUT/'review_queue.jsonl');rows=[]
 for r in q:
  if r['queue_index'] in PILOT_APPROVED_QUEUE_INDICES:rows.append(annotate(events[r['modification_id']],r,sources,edges[r['modification_id']],'001_pilot_v3' if revision else '001_pilot'))
 receipt=validate(rows,events,sources,edges);p=OUT/('batches/001_pilot_v3' if revision else 'batches/001_pilot');p.mkdir(parents=True,exist_ok=False)
 s.lines(p/'reviews.jsonl',rows);s.write(p/'validation.json',receipt)
 s.write(p/'review_notes.json',{'at':s.now(),'reviewer':'assistant','rereview':'all 40 target expressions and scoped citations read; prior-stage motive retained','corrections':['free-form credential masking strengthened before export','source redaction/storage claims separated from target log statements','counts and durations not transcript contents','source conflict scope separated from log-purpose conflict'],'independent_evaluation':False})
 s.write(OUT/'progress.json',{'at':s.now(),'phase':'pilot_validated','screened':1757,'selected':len(q),'reviewed':len(rows),'pending':len(q)-len(rows),'pilot':40})
 print('pilot',len(rows),'PASS',collections.Counter(x['sensitivity_assessment'] for x in rows))
if __name__=='__main__':pilot('--revision' in sys.argv)
