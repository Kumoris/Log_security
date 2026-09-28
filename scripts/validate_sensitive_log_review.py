"""Adversarial contracts and immutable-input checks for the redacted audit."""
import collections,copy,hashlib,json,re
import sensitive_log_review as s
from annotate_sensitive_log_review import validate,safe_excerpt,types_for
from run_sensitive_review_batches import run

def contract(rows,expected_ids):
 assert len(rows)==len(expected_ids) and {r['modification_id'] for r in rows}==expected_ids
 for r in rows:
  state=r['sensitivity_motive_status'];assert r['review_state']=='assistant_reviewed'
  assert state in {'explicit','inferred','unknown','conflicting'}
  if state=='unknown':assert r['unknown_reason_codes']
  if state=='explicit':assert r['explicit_sensitive_purpose'] and any(c['role']=='direct_privacy_purpose_support' for c in r['citations'])
  if state=='inferred':assert r['privacy_purpose_inference'] and any(c['role']=='privacy_inference_support' for c in r['citations'])
  if state=='conflicting':assert len(r.get('direct_opposed_privacy_claims',[]))>=2
  assert r['novelty']=='no_new_type_established' and not r['confirmed_actual_sensitive_value_in_target_log']
 return True

def main():
 delivery=s.OUT/'delivery';rows=s.read(delivery/'reviews.jsonl');ee,src,edges,ctx=s.load();events={r['modification_id']:r for r in ee};expected={r['modification_id'] for r in s.read(s.OUT/'review_queue.jsonl')}
 tests=[]
 def check(name,f):assert f(),name;tests.append({'test':name,'status':'PASS'})
 def rejects(f):
  try:f()
  except (AssertionError,KeyError,ValueError):return True
  return False
 check('all_selected_exactly_once',lambda:contract(rows,expected))
 check('valid_rows_accepted_by_same_validator',lambda:validate(rows,events,src,edges)['status']=='PASS')
 check('missing_event_rejected',lambda:rejects(lambda:contract(rows[1:],expected)))
 check('duplicate_event_rejected',lambda:rejects(lambda:contract(rows+[rows[0]],expected)))
 for field,bad in [('modification_sha','0'*40),('file_path','wrong/path'),('association_event_ids',[])]:
  r=copy.deepcopy(rows[0]);r[field]=bad
  check('wrong_'+field+'_rejected',lambda r=r:rejects(lambda:validate([r],events,src,edges)))
 r=copy.deepcopy(rows[0]);r['citations'][0]['quote_redacted']+=' edited'
 check('tampered_quote_rejected',lambda:rejects(lambda:validate([r],events,src,edges)))
 r=copy.deepcopy(rows[0]);r['citations'][0]['evidence_id']='unlinked-source'
 check('unlinked_evidence_rejected',lambda:rejects(lambda:validate([r],events,src,edges)))
 for state in ['explicit','inferred','conflicting']:
  r=copy.deepcopy(rows[0]);r['sensitivity_motive_status']=state
  check('unsupported_'+state+'_rejected',lambda r=r:rejects(lambda:contract([r],{r['modification_id']})))
 check('source_context_conflict_not_target_conflict',lambda:all(r['sensitivity_motive_status']!='conflicting' for r in rows if r['source_conflict_scope']=='storage_redaction_claims_and_rebuttals_not_this_log'))
 check('missing_prompt_event_retained_unknown',lambda:any('prompt' not in r['source_coverage'] and r['sensitivity_motive_status']=='unknown' for r in rows))
 check('all_unselected_remain_unreviewed_null',lambda:all(r['review_state']=='not_selected_not_reviewed' and r['sensitivity_motive_status'] is None for r in s.read(delivery/'all_event_screening.jsonl') if not r['selected']))
 synthetic=['SyntheticPass9','Bearer abcdefghijklmnop','person@example.test','custom://test-user:SyntheticPass9@example.test/path','/home/testperson/private-file']
 for n,value in enumerate(synthetic):check(f'synthetic_redaction_{n+1}',lambda value=value:value not in s.redact(value,True))
 mock={'text':'prefix\ncustom://test-user:SyntheticPass9@example.test/segment\nsuffix','content_sha256':'synthetic'}
 check('clipped_excerpt_expands_before_redaction',lambda:'SyntheticPass9' not in safe_excerpt(mock,15,25)['quote_redacted'])
 def hints(statement):return {r['baseline_type'] for r in types_for({'current_observation':{'before_statement':statement,'after_statement':statement}})[0]}
 check('stderr_control_not_error_value',lambda:'DIAG.exception_message' not in hints('print("fixed", file=sys.stderr)'))
 check('error_callee_not_error_value',lambda:'DIAG.exception_message' not in hints('log.Error("fixed")'))
 check('token_count_not_auth_token',lambda:not any(t.startswith('AUTH.') for t in hints('logger.info(total_tokens)')))
 byq={r['queue_index']:r for r in rows}
 check('payload_keys_not_body_value',lambda:'BIZ.request_body' not in {t['baseline_type'] for t in byq[54]['potential_types']})
 check('api_public_id_not_key_secret',lambda:'AUTH.api_key' not in {t['baseline_type'] for t in byq[276]['potential_types']})
 check('signature_value_and_presence_distinguished',lambda:byq[491]['value_kind']!=byq[492]['value_kind'] and not byq[491]['confirmed_actual_sensitive_value_in_target_log'])
 check('error_message_not_business_chat',lambda:all('BIZ.message_content' not in {t['baseline_type'] for t in byq[q]['potential_types']} for q in [47,51,462,463]))
 check('refusal_payload_direction_unproven',lambda:'BIZ.request_body' not in {t['baseline_type'] for t in byq[88]['potential_types']})
 evidence=s.read(delivery/'evidence_redacted.jsonl');stats=json.loads((delivery/'statistics.json').read_text())
 check('source_equivalence_count_reproduces',lambda:len({r['equivalence_group'] for r in evidence})==stats['equivalent_unique_sources'])
 check('original_source_hashes_match',lambda:all(hashlib.sha256(src[r['evidence_id']]['text'].encode()).hexdigest()==r['source_content_sha256'] for r in evidence))
 # Scan every current task output (including superseded masked trial files) without exposing the known value.
 secret=src['cd368fde85d16f311fc4c66a']['text'].strip().split()[-1]
 scanned=0
 for path in s.OUT.rglob('*'):
  if path.is_file() and path.suffix in {'.json','.jsonl','.csv','.md','.html'}:
   assert secret.encode() not in path.read_bytes(),'known_literal_found';scanned+=1
 check('known_observed_literal_absent_from_all_new_files',lambda:scanned>0)
 oldhashes={str(p.relative_to(s.OUT)):s.sha(p) for p in (s.OUT/'batches').rglob('*') if p.is_file()}
 run()
 newhashes={str(p.relative_to(s.OUT)):s.sha(p) for p in (s.OUT/'batches').rglob('*') if p.is_file()}
 check('actual_resume_creates_no_batches_changes_no_files',lambda:oldhashes==newhashes)
 frozen=json.loads((s.OUT/'input_hashes.json').read_text())
 check('all_9_original_inputs_unchanged',lambda:all(s.sha(s.ROOT/k)==v for k,v in frozen.items()))
 receipt={'at':s.now(),'status':'PASS','tests':tests,'tests_passed':len(tests),'new_text_files_secret_scanned':scanned,'resume_batch_files_unchanged':len(oldhashes),'independent_evaluation':False,'limits':'Protocol and structural tests; not independent semantic accuracy, runtime disclosure confirmation, or an exhaustive secret detector.'}
 s.write(s.OUT/'adversarial_validation.json',receipt)
 s.write(s.OUT/'resume_validation.json',{'at':s.now(),'status':'PASS','new_batches':0,'files_unchanged':len(oldhashes)})
 progress=json.loads((s.OUT/'progress.json').read_text());progress.update(at=s.now(),phase='complete',validation='PASS',adversarial_tests_passed=len(tests),remaining_selected_reviews=0)
 s.write(s.OUT/'progress.json',progress)
 manifest={'at':s.now(),'algorithm':'sha256','files':{str(p.relative_to(s.OUT)):s.sha(p) for p in s.OUT.rglob('*') if p.is_file() and p.name!='artifact_manifest.json'},'scripts':{str(p.relative_to(s.ROOT)):s.sha(p) for p in (s.ROOT/'scripts').glob('*sensitive*review*.py')}}
 s.write(s.OUT/'artifact_manifest.json',manifest)
 print(json.dumps({k:v for k,v in receipt.items() if k!='tests'},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
