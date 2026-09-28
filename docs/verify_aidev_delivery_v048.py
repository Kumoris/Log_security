"""Terminal-only documentation/metadata consistency check; never reads source rows."""
from pathlib import Path
from contextlib import ExitStack
from datetime import datetime, timezone
import argparse,fcntl,hashlib,json,re,tomllib
from importlib.metadata import version
BASE=Path('/Users/lzh/Downloads/Log 研究/agentlog_unified')

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 return h.hexdigest()

def run():
 docs=BASE/'docs';folder=BASE/'structured-runs/aidev-v048';checks={};metadata={};reads={}
 def read(p):
  raw=p.read_bytes();reads[str(p)]=hashlib.sha256(raw).hexdigest();return json.loads(raw)
 def check(name,value):checks[name]=bool(value)
 with ExitStack() as stack:
  lock=stack.enter_context((folder/'.structured.lock').open('rb'))
  fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
  manifest=read(folder/'manifest.json');state=read(folder/'export_state.json');coverage=read(folder/'structured_coverage.json')
  if state['status']!='complete':raise ValueError('Refuse nonterminal export')
  check('terminal_export_same_fingerprint',state['fingerprint']==manifest['fingerprint'])
  check('coverage_committed_all_source_rows',coverage['all_source_rows_visited'] and coverage['processed_rows']==2456073 and len(coverage['tables'])==18)
  check('coverage_semantic_gaps_preserved',coverage['status']=='complete_with_semantic_gaps' and coverage['runtime_confirmed'] is False and coverage['human_review_status']=='pending')
  check('coverage_current_digest',sha(folder/'structured_coverage.json')==state['outputs']['structured_coverage.json']['sha256'])
  metadata['structured_counts']={k:coverage[k] for k in ('processed_rows','documents','candidate_occurrences','excluded_occurrences','data_gap_records','unknown_review_source_cells')}
  metadata['gzip_group_digest_validation']='Delegated to the independent structured export verifier; this check hashes terminal coverage and documentation only.'
  progress=read(docs/'datasets_progress.json');commands=read(docs/'aidev_v048_commands.json')
  pkg=tomllib.loads((BASE/'pyproject.toml').read_text())['project']['version']
  check('package_and_progress_version',pkg==progress['tool_version']=='0.4.8')
  installed=version('agentlog-unified');check('installed_package_version',installed==pkg=='0.4.8');metadata['installed_package_version']=installed
  check('progress_sensitive_type_exhaustion_not_claimed',progress.get('all_real_sensitive_types_identified') is False)
  check('progress_current_report',str(progress.get('current_report','')).endswith('aidev_v048_report.md'))
  check('progress_current_commands',str(progress.get('latest_commands','')).endswith('aidev_v048_commands.json'))
  check('commands_aidev_scope',commands.get('dataset_scope')=='aidev_only')
  check('progress_structured_matches_terminal_coverage',progress['structured_scan']==coverage)
  for item in commands['executions']:
   p=Path(item['path']);record=read(p)
   check('command_index_'+p.stem,sha(p)==item['sha256'] and record['command']==item['command'] and record['exit_code']==item['exit_code'])
  gain=read(docs/'aidev_structured_gain_v048.json')
  check('gain_progress_and_report_scope',all(progress['structured_gain'][k]==gain[k] for k in progress['structured_gain']))
  check('gain_arithmetic_nonadditive',gain['structured_controlled_cell_type_pairs']==gain['shared_cell_type_pairs']+gain['gained_cell_type_pairs'] and gain['gained_cell_type_pairs']==14 and gain['labels_observed_only_in_structured']==0)
  check('gain_pending_not_confirmed',gain['runtime_confirmed'] is False and gain['new_sensitive_type_established'] is False and gain['human_review_status']=='pending')
  independent=read(docs/'aidev_structured_v048_verification.json')
  check('independent_71_checks_terminal',independent['all_checks_passed'] and independent['total']==independent['passed']==71)
  check('independent_counts_match_terminal',independent['processed_rows']==coverage['processed_rows'] and independent['processed_nonempty_cells']==coverage['unknown_review_source_cells'] and independent['candidate_status_counts']==coverage['candidate_status_counts'] and independent['document_status_counts']==coverage['document_status_counts'])
  resume=read(docs/'aidev_structured_v048_resume_verification.json')
  check('resume_verified',resume['all_passed'] and coverage['rows_this_invocation']==0 and coverage['resumed'])
  iv=read(docs/'aidev_inventory_v048_verification.json')
  check('inventory_independent_counts',iv['all_checks_passed'] and iv['grid_rows']==336 and iv['independent_sources']==8 and iv['historical_rows_preserved']==294 and iv['zero_grid_rows']==231)
  schema=read(BASE/'schema-runs/aidev-v047/schema_coverage.json')
  check('remaining_schema_138_not_removed',schema['unresolved_field_records']==138 and schema['selected_fields']==22)
  tests=read(docs/'aidev_v048_tests_execution.json')
  testout=Path(tests['stdout_path']).read_text()
  check('full_test_627_actual','627 passed in 30.06s' in testout and tests['exit_code']==0)
  check('all_tested_source_files_current',all(sha(BASE/p)==expected for p,expected in tests['source_after'].items()))
  check('structured_classifier_source_current',all(sha(BASE/'src/agentlog_unified'/name)==expected for name,expected in manifest['fingerprint']['source_sha256'].items()))
  paths=[BASE.parent/'README.md',BASE/'README.md',docs/'aidev_v048_report.md'];texts={p:p.read_text() for p in paths}
  badlinks=[];links=0
  for p,body in texts.items():
   reads[str(p)]=sha(p)
   for target in re.findall(r'(?<!!)\[[^\]]+\]\(([^)]+)\)',body):
    target=target.strip('<>')
    if target.startswith(('http:','https:','#','mailto:')):continue
    target=target.split('#')[0]
    if not target:continue
    links+=1
    if not (p.parent/target).exists() and (p.parent/target).resolve() != (docs/'aidev_delivery_v048_verification.json').resolve():badlinks.append({'document':str(p),'target':target})
  check('local_markdown_links_resolve',not badlinks);metadata['links_checked']=links;metadata['missing_links']=badlinks
  readme=texts[BASE/'README.md'];report=texts[docs/'aidev_v048_report.md']
  check('readme_current_version_and_report','当前版本 **0.4.8**' in readme and 'aidev_v048_report.md' in readme[:1500])
  check('report_identifies_v048','0.4.8' in report[:600])
  check('report_full_source_row_count', '2,456,073' in report or '2456073' in report)
  check('report_does_not_relabel_structured_as_log_evidence', 'PyDriller' in report and ('不是' in report or '不代表' in report or '不提供' in report))
  check('report_notes_nonadditive_scopes',any(x in report for x in ('不能直接相加','不能相加','不可相加')))
  check('report_pending_evidence_boundary', 'pending' in report and 'runtime_confirmed' in report and 'new_type_status' in report)
  mentioned={}
  for name,count in metadata['structured_counts'].items():
   mentioned[name]=str(count) in report or f'{count:,}' in report
  metadata['primary_counts_mentioned_in_report']=mentioned
  check('report_primary_counts_mentioned',all(mentioned.values()))
  check('report_unicode_character_limit','1,048,576 个 Unicode 字符' in report)
  check('root_readme_current_scope', 'aidev_v048_report.md' in texts[BASE.parent/'README.md'] and '静态候选不等于运行时泄露' in texts[BASE.parent/'README.md'])
  check('report_gain_table_matches_actual',all('| `'+r['category']+'.'+r['subtype']+'` | '+str(r['gained_cell_type_pairs'])+' |' in report for r in gain['type_summary'] if r['gained_cell_type_pairs']))
  metadata['manual_review']={'candidate_units':'1,140 structured observations, 866 cell/type pairs, 14 gained relations and 18 supporting observations are distinguished; prior 1,479,597 identities are not added.','unknown_semantics':'Every nonempty cell remains pending; zero unknown-label row is explicitly not absence of unknown types.','remaining_scope':'138 unmapped fields and 485,812 unmatched account-field cells remain; mixed author fallback not promoted to person name.','executions':'Full resume and no-new-row resume distinguished; 627 full-suite tests, no separate synthetic-v048 run claimed; failed gain audit is preserved.','format_boundaries':'Source envelopes and decoded leaf offsets distinguished; Unicode character cap explicit; no new application-log evidence or new true sensitive type claimed.'}
  records=[]
  for p in sorted(docs.glob('aidev_v048_*_execution.json')):
   data=read(p)
   if not all(k in data for k in ('command','source_before','source_after','source_unchanged','finished_at','exit_code')):continue
   records.append(p.name)
   check(p.stem+'_frozen_source',data['source_unchanged'] and data['source_before']==data['source_after'])
   for stream in ('stdout','stderr'):
    if stream+'_path' in data and stream+'_sha256' in data:
     check(p.stem+'_'+stream+'_digest',sha(Path(data[stream+'_path']))==data[stream+'_sha256'])
  metadata['execution_records_checked']=records
  inventory=read(docs/'aidev_observed_types_v048_provenance.json')
  check('inventory_eight_sources_and_zero_label_rows',inventory['row_count']==336 and len(inventory['sources'])==8 and inventory['catalog_subtypes']==42)
  check('inventory_nonadditive',inventory['counts_additive_across_scopes_or_runs'] is False)
  metadata['observed_controlled_type_union']=inventory['observed_catalog_type_union_count']
  check('all_metadata_unchanged',all(sha(Path(p))==expected for p,expected in reads.items()))
 result={'recorded_utc':datetime.now(timezone.utc).isoformat(),'checks':checks,'all_checks_passed':all(checks.values()),'metadata':metadata,'input_sha256':reads,'verifier_path':str(Path(__file__).resolve()),'verifier_sha256':sha(Path(__file__)),'self_report_link':'The report links this verification output; all other links were checked before publication.','raw_source_values_read':False,'source_or_tests_modified':False,'live_output_read':False,'limitations':['This audit checks presentation/metadata consistency, not a repeated full source scan or an independent reproduction of all gzip rows.','Exact document wording and ambiguous count/unit assertions require the accompanying human-readable review.']}
 target=docs/'aidev_delivery_v048_verification.json'
 if target.exists() and (docs/'aidev_delivery_v048_verification_initial_60checks.json').read_bytes()!=target.read_bytes():raise FileExistsError('Preserve previous verification')
 target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'path':str(target),'checks':len(checks),'passed':sum(checks.values()),'all_checks_passed':result['all_checks_passed'],'failed':[k for k,v in checks.items() if not v]},ensure_ascii=False))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--run',action='store_true');args=p.parse_args()
 if args.run:run()
 else:print('Prepared only. Run after root explicitly confirms terminal exports and completed final documentation.')
