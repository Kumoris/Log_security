#!/usr/bin/env python3
"""Streaming producer-to-merged metadata audit, with advance ancestry support.

No historical expected counts. Complete/gap-free replacement, partial/gap union,
conflicts, removals, duplicate audits and evidence variants are checked separately.
"""
from collections import Counter, defaultdict
from contextlib import ExitStack
from pathlib import Path
import argparse, heapq, itertools, json
from agentlog_unified.storage import stable_id
from agentlog_unified.taxonomy import TAXONOMY_VERSION
from verify_aidev_repair_v049 import (BASE,FIELDS,SOURCE,REVIEW_SQL,Audit,PairReader,canonical,
    identity,variant,valid_detail,lock,repair_view,digest,stat)

SCOPE={'observation_scope':'dataset_text_reconciled','human_review_status':'pending','runtime_confirmed':False,'application_log_evidence':False,'new_type_status':'not_established','full_dataset_coverage_claim':False,'taxonomy_version':TAXONOMY_VERSION}
ORDER="json_extract(details,'$.start'),json_extract(details,'$.end'),json_extract(details,'$.rule'),COALESCE(category,''),COALESCE(subtype,''),id"
STEMS=('merged_type_occurrences','merged_excluded','reconciliation_audit','repair_overlay','merged_unknown_type_review_queue','repair_data_gaps','merged_type_summary')


def expected_variants(records,complete):
 parents=[r for r in records if r['origin']=='parent'];fixes=[r for r in records if r['origin']=='repair']
 if parents and not fixes and complete:return [],'completed_repair_removed_parent_identity'
 groups=defaultdict(list)
 for r in records:groups[variant(r['detail'],r['excluded'])].append(r)
 reason='details_conflict_pending' if len(groups)>1 else 'exact_duplicate' if parents and fixes else None
 return sorted(groups.items()),reason


def verify(run,report,execution=None):
 a=Audit();totals=Counter();types=defaultdict(Counter);states=defaultdict(Counter);delta_cases=[]
 with ExitStack() as stack:
  lock(stack,run/'.reconcile.lock');manifest=a.read(run/'manifest.json');coverage=a.read(run/'merged_coverage.json')
  parent=Path(manifest['parent_run']).resolve();fixed=Path(manifest['repair_run']).resolve();v=repair_view(stack,a,fixed,parent)
  source_manifest=v['parent_manifest']['source_manifest_sha256'];parentdb=v['parent_db'];fixdb=v['db'];fp=manifest['fingerprint']
  a.check('terminal_merge_manifest_and_evidence_boundaries',manifest['status']=='complete' and manifest['engine']=='content_reconcile_v1' and coverage['status']=='reconciled_with_semantic_gaps' and all(coverage.get(k)==value for k,value in SCOPE.items()) and coverage['parent_and_repair_counts_additive'] is False and coverage['source_verification_complete'] is True)
  a.check('manifest_coverage_fingerprint_equal',fp==coverage['fingerprint'])
  def current_hash(path):
   path=Path(path);record=a.files.get(str(path))
   return record['sha256'] if record and tuple(record['stat'])==stat(path) else a.capture(path)
  a.check('all_producer_input_snapshot_hashes_match',all(current_hash(path)==expected for path,expected in fp['input_files'].items()))
  a.check('all_verified_source_byte_hashes_match',all(current_hash(path)==expected for path,expected in fp['verified_source_files'].items()))
  a.check('merge_current_implementation_and_dependencies',current_hash(BASE/'src/agentlog_unified/content_reconcile.py')==fp['implementation_sha256'] and all(current_hash(BASE/'src/agentlog_unified'/name)==sha for name,sha in fp['execution_dependency_sha256'].items()))
  a.check('merge_original_classifier_provenance',fp['original_classifier_sha256']==v['original']['fingerprint']['source_sha256'] and fp['source_manifest_sha256']==source_manifest)
  expected_names={s+ext+'.gz' for s in STEMS for ext in ('.jsonl','.csv')}
  a.check('complete_compressed_output_names',set(manifest['outputs'])==expected_names and {p.name for p in run.glob('*.gz')}==expected_names)
  a.check('all_compressed_output_sha_and_bytes',all(current_hash(run/name)==info['sha256'] and (run/name).stat().st_size==info['bytes'] for name,info in manifest['outputs'].items()))
  if execution:
   e=a.read(execution);after=e.get('source_after')
   a.check('execution_terminal_sources_unchanged',e['exit_code']==2 and e['source_unchanged'] is True and (not after or all(current_hash(BASE/path)==sha for path,sha in after.items())))
  readers={stem:PairReader(stack,a,run,stem,True) for stem in STEMS}
  source_ok=details_ok=True;parent_n=Counter();fix_n=Counter();seen_fixed=set();mode_counts=Counter()
  def records(db,cid,origin,source):
   nonlocal details_ok
   for r in db.execute('SELECT * FROM matches WHERE cell_id=? ORDER BY '+ORDER,(cid,)):
    detail=json.loads(r['details']);details_ok &= valid_detail(r,detail,source,origin)
    (parent_n if origin=='parent' else fix_n)[int(r['excluded'])]+=1
    yield identity(detail),{'id':r['id'],'origin':origin,'detail':detail,'excluded':bool(r['excluded'])}
  for rawsource in parentdb.execute('SELECT * FROM cells ORDER BY id'):
   source=dict(rawsource);cid=source['id'];fixedcell=v['cells'].get(cid);stats=Counter();touched=set()
   source_ok &= cid==stable_id('content-cell',source_manifest,source['table_path'],source['source_row'],source['column_name'])
   gap_count=fixdb.execute('SELECT COUNT(*) FROM gaps WHERE cell_id=?',(cid,)).fetchone()[0] if fixedcell else 0
   complete=fixedcell is not None and fixedcell['status']=='complete_with_semantic_gaps' and gap_count==0
   streams=[records(parentdb,cid,'parent',source)]
   if fixedcell:streams.append(records(fixdb,cid,'repair',source));seen_fixed.add(cid)
   current_base=None;base_types={'parent':set(),'repair':set()};base_ids={'parent':[],'repair':[]}
   def finish_base():
    if base_types['parent'] and base_types['repair'] and base_types['parent']!=base_types['repair']:
     stats['type_set_changes']+=1;totals['type_set_changes_pending']+=1
     readers['reconciliation_audit'].take({'cell_id':cid,'identity_id':stable_id('reconciled-span-rule',source_manifest,cid,current_base),'reason':'type_set_changed_pending','parent_occurrence_ids':sorted(base_ids['parent']),'repair_occurrence_ids':sorted(base_ids['repair']),'retained_variant_ids':[],**SCOPE})
   for key,group in itertools.groupby(heapq.merge(*streams,key=lambda x:x[0]),key=lambda x:x[0]):
    if current_base is not None and current_base!=key[:3]:finish_base();base_types={'parent':set(),'repair':set()};base_ids={'parent':[],'repair':[]}
    current_base=key[:3];members=[]
    for _,r in group:
     members.append(r)
     if len(members)>10000:raise ValueError('Verification identity group exceeds bounded evidence limit')
     base_types[r['origin']].add(key[3:]);base_ids[r['origin']].append(r['id'])
    p=[r for r in members if r['origin']=='parent'];f=[r for r in members if r['origin']=='repair']
    stats['parent_rows']+=len(p);stats['repair_rows']+=len(f)
    if p and f:stats['shared_identities']+=1
    elif f:stats['new_identities']+=1
    elif complete:stats['removed_parent_identities']+=1;stats['removed_parent_rows']+=len(p)
    variants,reason=expected_variants(members,complete);conflict=len(variants)>1;stats['conflicting_identities']+=int(conflict)
    identity_id=stable_id('reconciled-identity',source_manifest,cid,key);accepted=[];identity_flags=set()
    for metadata,values in variants:
     record=values[0];d=record['detail'];flag=record['excluded'];typekey=d['category'],d['subtype'];vid=stable_id('reconciled-variant',identity_id,metadata)
     expected={'id':vid,'identity_id':identity_id,'cell_id':cid,**{k:source[k] for k in SOURCE},'text_hmac_sha256':source['text_hmac_sha256'],**d,'excluded':flag,'origins':sorted({r['origin'] for r in values}),'source_occurrence_ids':{o:sorted({r['id'] for r in values if r['origin']==o}) for o in ('parent','repair')},'classification_conflict':conflict,**SCOPE}
     readers['merged_excluded' if flag else 'merged_type_occurrences'].take(expected)
     accepted.append(vid);identity_flags.add(flag);types[typekey]['excluded_variant_count' if flag else 'candidate_variant_count']+=1
     if not flag:states[typekey][d['candidate_status']]+=1;touched.add(typekey)
    if variants:
     totals['logical_identities']+=1;typekey=key[3] or None,key[4] or None
     for flag in identity_flags:
      totals['excluded_identities' if flag else 'candidate_identities']+=1
      types[typekey]['excluded_identity_count' if flag else 'candidate_identity_count']+=1
    if reason:
     totals[reason]+=1
     readers['reconciliation_audit'].take({'cell_id':cid,'identity_id':identity_id,'reason':reason,'parent_occurrence_ids':sorted(r['id'] for r in p),'repair_occurrence_ids':sorted(r['id'] for r in f),'retained_variant_ids':accepted,**SCOPE})
     if reason!='exact_duplicate' and len(delta_cases)<100:delta_cases.append({'cell_id':cid,'start':key[0],'end':key[1],'rule':key[2],'category':key[3] or None,'subtype':key[4] or None,'reason':reason,'parent_rows':len(p),'repair_rows':len(f),'retained_variants':len(accepted)})
   finish_base()
   for typekey in touched:types[typekey]['distinct_candidate_cells']+=1
   if fixedcell:
    mode='complete_replace_with_conflicts_retained' if complete else 'data_gap_union' if gap_count else 'partial_union';mode_counts[mode]+=1
    expected={'cell_id':cid,**{k:source[k] for k in SOURCE},'status':fixedcell['status'],'cursor':fixedcell['cursor'],'pages':fixedcell['pages'],'data_gap_records':gap_count,'mode':mode,**{k:stats[k] for k in ('parent_rows','repair_rows','shared_identities','new_identities','removed_parent_identities','removed_parent_rows','conflicting_identities','type_set_changes')},**SCOPE}
    readers['repair_overlay'].take(expected)
    totals.update({'replaced_parent_rows':stats['parent_rows'] if complete else 0,'removed_parent_identities':stats['removed_parent_identities'],'removed_parent_rows':stats['removed_parent_rows'],'new_repair_identities':stats['new_identities']})
  a.check('all_producer_metadata_spans_and_identities_valid',source_ok and details_ok)
  a.check('all_selected_repair_cells_accounted_for',seen_fixed==set(v['selected']))
  a.check('producer_detail_counts_equal_coverages',parent_n[0]==v['parent_coverage']['candidate_occurrences'] and parent_n[1]==v['parent_coverage']['excluded_occurrences'] and fix_n[0]==v['coverage']['candidate_occurrences'] and fix_n[1]==v['coverage']['excluded_occurrences'])
  print(json.dumps({'phase':'all_parent_repair_occurrences_and_replacements','parent_rows':sum(parent_n.values()),'repair_rows':sum(fix_n.values())}),flush=True)
  expanded=0
  for r in parentdb.execute(REVIEW_SQL):
   readers['merged_unknown_type_review_queue'].take({**dict(r),'reason':'text_semantics_and_sensitive_type_completeness_unresolved',**SCOPE});expanded+=r['row_count']
  for r in fixdb.execute('SELECT * FROM gaps ORDER BY id'):
   readers['repair_data_gaps'].take({'cell_id':r['cell_id'],**json.loads(r['details']),**SCOPE})
  summary_fields=('candidate_variant_count','candidate_identity_count','excluded_variant_count','excluded_identity_count','distinct_candidate_cells')
  for key,count in sorted(types.items(),key=lambda x:(x[0][0] or '',x[0][1] or '')):
   readers['merged_type_summary'].take({'category':key[0],'subtype':key[1],**{k:count[k] for k in summary_fields},'candidate_status_variant_counts':dict(states[key]),**SCOPE})
  counts={stem:reader.finish() for stem,reader in readers.items()}
  expected_counts={**totals,'candidate_occurrence_variants':counts['merged_type_occurrences'],'excluded_occurrence_variants':counts['merged_excluded'],'audit_records':counts['reconciliation_audit'],'repair_overlay_cells':counts['repair_overlay'],'unknown_type_review_export_records':counts['merged_unknown_type_review_queue'],'unknown_type_review_cells':expanded,'repair_data_gap_records':counts['repair_data_gaps'],'type_summary_records':counts['merged_type_summary']}
  a.check('all_merge_coverage_units_and_reason_totals',all(coverage.get(k,0)==value for k,value in expected_counts.items()))
  a.check('parent_unknown_range_denominator_preserved',expanded==v['parent_coverage']['unknown_type_review_cells'] and counts['merged_unknown_type_review_queue']==v['parent_coverage']['unknown_type_review_export_records'])
  a.check('type_summary_variant_identity_status_sums',sum(r['candidate_variant_count'] for r in types.values())==counts['merged_type_occurrences'] and sum(r['excluded_variant_count'] for r in types.values())==counts['merged_excluded'] and sum(r['candidate_identity_count'] for r in types.values())==totals['candidate_identities'] and sum(sum(s.values()) for s in states.values())==counts['merged_type_occurrences'])
  results={'run':str(run),'parent':str(parent),'repair':str(fixed),**expected_counts,'repair_modes':dict(mode_counts),'outside_catalog_candidate_variants':types[(None,None)]['candidate_variant_count'],'delta_case_metadata':delta_cases,'delta_case_metadata_limit':100,'semantic_complete':False,'memory_boundary':'Producer records are streamed by source cell and identity; at most10000 records per identity and finite type counters retained. Source values never decoded.'}
  return a.finish(report,'readonly_advance_repair_reconcile_metadata_verification',results)


def self_test():
 d={'start':1,'end':4,'rule':'email_shape','category':'PII','subtype':'email','basis':'literal_shape','confidence':'low','candidate_status':'literal_candidate','value_status':'unverified'}
 p={'id':'parent','origin':'parent','detail':d,'excluded':False};f={**p,'id':'repair','origin':'repair'}
 assert expected_variants([p,f],True)[1]=='exact_duplicate' and len(expected_variants([p,f],True)[0])==1
 assert expected_variants([p],True)==([],'completed_repair_removed_parent_identity')
 assert len(expected_variants([p],False)[0])==1
 changed={**f,'detail':{**d,'candidate_status':'identifier_reference'}}
 assert expected_variants([p,changed],True)[1]=='details_conflict_pending' and len(expected_variants([p,changed],True)[0])==2
 assert expected_variants([f],True)[1] is None
 assert len(expected_variants([p],False)[0])==1  # A gap forces union even when its rule cursor ended.
 print(json.dumps({'self_test':'passed','assertions':6,'real_outputs_read':False}))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runs-confirmed-terminal',action='store_true');p.add_argument('--self-test',action='store_true');p.add_argument('--run',type=Path,default=BASE/'reconciled-runs/aidev-v049');p.add_argument('--report',type=Path,default=BASE/'docs/aidev_reconcile_v049_verification.json');p.add_argument('--execution',type=Path);args=p.parse_args()
 if args.self_test:self_test()
 elif args.runs_confirmed_terminal:raise SystemExit(verify(args.run.resolve(),args.report.resolve(),args.execution.resolve() if args.execution else None))
 else:p.error('--runs-confirmed-terminal is required before reading real outputs')
