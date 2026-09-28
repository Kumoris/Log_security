"""Export and verify the completed scoped review without modifying parent deliveries."""
from pathlib import Path
import json,collections,copy,shutil,sys
import complete_agent_log_motive_reviews as m

O=m.OUT;D=O/'delivery';V=O/'verification'

def build():
 events,contexts,repairs=m.verified_events();es={e['modification_id']:e for e in events};aa=m.load_batches();annotations={a['modification_id']:a for a in aa}
 assert len(aa)==1757 and set(es)==set(annotations),'review_incomplete'
 ev,links=m.sources();ev,links=m.supplemental(ev,links,events)
 D.mkdir(exist_ok=False);V.mkdir(exist_ok=True)
 # Preserve actual old annotations and record new line corrections as an overlay.
 reviews=[];citations=[];uncertainty=[]
 for e0 in events:
  mid=e0['modification_id'];a=annotations[mid];e=copy.deepcopy(e0)
  e.update(review_state='assistant_reviewed',motive_status=a['status'],motive_labels=a['labels'],current_batch=a['batch_id'],
    observed_change_review=a['observed_change_review'],stated_purpose=a.get('stated_purpose'),contextual_inference=a.get('contextual_inference'),
    unknown_reason=a.get('unknown_reason'),citations=a['citations'],conclusion_scope=a.get('conclusion_scope'),reviewed_at=a.get('reviewed_at'),
    reviewed_material_scope=a.get('review_scope'),source_types=sorted({l['source_type'] for l in links[mid]}),
    evidence_ids=sorted({l['evidence_id'] for l in links[mid]}),conflict_review=a.get('conflict_review') or {'state':'prior annotation audited; no supported opposing purpose in reviewed material'})
  e['line_verification_note']='upstream spans retained; see span_corrections for unique exact-statement alignment' if e['span_corrections'] else 'no contradictory changed-line text found in inspected target spans'
  # Historical association-layer motive counts are not this event's conclusion.
  e['association_motive_status_counts_scope']='unchanged inherited association layer; do not aggregate as current event motive status'
  reviews.append(e)
  if a['status'] in ('unknown','conflicting'):uncertainty.append({'modification_id':mid,'repository':e['repository'],'modification_sha':e['modification_sha'],
    'file_path':e['file_path'],'review_state':e['review_state'],'motive_status':a['status'],'reason':a.get('unknown_reason') or a.get('conflict_review'),
    'available_source_types':e['source_types'],'missing_source_types':[t for t in m.TYPES if t not in e['source_types']],
    'target_observation':e['current_observation']['classification'],'group_context_note':a.get('group_context_note'),
    'inspected_excerpt_ids':[c['evidence_id'] for c in a['citations']]})
  for c in a['citations']:
   source=ev[c['evidence_id']];edges=[l for l in links[mid] if l['evidence_id']==c['evidence_id']]
   citations.append(dict(c,modification_id=mid,review_batch=a['batch_id'],motive_status=a['status'],repository=e['repository'],modification_sha=e['modification_sha'],file_path=e['file_path'],
       source_type=source['source_type'],source_id=source['source_id'],source_url=source.get('source_url'),source_local_path=source.get('source_local_path'),
       source_time=source.get('source_time'),session_id=source.get('session_id'),checkpoint_pk=source.get('checkpoint_pk'),
       pr_number=source.get('pr_number'),issue_number=source.get('issue_number'),comment_id=source.get('comment_id'),
       association_links=edges,direct_correspondence=a.get('direct_correspondence')))
 m.lines(D/'log_modification_reviews.jsonl',reviews);m.csv_table(D/'log_modification_reviews.csv',reviews)
 m.lines(D/'annotations.jsonl',aa);m.lines(D/'motive_evidence.jsonl',ev.values());m.lines(D/'evidence_links.jsonl',[l for ll in links.values() for l in ll])
 m.lines(D/'event_evidence_citations.jsonl',citations);m.csv_table(D/'event_evidence_citations.csv',citations)
 m.lines(D/'unresolved_motives.jsonl',uncertainty);m.csv_table(D/'unresolved_motives.csv',uncertainty);m.lines(D/'pending_events.jsonl',[])
 m.lines(D/'span_corrections.jsonl',repairs)
 # Keep historical source failures as request history, not a false absence claim.
 gaps=[]
 for r0 in m.read(m.OLD/'delivery_v2/unresolved_records.jsonl'):
  if r0['source_type']=='motive':continue
  r=dict(r0);mid=r['modification_id'];r['source_type_has_available_evidence_now']=r['source_type'] in {l['source_type'] for l in links[mid]}
  r['scope']='inherited request gap, not evidence absence; not reissued unless recorded in external_readonly'
  if es[mid]['repository']=='obmondo/gfetch' and any('issues/22' in loc for loc in r.get('locators',[])):
   r['interpretation_correction']='commit Reviewed-on points to gitea.obmondo.com/EnableIT/gfetch/pulls/22; same-number GitHub issue failure is not a valid availability check for that Gitea PR'
  gaps.append(r)
 outcomes=[]
 for p in sorted((O/'external_readonly').glob('*.json')):
  r=json.loads(p.read_text());error=r.get('isError',False);detail=' '.join(x.get('text','') for x in r.get('tool_result',{}).get('content',[]))
  state='authentication_token_expired' if 'token_expired' in detail else 'connector_error_without_retained_detail' if error else 'success_empty' if r.get('response_text')=='[]' else 'success'
  outcomes.append({'url':r['url'],'state':state,'at':r['fetched_at'],'receipt':str(p.relative_to(O)),'receipt_sha256':m.sha(p),'method':'GET'})
  if error:
   for e in events:
    if e['modification_sha'] in r['url'] and '/repos/'+e['repository']+'/' in r['url']:
     gaps.append({'modification_id':e['modification_id'],'source_type':'pr_description','reason':state,'endpoint':r['url'],
        'scope':'this exact commit PR lookup failed; not proof no PR exists','receipt':str(p.relative_to(O))})
 m.lines(D/'source_gaps.jsonl',gaps);m.lines(D/'external_request_outcomes.jsonl',outcomes)
 eq=collections.defaultdict(list)
 for v in ev.values():eq[v['equivalence_group']].append(v['evidence_id'])
 m.lines(D/'evidence_equivalence_groups.jsonl',[{'group':k,'evidence_ids':ids,'count':len(ids),'policy':'same source identity and CRLF/trailing-whitespace normalized text; not independent corroboration'} for k,ids in eq.items() if len(ids)>1])
 stats={'at':m.now(),'total_events':len(events),'reviewed':len(reviews),'unreviewed':0,'prior_reviewed_audited':110,'newly_reviewed':len(reviews)-110,
  'newly_reviewed_prior_pending':1646,'inherited_only_rereviewed':1,'review_state_distribution':dict(collections.Counter(r['review_state'] for r in reviews)),
  'motive_distribution':{s:sum(a['status']==s for a in aa) for s in ('explicit','inferred','unknown','conflicting')},
  'unknown_reasons':dict(collections.Counter(a['unknown_reason'] for a in aa if a['status']=='unknown')),
  'motive_label_distribution':dict(collections.Counter(label for a in aa for label in a['labels'])),
  'association_rows':sum(e['association_count'] for e in events),'distinct_candidate_ids':len({x for e in events for x in e['stage1_log_ids']}),
  'evidence_rows':len(ev),'new_evidence_rows':len(ev)-3629,'relation_edges':sum(map(len,links.values())),
  'unique_event_source_pairs':len({(mid,l['evidence_id']) for mid,ll in links.items() for l in ll}),
  'duplicate_equivalence_groups':sum(len(x)>1 for x in eq.values()),'duplicate_evidence_excess':sum(len(x)-1 for x in eq.values()),
  'source_coverage':{},'purpose_support_coverage':{},'events_without_any_evidence':sum(not links[e['modification_id']] for e in events),
  'target_span_corrections':len(repairs),'batches_new':len(list((O/'batches').glob('*_review/validation.json'))),
  'review_scope':'assistant conservative event review with exact code checks and selected source passages; not independent accuracy evaluation',
  'conflicting_zero_meaning':'No distinct opposed event-purpose claims established in inspected material; not an exhaustive claim about every full source.',
  'stage_counts_unchanged':json.loads((m.PARENT/'delivery/summary.json').read_text())['stage_counts']}
 for t in m.TYPES:
  n=sum(any(l['source_type']==t for l in links[e['modification_id']]) for e in events)
  supported={c['modification_id'] for c in citations if c['source_type']==t and c['role']=='purpose_support'}
  stats['source_coverage'][t]={'events':n,'denominator':1757,'fraction':n/1757,'missing':1757-n}
  stats['purpose_support_coverage'][t]={'events':len(supported),'denominator':1757,'fraction':len(supported)/1757}
 m.write(D/'statistics.json',stats)
 history=[]
 for p in sorted((O/'batches').glob('*/validation.json')):
  r=json.loads(p.read_text());ans=m.read(p.parent/'annotations.jsonl');history.append({'batch_id':p.parent.name,'at':r['at'],'events':len(ans),'validation':r['status'],
   'motive_distribution':dict(collections.Counter(a['status'] for a in ans))})
 m.lines(D/'batch_progress.jsonl',history);m.csv_table(D/'batch_progress.csv',history)
 # Examples include source identity, full edge chains and the exact target diff.
 prefixes=['4f490ef9','f091301e','208039e3','cdfaf09f','d70d714e','a87b7f66','178db020','0295e62c']
 examples=[];md=['# 可追溯样例\n','本轮全部为开发阶段助手判读，不是独立人工评估。完整原文在 motive_evidence.jsonl；每条候选归因仍按原账本保留。\n']
 for prefix in prefixes:
  r=next(x for x in reviews if x['modification_id'].startswith(prefix));cs=[x for x in citations if x['modification_id']==r['modification_id']]
  examples.append({'event':r,'annotation':annotations[r['modification_id']],'citations_and_chains':cs,'source_metadata':[ev[x['evidence_id']] for x in cs]})
  md+=['## '+r['modification_id']+'\n',f"{r['repository']} · `{r['modification_sha']}` · `{r['file_path']}`\n",
       f"状态：{r['review_state']} / **{r['motive_status']}**\n",r['observed_change_review']+'\n',
       (r.get('stated_purpose') or r.get('contextual_inference') or r.get('unknown_reason'))+'\n']
  for c in cs[:2]:
   loc=c.get('source_url') or c.get('source_local_path');md+=[f"来源 {c['source_type']} · {c['source_id']} · {c.get('source_time')} · {loc}\n",'> '+c['quote'].replace('\n','\n> ')+'\n']
  md+=['完整链路、原始/核实行号和 diff：见同 ID 的 traceable_examples.jsonl。\n']
 m.lines(D/'traceable_examples.jsonl',examples);(D/'可追溯样例.md').write_text('\n'.join(md),encoding='utf-8')
 fields=m.read(m.OLD/'delivery_v2/field_dictionary.jsonl')
 extra=[('review_state','审阅状态：assistant_reviewed 表示已按本轮协议判读；pending 必须 motive_status=null。'),('motive_status','动机状态：explicit/inferred/unknown/conflicting；仅对已审阅事件计数。'),
  ('current_observation','独立目标 diff 核验；不覆盖原 observed_change。'),('span_corrections','同路径同父/目标 SHA 中完整语句唯一匹配得出的原行号与核实行号；本次 9 条。'),
  ('reviewed_material_scope','实际阅读范围；全文保存不代表逐字人工通读。'),('association_motive_status_counts_scope','历史关联层计数只作来历，不是本轮最终事件分类。'),
  ('event_evidence_citations','一事件多证据，每项分别保存原文偏移、来源元数据、角色及关联链。'),('source_gaps','具体请求失败/缺失原因；有其他同类材料时不表示整个来源类型缺失。')]
 fields = [r for r in fields if r['field'] not in {k for k,v in extra}]
 fields += [{'field':k,'definition':v,'origin_and_caveat':'completion review overlay; original fields retained'} for k,v in extra]
 m.lines(D/'field_dictionary.jsonl',fields);m.csv_table(D/'field_dictionary.csv',fields)
 shutil.copy2(m.OLD/'delivery_v2/source_types.jsonl',D/'source_types.jsonl')
 m.write(D/'original_chain_reference.json',{'path':str(m.PARENT/'stage3_final/evidence_links.jsonl'),'sha256':m.sha(m.PARENT/'stage3_final/evidence_links.jsonl'),
   'relation':'use evidence_links.original_link_ids to retrieve every association-level chain, including checkpoint/session and exact API basis','expected_rows':191672})
 # This saves space without dropping any parent chain identity.
 print(json.dumps({k:stats[k] for k in ('total_events','reviewed','unreviewed','newly_reviewed','motive_distribution','evidence_rows','relation_edges')},ensure_ascii=False))
 return stats

def verify():
 events,contexts,repairs=m.verified_events();es={e['modification_id']:e for e in events};aa=m.read(D/'annotations.jsonl');ev={x['evidence_id']:x for x in m.read(D/'motive_evidence.jsonl')};links=collections.defaultdict(list)
 for l in m.read(D/'evidence_links.jsonl'):links[l['modification_id']].append(l)
 checks={};checks['all_1757_events_once']=len(aa)==1757 and {a['modification_id'] for a in aa}==set(es)
 m.batch_validate(aa,es,ev,links);checks['all_annotations_quotes_targets_and_conflicts']=True
 reviews=m.read(D/'log_modification_reviews.jsonl');checks['review_state_not_unknown']=all(x['review_state']=='assistant_reviewed' and x['motive_status'] is not None for x in reviews)
 checks['all_18173_associations_retained']=sum(x['association_count'] for x in reviews)==18173
 old_reviews={x['modification_id']:x for x in m.read(m.OLD/'delivery_v2/log_modification_reviews.jsonl')}
 immutable=['modification_id','repository','modification_sha','file_path','old_path','new_path','parent_sha','observed_change','association_event_ids','stage1_log_ids','lineage_confidence_counts','guard_status']
 checks['event_and_lineage_fields_unchanged']=all(all(x[k]==old_reviews[x['modification_id']][k] for k in immutable) for x in reviews)
 guard=json.loads((O/'guard_receipt.json').read_text())
 checks['all_development_guard_allowed']=all(x['guard_status']=='allowed' for x in reviews) and guard['checks']=={'allowed':829} and guard['allowed_associations']==18173 and guard['parent_code_matched']
 checks['unique_relation_edges']=len({(mid,l['evidence_id'],l['relation']) for mid,ll in links.items() for l in ll})==sum(map(len,links.values()))
 required={lid:(mid,l['evidence_id']) for mid,ll in links.items() for l in ll for lid in l.get('original_link_ids',[])};seen=set();count=0
 with (m.PARENT/'stage3_final/evidence_links.jsonl').open(encoding='utf-8-sig') as f:
  for line in f:
   l=json.loads(line);count+=1;mid,eid=required[l['link_id']];e=es[mid]
   assert eid==l['evidence_id'] and l['event_id'] in e['association_event_ids']
   assert all(l[k]==e[k] for k in ('repository','modification_sha','file_path'));seen.add(l['link_id'])
 checks['all_original_chain_ids_and_targets_verified']=count==191672 and len(seen)==len(required)==191672
 # Reuse source identity, don't let equivalent rows act as independent votes.
 oldev={x['evidence_id']:x for x in m.read(m.OLD/'delivery_v2/motive_evidence.jsonl')}
 checks['all_parent_source_text_and_provenance_retained']=all(ev[k]==v for k,v in oldev.items())
 checks['source_text_hashes_valid']=all(__import__('hashlib').sha256(v['text'].encode()).hexdigest()==v['content_sha256'] for v in ev.values())
 old_hashes=json.loads((O/'input_hashes.json').read_text());hash_result={p:m.sha(m.ROOT/p)==h for p,h in old_hashes.items()}
 checks['parent_input_hashes_unchanged']=all(hash_result.values());m.write(V/'parent_hash_check.json',hash_result)
 checks['nine_span_repairs_preserve_original_fields']=len(repairs)==9 and all(x['upstream_fields_unchanged'] for x in repairs)
 tests=json.loads((V/'regression_tests.json').read_text());checks['adversarial_regressions_pass']=tests['status']=='PASS'
 checks['empty_pending_queue']=not m.read(D/'pending_events.jsonl')
 checks['batch_count_and_sizes']=len(list((O/'batches').glob('*_review/validation.json')))==33 and all(len(m.read(p))==50 for p in sorted((O/'batches').glob('*_review/annotations.jsonl'))[:-1]) and len(m.read(O/'batches/033_review/annotations.jsonl'))==47
 status='PASS' if all(checks.values()) else 'FAIL';m.write(V/'validation.json',{'status':status,'checks':checks,'at':m.now(),'scope':'data retention, provenance, precise target conditions, conservative annotation contracts; not independent semantic accuracy'})
 print(status,checks);assert status=='PASS'
 return checks

if __name__=='__main__':
 if sys.argv[1]=='build':build()
 elif sys.argv[1]=='verify':verify()
 else:raise SystemExit('build | verify')
