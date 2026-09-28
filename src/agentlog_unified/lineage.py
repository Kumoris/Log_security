"""Separate PR origin timelines from frozen target-branch integrations."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime,timedelta,timezone
from .analysis import behavior
from .provenance import classify_actor
from .storage import stable_id


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        result=datetime.fromisoformat(value.replace('Z','+00:00'))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except (ValueError,TypeError):
        return None


def same_entity(left: dict | None, right: dict | None) -> bool:
    return bool(left and right and left['path']==right['path'] and left['symbol']==right['symbol'] and left['identity']==right['identity'])


def sensitive_sources(entity: dict | None) -> set[tuple]:
    if not entity or entity.get('privacy_assessment')!='supported':
        return set()
    return {(str(e.get('source')),tuple(sorted(e.get('types',[])))) for e in entity.get('source_to_sink',[]) if e.get('types')}


def change_labels(before: dict | None,after: dict | None,kind: str,relation: str) -> tuple[list[str],str]:
    old=sensitive_sources(before); new=sensitive_sources(after)
    if after is None:
        return ['delete_feature'],'unknown'
    if before is None:
        return ['unclear'],'unknown'
    labels=[]
    if before.get('level')!=after.get('level') or before.get('trigger_conditions')!=after.get('trigger_conditions'):
        labels.append('level_or_condition_change')
    if kind=='moved' or before['path']!=after['path']:
        labels.append('refactor_or_move')
    if old-new and before.get('privacy_assessment')=='supported':
        if after.get('existing_sanitization'):
            labels.append('add_redaction')
        if relation=='dependency_change':
            labels.append('fix_shared_sanitizer')
        else:
            labels.append('remove_sensitive_field')
        if after.get('privacy_assessment')=='not_supported' and not new:
            return labels,'eliminates_observed_flow'
        return labels,'partial' if after.get('privacy_assessment')=='supported' and new else 'unknown'
    if labels:
        return labels,'unknown' if 'level_or_condition_change' in labels and old else 'not_privacy_related'
    return ['message_or_format'] if before['statement']!=after['statement'] else ['unclear'],'not_privacy_related' if not old else 'unknown'


def trace_logs(repositories: list[dict],prs: list[dict],mined_rows: list[dict],events: list[dict],snapshots: list[dict],cutoff: str,days: int,all_gaps: list[dict],external_evidence: list[dict] | None=None) -> dict:
    l1,followups,provenance,integrations=[],[],[],[]
    by_repo=defaultdict(list)
    for event in events:
        by_repo[event['repository_id']].append(event)
    snapshots_by={(s['repository_id'],s['sha']):s['entities'] for s in snapshots}
    for repo in repositories:
        rid=repo['id']; mined=next(m for m in mined_rows if m['repository_id']==rid)
        commits={c['sha']:c for c in mined['commits']}
        parents={g['sha']:g['parents'] for g in mined['graph']}
        ancestor_cache={}
        def ancestor(older: str,newer: str) -> bool:
            key=(older,newer)
            if key not in ancestor_cache:
                seen=set(); todo=[newer]
                while todo:
                    c=todo.pop()
                    if c in seen: continue
                    seen.add(c);todo.extend(parents.get(c,[]))
                ancestor_cache[key]=older in seen
            return ancestor_cache[key]
        ordered=sorted(by_repo[rid],key=lambda e:(e['topo_index'],e['id']))
        repo_prs=[p for p in prs if p['id'] in repo['pr_ids']]
        def actor(sha: str,pr: dict) -> dict:
            return classify_actor(commits.get(sha,{'sha':sha}),pr,external_evidence or [])
        for pr in repo_prs:
            initial=set(pr.get('commit_shas') or pr.get('initial_commit_shas') or ([pr['head_sha']] if pr.get('head_sha') else []))
            # Initial PR commits include human/mixed/unknown; no actor filter.
            origins=[e for e in ordered if e['sha'] in initial]
            merge_sha=pr.get('merge_commit_sha') if pr.get('merged_at') else None
            originals=list(origins)
            for merged_event in [e for e in ordered if e['sha']==merge_sha and e not in origins]:
                if not any(same_entity(merged_event['after'] or merged_event['before'],e['after'] or e['before']) for e in originals):
                    origins.append({**merged_event,'origin_view':'merge_resolution_or_rewrite_unattributed'})
            for intro in origins:
                row={**intro,'pr_id':pr['id'],'repository':pr.get('repository'),'pr_number':pr.get('pr_number'),'pr_url':pr.get('pr_url'),'cohort':pr['cohort'],'is_synthetic':pr['is_synthetic'],'pr_actor_type':pr.get('pr_actor_type'),'provided_label':pr.get('provided_label'),'application_domain':'unknown','case_id':stable_id(pr['id'],intro['id']),'defect_cluster_id':stable_id(rid,intro['entity_fingerprint']),'intro_sha':intro['sha'],'before_sha':intro['parent_sha'],'log_added_sha':intro['sha'] if intro['before'] is None else None,'sensitive_flow_introduced_sha':None,'risk_introducer_type':'unknown','issue_raiser_type':'unknown','target_ref':repo['target_ref'],'frozen_target_tip':repo['frozen_target_tip']}
                row['id']=row['case_id']
                a=actor(intro['sha'],pr)
                row.update(log_change_actor_type=a['actor_type'],provenance_confidence=a['confidence'],provenance_evidence=a['evidence'])
                provenance.append({'id':stable_id(pr['id'],intro['sha']),'repository_id':rid,'sha':intro['sha'],'pr_id':pr['id'],**a})
                before,after=intro['before'],intro['after']; entity=after or before
                repeated=sum(entity['path']==e['path'] and entity['symbol']==e['symbol'] and entity.get('message_template')==e.get('message_template') for e in snapshots_by.get((rid,intro['sha']),[]))>1
                old=sensitive_sources(before); new=sensitive_sources(after)
                row['introduction_relation']='new_sensitive_flow' if new and not old else 'expanded_sensitive_flow' if new-old else 'preexisting_unchanged' if old else 'unknown'
                if new-old and (after or {}).get('privacy_assessment')=='supported':
                    row.update(sensitive_flow_introduced_sha=intro['sha'],risk_introducer_type=a['actor_type'])
                integration=None; mapping='unknown'
                merge=pr.get('merge_commit_sha') if pr.get('merged_at') else None
                if merge in mined['first_parent_shas']:
                    integration=merge;mapping='metadata_integration_sha'
                elif intro['sha'] in mined['first_parent_shas']:
                    integration=intro['sha'];mapping='direct_target_commit'
                elif intro['target_reachable']:
                    integration=next((s for s in mined['first_parent_shas'] if ancestor(intro['sha'],s)),None)
                    mapping='ancestry_to_first_parent_integration'
                mapped=[e for e in snapshots_by.get((rid,integration),[]) if same_entity(entity,e)]
                present=bool(len(mapped)==1 and behavior(entity)==behavior(mapped[0])) if integration else False
                if integration and not present:
                    mapping+=':behavior_changed_or_absent'
                row.update(integration_sha=integration,merged_sha=integration,pr_to_target_mapping=mapping,behavior_present_at_integration=present)
                integration_time=parse_time(pr.get('merged_at')) if merge else None
                source='github_merged_at' if integration_time else 'unknown'
                if pr['is_synthetic'] and integration in commits:
                    integration_time=parse_time(commits[integration]['committer_date']);source='synthetic_committer_date'
                row['integration_time_source']=source
                end=parse_time(cutoff)
                obs_end=min(end,integration_time+timedelta(days=days)) if integration_time else end
                observed=max(0,(obs_end-integration_time).total_seconds()/86400) if integration_time else None
                repo_gaps=[g for g in all_gaps if g.get('repository_id')==rid or g.get('repository')==repo['repository_id']]
                history_gap=bool(repo['shallow'] or repo.get('missing_shas') or any(g.get('stage') in {'collect','mine'} for g in repo_gaps))
                censor='history_incomplete' if history_gap else 'not_integrated' if not integration else 'integration_time_unknown' if not integration_time else 'right_censored' if observed<days else None
                # Existing user clones have a frozen local history, not proof that
                # all remote changes through wall-clock cutoff were fetched.
                if repo.get('local_snapshot_only') and not pr['is_synthetic'] and censor is None:
                    censor='remote_collection_cutoff_unverified'
                row.update(observation_start=integration_time.isoformat() if integration_time else None,observation_end=obs_end.isoformat(),observed_days=observed,censoring_reason=censor,coverage_gaps=repo_gaps,followup_status='history_incomplete' if history_gap else 'no_observed_followup',lineage_status='ambiguous' if intro['behavior_match_status']=='ambiguous' or repeated else 'tracked',fix_sha=None,pre_fix_sha=None,first_mitigation_sha=None,first_eliminated_flow_sha=None)
                current=after
                timeline=[]
                unresolved_mapping_seen=False
                row['observation_gaps']=[]
                integration_switched=False
                for later in ordered:
                    if later['sha']==intro['sha']:
                        continue
                    pre=later['sha'] in initial and ancestor(intro['sha'],later['sha']) and (not integration or later['sha']!=integration)
                    post=bool(integration and later['on_target_first_parent'] and later['sha']!=integration and ancestor(integration,later['sha']))
                    if not pre and not post:
                        continue
                    when=parse_time(commits[later['sha']]['committer_date'])
                    if post and integration_time and when and (when>obs_end or when<integration_time):
                        # Dates never determine ancestry; nonmonotonic times stay
                        # visible and cannot establish exact observation latency.
                        if when>obs_end: continue
                        row['censoring_reason']=row['censoring_reason'] or 'nonmonotonic_commit_time'
                    if post and not integration_switched:
                        current=mapped[0] if len(mapped)==1 else None
                        integration_switched=True
                    if current is None or later['before'] is None:
                        continue
                    manual_here=[e for e in ordered if e['sha']==later['sha'] and e.get('match_review')
                                 and same_entity(current,e['before'])]
                    if manual_here and later['id'] not in {e['id'] for e in manual_here}:
                        continue
                    if later.get('match_review') and same_entity(current,later['before']) and not unresolved_mapping_seen:
                        row['lineage_status']='tracked'
                    gap_event=later['change_kind'] in {'coverage_gap','gap_resumed'}
                    possible=(row['lineage_status']=='ambiguous' or later['behavior_match_status']=='ambiguous') and current['path']==later['before']['path'] and current['symbol']==later['before']['symbol'] and current.get('message_template')==later['before'].get('message_template')
                    if not same_entity(current,later['before']) and not possible:
                        continue
                    if behavior(current)!=behavior(later['before']):
                        row['lineage_status']='ambiguous'
                    labels,effect=change_labels(later['before'],later['after'],later['change_kind'],later['relation'])
                    if possible or row['lineage_status']=='ambiguous' or later['behavior_match_status']=='ambiguous':
                        row['lineage_status']='ambiguous';effect='unknown';unresolved_mapping_seen=True
                    if gap_event:
                        labels=[later['change_kind']]
                        effect='unknown'
                        row['observation_gaps'].append(later['gap_interval'])
                        row['censoring_reason']=row['censoring_reason'] or 'parse_or_source_coverage_gap'
                    follow_actor=actor(later['sha'],pr)
                    f={**later,'id':stable_id(row['case_id'],later['id']),'case_id':row['case_id'],'log_change_id':intro['id'],'followup_sha':later['sha'],'followup_pr_number':pr.get('pr_number') if later['sha'] in initial else None,'phase':'pre_merge' if pre else 'post_merge','behavior_relation':'same_symbol' if possible else 'same_call' if later['relation']=='direct_call_change' else 'dependency','behavior_confidence':'possible' if possible or row['lineage_status']=='ambiguous' else 'supported','candidate_before_identity':later['before']['identity'],'followup_change_types':labels,'fix_effect':effect,'fix_executor_type':follow_actor['actor_type'],'provenance_confidence':follow_actor['confidence'],'provenance_evidence':follow_actor['evidence'],'effective_target_sha':later['sha'] if post else integration,'effective_on_target':post,'time_source':'committer_date_proxy','source_to_sink_before':(later['before'] or {}).get('source_to_sink',[]),'source_to_sink_after':(later['after'] or {}).get('source_to_sink',[])}
                    if gap_event:
                        f.update(behavior_relation=later['change_kind'], behavior_confidence='possible',
                                 fix_executor_type='unknown', change_commit_attribution='interval_unknown',
                                 observed_endpoint_actor_type=follow_actor['actor_type'],
                                 effective_target_sha=None, time_source='interval_censored')
                    if not gap_event and not possible and row['lineage_status']!='ambiguous' and not row['sensitive_flow_introduced_sha'] and (later['after'] or {}).get('privacy_assessment')=='supported' and not sensitive_sources(after):
                        row.update(introduction_relation='later_activated',sensitive_flow_introduced_sha=later['sha'],risk_introducer_type=follow_actor['actor_type'])
                    if effect in {'eliminates_observed_flow','partial','mitigates_under_condition'} :
                        if not row['first_mitigation_sha']:
                            row['first_mitigation_sha']=later['sha']
                        if effect=='eliminates_observed_flow' and not row['first_eliminated_flow_sha']:
                            row['first_eliminated_flow_sha']=later['sha']
                        row.update(fix_sha=later['sha'],pre_fix_sha=later['parent_sha'])
                    timeline.append(f)
                    if f['behavior_confidence']=='supported' or (later['change_kind']=='gap_resumed' and later['behavior_match_status']!='ambiguous'):
                        current=later['after']
                row['followup_ids']=[f['id'] for f in timeline]
                row['followup_status']='observed_followup' if timeline else row['followup_status']
                row['missing_evidence']=list(dict.fromkeys(entity.get('missing_evidence',[])+(['commit_authorship_unverified'] if a['actor_type']=='unknown' else [])+(['target_integration_unknown'] if not integration else [])+(['change_time_and_executor_unknown_inside_coverage_gap'] if row['observation_gaps'] else [])))
                followups.extend(timeline);l1.append(row)
                integrations.append({'id':stable_id(row['case_id'],'integration'),'case_id':row['case_id'],'origin_sha':intro['sha'],'integration_sha':integration,'pr_to_target_mapping':mapping,'behavior_present':present,'time_source':source})
    return {'log_changes':l1,'followups':followups,'provenance':provenance,'target_branch_integration_events':integrations}


def assess(logs: list[dict],followups: list[dict]) -> list[dict]:
    by_case=defaultdict(list)
    for f in followups:by_case[f['case_id']].append(f)
    rows=[]
    for row in logs:
        history=by_case[row['case_id']]
        intro_entity=row['after'] or row['before']
        risk_entity=intro_entity
        if row['introduction_relation']=='later_activated':
            risk_entity=next((f['after'] for f in history if f['sha']==row['sensitive_flow_introduced_sha']),intro_entity)
        risk=risk_entity.get('privacy_assessment','unknown')
        repairs=[f for f in history if f['fix_effect'] in {'eliminates_observed_flow','partial','mitigates_under_condition'}]
        missing=list(row['missing_evidence'])
        if row['lineage_status']=='ambiguous':missing.append('ambiguous_entity_mapping')
        if row['extraction_status']!='ok' or row['censoring_reason']=='history_incomplete':
            bucket='BLOCKED_BY_DATA'
        elif row.get('observation_gaps'):
            bucket='NEEDS_CONTEXT'
        elif risk=='not_supported':
            bucket='OUT_OF_SCOPE_OR_FALSE_POSITIVE'
        elif risk=='supported' and repairs and row['lineage_status']!='ambiguous' and row.get('sensitive_flow_introduced_sha') and row['parser_status']!='lexical_only':
            bucket='REVIEW_READY'
        elif risk in {'unknown','possible'} or row['lineage_status']=='ambiguous':
            bucket='NEEDS_CONTEXT'
        else:bucket='NO_OBSERVED_PRIVACY_FIX'
        priority='P1' if bucket=='REVIEW_READY' and row['provenance_confidence']=='high' and row['log_change_actor_type']!='unknown' else 'P2' if risk in {'possible','supported'} else 'P3'
        rows.append({**row,'privacy_assessment':risk,'data_type':risk_entity.get('data_types',[]),'source_to_sink':risk_entity.get('source_to_sink',[]),'existing_sanitization':risk_entity.get('existing_sanitization',[]),'trigger_conditions':risk_entity.get('trigger_conditions',[]),'sink':risk_entity.get('callee'),'access_boundary':'unknown','screening_bucket':bucket,'priority':priority,'matched_rules':risk_entity.get('matched_rules',[]),'exclusion_reason':'no_sensitive_flow_supported_by_bounded_analysis' if bucket=='OUT_OF_SCOPE_OR_FALSE_POSITIVE' else None,'machine_assessment':'bounded_static_rule_screening','human_review_status':'pending','human_review_decision':None,'validation_method':'static_only','runtime_leak_claim':False,'new_type_status':'not_established','mechanism_evidence_level':'code_only','agent_process_hypothesis':None,'leak_mechanism':'sensitive_value_to_log' if risk=='supported' else 'unresolved','alternative_explanations':['human_authored_code_can_exhibit_same_behavior','authorized_logging_and_access_configuration_need_review'],'missing_evidence':missing,'followup_change_types':sorted({v for f in history for v in f['followup_change_types']}),'fix_effect':repairs[-1]['fix_effect'] if repairs else 'unknown','fix_executor_type':repairs[-1]['fix_executor_type'] if repairs else 'unknown','evidence_refs':[f'evidence/{row["case_id"]}/evidence.json'],'candidate_without_observed_fix':risk in {'possible','supported'} and not repairs})
    return rows
