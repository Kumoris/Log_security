"""Verify and document an executed continuation. No mining or remote writes."""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from agent_log_motivation_v11 import rows, digest, file_hash, table, write_json, TYPES, STATUSES


def read(p):
    return json.loads(Path(p).read_text(encoding='utf-8-sig'))


def package(root, stage3):
    root, stage3 = Path(root), Path(stage3)
    out = root / 'delivery'; out.mkdir(exist_ok=False)
    snapshot=root/'stage2_snapshot'; legacy=root/'legacy_audit'
    a,b,c=read(snapshot/'summary.json'),read(stage3/'summary.json'),read(legacy/'summary.json')
    if read(snapshot/'validation.json')['status']!='PASS' or read(stage3/'validation.json')['status']!='PASS':
        raise ValueError('stage_validation_required')
    event_keys={}; row_keys={}; physical={}
    for line,r in rows(snapshot/'followups.jsonl'):
        key=[r['repository_id'],r['sha'],r['parent_sha'],r['file_path'],(r.get('before') or {}).get('start_line'),
             (r.get('after') or {}).get('start_line'),r['entity_fingerprint'],r['change_kind']]
        event_keys[r['id']]=digest(key)[:24]
        row_keys[line]=event_keys[r['id']]
    events={}
    for _,r in rows(stage3/'log_modifications.jsonl'):
        e={k:v for k,v in r.items() if k not in {'diffs','source_anchors'}}
        events[e['event_id']]=e
        uid=event_keys.get(e['upstream_event_id']) or row_keys[e['input_row']]
        group=physical.setdefault(uid,dict(modification_id=uid,repository=e['repository'],modification_sha=e['modification_sha'],
            parent_sha=e['parent_sha'],file_path=e['file_path'],old_path=e['old_path'],new_path=e['new_path'],
            observed_change=e['observed_change'],change_relation=e['change_relation'],association_event_ids=[],stage1_log_ids=set(),
            association_motive_status_counts=Counter(),lineage_confidence_counts=Counter()))
        group['association_event_ids'].append(e['event_id'])
        group['stage1_log_ids'].update(e['stage1_log_ids'])
        group['association_motive_status_counts'][e['motive_status']]+=1
        group['lineage_confidence_counts'][e['upstream_confidence']]+=1
        e['modification_id']=uid
    evidence={r['evidence_id']:r for _,r in rows(stage3/'motive_evidence.jsonl')}
    links=[r for _,r in rows(stage3/'evidence_links.jsonl')]
    motives={r['event_id']:r for _,r in rows(stage3/'motives.jsonl')}
    grouped_links={};association_coverage=defaultdict(set);unique_coverage=defaultdict(set)
    links_by_event=defaultdict(list)
    for link in links:
        e=events[link['event_id']];uid=e['modification_id'];eid=link['evidence_id']
        if eid not in evidence:raise ValueError('orphan_evidence')
        if (link['repository'],link['modification_sha'],link['file_path']) != (e['repository'],e['modification_sha'],e['file_path']):
            raise ValueError('event_link_locator_mismatch')
        links_by_event[e['event_id']].append(link)
        association_coverage[link['source_type']].add(e['event_id']);unique_coverage[link['source_type']].add(uid)
        key=(uid,eid,link['relation'])
        edge=grouped_links.setdefault(key,dict(modification_id=uid,evidence_id=eid,source_type=link['source_type'],relation=link['relation'],
            association_methods=set(),original_link_ids=[],original_event_ids=set()))
        edge['association_methods'].add(link['association_method']);edge['original_link_ids'].append(link['link_id']);edge['original_event_ids'].add(e['event_id'])
    for r in physical.values():
        r['association_count']=len(r['association_event_ids']);r['stage1_log_ids']=sorted(r['stage1_log_ids'])
        # Different certainty across origin associations is not a motive conflict.
        r['motive_aggregation_policy']='retain association statuses; do not synthesize conflicting from certainty differences'
    for r in grouped_links.values():
        r['association_methods']=sorted(r['association_methods']);r['original_event_ids']=sorted(r['original_event_ids'])
    table(out,'unique_log_modifications',list(physical.values()),['modification_id','repository','modification_sha','file_path','observed_change','association_count'])
    table(out,'unique_modification_evidence',list(grouped_links.values()),['modification_id','evidence_id','source_type','relation','original_link_ids'])
    table(out,'association_to_modification',[dict(event_id=e['event_id'],upstream_event_id=e['upstream_event_id'],modification_id=e['modification_id']) for e in events.values()],['event_id','upstream_event_id','modification_id'])
    coverage=[dict(source_type=k,association_events=len(association_coverage[k]),association_denominator=len(events),
        association_fraction=len(association_coverage[k])/len(events) if events else None,
        unique_modifications=len(unique_coverage[k]),unique_denominator=len(physical),
        unique_fraction=len(unique_coverage[k])/len(physical) if physical else None,
        evidence_rows=sum(r['source_type']==k for r in evidence.values())) for k in TYPES]
    table(out,'source_coverage',coverage,['source_type','association_events','association_denominator','association_fraction','unique_modifications','unique_denominator','unique_fraction','evidence_rows'])
    w=Path(__file__).resolve().parents[1]
    scope=read(w/'outputs/swechat_agent_scope_20260919/final/summary.json')
    with (w/'outputs/swechat_log_alignment_20260921/final/changed_logs.csv').open(encoding='utf-8-sig',newline='') as f:
        candidates=list(csv.DictReader(f))
    file_units=len({(r['repo_id'],r['commit_sha'],r['path']) for r in candidates})
    stage_rows=[dict(stage='scope',input_unit='repo+SHA+path',input_count=scope['file_units_repo_commit_path'],output_count=scope['main_code_files'],output_unit='原范围代码文件单元',fraction=scope['main_code_files']/scope['file_units_repo_commit_path']),
        dict(stage='1',input_unit='原范围代码文件单元',input_count=scope['main_code_files'],output_count=file_units,output_unit='已观察到日志候选的文件单元',fraction=file_units/scope['main_code_files']),
        dict(stage='1_logs',input_unit='日志候选',input_count=len(candidates),output_count=a['stage2_input_candidates'],output_unit='原样送入第二步',fraction=1.0),
        dict(stage='2_observed',input_unit='原日志候选',input_count=a['stage2_input_candidates'],output_count=a['changed_candidates_observed'],output_unit='已观察到后续修改的候选',fraction=a['stage2_observed_lower_bound_fraction'],final_fraction=a['stage2_final_filter_fraction'],pending=a['pending_candidates']),
        dict(stage='2_events',input_unit='追踪起点—修改关联',input_count=a['stage2_event_links'],output_count=a['unique_modification_events'],output_unit='按既有事件键汇总的修改事件',fraction=None),
        dict(stage='3',input_unit='第二步修改关联',input_count=a['stage2_event_links'],output_count=b['events'],output_unit='保留的动机分析记录',fraction=b['events']/a['stage2_event_links'])]
    table(out,'stage_counts',stage_rows,['stage','input_unit','input_count','output_unit','output_count','fraction'])
    table(out,'motive_distribution',[dict(status=s,count=b['motive_distribution'][s],denominator=len(events),fraction=b['motive_distribution'][s]/len(events)) for s in STATUSES],['status','count','denominator','fraction'])
    table(out,'unknown_reasons',[dict(reason=k,count=v) for k,v in Counter(m.get('unknown_reason') for m in motives.values() if m['motive_status']=='unknown').items()],['reason','count'])
    checks={
        'all_second_stage_rows_preserved':len(events)==a['stage2_event_links']==len(event_keys),
        'all_physical_event_keys_preserved':len(physical)==a['unique_modification_events'],
        'all_motives_resolve':set(motives)==set(events),
        'unique_evidence_ids':len(evidence)==b['evidence_rows'],
        'unique_link_ids':len({r['link_id'] for r in links})==len(links),
        'evidence_text_hashes_match':all(digest(r['text'])==r['content_sha256'] for r in evidence.values()),
        'coverage_reconciles':all(len(association_coverage[k])==b['source_coverage'][k]['events'] for k in TYPES),
        'valid_citations':all(ref['quote'] in evidence[ref['evidence_id']]['text'] and any(l['evidence_id']==ref['evidence_id'] for l in links_by_event[mid]) for mid,m in motives.items() for claim in m['claims'] for ref in claim['citations']),
        'snapshot_original_inputs_still_unchanged':all(file_hash(p)==h for p,h in read(snapshot/'validation.json')['input_sha256'].items()),
        'legacy_parent_unchanged':read(legacy/'input_integrity.json')['all_match_accepted_parent'],
        'no_claim_of_independent_human_validation':all(m['human_validated'] is False for m in motives.values()),
    }
    joined_ids={r['event_id'] for _,r in rows(stage3/'modifications_with_evidence.jsonl')}
    checks['left_join_preserves_all_events']=joined_ids==set(events)
    write_json(out/'verification.json',{'status':'PASS' if all(checks.values()) else 'FAIL','checks':checks,'executed':True,'holdout_evaluated':False})
    if not all(checks.values()):raise ValueError('delivery_verification_failed')
    selected=[e for e,m in motives.items() if m['motive_status']!='unknown']
    connected=next((e for e in events if {'pr_description','review_comment','issue'} <= {l['source_type'] for l in links_by_event[e]}),None)
    if connected and connected not in selected:selected.append(connected)
    example_rows=[];paragraphs=['# 可追溯样例','\n以下为已通过 guard 的开发材料。助手审阅不是独立人工真值。']
    for eid in selected:
        e=events[eid];m=motives[eid];ls=links_by_event[eid]
        cited={ref['evidence_id'] for a in m['claims'] for ref in a['citations']}
        chosen=[];types=set()
        for link in ls:
            if link['evidence_id'] in cited or link['source_type'] not in types:
                chosen.append(link);types.add(link['source_type'])
        source_rows=[{**evidence[l['evidence_id']],'association_method':l['association_method'],'association_basis':l['association_basis'],'relation':l['relation']} for l in chosen]
        example_rows.append(dict(event=e,motive=m,evidence=source_rows))
        obs=e['observed_change']
        paragraphs.extend([f"\n## {eid}：{m['motive_status']}",f"\n仓库 `{e['repository']}`；修改 `{e['modification_sha']}`；文件 `{e['file_path']}`。",
            '\n观察到的变化：\n```text\n'+str(obs.get('before_statement'))+'\n→\n'+str(obs.get('after_statement'))+'\n```',
            '\n材料明确目的：'+json.dumps(m['stated_purposes'],ensure_ascii=False), '\n上下文推断：'+json.dumps(m['inferences'],ensure_ascii=False),
            '\n未定原因：'+str(m.get('unknown_reason'))])
        for s in source_rows:
            paragraphs.extend([f"\n- `{s['source_type']}` / `{s['source_id']}`；时间 `{s.get('source_time')}`；关系 `{s['relation']}`。",
                '  来源：'+str(s.get('source_url') or s.get('source_local_path')),
                '  关联依据：`'+json.dumps(s['association_basis'],ensure_ascii=False)+'`',
                '\n```text\n'+s['text'][:1200]+'\n```'])
    table(out,'traceable_examples',example_rows,['event','motive','evidence'])
    (out/'可追溯样例.md').write_text('\n'.join(paragraphs)+'\n',encoding='utf-8')
    supplement=[
        ('unique_log_modifications','modification_id','sha256(原 repository_id、修改SHA、父SHA、路径、before/after起始行、entity_fingerprint、change_kind) 的前24位；仅报告视图，不删除原行'),
        ('unique_log_modifications','association_event_ids','本次修改对应的全部原关联行；不同追踪起点不冒充多个独立代码修改'),
        ('unique_log_modifications','association_motive_status_counts','各原关联行的动机状态分布；不同确定性不等于冲突证据'),
        ('unique_modification_evidence','original_link_ids','原证据关联ID列表；完整关联依据留在第三步 evidence_links'),
        ('source_coverage','association_fraction / unique_fraction','前者按保留关联行计，后者按既有事件键去重计；两者均是材料覆盖率，不是动机明确率'),
        ('stage_counts','final_fraction','尚有上游 pending 时为 null；当前 observed fraction 是已经观察到的比例'),
        ('candidate_ledger','pending_upstream_execution','本次快照时未获得完成回执；不可解释为无后续变化'),
        ('request_outcomes','status','retrieved 或 failed_or_partial；读取失败不等价于空查询结果'),
    ]
    table(out,'field_dictionary_supplement',[dict(table=t,field=f,definition=d,definition_status='verified_against_incremental_code') for t,f,d in supplement],['table','field','definition','definition_status'])
    write_json(out/'summary.json',dict(stage_counts=stage_rows,source_coverage=coverage,motive_distribution=b['motive_distribution'],
        association_events=len(events),unique_modifications=len(physical),evidence_rows=len(evidence),original_links=len(links),
        unique_modification_evidence_links=len(grouped_links),legacy=c,full_stage2_complete=a['full_stage2_complete'],pending_candidates=a['pending_candidates']))
    print(json.dumps({'status':'PASS','events':len(events),'unique_modifications':len(physical),'evidence_rows':len(evidence),'links':len(links),'motives':b['motive_distribution']}),flush=True)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--root',type=Path,required=True);ap.add_argument('--stage3',type=Path,required=True)
    a=ap.parse_args();package(a.root,a.stage3)
