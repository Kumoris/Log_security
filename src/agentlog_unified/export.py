"""Redacted evidence packages, separate units, and human review queues."""
from __future__ import annotations
from collections import Counter,defaultdict
import csv
import io
import json
import random
from pathlib import Path
import jsonschema
from .storage import atomic_write,canonical,redact,csv_cell,stable_id


def write_json(path: Path,value) -> None:
    atomic_write(path,json.dumps(redact(value),ensure_ascii=False,indent=2)+'\n')


def write_jsonl(path: Path,rows: list[dict]) -> None:
    atomic_write(path,''.join(canonical(redact(r))+'\n' for r in sorted(rows,key=lambda r:str(r.get('id') or r.get('case_id') or stable_id(r)))))


def write_csv(path: Path,rows: list[dict],fields: list[str] | None=None) -> None:
    names=fields or sorted({k for row in rows for k in row}) or ['case_id','status']
    out=io.StringIO(newline='');writer=csv.DictWriter(out,fieldnames=names,extrasaction='ignore');writer.writeheader()
    for row in rows:writer.writerow({k:csv_cell(v) for k,v in redact(row).items() if k in names})
    atomic_write(path,out.getvalue())


def export_run(run: Path,store,manifest: dict,config: dict) -> dict:
    from .review import review_annotations, review_history
    from .type_audit import build_type_audit
    annotations=review_annotations(store)
    candidates=store.rows('candidates'); logs=store.rows('log_changes'); followups=store.rows('followups')
    candidates=[{**c,'human_review':annotations.get(c['case_id'])} for c in candidates]
    followby=defaultdict(list)
    for f in followups:followby[f['case_id']].append(f)
    tables={name:store.rows(name) for name in ['repositories','prs','commits','file_changes','provenance','log_events','log_entities','dependency_edges','pr_commit_links','target_branch_integration_events','human_controls','failures','coverage_gaps','retrieval_audit']}
    tables.update(log_changes=logs,followups=followups,candidates=candidates,
                  logs_with_followups=[r for r in candidates if r['followup_ids']],
                  logs_without_observed_followups=[r for r in candidates if not r['followup_ids']],
                  privacy_review_candidates=[r for r in candidates if r['privacy_assessment'] in {'possible','supported'} and r['screening_bucket']!='OUT_OF_SCOPE_OR_FALSE_POSITIVE'],
                  unknown_provenance=[r for r in candidates if r['log_change_actor_type']=='unknown'],
                  exclusions=[r for r in candidates if r['screening_bucket']=='OUT_OF_SCOPE_OR_FALSE_POSITIVE'],
                  blocked_by_data=[r for r in candidates if r['screening_bucket']=='BLOCKED_BY_DATA'],
                  calibration_cases=[r for r in candidates if r['cohort']=='calibration_only'])
    tables['human_review_annotations']=list(annotations.values())
    tables['human_review_history']=review_history(store)
    tables['reverse_candidates']=store.rows('reverse_candidates')
    tables['match_overrides']=store.rows('match_overrides')
    tables['match_review_candidates']=[{'event_id':e['id'],'repository_id':e['repository_id'],
        'before_sha':e['parent_sha'],'after_sha':e['sha'],'candidates':e.get('match_candidates',[])}
        for e in tables['log_events'] if e.get('match_candidates')]
    rng=random.Random(config['random_seed']);audits=[]
    strata={'no_log_behavior':tables['retrieval_audit'],'not_supported':[r for r in candidates if r['privacy_assessment']=='not_supported'],'no_followup':tables['logs_without_observed_followups']}
    for stratum,population in strata.items():
        n=min(len(population),max(20,int(len(population)*0.1+0.999)))
        for row in rng.sample(population,n):
            audits.append({'id':stable_id(stratum,row.get('id') or row.get('case_id')),'stratum':stratum,'reference_id':row.get('case_id') or row.get('id'),'sampling_probability':n/len(population),'random_seed':config['random_seed'],'human_review_status':'pending'})
    tables['screening_audit_sample']=audits
    tables['possible_followups']=[f for f in followups if f.get('behavior_confidence')=='possible']
    tables['supported_followups']=[f for f in followups if f.get('behavior_confidence')!='possible']
    type_audit=build_type_audit(**{key:tables[key] for key in (
        'prs','repositories','commits','file_changes','log_events','log_entities','log_changes',
        'followups','coverage_gaps','retrieval_audit')},snapshots=store.rows('snapshots'),languages=config.get('languages'))
    for name in ('type_occurrences','unknown_type_review_queue','pr_coverage_audit'):
        tables[name]=type_audit[name]
    write_json(run/'data/taxonomy_catalog.json',type_audit['taxonomy_catalog'])
    write_csv(run/'reports/type_summary.csv',type_audit['type_summary'])
    write_json(run/'reports/type_summary.json',type_audit['type_summary_metadata'])
    write_json(run/'reports/code_coverage_audit.json',type_audit['code_coverage_audit'])
    write_csv(run/'reports/code_coverage_audit.csv',type_audit['code_coverage_audit']['metrics'])
    type_headers=['id','occurrence_id','unit','taxonomy_version','repository_id','snapshot_sha','path',
        'symbol','identity','start_line','end_line','statement','parser_status','privacy_assessment',
        'source_to_sink','dependencies','missing_evidence','taxonomy_labels','taxonomy_status',
        'unknown_type_review','event_references','snapshot_entity_ids','initial_pr_ids','tracked_followup_pr_ids',
        'initial_case_ids','observation_scopes','human_review_status','runtime_confirmed','new_type_status']
    write_csv(run/'reports/type_occurrences.csv',type_audit['type_occurrences'],type_headers)
    write_csv(run/'reports/unknown_type_review_queue.csv',type_audit['unknown_type_review_queue'],
        type_headers+['queue_reason','unclassified_sources'])
    write_csv(run/'reports/pr_coverage_audit.csv',type_audit['pr_coverage_audit'])
    schema=json.loads((Path(config['project_dir'])/'schemas/candidate.schema.json').read_text())
    for case in candidates:jsonschema.validate(case,schema)
    for name,rows in tables.items():
        write_jsonl(run/'data'/f'{name}.jsonl',rows)
        if name in {'log_changes','logs_with_followups','logs_without_observed_followups','privacy_review_candidates','unknown_provenance','exclusions','blocked_by_data','failures','coverage_gaps'}:
            write_csv(run/'reports'/f'{name}.csv',rows)
    # Blind first pass deliberately excludes provenance, future fixes, and labels.
    blind=[{'blind_id':stable_id('blind',r['case_id']),'file_path':r['file_path'],'symbol':r['symbol'],'before_statement':(r['before'] or {}).get('statement'),'after_statement':(r['after'] or {}).get('statement'),'dependencies':(r['after'] or r['before']).get('dependencies'),'human_review_status':'pending','human_review_decision':None} for r in candidates]
    write_csv(run/'reports/candidates_review_blind.csv',blind)
    write_csv(run/'reports/blind_key.csv',[{'blind_id':stable_id('blind',r['case_id']),'case_id':r['case_id']} for r in candidates])
    write_csv(run/'reports/human_review_template.csv',[{'case_id':r['case_id'],'human_review_status':'pending','human_review_decision':None,'reviewer':None,'evidence_notes':None} for r in candidates])
    write_csv(run/'reports/human_review_annotations.csv',tables['human_review_annotations'])
    write_csv(run/'reports/reverse_candidates.csv',tables['reverse_candidates'])
    changes={c['change_id']:c for c in tables['file_changes']}
    for row in candidates:
        folder=run/'evidence'/row['case_id'];timeline=sorted(followby[row['case_id']],key=lambda f:(f['topo_index'],f['id']))
        write_json(folder/'evidence.json',row);write_json(folder/'timeline.json',timeline);write_jsonl(folder/'timeline.jsonl',timeline)
        for event in [row]+timeline:
            for cid in event['file_change_ids']:
                change=changes.get(cid)
                if change:atomic_write(folder/'patches'/f'{cid}.diff',redact(change.get('diff') or 'DIFF_UNAVAILABLE'))
        entity=row['after'] or row['before']
        link=f"https://github.com/{row['repository']}/blob/{row['intro_sha']}/{row['file_path']}#L{entity['start_line']}-L{entity['end_line']}" if row['repository'] else f"local:{row['intro_sha']}:{row['file_path']}:{entity['start_line']}-{entity['end_line']}"
        text=f'''# Case {row['case_id']}

机器候选：{row['screening_bucket']} / {row['priority']}；人工复核 {((row.get('human_review') or {}).get('human_review_status') or 'pending')}；新类型 not_established。

人工记录独立于机器判断：{canonical(row.get('human_review'))}。过期标注须重新核对；不会自动确认运行泄露或作者。

- 改了什么：{row['change_kind']} / {row['relation']}，{row['file_path']}::{row['symbol']}。
- 谁引入：日志改动者 {row['log_change_actor_type']}；敏感路径引入者 {row['risk_introducer_type']}；来源置信度 {row['provenance_confidence']}。
- 数据为何可能敏感：{canonical(row['data_type'])}；机器判断 {row['privacy_assessment']}。
- 如何到达日志：{canonical(row['source_to_sink'])}。
- 触发条件：{canonical(row['trigger_conditions'])}；输出读者/权限 unknown。
- 后来如何改变：{len(timeline)} 个相关事件；标签 {canonical(row['followup_change_types'])}。
- 修复/缓解依据：{row['fix_effect']}，仅对所观察的静态路径；不等于已部署或确认运行泄露。
- 仍缺什么：{canonical(row['missing_evidence'])}；删失 {row['censoring_reason']}。
- 非 Agent 解释：{canonical(row['alternative_explanations'])}。

代码证据：[固定版本]({link})。before={row['before_sha']} intro={row['intro_sha']} merged={row['merged_sha']} pre_fix={row['pre_fix_sha']} fix={row['fix_sha']}。

```text
{(row['before'] or {}).get('statement','<ABSENT>')}
```

```text
{(row['after'] or {}).get('statement','<ABSENT>')}
```

完整依赖和逐事件差异见 evidence.json、timeline.json 与 patches/。原始数据仅在本地受限 SQLite 中；本包已脱敏。
'''
        atomic_write(folder/'case.md',redact(text));write_json(folder/'validation/status.json',{'validation_method':'static_only','target_code_executed':False,'runtime_leak_claim':False,'human_review_status':((row.get('human_review') or {}).get('human_review_status') or 'pending')})
    for row in tables['reverse_candidates']:
        folder=run/'evidence'/('reverse-'+row['id'])
        write_json(folder/'evidence.json',row)
        atomic_write(folder/'case.md',redact('# 反向补充候选\n\n仅属于 repair_enriched 队列，不进入正向主样本分母；人工 pending。\n\n'+
            f"- 修复说明命中提交：{row['fix_sha']}\n- 路径：{row['path']}\n- 提取后端：{row['backend']}\n\n```text\n{row['statement']}\n```\n\nSZZ 给出被删除日志行的最后修改者候选，不证明缺陷引入、Agent 作者或实际隐私修复。\n"))
    funnel=[]
    for name,unit,rows in [('repositories','repository',tables['repositories']),('input_records','input_record',tables['prs']),('prs','GitHub_PR',[p for p in tables['prs'] if p.get('repository') and p.get('pr_number')]),('local_inputs','local_fixture_or_commit_input',[p for p in tables['prs'] if not p.get('pr_number')]),('commits','commit',tables['commits']),('file_changes','parent_file_diff',tables['file_changes']),('log_events','log_event_all_history',tables['log_events']),('log_changes','initial_log_change_PR_context',logs),('logs_with_followups','initial_log_change',tables['logs_with_followups']),('logs_without_observed_followups','initial_log_change',tables['logs_without_observed_followups']),('followups','followup_event',followups),('possible_followups','followup_event',tables['possible_followups']),('supported_followups','followup_event',tables['supported_followups']),('privacy_review_candidates','initial_log_change',tables['privacy_review_candidates'])]:
        funnel.append({'stage':name,'unit':unit,'count':len(rows)})
    for key,count in sorted(Counter(r['screening_bucket'] for r in candidates).items()):funnel.append({'stage':key,'unit':'initial_log_change','count':count})
    write_csv(run/'reports/screening_funnel.csv',funnel,['stage','unit','count'])
    funnel.append({'stage':'unique_initial_log_changes','unit':'distinct_log_change','count':len({r['log_change_id'] for r in logs})})
    write_csv(run/'reports/screening_funnel.csv',funnel,['stage','unit','count'])
    summary={'counts':{k:len(v) for k,v in tables.items()},'funnel':funnel,'buckets':dict(Counter(r['screening_bucket'] for r in candidates)),'authors':dict(Counter(r['log_change_actor_type'] for r in candidates)),'cohorts':dict(Counter(r['cohort'] for r in candidates)),'machine_only':True,'schema_validation':'passed'}
    write_json(run/'reports/summary.json',summary)
    blockers=Counter(g.get('error_type','unknown') for g in tables['coverage_gaps'])
    atomic_write(run/'reports/blockers.md','# 实际缺口\n\n'+('\n'.join(f'- {k}: {v}' for k,v in sorted(blockers.items())) or '无已记录数据阻塞。')+'\n\n缺历史、解析降级、观察窗口不足均不代表安全。详细 SHA/路径见 data/coverage_gaps.jsonl。\n')
    atomic_write(run/'reports/coverage_report.md','# 历史覆盖\n\n'+ '\n'.join(f"- {r['repository_id']}：{r['target_ref']} @ {r['frozen_target_tip']}；shallow={r['shallow']}；local_snapshot_only={r['local_snapshot_only']}。" for r in tables['repositories'])+'\n\n截止：'+manifest['collection_cutoff_utc']+'。只覆盖冻结目标分支及列出的 PR 对象；不代表部署历史。\n')
    atomic_write(run/'reports/pilot_report.md','# 实际筛选运行\n\n'+f"Run `{manifest['run_id']}`；PyDriller {manifest['versions']['PyDriller']}；Python {manifest['versions']['python']}。\n\n"+'\n'.join(f"- {f['stage']}: {f['count']} ({f['unit']})" for f in funnel)+'\n\n已执行 ingest → collect → mine → detect → trace → assess → export。普通提交与后续历史实际经 PyDriller；合并每父差异、历史源码和回退记录见 file_changes 与 manifest。\n\n仅合成/技术校准和真实样本按 cohort/is_synthetic 分开，不将 calibration_only 作为发生率分母。机器判断均待人工复核；未运行目标代码、未验证凭据、未调用模型、未修改远程仓库。JS/TS 为显式词法降级；一跳静态依赖不能证明全程序安全。\n\n未实现完整污点分析和大规模匹配对照；这些不阻塞核心筛选。阻塞详情见 blockers.md。\n')
    return summary
