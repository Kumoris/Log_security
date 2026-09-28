"""Read-only verification/aggregation of this fixed pilot, no model calls."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sqlite3

from agentlog_unified.config import sha256_file
from agentlog_unified.export import write_csv, write_json, write_jsonl
from agentlog_unified.semantic_context import HistoricalContext, load_run
from agentlog_unified.semantic_demand import gate, validate


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--project',type=Path,default=Path(__file__).resolve().parents[1]);args=parser.parse_args()
    root=args.project;docs=root/'docs/demand-v080';runs=root/'outputs/semantic-runs'
    freeze=json.loads((docs/'cohort-freeze-evaluation.json').read_text())
    verification=[]
    for name in ('real-v070-final','synthetic-demand-v080','demand-smoke-v080','demand-development-v080','demand-development-v080-final','demand-evaluation-v080','demand-offline-v080-final','demand-post-fix-v080'):
        directory=runs/name;manifest=json.loads((directory/'manifest.json').read_text())
        hashes=manifest.get('artifacts',manifest.get('artifact_sha256',{}))
        valid=all(sha256_file(directory/p)==h for p,h in hashes.items())
        assert valid,name
        verification.append({'run':name,'artifact_count':len(hashes),'hashes_valid':valid})
    changed=[p for p,h in freeze['source_code_sha256'].items() if sha256_file(root/'src/agentlog_unified'/p)!=h]
    assert set(changed)=={'semantic_context.py','semantic_demand.py'},'unrecorded post-evaluation source change'
    execution=json.loads((runs/'demand-evaluation-v080/manifest.json').read_text())
    assert execution['fingerprint']['sources']==freeze['source_code_sha256']
    db=sqlite3.connect(f'file:{runs}/demand-v080-budget.sqlite?mode=ro',uri=True)
    ledger=[json.loads(r[0]) for r in db.execute('SELECT data FROM attempts ORDER BY rowid')];db.close()
    assert len(ledger)<=80
    per_case=Counter(r['case_id'] for r in ledger);assert max(per_case.values())<=6
    usage=Counter();runtime=Counter()
    for r in ledger:
        runtime[str(r.get('receipt',{}).get('model_reported_by_runtime'))]+=1
        for u in r.get('receipt',{}).get('usage',[]):usage.update({k:v for k,v in (u or {}).items() if isinstance(v,int)})
    selected={x['id']:x for x in freeze['cases']};cases=[]
    for name in ('demand-development-v080-final','demand-evaluation-v080'):
        cases += [json.loads(p.read_text()) for p in (runs/name/'evidence').glob('*.json')]
    assert len(cases)==12 and {c['case_id'] for c in cases}==set(selected)
    rows=[];retrievals=[];records=[];availability=[]
    original_cases,snapshots,_=load_run(runs/'real-v070-final');post_recheck=[]
    for c in sorted(cases,key=lambda c:c['case_id']):
        r=c['result_metadata'];base=selected[c['case_id']];a=c['conditions']['A'];b=c['conditions']['B']['post_review'];d=c['conditions']['C']['post_review']
        row={'case_id':c['case_id'],'repository':r['repository'],'sha':r['sha'],'path':r['path'],'line':r['use_anchor']['line'],
             'field':r['field'],'language':r['language'],'ambiguity_source':r['ambiguity_source'],'role':base['experiment_role'],
             'type_control':base['explicit_type_context'],'tutorial_or_example':any(x in r['path'].lower() for x in ('tutorial','example','test','fixture')),
             'A_semantics_status':a['independent_review_status'],'A_types':a['program_semantics'].get('types',[]),
             'primary_blocker':c['primary_blocker'],'queues':c['queues'],'stop':c['stop'],'human_truth':'pending'}
        for condition,value in [('B',b),('C',d)]:
            for dimension in ('program_semantics','sensitive_type','log_relation','privacy_risk'):
                row[condition+'_'+dimension+'_status']=value[dimension]['status'] if value else 'not_run_or_failed'
                row[condition+'_'+dimension+'_value']=value[dimension]['value'] if value else 'unknown'
            row[condition+'_types']=value['sensitive_type']['types'] if value else []
        row['new_supported_C_vs_B']=bool(b and d and b['program_semantics']['status']!='supported' and d['program_semantics']['status']=='supported')
        row['lost_supported_C_vs_B']=bool(b and d and b['program_semantics']['status']=='supported' and d['program_semantics']['status']!='supported')
        row['C_reviewer_changed_dimensions']=[k for k in ('program_semantics','sensitive_type','log_relation','privacy_risk')
            if c['conditions']['C']['pre_review'] and d and (c['conditions']['C']['pre_review'][k]['status'],c['conditions']['C']['pre_review'][k]['value'])!=(d[k]['status'],d[k]['value'])]
        rows.append(row);retrievals+=c['retrievals'];records+=c['model_records']
        cached=set(snapshots[r['repository'],r['sha']]['files'])
        initial_paths={b['anchor']['path'] for b in c['initial_context']['blocks']}
        model_paths={b['anchor']['path'] for b in c['final_context']['blocks']}
        availability.append({'case_id':c['case_id'],'repository':r['repository'],'sha':r['sha'],
            'cached_snapshot_files_loaded':len(cached),'python_files_indexed':sum(p.endswith('.py') for p in cached),
            'initial_model_paths':sorted(initial_paths),'supplementary_model_paths':sorted(model_paths-initial_paths),
            'cached_paths_not_sent_to_model':sorted(cached-model_paths),
            'budget_scope':'8 supplementary evidence paths, not a bound on existing private snapshot cache loading/indexing',
            'new_remote_fetches':0})
        for condition in ('B','C'):
            record=next(x for x in reversed(c['model_records']) if x['condition']==condition and x['stage']=='review')
            ctx=HistoricalContext(original_cases[c['case_id']],snapshots[r['repository'],r['sha']])
            # Replay precisely the evidence received then, without acquiring more
            # files or calling a model. The original wrong checks stay immutable.
            ctx.blocks=record['context']['blocks'];checks=ctx.checks()
            response=validate(record['response'],c['case_id'],'review',record['context'],checks)
            corrected,rejected=gate(response,checks)
            diff=[k for k in ('program_semantics','sensitive_type','log_relation','privacy_risk') if corrected[k]!=record['gated'][k]]
            post_recheck.append({'case_id':c['case_id'],'condition':condition,'phase':'post_evaluation_program_replay_only',
                'origin':'rules_applied_to_previous_model_response','model_rerun':False,'human_confirmed':False,
                'original_model_prompt_sha256':record['prompt_sha256'],'changed_dimensions':diff,
                'original_gated':record['gated'],'corrected_gated':corrected,'checks':checks,'rejections':rejected})
    groups={}
    for group in ('all_real','development','frozen_evaluation_pending_human','exploratory_source_debug_exposed'):
        items=rows if group=='all_real' else [r for r in rows if r['role']==group]
        groups[group]={'denominator':len(items),'A_supported':sum(r['A_semantics_status']=='supported' for r in items),
            'B_supported':sum(r['B_program_semantics_status']=='supported' for r in items),
            'C_supported':sum(r['C_program_semantics_status']=='supported' for r in items),
            'C_sensitive_supported_mapped':sum(r['C_sensitive_type_status']=='supported' and r['C_sensitive_type_value']=='mapped' for r in items),
            'C_semantics_ambiguous_or_failed':sum(r['C_program_semantics_status']!='supported' for r in items),
            'new_supported_C_vs_B':sum(r['new_supported_C_vs_B'] for r in items),
            'lost_supported_C_vs_B':sum(r['lost_supported_C_vs_B'] for r in items),
            'C_reviewer_changed_cases':sum(bool(r['C_reviewer_changed_dimensions']) for r in items),
            'C_semantic_granularity':dict(Counter(r['C_program_semantics_value'] for r in items)),
            'C_log_relation':dict(Counter(r['C_log_relation_value'] for r in items)),
            'C_sensitive_type_states':dict(Counter(r['C_sensitive_type_value'] for r in items)),
            'C_privacy_risk':dict(Counter(r['C_privacy_risk_value'] for r in items))}
    reasons=Counter(q for c in cases for q in c['queues'])
    validation_failures=[{'attempt_id':r['receipt'].get('id'),'case_id':r['case_id'],'reason':r['validation']} for r in records if r['validation'] not in {'valid','not_run'}]
    all_failures={}
    for name in ('demand-smoke-v080','demand-development-v080','demand-development-v080-final','demand-evaluation-v080','demand-post-fix-v080'):
        for line in (runs/name/'model_records.jsonl').read_text().splitlines():
            r=json.loads(line)
            if r['validation'] not in {'valid','not_run'}:
                key=r['receipt'].get('id')
                all_failures[key]={'attempt_id':key,'case_id':r['case_id'],'reason':r['validation'],'run':name}
    summary={'cohort_groups':groups,'model_invocations_total':len(ledger),'attempts_per_case':dict(per_case),'usage_total':dict(usage),
        'model_requested':dict(Counter(r['requested_model'] for r in ledger)),'model_runtime_reported':dict(runtime),
        'elapsed_model_seconds':round(sum(r.get('receipt',{}).get('elapsed_seconds',0) for r in ledger),3),
        'transport_status':dict(Counter(r['status'] for r in ledger)),
        'host_automatic_retries':0,'cli_internal_transport_retries':'not_exposed_by_runtime_receipts',
        'validation_failures_final_cohort':validation_failures,'cases_with_current_model_failure':sum('model_not_run_or_failed' in c['queues'] for c in cases),
        'validation_failures_all_attempts':list(all_failures.values()),
        'retrievals_final_cohort':len(retrievals),'retrieval_status':dict(Counter(r['status'] for r in retrievals)),
        'requests_new_blocks':sum(bool(r['blocks_added']) for r in retrievals),
        'retrieval_failure_reasons':dict(Counter(r['reason'] for r in retrievals if r.get('reason'))),
        'queue_reasons_nonexclusive':dict(reasons),
        'code_view_chars_max':max(r['context']['context_chars'] for r in records),
        'max_supplementary_files':max([r['extra_files_used'] for r in retrievals] or [0]),
        'program_rejections_per_condition_record':sum(len(r['rejections']) for r in records),
        'funnel':{'original_detected_uses':821,'previous_frozen_cases':100,'selected_this_round':12,'not_selected_this_round':88,
                  'development':4,'previously_unexposed_evaluation':7,'source_debug_exposed_exploratory':1,
                  'actual_human_truth':0,'runtime_verified_leaks':0},
        'source_integrity':verification,'frozen_execution_source_valid':True,'current_source_matches_evaluation_freeze':False,
        'comparison_status':'exploratory_after_evaluation_informed_program_gate_fix','post_eval_changed_sources':changed,
        'post_eval_replay_changed_case_conditions':sum(bool(r['changed_dimensions']) for r in post_recheck),
        'post_eval_replay_affected_cases':sorted({r['case_id'] for r in post_recheck if r['changed_dimensions']}),
        'post_eval_model_rerun_for_frozen_cohort':False,'accuracy':None,'recall':None,'human_agreement':None,
        'post_eval_C_log_relation':dict(Counter(r['corrected_gated']['log_relation']['value'] for r in post_recheck if r['condition']=='C')),
        'post_eval_C_sensitive_type_states':dict(Counter(r['corrected_gated']['sensitive_type']['value'] for r in post_recheck if r['condition']=='C')),
        'post_fix_live_validation':{'original_cohort_case':'1e6358e4816e012b37c54289','model_calls':sum(r['phase'].startswith('post_fix') for r in ledger),'role':'development_already_exposed'},
        'interpretation_counts_are_not_correctness_metrics':True}
    write_json(docs/'results.json',summary);write_jsonl(docs/'comparison-cohort.jsonl',rows);write_csv(docs/'comparison-cohort.csv',rows)
    write_jsonl(docs/'context-file-availability.jsonl',availability);write_csv(docs/'context-file-availability.csv',availability)
    write_jsonl(docs/'post-evaluation-gate-replay.jsonl',post_recheck);write_csv(docs/'post-evaluation-gate-replay.csv',post_recheck)
    write_jsonl(docs/'global-model-attempts.jsonl',ledger);write_csv(docs/'global-model-attempts.csv',ledger)
    print(json.dumps(summary,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
