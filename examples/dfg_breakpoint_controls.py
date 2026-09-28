"""Purposive Go field controls from already-frozen historical log statements.

This is context sampling, not a claim these additional logs were agent-modified.
Bound and unresolved declaration strata remain separate from semantic truth.
"""
import argparse
import json
from pathlib import Path

from agentlog_unified.config import sha256_file
from agentlog_unified.detector import detect_snapshot
from agentlog_unified.export import write_json,write_jsonl,write_csv
from agentlog_unified.semantic_context import HistoricalContext,load_run
from agentlog_unified.semantic_dfg import export_dfg
from agentlog_unified.semantic_evidence import digest
from agentlog_unified.semantic_go import field_binding
from agentlog_unified.semantic_scan import use_sites
from agentlog_unified.storage import Store,stable_id


def controls(run,output):
    output=Path(output)
    if output.exists() and any(output.iterdir()):raise ValueError('use_new_control_output')
    cases,snapshots,_=load_run(run);frames={};excluded=[]
    for (repository,sha),raw in sorted(snapshots.items()):
        go={p:t for p,t in raw['files'].items() if p.endswith('.go')}
        if not go:continue
        for entity in detect_snapshot(go,['go'])['entities']:
            for site in use_sites(entity,go)[0]:
                if (site.get('anchor') or {}).get('node_kind')!='selector_expression':continue
                key=stable_id(repository,sha,entity['path'],site['anchor'])
                row={'id':key,'repository':repository,'sha':sha,'path':entity['path'],'scope':entity['symbol'],
                     'field':site['field'],'language':'go','use_role':site['field_origin'],'use_anchor':site['anchor']}
                case={'id':key,'result':row,'log_start_line':entity['start_line'],'log_end_line':entity['end_line'],
                      'log_statement_sha256':digest(entity['statement']),
                      'selection_scope':'supplementary_historical_context_not_agent_attribution'}
                ctx=HistoricalContext(case,raw);ctx.node(site['anchor'])
                binding=field_binding(ctx,site['anchor'])
                frames[key]=(case,binding)
    selected=[]
    # Up to ten declared-field controls and ten unresolved controls, fixed IDs.
    for status in ('bound','unresolved'):
        members=sorted(k for k,(_,b) in frames.items() if b and b['status']==status)
        selected+=members[:10]
        excluded += [{'id':k,'reason':'control_stratum_budget','stratum':status} for k in members[10:]]
    frozen=output/'frozen';store=Store(frozen/'checkpoint.sqlite')
    try:
        store.replace('mined_units',[{'id':stable_id(repo),'repository':repo,
            'snapshots':{sha:raw for (r,sha),raw in snapshots.items() if r==repo}}
            for repo in sorted({frames[k][0]['result']['repository'] for k in selected})]);store.db.commit()
    finally:store.close()
    rows=[]
    for key in selected:
        case,binding=frames[key];write_json(frozen/'evidence'/(key+'.json'),case)
        rows.append({'id':key,'stratum':binding['status'],'binding':binding,'human_review':'pending',
                     'agent_attribution':'not_assessed_context_log'})
    write_jsonl(output/'controls.jsonl',rows);write_csv(output/'controls.csv',rows)
    write_jsonl(output/'not_selected.jsonl',excluded)
    write_json(frozen/'manifest.json',{'status':'complete','source_manifest':sha256_file(Path(run)/'manifest.json'),
        'artifact_sha256':{str(p.relative_to(frozen)):sha256_file(p) for p in frozen.rglob('*') if p.is_file()}})
    report=export_dfg(frozen,output/'dfg',max_cases=20)
    report.update(eligible_field_uses=len(frames),selected_bound_controls=sum(r['stratum']=='bound' for r in rows),
                  selected_unresolved_controls=sum(r['stratum']=='unresolved' for r in rows),
                  selection='purposive_declaration_controls_not_independent_semantic_evaluation')
    write_json(output/'coverage.json',report)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',required=True);p.add_argument('--output',required=True)
    p.add_argument('--offline',action='store_true');a=p.parse_args()
    print(json.dumps(controls(a.input,a.output),ensure_ascii=False))
