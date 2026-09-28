"""Structural verification only; does not inspect source text or adjust rules."""
from run_swechat_followups import *
from package_swechat_followups import ancestor,readrows
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,default=OUT/'intermediate_graph_validation.json');args=ap.parse_args()
    if args.output.exists():raise FileExistsError('Use a new validation receipt path')
    reports=[]
    for p in sorted((OUT/'repositories').iterdir()):
        if p.name.startswith('pilot-') or not (p/'summary.json').exists():continue
        summary=json.loads((p/'summary.json').read_text(encoding='utf-8'))
        if summary['status']!='executed':continue
        h=json.loads((p/'history_scope.json').read_text(encoding='utf-8'))
        graph={r['sha']:r['parents'] for r in h['graph']};fp=set(h['first_parent_shas'])
        cases={r['case_id']:r for r in readrows(p/'log_changes.jsonl')};events=list(readrows(p/'followups.jsonl'))
        cache={};failures=[]
        for event in events:
            c=cases.get(event['case_id']);k=(c.get('integration_sha') if c else None,event['sha'])
            if k not in cache:cache[k]=bool(k[0] and ancestor(k[0],k[1],graph))
            if not c or event['sha']==c['intro_sha'] or event['sha'] not in fp or not cache[k] or event['parent_sha']!=(graph.get(event['sha']) or [None])[0]:
                failures.append(event['id'])
        reports.append(dict(repository=summary['repository'],events=len(events),distinct_event_ids=len({e['id'] for e in events}),graph_failures=failures))
    result=dict(complete_population=False,completed_repository_checks=len(reports),checked_events=sum(r['events'] for r in reports),
        passed=all(not r['graph_failures'] and r['events']==r['distinct_event_ids'] for r in reports),repositories=reports)
    dump(args.output,result)
    print(json.dumps({k:v for k,v in result.items() if k!='repositories'}),flush=True)
