from run_swechat_followups import resolve_path
from execute_swechat_followups import *
if __name__=='__main__':
    name='adhishthite/anthropic-clio-impl'
    inv=json.loads((OUT/'inventory.json').read_text(encoding='utf-8'))
    source=next(r['selected'] for r in inv['repositories'] if r['repository']==name)
    p=resolve_path(source['path']);os.environ.update(environment(p));g=Guard(PROJECT)
    for r in inputs():
        if r['repo_id']!=name:continue
        raw=git(p,['show',r['commit_sha']+':'+r['path']])
        if raw is None:print('missing source');continue
        status=g.check(name,r['path'],raw)
        if status!='allowed':print(status);continue
        parsed=analysis.detect_snapshot({r['path']:raw})
        lines=raw.splitlines();a=int(r['start_line']);b=int(r['end_line'])
        print(json.dumps(dict(log_id=r['log_id'],source_anchor_present=r['statement'].strip() in '\n'.join(lines[a-1:b]),entities=len(parsed['entities']),matches=[{'start':e['start_line'],'end':e['end_line'],'callee':e['callee'],'same_statement':r['statement'].strip() in e['statement']} for e in parsed['entities'] if e['start_line']==a],gaps=[x.get('reason') for x in parsed['gaps']]),ensure_ascii=False))
