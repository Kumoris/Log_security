from run_swechat_followups import *
if __name__=='__main__':
    result=[];rows=inputs()
    for r in json.loads((OUT/'collection_effective.json').read_text(encoding='utf-8')):
        if r['status']!='fetched':continue
        p=resolve_path(r['path']);initials={x['commit_sha'] for x in rows if x['repo_id']==r['repository']}
        target=(git(p,['rev-list','--topo-order','--reverse',r['tip']]) or '').splitlines()
        positions=[i for i,s in enumerate(target) if s in initials]
        eligible=set(target[min(positions) if positions else 0:])|initials
        result.append(dict(repository=r['repository'],target_commits=len(target),eligible_commits=len(eligible),initial_commits=len(initials),initial_reachable=len(initials&set(target))))
    dump(OUT/'collected_history_scope.json',result)
    print(json.dumps(dict(total_eligible_commits=sum(r['eligible_commits'] for r in result),largest=sorted(result,key=lambda r:r['eligible_commits'],reverse=True)[:12]),ensure_ascii=False))
