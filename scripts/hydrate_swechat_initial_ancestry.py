"""Verify/fill initial commit ancestry in NEW caches; frozen target tips stay fixed."""
from run_swechat_followups import *
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime,timezone

def check(r):
    name=r['repository'];p=resolve_path(r['path']);out=OUT/'ancestry_collection'/(name.replace('/','--')+'.json')
    if out.exists():return json.loads(out.read_text(encoding='utf-8'))
    initial=sorted({x['commit_sha'] for x in inputs() if x['repo_id']==name})
    before=git(p,['rev-list','--parents',r['tip'],*initial])
    result=dict(repository=name,initial_commits=len(initial),graph_initially_readable=before is not None,
                frozen_target_tip=r['tip'],remote_operations='fetch_exact_initial_commit_objects_only')
    if before is None:
        try:
            q=subprocess.run(['git','-C',str(p),'fetch','--no-tags','https://github.com/'+name+'.git',
                *[sha+':refs/hydrated-initial/'+sha for sha in initial]],capture_output=True,env=environment(p),timeout=300)
            result.update(fetch_returncode=q.returncode,fetch_error=q.stderr.decode('utf-8',errors='replace')[-1500:] if q.returncode else None)
        except Exception as ex:result.update(fetch_error_type=type(ex).__name__)
    result['graph_readable']=before is not None or git(p,['rev-list','--parents',r['tip'],*initial]) is not None
    result['target_unchanged']=(git(p,['rev-parse','HEAD']) or '').strip()==r['tip']
    result['checked_at']=datetime.now(timezone.utc).isoformat();dump(out,result);return result

if __name__=='__main__':
    rows=[json.loads(p.read_text(encoding='utf-8')) for p in (OUT/'collection').glob('*.json') if 'attempt' not in p.name]
    with ThreadPoolExecutor(max_workers=4) as pool:
        for f in as_completed([pool.submit(check,r) for r in rows if r['status']=='fetched']):
            r=f.result();print(r['repository'],r['graph_initially_readable'],r['graph_readable'],flush=True)
