"""Acquire isolated Git history; never modify pre-existing repositories."""
from run_swechat_followups import *
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

def collect(row):
    name=row['repository']; dest=OUT/'git-history'/name.replace('/','--')
    receipt=OUT/'collection'/ (name.replace('/','--')+'.json')
    if receipt.exists(): return json.loads(receipt.read_text(encoding='utf-8'))
    r={'repository':name,'started_at':datetime.now(timezone.utc).isoformat(),'remote_operations':'ls-remote_and_fetch_read_only','original_cache_modified':False}
    env={**os.environ,'GIT_CONFIG_COUNT':'2','GIT_CONFIG_KEY_0':'credential.interactive','GIT_CONFIG_VALUE_0':'false','GIT_CONFIG_KEY_1':'core.longpaths','GIT_CONFIG_VALUE_1':'true'}
    def command(args,timeout=180):
        q=subprocess.run(['git',*args],env=env,capture_output=True,timeout=timeout)
        if q.returncode: raise RuntimeError(q.stderr.decode('utf-8',errors='replace')[-1200:])
        return q.stdout.decode('utf-8',errors='replace')
    try:
        dest.mkdir(parents=True,exist_ok=True)
        command(['init','--bare',str(dest)])
        # This new repository refers to immutable original objects; original config is untouched.
        olds=[p for p in (PROJECT/'data/cache/swechat-full-20260912').iterdir() if p.name.startswith(name.replace('/','--')+'-')]
        if row['selected']: olds.insert(0,resolve_path(row['selected']['path']))
        obj=[]
        for old in olds:
            base=old/'.git/objects' if (old/'.git').is_dir() else old/'objects'
            obj.append(str(base.resolve()).replace('\\','/'))
            obj.extend(environment(old).get('GIT_ALTERNATE_OBJECT_DIRECTORIES','').split(os.pathsep))
        obj=list(dict.fromkeys(x.replace('\\','/') for x in obj if x and Path(x).exists()))
        (dest/'objects/info/alternates').write_bytes(('\n'.join(obj)+'\n').encode('utf-8'))
        if row['selected']:
            command(['-C',str(dest),'update-ref','refs/heads/local-cache-tip',row['selected']['tip']])
        for sha in sorted({x['commit_sha'] for x in inputs() if x['repo_id']==name}):
            # Missing initial objects are reported later, not invented or fetched by a different identity.
            q=subprocess.run(['git','-C',str(dest),'cat-file','-e',sha+'^{commit}'],env=env,capture_output=True)
            if not q.returncode: command(['-C',str(dest),'update-ref','refs/initial/'+sha,sha])
        remote='https://github.com/'+name+'.git'
        refs=command(['ls-remote','--symref',remote,'HEAD'],timeout=45)
        lines=[x.split() for x in refs.splitlines()]
        sha=next(x[0] for x in lines if len(x)==2 and x[1]=='HEAD')
        ref=next((x[1] for x in lines if x[0]=='ref:'),'HEAD')
        r.update(remote_tip=sha,target_ref=ref,remote_tip_observed_at=datetime.now(timezone.utc).isoformat())
        command(['-C',str(dest),'fetch','--no-tags',remote,sha+':refs/heads/frozen-target'],timeout=300)
        command(['-C',str(dest),'symbolic-ref','HEAD','refs/heads/frozen-target'])
        r.update(status='fetched',path=str(dest),tip=sha,shallow=False)
    except Exception as ex:
        r.update(status='collection_failed',error_type=type(ex).__name__,reason=str(ex),fallback=row['selected'])
    r['finished_at']=datetime.now(timezone.utc).isoformat(); dump(receipt,r)
    return r

if __name__=='__main__':
    inv=json.loads((OUT/'inventory.json').read_text(encoding='utf-8'))
    result=[]
    with ThreadPoolExecutor(max_workers=4) as pool:
        for f in as_completed([pool.submit(collect,r) for r in inv['repositories']]):
            r=f.result(); result.append(r); print(r['repository'],r['status'],flush=True)
    dump(OUT/'collection.json',result)
