from run_swechat_followups import *
from concurrent.futures import ThreadPoolExecutor, as_completed

def run(row):
    name=row['repository'];p=OUT/'repositories'/name.replace('/','--')
    if (p/'summary.json').exists():return name,'already_completed'
    log=OUT/'execution_logs'/(name.replace('/','--')+'.'+str(os.getpid())+'.txt');log.parent.mkdir(parents=True,exist_ok=True)
    with log.open('w',encoding='utf-8') as f:
        q=subprocess.run([sys.executable,str(ROOT/'scripts/execute_swechat_followups.py'),'--repository',name],stdout=f,stderr=subprocess.STDOUT)
    return name,q.returncode

if __name__=='__main__':
    inv=json.loads((OUT/'inventory.json').read_text(encoding='utf-8'))
    rows=sorted(inv['repositories'],key=lambda r:(r['selected'] or {}).get('eligible_commits',500))
    with ThreadPoolExecutor(max_workers=3) as pool:
        for f in as_completed([pool.submit(run,r) for r in rows]): print(*f.result(),flush=True)
