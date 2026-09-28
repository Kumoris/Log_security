from collect_swechat_followup_history import *
if __name__=='__main__':
    for a in (OUT/'git-history').glob('*/objects/info/alternates'):
        b=a.read_bytes()
        if b'\r\n' in b:a.write_bytes(b.replace(b'\r\n',b'\n'))
    inv=json.loads((OUT/'inventory.json').read_text(encoding='utf-8'))
    retry=[]
    for row in inv['repositories']:
        p=OUT/'collection'/(row['repository'].replace('/','--')+'.json')
        if not p.exists():continue
        r=json.loads(p.read_text(encoding='utf-8'))
        if r['status']=='collection_failed' and 'update_ref failed' in r.get('reason',''):
            p.rename(p.with_suffix('.attempt1.json'));retry.append(row)
    with ThreadPoolExecutor(max_workers=4) as pool:
        for f in as_completed([pool.submit(collect,r) for r in retry]):
            r=f.result();print(r['repository'],r['status'],flush=True)
    dump(OUT/'collection_effective.json',[json.loads((OUT/'collection'/(r['repository'].replace('/','--')+'.json')).read_text(encoding='utf-8')) for r in inv['repositories'] if (OUT/'collection'/(r['repository'].replace('/','--')+'.json')).exists()])
