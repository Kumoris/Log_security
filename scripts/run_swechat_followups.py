"""Read-only SWE-chat adapter for the existing history detector and tracer."""
import os, sys, json, csv, hashlib, subprocess, argparse, time
from pathlib import Path
from collections import Counter, defaultdict

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT
INPUT = ROOT / 'outputs/swechat_log_alignment_20260921/final/changed_logs.csv'
OUT = Path(os.environ.get('SWECHAT_FOLLOWUP_OUTPUT', str(ROOT / 'outputs/swechat_followup_20260922')))
sys.path.insert(0, str(PROJECT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))
from agentlog_unified.paths import resolve_path

os.environ.update(GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0', GIT_OPTIONAL_LOCKS='0', PYTHONDONTWRITEBYTECODE='1')

def dump(p,x):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(x,ensure_ascii=False,indent=2,default=str)+'\n',encoding='utf-8')

def jl(p,rs):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',encoding='utf-8') as f:
        for r in rs: f.write(json.dumps(r,ensure_ascii=False,default=str)+'\n')

def repository_output_directory(name):
    """Read a verified attempt override; writers always keep their own directory."""
    selection=OUT/'selected_repository_attempts.json'
    if selection.exists():
        entry=json.loads(selection.read_text(encoding='utf-8')).get(name)
        if entry:
            path=resolve_path(entry['directory'], project=PROJECT)
            if entry.get('validation_status')!='PASS' or not path.is_relative_to((OUT/'additional-attempts').resolve()):
                raise ValueError('Invalid selected repository attempt')
            return path
    return OUT/'repositories'/name.replace('/','--')

def inputs():
    with INPUT.open(encoding='utf-8-sig',newline='') as f: return list(csv.DictReader(f))

def map_old(s,base):
    return resolve_path(s, project=PROJECT, base=base)

def environment(p):
    gd=p/'.git' if (p/'.git').is_dir() else p
    pending=[gd/'objects']; seen=set(); mapped=[]
    while pending:
        obj=pending.pop()
        if str(obj) in seen: continue
        seen.add(str(obj)); a=obj/'info/alternates'
        if a.exists():
            for line in a.read_text(encoding='utf-8').splitlines():
                if line:
                    actual=map_old(line,obj); mapped.append(actual); pending.append(actual)
    return {**os.environ,'GIT_ALTERNATE_OBJECT_DIRECTORIES':os.pathsep.join(str(x) for x in mapped)}

def git(p,args,stdin=None):
    q=subprocess.run(['git','--no-pager','-c','core.hooksPath='+str(OUT/'empty-hooks'),'-c','core.fsmonitor=false','-C',str(p),*args],input=stdin,capture_output=True,env=environment(p),timeout=120)
    return q.stdout.decode('utf-8',errors='replace') if q.returncode==0 else None

def inventory():
    assert not (OUT/'inventory.json').exists(), 'Inventory is frozen; use existing inventory'
    groups=defaultdict(list)
    for r in inputs(): groups[r['repo_id']].append(r)
    roots=[PROJECT/'data/cache'/x for x in ['swechat-full-20260912','batch-repos','semantic-full-v070','repos','object-repos','anchor-object-repos']]
    directories=[p for root in roots if root.exists() for p in root.iterdir() if p.is_dir()]
    result=[]
    for name,rs in sorted(groups.items()):
        shas=sorted({r['commit_sha'] for r in rs}); prefix=name.replace('/','--'); options=[]
        for p in directories:
            if p.name!=prefix and not p.name.startswith(prefix+'-'): continue
            tip=git(p,['rev-parse','--verify','HEAD^{commit}'])
            if not tip: continue
            tip=tip.strip()
            ans=git(p,['cat-file','--batch-check=%(objectname) %(objecttype)'], ('\n'.join(shas)+'\n').encode()) or ''
            available=[s for s,a in zip(shas,ans.splitlines()) if a==s+' commit']
            graph=git(p,['rev-list','--topo-order','--reverse','--parents',tip,*available])
            fp=git(p,['rev-list','--first-parent','--reverse',tip])
            tg=git(p,['rev-list','--topo-order','--reverse',tip])
            order=(tg or '').splitlines(); starts=[i for i,s in enumerate(order) if s in available]
            eligible=set(order[min(starts) if starts else 0:])|set(available)
            options.append(dict(path=str(p),tip=tip,target_ref=(git(p,['symbolic-ref','-q','HEAD']) or 'HEAD').strip(),
                available_initial_shas=available,missing_initial_shas=sorted(set(shas)-set(available)),
                graph_valid=graph is not None,graph_commits=len((graph or '').splitlines()),target_commits=len(order),eligible_commits=len(eligible),
                first_parent_commits=len((fp or '').splitlines()),shallow=(git(p,['rev-parse','--is-shallow-repository']) or '').strip()=='true'))
        options.sort(key=lambda x:(x['graph_valid'],len(x['available_initial_shas']),not x['shallow'],x['eligible_commits']),reverse=True)
        result.append(dict(repository=name,candidates=len(rs),initial_commits=len(shas),selected=options[0] if options else None,options=options))
        print(json.dumps({k:v for k,v in result[-1].items() if k!='options'}),flush=True)
    dump(OUT/'inventory.json',dict(input=str(INPUT),input_sha256=hashlib.sha256(INPUT.read_bytes()).hexdigest(),repositories=result))

if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('--inventory',action='store_true'); a=ap.parse_args()
    if a.inventory: inventory()
