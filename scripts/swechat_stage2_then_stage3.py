"""Sequential entry point: complete/reconcile stage two before collecting motives."""
import os,sys,argparse,subprocess,json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output-root',type=Path,required=True)
    ap.add_argument('--offline-evidence',action='store_true')
    a=ap.parse_args();os.environ['SWECHAT_FOLLOWUP_OUTPUT']=str(a.output_root.resolve())
    os.environ['PYTHONDONTWRITEBYTECODE']='1'
    from run_swechat_followups import ROOT,OUT
    def run(name,*args):subprocess.run([sys.executable,str(ROOT/'scripts'/name),*args],check=True)
    if not (OUT/'inventory.json').exists():run('run_swechat_followups.py','--inventory')
    run('collect_swechat_followup_history.py')
    run('hydrate_swechat_initial_ancestry.py')
    run('batch_swechat_followups.py')
    if not (OUT/'stage2/manifest.json').exists():run('package_swechat_followups.py')
    validation=json.loads((OUT/'stage2/validation.json').read_text(encoding='utf-8'))
    if validation['status']!='PASS':raise RuntimeError('Stage-two validation failed; evidence stage not started')
    if not (OUT/'stage3/manifest.json').exists():
        args=['--workspace',str(ROOT),'--trace-run',str(OUT/'stage2'),'--output',str(OUT/'stage3'),
              '--swechat-frozen',str(ROOT/'data/cache/swechat-frozen')]
        if not a.offline_evidence:args.append('--online')
        run('agent_log_motivation_v11.py',*args)

if __name__=='__main__':main()
