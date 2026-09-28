from run_swechat_followups import *
from agent_log_motivation_v11 import file_hash
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path);args=ap.parse_args()
    destination=args.output or OUT/'parent_integrity_validation.json'
    if destination.exists():raise FileExistsError(destination)
    reports=[]
    for folder,key in [('swechat_log_alignment_20260921/final','files'),('swechat_motivation_20260921/delivery','artifacts')]:
        base=ROOT/'outputs'/folder;manifest=json.loads((base/'manifest.json').read_text(encoding='utf-8'))
        for name,h in manifest[key].items():
            p=base/name;current=file_hash(p) if p.exists() else None
            reports.append(dict(path=str(p),expected_sha256=h,current_sha256=current,unchanged=current==h))
    p=PROJECT/'data/cache/swechat-frozen/commits.parquet';expected='e93d2bb76c862742396b6d35be2c48a3ce7132d077868f4660cf4cbe7d8ef08f';h=file_hash(p)
    reports.append(dict(path=str(p),expected_sha256=expected,current_sha256=h,unchanged=h==expected))
    baseline=OUT/'raw_stage3_input_baseline.json'
    if baseline.exists():
        existing={os.path.normcase(str(resolve_path(r['path']).resolve())) for r in reports}
        for r in json.loads(baseline.read_text(encoding='utf-8'))['files']:
            p=resolve_path(r['path'])
            if os.path.normcase(str(p.resolve())) in existing:continue
            current=file_hash(p) if p.exists() else None
            reports.append(dict(path=str(p),expected_sha256=r['sha256'],current_sha256=current,unchanged=current==r['sha256'],baseline_scope='before_stage3_in_this_task'))
    result=dict(status='PASS' if all(r['unchanged'] for r in reports) else 'FAIL',checked_files=len(reports),files=reports)
    dump(destination,result);print(result['status'],result['checked_files'],flush=True)
    sys.exit(0 if result['status']=='PASS' else 1)
