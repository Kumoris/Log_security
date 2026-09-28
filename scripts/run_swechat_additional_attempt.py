"""Start one isolated equivalent attempt without interrupting existing work."""
from run_swechat_followups import *
from execute_swechat_followups import memory_capacity_bytes
from datetime import datetime, timezone
import shutil

if __name__ == '__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--repository', required=True)
    ap.add_argument('--output-root', required=True, type=Path)
    ap.add_argument('--wait-for-finished-attempt', type=Path)
    ap.add_argument('--minimum-free-gib',type=float,default=10)
    ap.add_argument('--python-file-cache',choices=['transitive-imports','accessed-imports'],default='transitive-imports')
    args=ap.parse_args()
    if not 6<=args.minimum_free_gib<=32:raise ValueError('Memory gate must be within 6 to 32 GiB')
    output=args.output_root.resolve()
    output.mkdir(parents=True, exist_ok=False)
    original_summary=OUT/'repositories'/args.repository.replace('/','--')/'summary.json'
    inv=json.loads((OUT/'inventory.json').read_text(encoding='utf-8'))
    selected=[r for r in inv['repositories'] if r['repository']==args.repository]
    if len(selected)!=1:raise ValueError('Repository is not uniquely in the frozen input scope')
    dump(output/'inventory.json',dict(inv, repositories=selected))
    (output/'collection').mkdir()
    name=args.repository.replace('/','--')+'.json'
    shutil.copyfile(OUT/'collection'/name, output/'collection'/name)
    dump(output/'attempt_provenance.json',dict(repository=args.repository, original_run=str(OUT),
        original_input_sha256=inv['input_sha256'], frozen_collection_receipt_sha256=hashlib.sha256((OUT/'collection'/name).read_bytes()).hexdigest(),
        purpose='Equivalent separate execution using validated I/O/cache optimizations; original process and outputs untouched',
        minimum_free_gib=args.minimum_free_gib,python_file_cache_mode=args.python_file_cache,minimum_commit_free_gib=args.minimum_free_gib,
        created_at=datetime.now(timezone.utc).isoformat()))
    while True:
        if original_summary.exists() or (repository_output_directory(args.repository)/'summary.json').exists():
            dump(output/'attempt_status.json',dict(status='not_started_original_already_finished'))
            print('Original attempt finished before additional execution was needed',flush=True)
            sys.exit(0)
        if args.wait_for_finished_attempt:
            prior=args.wait_for_finished_attempt/'attempt_status.json'
            state=json.loads(prior.read_text(encoding='utf-8')).get('status') if prior.exists() else None
            if state not in {'finished','execution_failed','not_started_original_already_finished'}:
                dump(output/'attempt_status.json',dict(status='waiting_for_earlier_attempt',dependency=str(args.wait_for_finished_attempt),
                    checked_at=datetime.now(timezone.utc).isoformat()))
                time.sleep(30)
                continue
        capacity=memory_capacity_bytes()
        if capacity is None or min(capacity.values())>=args.minimum_free_gib*1024**3:break
        dump(output/'attempt_status.json',dict(status='waiting_for_memory',required_gib=args.minimum_free_gib,available_gib=round(capacity['physical']/1024**3,2),available_commit_gib=round(capacity['commit']/1024**3,2),
            checked_at=datetime.now(timezone.utc).isoformat()))
        time.sleep(30)
    dump(output/'attempt_status.json',dict(status='running',started_at=datetime.now(timezone.utc).isoformat()))
    with (output/'execution.txt').open('x',encoding='utf-8') as log:
        completed=subprocess.run([sys.executable,str(ROOT/'scripts/execute_swechat_followups.py'),'--repository',args.repository],
            env={**os.environ,'SWECHAT_FOLLOWUP_OUTPUT':str(output),'SWECHAT_PYTHON_FILE_CACHE_MODE':args.python_file_cache},stdout=log,stderr=subprocess.STDOUT)
    dump(output/'attempt_status.json',dict(status='finished' if completed.returncode==0 else 'execution_failed',
        returncode=completed.returncode,finished_at=datetime.now(timezone.utc).isoformat()))
    sys.exit(completed.returncode)
