from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,subprocess,time,sys
root=Path('/Users/lzh/Downloads/Log 研究');base=root/'agentlog_unified';docs=base/'docs'
mode=sys.argv[1]
if mode not in ('resume','verify'):raise ValueError('Use resume or verify')
helper=docs/('verify_resume_aidev_v050.py' if mode=='resume' else 'verify_aidev_structured_v050.py')
helpers=[helper,docs/'run_agentlog_v050.py'] if mode=='resume' else [helper]
command=[str(root/'agent_log_privacy/.venv/bin/python'),str(helper)]+([] if mode=='resume' else ['--runs-confirmed-terminal'])
prefix='aidev_structured_v050_'+('resume_check' if mode=='resume' else 'verification')
stdout=docs/(prefix+'_stdout.txt');stderr=docs/(prefix+'_stderr.txt');record=docs/(prefix+'_execution.json')
for p in (stdout,stderr,record):
 if p.exists():raise FileExistsError('Preserve prior execution evidence')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot():return {str(p.relative_to(base)):sha(p) for p in list((base/'src/agentlog_unified').glob('*.py'))+list((base/'tests').glob('test_*.py'))}
before=snapshot();helper_before={str(p):sha(p) for p in helpers};start=time.monotonic();started=datetime.now(timezone.utc).isoformat()
with stdout.open('x') as out,stderr.open('x') as err:result=subprocess.run(command,cwd=root,stdout=out,stderr=err)
after=snapshot();helper_after={str(p):sha(p) for p in helpers}
data={'command':command,'cwd':str(root),'started_at':started,'finished_at':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-start,'exit_code':result.returncode,'source_before':before,'source_after':after,'source_unchanged':before==after,'helpers_sha256_before':helper_before,'helpers_sha256_after':helper_after,'helpers_unchanged':helper_before==helper_after,'stdout_path':str(stdout),'stderr_path':str(stderr),'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr),'scope':'terminal_aidev_structured_'+mode}
record.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({k:data[k] for k in ('exit_code','elapsed_seconds','source_unchanged','helpers_unchanged')}),flush=True)
sys.exit(result.returncode)
