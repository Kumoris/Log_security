from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,subprocess,time,sys
root=Path('/Users/lzh/Downloads/Log 研究');base=root/'agentlog_unified';docs=base/'docs'
helper=docs/'verify_aidev_repair_v050.py';helpers=[helper,docs/'verify_aidev_repair_v049.py',docs/'verify_aidev_structured_v048.py']
command=[str(root/'agent_log_privacy/.venv/bin/python'),str(helper),'--runs-confirmed-terminal']
stdout=docs/'aidev_repair_v050_verification_stdout.txt';stderr=docs/'aidev_repair_v050_verification_stderr.txt';record=docs/'aidev_repair_v050_verification_execution.json'
for p in (stdout,stderr,record):
 if p.exists():raise FileExistsError('Preserve prior execution evidence')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot():return {str(p.relative_to(base)):sha(p) for p in list((base/'src/agentlog_unified').glob('*.py'))+list((base/'tests').glob('test_*.py'))}
before=snapshot();helper_before={str(p):sha(p) for p in helpers};start=time.monotonic();started=datetime.now(timezone.utc).isoformat()
with stdout.open('x') as out,stderr.open('x') as err:result=subprocess.run(command,cwd=root,stdout=out,stderr=err)
after=snapshot();helper_after={str(p):sha(p) for p in helpers}
data={'command':command,'cwd':str(root),'started_at':started,'finished_at':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-start,'exit_code':result.returncode,'source_before':before,'source_after':after,'source_unchanged':before==after,'helpers_sha256_before':helper_before,'helpers_sha256_after':helper_after,'helpers_unchanged':helper_before==helper_after,'stdout_path':str(stdout),'stderr_path':str(stderr),'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr),'scope':'readonly_terminal_aidev_repair_snapshot_verification'}
record.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({k:data[k] for k in ('exit_code','elapsed_seconds','source_unchanged','helpers_unchanged')}),flush=True)
sys.exit(result.returncode)
