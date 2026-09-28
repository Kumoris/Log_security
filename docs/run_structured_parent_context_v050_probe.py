from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,subprocess,time,sys
root=Path('/Users/lzh/Downloads/Log 研究');base=root/'agentlog_unified';docs=base/'docs';helper=docs/'probe_structured_parent_context_v050.py'
command=[str(root/'agent_log_privacy/.venv/bin/python'),str(helper),'--run']
prefix=docs/'aidev_structured_parent_context_v050_probe';out=Path(str(prefix)+'_stdout.txt');err=Path(str(prefix)+'_stderr.txt');rec=Path(str(prefix)+'_execution.json')
for p in (out,err,rec):
 if p.exists():raise FileExistsError('Preserve prior probe execution')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot():return {str(p.relative_to(base)):sha(p) for p in list((base/'src/agentlog_unified').glob('*.py'))+list((base/'tests').glob('test_*.py'))}
before=snapshot();hbefore=sha(helper);started=datetime.now(timezone.utc).isoformat();clock=time.monotonic()
with out.open('x') as stdout,err.open('x') as stderr:r=subprocess.run(command,cwd=root,stdout=stdout,stderr=stderr)
after=snapshot();data={'command':command,'cwd':str(root),'started_at':started,'finished_at':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-clock,'exit_code':r.returncode,'source_before':before,'source_after':after,'source_unchanged':before==after,'helper_sha256_before':hbefore,'helper_sha256_after':sha(helper),'helper_unchanged':hbefore==sha(helper),'stdout_path':str(out),'stderr_path':str(err),'stdout_sha256':sha(out),'stderr_sha256':sha(err)}
rec.write_text(json.dumps(data,indent=2)+'\n');print(json.dumps({k:data[k] for k in ('exit_code','elapsed_seconds','source_unchanged','helper_unchanged')}));sys.exit(r.returncode)
