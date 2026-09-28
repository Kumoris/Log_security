import hashlib,json,sqlite3,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path('/Users/lzh/Downloads/Log 研究'); RUN=ROOT/'agentlog_unified/structured-runs/aidev-v049'; DOCS=ROOT/'agentlog_unified/docs'
def snapshot():
 with sqlite3.connect((RUN/'structured.sqlite').as_uri()+'?mode=ro',uri=True) as db:
  tables={}
  for name in ('progress','documents','matches','gaps','review_ranges'):
   digest=hashlib.sha256(); count=0
   columns=[r[1] for r in db.execute(f'PRAGMA table_info({name})')]
   for row in db.execute('SELECT * FROM '+name+' ORDER BY '+','.join('"'+c+'"' for c in columns)):
    digest.update((json.dumps(row,ensure_ascii=False,separators=(',',':'))+'\n').encode());count+=1
   tables[name]={'rows':count,'sha256':digest.hexdigest(),'columns':columns}
 return {'logical_tables':tables,'gzip_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(RUN.glob('*.gz'))},'manifest_sha256':hashlib.sha256((RUN/'manifest.json').read_bytes()).hexdigest(),'coverage':json.loads((RUN/'structured_coverage.json').read_text())}
before=snapshot(); pre=DOCS/'aidev_structured_v049_before_resume.json'
with pre.open('x') as f: json.dump(before,f,ensure_ascii=False,indent=2);f.write('\n')
cmd=[str(ROOT/'agent_log_privacy/.venv/bin/python'),str(DOCS/'run_agentlog_v049.py'),'structured_resume']
started=datetime.now(timezone.utc).isoformat();t=time.monotonic();ret=subprocess.run(cmd,cwd=ROOT)
after=snapshot()
checks={'resume_exit_2':ret.returncode==2,'no_new_rows':after['coverage']['rows_this_invocation']==0,'logical_tables_identical':before['logical_tables']==after['logical_tables'],'all_12_gzip_files_identical':len(after['gzip_sha256'])==12 and before['gzip_sha256']==after['gzip_sha256'],'manifest_identical':before['manifest_sha256']==after['manifest_sha256']}
result={'started_at':started,'elapsed_seconds':time.monotonic()-t,'command':cmd,'exit_code':ret.returncode,'checks':checks,'all_passed':all(checks.values()),'before_snapshot':str(pre),'before_snapshot_sha256':hashlib.sha256(pre.read_bytes()).hexdigest(),'after':after}
with (DOCS/'aidev_structured_v049_resume_verification.json').open('x') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
print(json.dumps(checks));assert all(checks.values())
