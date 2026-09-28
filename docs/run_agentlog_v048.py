import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path('/Users/lzh/Downloads/Log 研究')
BASE = ROOT / 'agentlog_unified'
PY = ROOT / 'agent_log_privacy/.venv/bin/python'
CLI = ROOT / 'agent_log_privacy/.venv/bin/agentlog-unified'
mode = sys.argv[1]
schema = [str(CLI), 'structured-scan', '--input', str(BASE/'inputs/aidev-full-v2'),
          '--output', str(BASE/'structured-runs/aidev-v048'), '--offline', '--batch-size', '32', '--max-seconds', '900']
commands = {'tests': [str(PY), '-m', 'pytest', str(BASE/'tests'), '-q'],
            'structured_dry_run': schema + ['--dry-run'], 'structured_smoke': schema + ['--max-rows', '1000'],
            'structured_full': schema + ['--resume'], 'structured_resume': schema + ['--resume'],
            'synthetic': [str(CLI), 'run', '--config', str(BASE/'examples/local_fixture_config.yaml'),
                          '--run-id', 'synthetic-v048', '--offline']}
command = commands[mode]
prefix = BASE / 'docs' / ('aidev_v048_' + mode)
record = Path(str(prefix) + '_execution.json')
if record.exists(): raise FileExistsError('Preserve prior execution record')
def snapshot():
    return {str(p.relative_to(BASE)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(list((BASE/'src/agentlog_unified').glob('*.py')) + list((BASE/'tests').glob('test_*.py')))}
before = snapshot()
started = datetime.now(timezone.utc).isoformat(); start = time.monotonic()
env = {**os.environ, 'GIT_NO_LAZY_FETCH': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1'}
stdout, stderr = Path(str(prefix)+'_stdout.txt'), Path(str(prefix)+'_stderr.txt')
with stdout.open('x') as out, stderr.open('x') as err:
    result = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err)
after = snapshot()
data = {'command': command, 'cwd': str(ROOT), 'started_at': started,
        'finished_at': datetime.now(timezone.utc).isoformat(), 'elapsed_seconds': time.monotonic()-start,
        'exit_code': result.returncode, 'source_before': before, 'source_after': after,
        'source_unchanged': before == after, 'stdout_path': str(stdout), 'stderr_path': str(stderr),
        'stdout_sha256': hashlib.sha256(stdout.read_bytes()).hexdigest(),
        'stderr_sha256': hashlib.sha256(stderr.read_bytes()).hexdigest()}
record.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n')
print(json.dumps({k: data[k] for k in ('exit_code','elapsed_seconds','source_unchanged')}, ensure_ascii=False))
if mode == 'tests': print(stdout.read_text()[-1500:])
if before != after: raise RuntimeError('Source changed during execution')
sys.exit(result.returncode)
