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
common = [str(CLI), 'structured-scan', '--input', str(BASE/'inputs/aidev-full-v2'),
          '--output', str(BASE/'structured-runs/aidev-v050'), '--offline', '--batch-size', '32', '--max-seconds', '900']
advance = [str(CLI), 'content-advance', '--input', str(BASE/'content-runs/aidev-v050-seed'),
           '--output', str(BASE/'content-runs/aidev-v050'), '--offline', '--batch-size', '64', '--max-seconds', '900', '--min-free-gib', '2']
repair = [str(CLI), 'content-repair', '--input', str(BASE/'content-runs/aidev-v050'), '--output', str(BASE/'repair-runs/aidev-v050'), '--offline', '--max-seconds', '300']
merge = [str(CLI), 'content-reconcile', '--input', str(BASE/'content-runs/aidev-v050'), '--repair-run', str(BASE/'repair-runs/aidev-v050'), '--output', str(BASE/'reconciled-runs/aidev-v050'), '--offline']
commands = {'install': [str(PY), '-m', 'pip', 'install', '--no-index', '--no-deps', '--no-build-isolation', '-e', str(BASE)],
    'tests_final': [str(PY), '-m', 'pytest', str(BASE/'tests'), '-q'],
    'repair_dry_run': repair + ['--dry-run'],
    'repair_full': repair,
    'repair_resume': repair + ['--resume'],
    'repair_resume02': repair + ['--resume'],
    'merge_dry_run': merge + ['--dry-run'],
    'merge_full': merge,
    'merge_resume': merge + ['--resume'],
    'tests': [str(PY), '-m', 'pytest', str(BASE/'tests'), '-q'],
    'content_seed': [str(CLI), 'content-scan', '--input', str(BASE/'inputs/aidev-full-v2'), '--output', str(BASE/'content-runs/aidev-v050-seed'), '--offline', '--max-seconds', '0.001'],
    'content_dry_run': advance + ['--dry-run'],
    'content_full': advance,
    'content_resume': advance + ['--resume'],
    'content_resume02': advance + ['--resume'],
    'structured_dry_run': common + ['--dry-run'],
    'structured_full': common,
    'structured_resume': common + ['--resume']}
command = commands[mode]
prefix = BASE / 'docs' / ('aidev_v050_' + mode)
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
if mode.startswith('tests'): print(stdout.read_text()[-1500:])
if before != after: raise RuntimeError('Source changed during execution')
sys.exit(result.returncode)
