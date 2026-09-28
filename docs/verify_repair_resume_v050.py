"""Compare completed repair exports before and after a real no-op resume."""
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
RUN = BASE / 'repair-runs/aidev-v050/scan'
OUT = BASE / 'docs/aidev_repair_v050_resume_verification.json'
if OUT.exists():
    raise FileExistsError(OUT)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot():
    return {'exports': {p.name: sha(p) for p in sorted([*RUN.glob('*.csv'), *RUN.glob('*.jsonl')])},
            'manifest': sha(RUN / 'manifest.json'),
            'coverage': json.loads((RUN / 'repair_coverage.json').read_text())}

before = snapshot()
assert before['coverage']['all_selected_cells_all_rules_finished']
command = [str(BASE.parent / 'agent_log_privacy/.venv/bin/python'),
           str(BASE / 'docs/run_agentlog_v050.py'), 'repair_resume']
started = datetime.now(timezone.utc).isoformat(); clock = time.monotonic()
result = subprocess.run(command, cwd=BASE)
after = snapshot()
checks = {'resume_exit_2': result.returncode == 2,
    'no_new_pages': after['coverage']['pages_this_invocation'] == 0,
    'all_ten_exports_identical': len(before['exports']) == 10 and before['exports'] == after['exports'],
    'manifest_identical': before['manifest'] == after['manifest'],
    'counts_identical': all(before['coverage'][k] == after['coverage'][k] for k in
        ('candidate_occurrences', 'excluded_occurrences', 'data_gap_records', 'committed_pages'))}
OUT.write_text(json.dumps({'command': command, 'started_at': started,
    'finished_at': datetime.now(timezone.utc).isoformat(), 'elapsed_seconds': time.monotonic() - clock,
    'exit_code': result.returncode, 'before': before, 'after': after,
    'checks': checks, 'all_checks_passed': all(checks.values())}, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(checks))
assert all(checks.values())
