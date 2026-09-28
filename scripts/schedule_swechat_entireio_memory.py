"""Preserve the live worker while allowing Windows-managed memory to recover.

Only suspend/resume the exact already-authorized main worker. Never terminate,
restart, inject code, edit pagefile settings, or remove a file. Each pause has a
separate recovery receipt; the existing identity-checked resume API is reused.
"""
import json
import time
from datetime import datetime, timezone
from preserve_duplicate_worker_state import OUT, pause, resume
from execute_swechat_followups import memory_capacity_bytes


def main():
    root = OUT / 'verification/entireio_memory_schedule'
    root.mkdir(exist_ok=False)
    receipt = OUT / 'verification/entireio_tracing_memory_preserved.json'
    attempt = OUT / 'additional-attempts/entireio-complete-cache-8g-resume-20260922/attempt_status.json'
    paused = True
    count = 0
    targets = {9076: 1790087332266}
    if json.loads(receipt.read_text())['status'] != 'paused_state_retained':
        raise RuntimeError('Expected the preserved main process')
    while True:
        status = json.loads(attempt.read_text())['status']
        memory = memory_capacity_bytes()
        free = memory['commit'] / 1024**3
        if status in {'finished', 'execution_failed'}:
            phase = 'worker_exited'
        else:
            if paused and free >= 1.0:
                resume(receipt)
                paused = False
            elif not paused and free < 0.65:
                count += 1
                receipt = root / f'pause-{count:04d}.json'
                pause(targets, receipt)
                paused = True
            phase = 'paused_for_commit_headroom' if paused else 'running_under_memory_monitor'
        report = dict(stage=phase, attempt_status=status, paused=paused,
                      available_commit_gib=round(free, 3), pause_count=count,
                      pause_receipt=str(receipt), worker_pid=9076,
                      resume_threshold_gib=1.0, pause_threshold_gib=0.65,
                      process_restarted=False, pagefile_settings_changed=False,
                      updated_at=datetime.now(timezone.utc).isoformat())
        (root / 'progress.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        if phase == 'worker_exited':
            print(json.dumps(report), flush=True)
            return
        time.sleep(1)


if __name__ == '__main__':
    main()
