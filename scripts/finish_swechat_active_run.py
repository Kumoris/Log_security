"""Finish this already-running batch only after every repository has a receipt.

Does not start, terminate or replace miners; no existing delivery is overwritten.
"""
from run_swechat_followups import *
from datetime import datetime, timezone


def main():
    inventory = json.loads((OUT / 'inventory.json').read_text(encoding='utf-8'))
    status = OUT / 'finalization_progress.json'
    while True:
        pending = [r['repository'] for r in inventory['repositories'] if not any(
            (repository_output_directory(r['repository']) / n).exists()
            for n in ('summary.json', 'execution_error.txt'))]
        dump(status, dict(stage='waiting_for_stage2', pending_repositories=pending,
                          updated_at=datetime.now(timezone.utc).isoformat()))
        if not pending:
            break
        time.sleep(30)
    commands = [
        ('stage2', ['package_swechat_followups.py']),
        ('stage3', ['agent_log_motivation_v11.py', '--workspace', str(ROOT),
                    '--trace-run', str(OUT / 'stage2'), '--output', str(OUT / 'stage3'),
                    '--online', '--swechat-frozen', str(PROJECT/'data/cache/swechat-frozen')]),
        ('independent_validation', ['verify_swechat_main_delivery.py']),
        ('parent_integrity', ['verify_swechat_parent_integrity.py']),
        ('delivery', ['document_swechat_main_delivery.py']),
    ]
    for stage, args in commands:
        if stage == 'stage3':
            v = json.loads((OUT / 'stage2/validation.json').read_text(encoding='utf-8'))
            if v['status'] != 'PASS':
                raise RuntimeError('Stage2 validation did not pass')
        dump(status, dict(stage=stage, updated_at=datetime.now(timezone.utc).isoformat()))
        with (OUT / 'execution_logs' / ('finalize-' + stage + '.txt')).open('x', encoding='utf-8') as log:
            subprocess.run([sys.executable, str(ROOT / 'scripts' / args[0]), *args[1:]],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
    dump(status, dict(stage='complete', updated_at=datetime.now(timezone.utc).isoformat()))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        import traceback
        dump(OUT / 'finalization_error.json', dict(error=traceback.format_exc()))
        raise
