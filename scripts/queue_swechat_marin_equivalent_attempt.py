"""Queue a separately validated runtime attempt without touching old workers."""
from run_swechat_followups import *
from datetime import datetime, timezone


def main():
    trigger=OUT/'additional-attempts/entireio-cli-native'
    receipt=OUT/'additional-attempts/marin-queue-status.json'
    while True:
        if (OUT/'repositories/marin-community--marin/summary.json').exists():
            dump(receipt,dict(status='not_started_original_finished'))
            return
        status=json.loads((trigger/'attempt_status.json').read_text(encoding='utf-8'))
        progress_path=trigger/'repositories/entireio--cli/progress.json'
        progress=json.loads(progress_path.read_text(encoding='utf-8')) if progress_path.exists() else {}
        if status.get('status') in {'finished','not_started_original_already_finished','execution_failed'} or progress.get('stage') in {'detecting','detected','complete'}:
            break
        dump(receipt,dict(status='waiting_for_prior_attempt_memory_allocation',checked_at=datetime.now(timezone.utc).isoformat()))
        time.sleep(30)
    dest=OUT/'additional-attempts/marin-exact-scope-index'
    dump(receipt,dict(status='handed_to_memory_gated_runner',output=str(dest)))
    subprocess.run([sys.executable,str(ROOT/'scripts/run_swechat_additional_attempt.py'),
                    '--repository','marin-community/marin','--output-root',str(dest)],check=True)


if __name__=='__main__':main()
