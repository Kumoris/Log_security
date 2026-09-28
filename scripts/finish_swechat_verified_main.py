"""Finish the two isolated runs, accept all stage two, then start main stage three.

One-shot local execution for the already frozen batch. No process termination,
remote writes, new acquisition, changed filters, or overwritten deliveries.
"""
from run_swechat_followups import *
from datetime import datetime, timezone

ATTEMPTS = {
    'marin-community/marin': 'marin-full-validated-cache-20260922',
    'entireio/cli': 'entireio-complete-cache-8g-resume-20260922',
}


def require_pass(path):
    result = json.loads(path.read_text(encoding='utf-8'))
    if result.get('status') != 'PASS':
        raise RuntimeError('Validation did not pass: ' + str(path))


def main(marin_attempt=None, execution_name='verified_main_execution', entireio_attempt=None):
    if Path(execution_name).name != execution_name:
        raise ValueError('Execution receipt name must be a basename')
    receipt = OUT / execution_name
    receipt.mkdir(exist_ok=False)

    def state(stage, **extra):
        dump(receipt / 'progress.json', dict(stage=stage,
             updated_at=datetime.now(timezone.utc).isoformat(), **extra))

    def run(name, args):
        state(name)
        with (receipt / (name + '.txt')).open('x', encoding='utf-8') as output:
            subprocess.run([sys.executable, str(ROOT / 'scripts' / args[0]), *args[1:]],
                           stdout=output, stderr=subprocess.STDOUT, check=True)

    try:
        remaining = dict(ATTEMPTS)
        if marin_attempt:
            remaining['marin-community/marin'] = marin_attempt
        if entireio_attempt:
            remaining['entireio/cli'] = entireio_attempt
        while remaining:
            for repo, attempt in list(remaining.items()):
                root = OUT / 'additional-attempts' / attempt
                result_path = root / 'attempt_status.json'
                result = json.loads(result_path.read_text(encoding='utf-8')) if result_path.exists() else {}
                if result.get('status') == 'execution_failed':
                    raise RuntimeError('Incomplete repository execution: ' + repo)
                if result.get('status') != 'finished':
                    continue
                if result.get('returncode') != 0:
                    raise RuntimeError('Repository returned nonzero: ' + repo)
                run('select-' + repo.replace('/', '--'), ['select_swechat_verified_attempt.py',
                    '--repository', repo, '--attempt-root', str(root)])
                require_pass(root / 'selection_validation.json')
                del remaining[repo]
            if remaining:
                state('waiting_for_complete_stage2_repositories', pending=list(remaining))
                time.sleep(30)

        inventory = json.loads((OUT / 'inventory.json').read_text(encoding='utf-8'))
        for row in inventory['repositories']:
            directory = repository_output_directory(row['repository'])
            summary = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
            if summary.get('status') not in {'executed', 'history_unavailable'}:
                raise RuntimeError('Repository has no acceptable execution receipt: ' + row['repository'])
        selections = json.loads((OUT / 'selected_repository_attempts.json').read_text(encoding='utf-8'))
        for repo, entry in selections.items():
            validation_path = Path(entry['validation_path'])
            if hashlib.sha256(validation_path.read_bytes()).hexdigest() != entry['validation_sha256']:
                raise RuntimeError('Selected validation changed: ' + repo)
            validation = json.loads(validation_path.read_text(encoding='utf-8'))
            directory = resolve_path(entry['directory'])
            for filename, expected in validation['artifact_sha256'].items():
                if hashlib.sha256((directory / filename).read_bytes()).hexdigest() != expected:
                    raise RuntimeError('Selected artifact changed: ' + repo + '/' + filename)

        run('stage2', ['package_swechat_followups.py'])
        require_pass(OUT / 'stage2/validation.json')
        run('stage3-local', ['agent_log_motivation_v11.py', '--workspace', str(ROOT),
            '--trace-run', str(OUT / 'stage2'), '--output', str(OUT / 'stage3'),
            '--swechat-frozen', str(PROJECT/'data/cache/swechat-frozen')])
        require_pass(OUT / 'stage3/validation.json')
        run('independent-validation', ['verify_swechat_main_delivery.py'])
        require_pass(OUT / 'stage3_independent_validation.json')
        run('plan-connected-reads', ['plan_swechat_connector_reads.py'])
        state('local_main_stage3_complete_external_collection_pending',
              stage2_validation='PASS', stage3_validation='PASS')
    except BaseException:
        import traceback
        state('failed', error=traceback.format_exc())
        raise


if __name__ == '__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--marin-attempt')
    ap.add_argument('--entireio-attempt')
    ap.add_argument('--execution-name',default='verified_main_execution')
    args=ap.parse_args()
    main(args.marin_attempt,args.execution_name,args.entireio_attempt)
