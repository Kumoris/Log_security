"""Synthetic orchestration tests; no research source records are used."""
import json
from pathlib import Path
import pytest
import finish_swechat_verified_main as runner


def setup_run(tmp_path, monkeypatch, stage2_status='PASS', failed_attempt=False):
    monkeypatch.setattr(runner, 'OUT', tmp_path)
    monkeypatch.setattr(runner, 'ATTEMPTS', {'example/repo': 'attempt'})
    directory = tmp_path / 'additional-attempts/attempt/repositories/example--repo'
    directory.mkdir(parents=True)
    runner.dump(directory / 'summary.json', {'status': 'executed'})
    runner.dump(directory.parents[1] / 'attempt_status.json',
                {'status': 'execution_failed' if failed_attempt else 'finished', 'returncode': 1 if failed_attempt else 0})
    runner.dump(tmp_path / 'inventory.json', {'repositories': [{'repository': 'example/repo'}]})
    monkeypatch.setattr(runner, 'repository_output_directory', lambda repo: directory)
    calls = []

    def execute(command, **kwargs):
        name = Path(command[1]).name
        calls.append(name)
        if name == 'select_swechat_verified_attempt.py':
            validation = directory.parents[1] / 'selection_validation.json'
            runner.dump(validation, {'status': 'PASS', 'artifact_sha256': {}})
            runner.dump(tmp_path / 'selected_repository_attempts.json', {'example/repo': {
                'directory': str(directory), 'validation_path': str(validation),
                'validation_sha256': runner.hashlib.sha256(validation.read_bytes()).hexdigest()}})
        elif name == 'package_swechat_followups.py':
            runner.dump(tmp_path / 'stage2/validation.json', {'status': stage2_status})
        elif name == 'agent_log_motivation_v11.py':
            assert json.loads((tmp_path / 'stage2/validation.json').read_text())['status'] == 'PASS'
            runner.dump(tmp_path / 'stage3/validation.json', {'status': 'PASS'})
        elif name == 'verify_swechat_main_delivery.py':
            runner.dump(tmp_path / 'stage3_independent_validation.json', {'status': 'PASS'})

    monkeypatch.setattr(runner.subprocess, 'run', execute)
    return calls


def test_stage3_starts_only_after_selection_and_stage2_acceptance(tmp_path, monkeypatch):
    calls = setup_run(tmp_path, monkeypatch)
    runner.main()
    assert calls == ['select_swechat_verified_attempt.py', 'package_swechat_followups.py',
                     'agent_log_motivation_v11.py', 'verify_swechat_main_delivery.py', 'plan_swechat_connector_reads.py']


def test_failed_stage2_blocks_all_stage3_work(tmp_path, monkeypatch):
    calls = setup_run(tmp_path, monkeypatch, stage2_status='FAIL')
    with pytest.raises(RuntimeError, match='Validation did not pass'):
        runner.main()
    assert calls == ['select_swechat_verified_attempt.py', 'package_swechat_followups.py']
    assert not (tmp_path / 'stage3').exists()


def test_failed_repository_cannot_be_packaged_as_complete(tmp_path, monkeypatch):
    calls = setup_run(tmp_path, monkeypatch, failed_attempt=True)
    with pytest.raises(RuntimeError, match='Incomplete repository'):
        runner.main()
    assert calls == []
    assert not (tmp_path / 'stage2').exists()
