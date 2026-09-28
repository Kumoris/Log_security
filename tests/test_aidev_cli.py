import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from agentlog_unified import cli
from test_cli_offline import local_project


def test_full_mode_removes_input_caps_but_keeps_git_budgets(local_project, capsys):
    project, config, _ = local_project
    rows = [{'repository': f'owner/repo{i}', 'pr_number': 1} for i in range(35)]
    (project/'prs.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows))
    args = ['--config', str(config), '--offline', '--run-mode', 'full']
    assert cli.main(['run', *args, '--dry-run']) == 0
    dry = json.loads(capsys.readouterr().out)
    assert dry['pr_limit'] is None and dry['repository_limit'] is None
    assert dry['history_commit_budget'] == 100
    assert not (project/'outputs/runs').exists()
    assert cli.main(['ingest', *args, '--run-id', 'full']) == 0
    selected = json.loads((project/'outputs/runs/full/sampling_manifest.json').read_text())
    assert len(selected['selected_ids']) == 35 and selected['excluded'] == []
    assert selected['source']['rows_read'] == 35


def test_aidev_cli_missing_lfs_is_a_gap_and_dry_run_writes_nothing(tmp_path, capsys):
    source = tmp_path/'source'; source.mkdir()
    (source/'pull_request.parquet').write_text(
        'version https://git-lfs.github.com/spec/v1\noid sha256:'+'a'*64+'\nsize 12345\n')
    output = tmp_path/'imported'
    args = ['aidev-import', '--aidev-dir', str(source), '--output', str(output), '--offline']
    assert cli.main([*args, '--dry-run']) == 0
    assert not output.exists()
    assert cli.main(args) == 2
    report = json.loads((output/'coverage.json').read_text())
    assert report['counts']['normalized_prs'] == 0
    assert report['tables'][0]['status'] == 'missing_lfs_object'
    assert report['evidence_boundary']['all_local_tables_scanned'] is False
    assert cli.main([*args, '--resume']) == 2


def test_aidev_import_to_pydriller_to_type_exports(local_project):
    project, config, repo = local_project
    fixture = json.loads((project/'prs.jsonl').read_text())
    source = project/'parquet'; source.mkdir()
    pq.write_table(pa.Table.from_pylist([{
        'id': 7, 'html_url': 'https://github.com/example/fixture/pull/3',
        'agent': 'synthetic_dataset_label', 'number': 3,
    }]), source/'pull_request.parquet')
    pq.write_table(pa.Table.from_pylist([{
        'pr_id': 7, 'sha': fixture['initial_commit_shas'][0],
    }]), source/'pr_commits.parquet')
    imported = project/'imported'
    assert cli.main(['aidev-import', '--aidev-dir', str(source), '--output', str(imported), '--offline']) in {0, 2}
    row = json.loads((imported/'mining_prs.jsonl').read_text())
    assert row['verified_actor_type'] == 'unknown'
    # The Parquet rows and Git repository are both synthetic test fixtures.
    # Their explicit fixture marker must be supplied before running the miner.
    row.update({k: fixture[k] for k in ('fixture_repository_id','is_synthetic','local_repo_path','target_ref','synthetic_author_mapping')})
    (project/'prs.jsonl').write_text(json.dumps(row)+'\n')
    assert cli.main(['run', '--config', str(config), '--run-id', 'aidev-e2e', '--offline', '--run-mode', 'full']) == 0
    run = project/'outputs/runs/aidev-e2e'
    manifest = json.loads((run/'run_manifest.json').read_text())
    assert manifest['mining_metrics'][0]['metrics']['pydriller_commits'] > 0
    assert manifest['mining_metrics'][0]['metrics']['pydriller_diff_parsed_calls'] > 0
    assert (run/'reports/type_summary.csv').is_file()
    assert (run/'data/unknown_type_review_queue.jsonl').is_file()
    assert not (repo/'executed').exists()


def test_swechat_cli_lfs_gap_and_read_only_dry_run(tmp_path, capsys):
    source = tmp_path/'swechat'; source.mkdir()
    (source/'commits.parquet').write_text(
        'version https://git-lfs.github.com/spec/v1\noid sha256:'+'b'*64+'\nsize 76543\n')
    output = tmp_path/'imported'
    args = ['swechat-import','--swechat-dir',str(source),'--output',str(output),'--offline']
    assert cli.main([*args,'--dry-run']) == 0
    assert not output.exists()
    assert cli.main(args) == 2
    assert json.loads((output/'coverage.json').read_text())['counts']['commit_contexts'] == 0
    assert cli.main([*args,'--resume']) == 2


def test_batch_cli_dry_run_and_network_option_conflict(tmp_path, capsys):
    output = tmp_path/'batch'
    assert cli.main(['batch-mine','--output',str(output),'--offline','--dry-run']) == 0
    assert not output.exists()
    assert json.loads(capsys.readouterr().out)['would_use_network'] is False
    assert cli.main(['batch-mine','--output',str(output),'--offline','--online']) == 1
    assert not output.exists()
