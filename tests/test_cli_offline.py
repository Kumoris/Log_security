import json
import shutil
from pathlib import Path
import pytest
from agentlog_unified import cli,config
from agentlog_unified.storage import csv_cell,redact
from synthetic_histories import RISK,SAFE,commit,init


@pytest.fixture
def local_project(tmp_path,monkeypatch):
    project=tmp_path/'tool';project.mkdir()
    shutil.copy(config.PROJECT/'config.example.yaml',project/'config.example.yaml')
    shutil.copytree(config.PROJECT/'schemas',project/'schemas')
    repo=tmp_path/'repo';init(repo)
    intro=commit(repo,{'app.py':RISK},'synthetic initial',day=2)
    commit(repo,{'app.py':SAFE},'synthetic normal human commit',actor='human',day=3)
    inp=project/'prs.jsonl'
    inp.write_text(json.dumps({'fixture_repository_id':'fixture-cli','is_synthetic':True,'local_repo_path':str(repo),'initial_commit_shas':[intro],'target_ref':'main','synthetic_author_mapping':{'agent@example.invalid':'agent','human@example.invalid':'human_led'}})+'\n')
    cfg=project/'config.yaml';cfg.write_text('input:\n  prs_path: prs.jsonl\n  offline: true\nmining:\n  max_history_commits_per_repository: 100\n')
    monkeypatch.setattr(config,'PROJECT',project);monkeypatch.setattr(cli,'PROJECT',project)
    return project,cfg,repo


def test_full_offline_cli_resume_schema_and_redaction(local_project,capsys):
    project,cfg,repo=local_project
    args=['run','--config',str(cfg),'--run-id','e2e','--offline']
    assert cli.main(args)==0
    run=project/'outputs/runs/e2e'
    initial=json.loads((run/'run_manifest.json').read_text())
    outputs=['log_changes','logs_with_followups','privacy_review_candidates']
    content={n:(run/f'data/{n}.jsonl').read_text() for n in outputs}
    assert all(len(text.splitlines())==1 for text in content.values())
    case=json.loads(content['privacy_review_candidates'])
    assert case['screening_bucket']=='REVIEW_READY'
    assert case['fix_executor_type']=='human_led'
    assert case['human_review_status']=='pending'
    assert case['new_type_status']=='not_established'
    assert cli.main(args+['--resume'])==0
    final=json.loads((run/'run_manifest.json').read_text())
    assert initial['collection_cutoff_utc']==final['collection_cutoff_utc']
    assert content=={n:(run/f'data/{n}.jsonl').read_text() for n in outputs}
    assert 'DUMMY_RESEARCH_SECRET_NOT_VALID' not in capsys.readouterr().out
    for path in [*run.glob('data/*.jsonl'),*run.glob('reports/*.csv'),*run.glob('evidence/**/*')]:
        if path.is_file():assert 'DUMMY_RESEARCH_SECRET_NOT_VALID' not in path.read_text()
    assert (run/'data/index.sqlite').stat().st_mode & 0o077 == 0
    # No fixture hooks or arbitrary application execution occurred.
    assert not (repo/'executed').exists()


def test_interrupt_rolls_back_then_resume_without_duplicates(local_project,monkeypatch):
    project,cfg,_=local_project
    real=cli.execute
    def stop(stage,*args,**kwargs):
        if stage=='trace':raise KeyboardInterrupt()
        return real(stage,*args,**kwargs)
    monkeypatch.setattr(cli,'execute',stop)
    args=['run','--config',str(cfg),'--run-id','interrupted','--offline']
    assert cli.main(args)==130
    before=json.loads((project/'outputs/runs/interrupted/run_manifest.json').read_text())
    monkeypatch.setattr(cli,'execute',real)
    assert cli.main(args+['--resume'])==0
    run=project/'outputs/runs/interrupted'
    assert len((run/'data/log_changes.jsonl').read_text().splitlines())==1
    assert json.loads((run/'run_manifest.json').read_text())['collection_cutoff_utc']==before['collection_cutoff_utc']


def test_changed_input_cannot_silently_resume(local_project):
    project,cfg,_=local_project
    args=['run','--config',str(cfg),'--run-id','frozen','--offline']
    assert cli.main(args)==0
    with (project/'prs.jsonl').open('a') as f:f.write('\n')
    assert cli.main(args+['--resume'])==1


def test_dry_run_does_not_create_run_or_access_repository(local_project,monkeypatch):
    project,cfg,_=local_project
    def forbidden(*args,**kwargs):raise AssertionError('target accessed')
    monkeypatch.setattr(cli,'collect_repositories',forbidden)
    assert cli.main(['run','--config',str(cfg),'--dry-run'])==0
    assert not (project/'outputs/runs').exists()


def test_missing_history_and_budget_do_not_become_safe(local_project):
    project,cfg,_=local_project
    row=json.loads((project/'prs.jsonl').read_text());row['initial_commit_shas'].append('f'*40)
    (project/'prs.jsonl').write_text(json.dumps(row)+'\n')
    assert cli.main(['run','--config',str(cfg),'--run-id','missing','--offline'])==2
    run=project/'outputs/runs/missing'
    assert (run/'data/coverage_gaps.jsonl').read_text()
    case=json.loads((run/'data/candidates.jsonl').read_text())
    assert case['screening_bucket']=='BLOCKED_BY_DATA'
    assert case['censoring_reason']=='history_incomplete'


def test_csv_formula_and_secret_values_redacted():
    assert csv_cell('  =HYPERLINK("https://example.invalid")').startswith("'")
    assert '<REDACTED' in redact('password="DUMMY_RESEARCH_SECRET_NOT_VALID"')
    assert redact({'password':'secret-value'})=={'password':'<REDACTED:VALUE>'}
