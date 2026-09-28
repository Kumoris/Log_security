import csv
import json
from pathlib import Path

from agentlog_unified import cli
from agentlog_unified.storage import Store, redact
from test_cli_offline import local_project
from synthetic_histories import commit


def test_cli_human_review_roundtrip_is_separate_and_redacted(local_project, capsys):
    project, config, repo = local_project
    base = ['--config', str(config), '--run-id', 'review-e2e', '--offline']
    assert cli.main(['run', *base]) == 0
    run = project/'outputs/runs/review-e2e'
    candidate = json.loads((run/'data/candidates.jsonl').read_text())
    review_file = project/'completed.csv'
    with review_file.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['case_id','human_review_status','human_review_decision','reviewer','evidence_notes'])
        writer.writeheader()
        writer.writerow({'case_id':candidate['case_id'],'human_review_status':'reviewed',
                         'human_review_decision':'privacy_candidate','reviewer':'synthetic-reviewer',
                         'evidence_notes':'synthetic code review'})
    assert cli.main(['review-import', *base, '--file', str(review_file)]) == 0
    reviewed = json.loads((run/'data/candidates.jsonl').read_text())
    assert reviewed['human_review']['human_review_status'] == 'reviewed'
    assert reviewed['human_review_status'] == 'pending'  # machine field was not overwritten
    assert reviewed['runtime_leak_claim'] is False
    assert cli.main(['run', *base]) == 0
    again = json.loads((run/'data/candidates.jsonl').read_text())
    assert again['human_review']['review_revision'] == 1
    assert again['human_review']['stale_against_current_candidate'] is False
    assert len((run/'data/human_review_history.jsonl').read_text().splitlines()) == 1


def test_ast_semantic_evidence_never_reexports_a_literal():
    marker = 'SYNTHETIC_AST_VALUE_ONLY'
    data = {'semantic_statement': f"Constant(value='{marker}')", 'dependencies': [
        {'semantic_code': f"Constant(value='{marker}')"}]}
    public = redact(data)
    assert marker not in json.dumps(public)
    assert public['semantic_statement'].startswith('<SEMANTIC_SHA256:')
    assert marker in data['semantic_statement']


def test_match_import_rejects_unknown_pairs_and_duplicate_destinations(tmp_path):
    store = Store(tmp_path/'index.sqlite')
    event = {'id':'e','repository_id':'r','parent_sha':'a','sha':'b',
             'match_candidates':[{'before_key':'x','after_key':'y'}]}
    with store.db:
        store.replace('log_events',[event]); store.finish('detect')
    p=tmp_path/'matches.jsonl'
    p.write_text(json.dumps({'event_id':'e','before_key':'x','after_key':'z','reviewer':'test'}))
    import pytest
    with pytest.raises(ValueError, match='not an exported candidate'):
        cli.apply_match_file(store,p)
    assert store.rows('match_overrides') == []
    p.write_text(json.dumps({'event_id':'e','before_key':'x','after_key':'y','reviewer':'test'}))
    validated=cli.apply_match_file(store,p)
    with store.db:store.replace('match_overrides',validated['overrides'])
    assert cli.apply_match_file(store,p)['applied'] == 0
    store.close()


def test_cli_extension_extracts_only_new_commit(local_project):
    project,config,repo=local_project
    base=['--config',str(config),'--offline']
    assert cli.main(['run',*base,'--run-id','earlier'])==0
    old=(project/'outputs/runs/earlier/run_manifest.json').read_bytes()
    commit(repo,{'app.py':(repo/'app.py').read_text().replace('logger.info','logger.debug')},'new level change',actor='human',day=4)
    assert cli.main(['run',*base,'--run-id','extended','--extend-from','earlier'])==0
    manifest=json.loads((project/'outputs/runs/extended/run_manifest.json').read_text())
    metrics=manifest['mining_metrics'][0]['metrics']
    assert metrics['pydriller_commits']==1 and metrics['reused_commits']==2
    assert (project/'outputs/runs/earlier/run_manifest.json').read_bytes()==old


def test_cli_match_override_replays_and_rebuilds_coverage(local_project):
    project,config,repo=local_project
    source=(repo/'app.py').read_text()
    log='logger.info("user=%s", payload)'
    commit(repo,{'app.py':source.replace(log,log+'\n'+log)},'duplicate log',day=4)
    base=['--config',str(config),'--offline','--run-id','match-e2e']
    assert cli.main(['run',*base])==0
    run=project/'outputs/runs/match-e2e'
    events=[json.loads(s) for s in (run/'data/log_events.jsonl').read_text().splitlines()]
    event=next(e for e in events if e.get('match_candidates') and any(c.get('after_key') for c in e['match_candidates']))
    pair=next(c for c in event['match_candidates'] if c.get('after_key'))
    matches=project/'matches.jsonl'
    matches.write_text(json.dumps({'event_id':event['id'],'before_key':pair['before_key'],
                                  'after_key':pair['after_key'],'reviewer':'synthetic-reviewer'}))
    # Seed a stale exported table: replay must rebuild it from current stage gaps.
    store=Store(run/'data/index.sqlite')
    with store.db:store.replace('coverage_gaps',[{'error_type':'stale_test_gap'}])
    store.close()
    code=cli.main(['resolve-match',*base,'--file',str(matches)])
    assert code==0
    manifest=json.loads((run/'run_manifest.json').read_text())
    assert manifest['exit_code']==code
    assert 'stale_test_gap' not in (run/'data/coverage_gaps.jsonl').read_text()
    overrides=[json.loads(s) for s in (run/'data/match_overrides.jsonl').read_text().splitlines()]
    assert len(overrides)==1 and overrides[0]['scope']=='entity_identity_only'
    assert cli.main(['resolve-match',*base,'--file',str(matches)])==0
