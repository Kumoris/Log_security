"""Real CLI batches beyond the legacy 100-case cap, interruption and paired audit."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from agentlog_unified import screening as s
from agentlog_unified.cli import main
from agentlog_unified.screening_history import extract_commit
from synthetic_histories import init,commit,HEADER


def fixture_run(tmp_path, n=60):
    repo=tmp_path/'repo';init(repo)
    body=HEADER+'def emit(value):\n'+''.join(f'    logger.info("done", value) # position {i}\n' for i in range(n))
    sha=commit(repo,{'app.py':body},'fictional output fixture')
    out=tmp_path/'run';result=extract_commit(repo,'fixture/project',sha,out/'fixture-mining')
    assert result['audit']['metrics']['pydriller_repository_traversals']==1
    files=[]
    for row in result['file_versions']:
        files.append({**row,'commit_id':'fixture-commit','repo_path':str(repo),'scope':'test',
                      'input_record_ids':['fixture-input'],'old_stratum':'not_hit','old_log_ids':[]})
    s.write_rows(out/'population/file_versions.jsonl',files)
    cfg=s.config();cfg.update(sample_size=105,evaluation_size=0,batch_case_limit=25)
    cpath=tmp_path/'config.json';s.write(cpath,cfg)
    return out,cpath,result


def test_real_cli_crosses_100_and_recovers_atomic_attempt(tmp_path):
    out,cpath,mined=fixture_run(tmp_path)
    assert main(['screening','discover','--output',str(out),'--config',str(cpath)])==0
    discovered=s.read(out/'discovery/coverage.json')
    assert discovered['output_units']==120
    assert main(['screening','freeze','--output',str(out),'--config',str(cpath)])==0
    selection=s.read(out/'selection/manifest.json')
    assert selection['primary_selected']==105
    assert len(list(s.rows(out/'selection/batches.jsonl')))==5
    with pytest.raises(InterruptedError):
        main(['screening','run','--output',str(out),'--interrupt-after','3'])
    db=sqlite3.connect(out/'analyses/main/checkpoint.sqlite')
    assert db.execute('SELECT count(*) FROM results').fetchone()[0]==3
    assert db.execute("SELECT count(*) FROM attempts WHERE status='started'").fetchone()[0]==1
    db.close()
    assert main(['screening','run','--output',str(out),'--resume'])==0
    assert main(['screening','export','--output',str(out)])==0
    report=s.read(out/'analyses/main/coverage.json')
    assert report['actual_analyses']==210 and report['missing']==[] and report['unexpected']==[]
    assert report['paired_base_evidence_equal'] and report['interrupted_attempts']==1
    assert report['graphs']==105 and report['graphs_with_structural_value_edges']>0
    assert report['batch_states'][-1]=={'id':4,'status':'complete'}
    assert report['precision'] is None and report['human_labels']==0
    results=list(s.rows(out/'analyses/main/results.jsonl'))
    assert len({r['analysis_id'] for r in results})==210
    assert all(r['processing_status']!='blocked' for r in results)
    before=len(list(s.rows(out/'analyses/main/attempts.jsonl')))
    res=s.execute_batches(out,resume=True)
    assert res['processed_this_invocation']==0 and res['cache_hits']==210
    s.export(out)
    assert len(list(s.rows(out/'analyses/main/attempts.jsonl')))==before
    # Corrupted cached graph must not be accepted just because a result exists.
    graph=next((out/'analyses/main/graphs').rglob('*.json'))
    graph.write_text('{}\n')
    with pytest.raises(ValueError,match='cached_evidence_hash_mismatch'):s.execute_batches(out,resume=True)


def test_actual_source_version_change_is_captured_without_git(tmp_path,monkeypatch):
    root=tmp_path/'project';(root/'src/agentlog_unified').mkdir(parents=True);(root/'configs').mkdir()
    source=root/'src/agentlog_unified/module.py';source.write_text('VALUE = 1\n')
    (root/'pyproject.toml').write_text('[project]\nname="fixture"\n')
    monkeypatch.setattr(s,'PROJECT',root)
    a=s.code_version();source.write_text('VALUE = 2\n');b=s.code_version()
    assert a['sources']!=b['sources'] and a['git_head'] is None
    s.snapshot_code(root/'snapshot',b)
    assert (root/'snapshot/source/src/agentlog_unified/module.py').read_text()=='VALUE = 2\n'


def test_analysis_id_captures_dependencies_config_variant_not_attempt():
    case={'case_id':'stable-case','source_versions':[{'path':'a.py','sha':'a'*40,'source_sha256':'hash1'}],
          'snapshot_sha256':'snapshot1'}
    a=s.analysis_identity(case,'baseline','signature-a')
    assert a==s.analysis_identity(case,'baseline','signature-a')
    assert a!=s.analysis_identity(case,'dfg_augmented','signature-a')
    assert a!=s.analysis_identity(case,'baseline','signature-b')
    changed=copy.deepcopy(case);changed['source_versions'][0]['source_sha256']='hash2'
    assert a!=s.analysis_identity(changed,'baseline','signature-a')
    assert case['case_id']==changed['case_id']


def test_freeze_grouping_keeps_repo_and_duplicate_context_together(tmp_path):
    group=s.Groups();group.join('a/repo','b/repo');group.join('b/repo','c/repo')
    assert group.find('a/repo')==group.find('c/repo')
    cases=[{'case_id':str(i),'language':'python' if i%2 else 'go','legacy_stratum':'unknown' if i%3 else 'candidate'} for i in range(40)]
    a,q=s.stratified(cases,20,42);b,_=s.stratified(list(reversed(cases)),20,42)
    assert [x['case_id'] for x in a]==[x['case_id'] for x in b]
    assert len(a)==20 and sum(q.values())==20
