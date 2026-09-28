"""Actual synthetic Git -> PyDriller -> DFG -> type/library alignment."""
import importlib.util
import json
from pathlib import Path

import pytest

from agentlog_unified.batch_mine import repository_cache_path
from agentlog_unified.config import sha256_file
from agentlog_unified.detector import detect_snapshot, PythonSnapshot
from agentlog_unified.export import write_json, write_jsonl
from agentlog_unified.semantic_dfg import export_dfg
from agentlog_unified.semantic_scan import use_sites
from synthetic_histories import init, commit, HEADER
from test_aidev_dfg_bridge import bridge

spec=importlib.util.spec_from_file_location('reference_mining',Path(__file__).parents[1]/'examples/mine_aidev_reference_types.py')
mining=importlib.util.module_from_spec(spec);spec.loader.exec_module(mining)


def test_reference_alignment_never_transfers_unmapped_or_null_types():
    index=[{'id':'r','concept':'password','category':None,'subtype':None,'origin':'human_source'}]
    assert mining.reference_matches([{'concept':'data'}],index)==[]
    hit=mining.reference_matches([{'concept':'password'}],index)[0]
    assert hit['target_gold_inherited'] is False


def test_real_git_sample_dfg_assess_and_resume(tmp_path):
    cache=tmp_path/'cache';cache.mkdir();repo=repository_cache_path(cache,'fixture/repo');init(repo)
    source=HEADER+'from pydantic import EmailStr\nfrom helper import relay\ndef typed(data: EmailStr):\n    logger.info(data)\ndef unknown(password):\n    logger.info(password)\ndef benign():\n    value=True\n    logger.info(value)\ndef wrapped(payload):\n    relay(payload)\n'
    files={'app.py':source,'helper.py':HEADER+'def relay(data):\n    logger.info(data)\n'}
    sha=commit(repo,files,'synthetic types')
    entity=next(e for e in detect_snapshot(files)['entities'] if e['path']=='app.py' and 'relay(' in e['statement'])
    assert use_sites(entity,files,python_snapshot=PythonSnapshot(files))==use_sites(entity,files)
    with pytest.raises(ValueError,match='snapshot_source_mismatch'):
        use_sites(entity,files,python_snapshot=PythonSnapshot({'app.py':'pass'}))
    row={**entity,'id':'source','repository':'fixture/repo','snapshot_sha':sha,
         'event_references':[{'id':'event','sha':sha,'side':'after','snapshot_sha':sha}]}
    original=tmp_path/'original.jsonl';write_jsonl(original,[row])
    example={k:row[k] for k in ('repository','snapshot_sha','path','start_line','end_line')}
    example.update(id='example',source_record_id='source',source_record_line=1,source_file=str(original),
        source_file_sha256=sha256_file(original),human_sensitive_reference_ids=['reference'],
        reference_concepts=['password'],category='AUTH',subtype='password')
    audit=tmp_path/'audit';write_jsonl(audit/'aidev_reference_examples.jsonl',[example])
    write_json(audit/'manifest.json',{'artifacts':{'aidev_reference_examples.jsonl':sha256_file(audit/'aidev_reference_examples.jsonl')}})
    seed=tmp_path/'seed';report=bridge.freeze(audit,seed,cache)
    assert report['metrics']['pydriller_commits']==1
    run=tmp_path/'sample'
    assert mining.sample(seed,run,dry_run=True)['files_written'] is False and not run.exists()
    assert mining.sample(seed,run)['selected_cases']==4
    assert mining.sample(seed,run,resume=True)['resumed_without_reprocessing']
    dfg=tmp_path/'dfg';assert export_dfg(run,dfg,max_cases=100)['graphs']==4
    library=tmp_path/'library'
    mining.tables(library,{'references':[{'id':'human-case-fixture'}],'field_answers':[],
        'type_index':[{'id':'p','concept':'password','category':'AUTH','subtype':'password'},
                      {'id':'e','concept':'email','category':'PII','subtype':'email'}]})
    mining.finish(library,{}, {})
    out=tmp_path/'assessment'
    assert mining.assess(run,dfg,library,out,dry_run=True)['files_written'] is False and not out.exists()
    result=mining.assess(run,dfg,library,out)
    rows={r['field']:r for r in mining.records(out/'field_types.jsonl')}
    assert rows['data']['type_status']=='known'
    assert rows['password']['type_status']=='unknown' and rows['password']['sensitive_types']==[]
    assert rows['payload']['dfg_log_relation']['value']=='possible'
    assert rows['value']['type_status']=='non_sensitive'
    assert result['cases_with_reference_alignment']==1 and result['human_field_labels']==0
    assert mining.assess(run,dfg,library,out,resume=True)['resumed_without_reprocessing']
    assert all(not r['human_confirmed'] and not r['runtime_confirmed'] for r in rows.values())
    (dfg/'graphs'/next(iter(rows.values()))['id']).with_suffix('.json').write_text('{}')
    with pytest.raises(ValueError,match='integrity_mismatch'):
        mining.assess(run,dfg,library,tmp_path/'bad')
