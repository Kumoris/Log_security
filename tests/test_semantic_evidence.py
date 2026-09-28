import ast
from copy import deepcopy
import json
from pathlib import Path

import pytest

from agentlog_unified.config import load_config, PROJECT
from agentlog_unified.semantic_evidence import analyze_use, classify, loc, review, digest, safe_code
from agentlog_unified.semantic_scan import scan_semantics
from synthetic_histories import commit, init, git

HEADER='import logging\nfrom pydantic import EmailStr, SecretStr\nlogger=logging.getLogger(__name__)\n'


def analyze(source, function, files=None, **kw):
    tree=ast.parse(source)
    fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==function)
    call=next(n for n in ast.walk(fn) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='info')
    arg=call.args[-1]
    return analyze_use({'app.py':source,**(files or {})},'fixture/repo','a'*40,'app.py',loc('app.py',arg),**kw)


def test_scoped_alias_and_unknown_names():
    source=HEADER+'''def sensitive(data: EmailStr):
    value=data
    logger.info("value", value)
def scalar(data):
    value=True
    logger.info("value", value)
def unknown(abbr):
    logger.info("value", abbr)
'''
    a=analyze(source,'sensitive'); b=analyze(source,'scalar'); c=analyze(source,'unknown')
    assert a['review']['status']=='supported'
    assert classify(a)['types']==[{'category':'PII','subtype':'email'}]
    assert classify(b)['queue']=='supported_non_sensitive'
    assert classify(c)['queue']=='semantic_unknown'
    assert c['review']['status']=='ambiguous'


def test_one_hop_unpacked_alias_mixed_projection_and_model():
    source=HEADER+'''from helpers import identity
class Account:
    value: EmailStr
    count: int
def use(data: EmailStr):
    value, count = (data, 3)
    payload={"secret": identity(value), "active": True}
    logger.info("value", payload["secret"])
def model(data: Account):
    logger.info("value", data.value)
'''
    files={'helpers.py':'def identity(value):\n    return value\n'}
    result=analyze(source,'use',files)
    assert result['review']['status']=='supported',result['review']
    assert classify(result)['types']==[{'category':'PII','subtype':'email'}]
    assert analyze(source,'use',files,one_hop=False)['review']['status']=='ambiguous'
    model=analyze(source,'model',files)
    assert model['review']['status']=='supported',model['review']
    assert classify(model)['types']==[{'category':'PII','subtype':'email'}]


def test_field_write_unknown_sanitizer_and_conflict():
    source=HEADER+'''def write(data: EmailStr):
    payload={"active":True}
    payload["v"]=data
    logger.info("value", payload["v"])
def sanitizer(data: EmailStr):
    logger.info("value", magic_redact(data))
def conflict(data: EmailStr, other: SecretStr, condition):
    logger.info("value", data if condition else other)
'''
    assert analyze(source,'write')['review']['status']=='supported'
    assert analyze(source,'sanitizer')['review']['status']=='ambiguous'
    assert classify(analyze(source,'conflict'))['queue']=='conflicting_explanations'


def test_names_or_primitive_types_do_not_prove_privacy():
    source=HEADER+'''data: EmailStr
def use(data: str):
    logger.info("value", data)
def unbound():
    logger.info("value", value)
    value=True
'''
    assert classify(analyze(source,'use'))['queue']=='semantic_unknown'
    assert analyze(source,'unbound')['review']['status']=='ambiguous'
    fake='import logging\nlogger=logging.getLogger(__name__)\nclass EmailStr: pass\ndef use(data: EmailStr):\n    logger.info("value",data)\n'
    assert not classify(analyze(fake,'use'))['types']


def test_independent_replay_rejects_forged_scope_history_and_flow():
    source=HEADER+'def use(data: EmailStr):\n    value=data\n    logger.info("value",value)\n'
    result=analyze(source,'use')
    for modification in ('sha','scope','child'):
        proof=deepcopy(result['proof'])
        if modification=='sha':proof['sha']='b'*40
        elif modification=='scope':proof['scope']='different_function'
        else:proof['children'][0]['anchor']['line']=1
        assert review({'app.py':source},'fixture/repo','a'*40,proof)['status']=='unsupported'
    assert review({'app.py':source+'\n'},'fixture/repo','a'*40,result['proof'])['status']=='unsupported'


def test_nominal_new_type_and_budget_unknown():
    source=HEADER+'''from typing import NewType
NHI=NewType("NHI",str)
def use(data:NHI):
    logger.info("value",data)
'''
    result=analyze(source,'use')
    assert result['review']['status']=='supported',result['review']
    assert classify(result)['queue']=='known_semantics_unmapped'
    assert classify(analyze(source,'use',max_chars=1))['queue']=='context_or_history_missing'


def test_literal_export_does_not_publish_unknown_secret():
    assert 'DUMMY_UNRECOGNIZED_SECRET' not in safe_code('value="DUMMY_UNRECOGNIZED_SECRET"\nlogger.info(value)')


def test_real_git_history_e2e_deletion_rename_cross_file_and_resume(tmp_path):
    repo=tmp_path/'repo';init(repo)
    initial=commit(repo,{'app.py':HEADER+'''from helpers import project
def use(data: EmailStr):
    payload=project(data)
    logger.info(
        "value",
        payload)
''','helpers.py':'def project(value):\n    return {"value":value}\n'},'introduce')
    repair=commit(repo,{'helpers.py':'def project(value):\n    return {"active":True}\n'},'cross-file projection',actor='human',day=3)
    git(repo,'mv','app.py','renamed.py')
    renamed=commit(repo,{},'rename',actor='ci',day=4)
    tip=commit(repo,{'renamed.py':HEADER+'def use(data:EmailStr):\n    pass\n'},'delete log',actor='human',day=5)
    inp=tmp_path/'input.jsonl';inp.write_text(json.dumps({'is_synthetic':True,'fixture_repository_id':'semantic-fixture','local_repo_path':str(repo),'initial_commit_shas':[initial],'target_ref':tip,'synthetic_author_mapping':{'agent@example.invalid':'agent','human@example.invalid':'human_led'}})+'\n')
    config=load_config(str(PROJECT/'config.example.yaml'))
    output=tmp_path/'out'
    dry=scan_semantics(inp,output,config,dry_run=True)
    assert not output.exists() and dry['files_written'] is False
    result=scan_semantics(inp,output,config)
    assert result['metrics']['pydriller_commits']==4
    assert result['metrics']['pydriller_diff_parsed_calls']>=4
    assert result['metrics']['pydriller_source_reads']>=8
    assert result['by_review_status'].get('supported',0)>0
    rows=[json.loads(line) for line in (output/'log_changes.jsonl').read_text().splitlines()]
    assert any(r['sha']==repair and r['relation']=='dependency_change' for r in rows)
    assert any(r['sha']==renamed for r in rows)
    assert any(r['sha']==tip and r['after'] is None for r in rows)
    followups=[json.loads(line) for line in (output/'followups.jsonl').read_text().splitlines()]
    assert followups
    assert scan_semantics(inp,output,config,resume=True)['resumed_without_reprocessing']
    with pytest.raises(ValueError):scan_semantics(inp,output,config)
    config['semantics']['max_context_chars']=42
    with pytest.raises(ValueError):scan_semantics(inp,output,config,resume=True)
    assert not (repo/'executed').exists()


def test_missing_history_retained(tmp_path):
    repo=tmp_path/'repo';init(repo)
    inp=tmp_path/'input.jsonl';inp.write_text(json.dumps({'is_synthetic':True,'fixture_repository_id':'missing','local_repo_path':str(repo),'initial_commit_shas':['f'*40],'target_ref':'f'*40})+'\n')
    result=scan_semantics(inp,tmp_path/'out',load_config(str(PROJECT/'config.example.yaml')))
    assert result['funnel']['gap_records']>=2
    assert result['funnel']['selected_field_uses']==0


def test_partial_clone_missing_blob_does_not_abort_other_files(tmp_path):
    from agentlog_unified.miner import snapshot_files
    repo=tmp_path/'repo';init(repo)
    tip=commit(repo,{'a_missing.py':'# unavailable\n','z_available.py':HEADER+'logger.info("ok")\n'},'files')
    oid=git(repo,'rev-parse',tip+':a_missing.py')
    # Only a newly generated fixture object is removed to model local data loss.
    (repo/'.git'/'objects'/oid[:2]/oid[2:]).unlink()
    snapshot=snapshot_files(str(repo),tip)
    assert 'z_available.py' in snapshot['files']
    assert any(g.get('path')=='a_missing.py' for g in snapshot['gaps'])
    assert not any(not g.get('path') for g in snapshot['gaps'])


def test_vocabulary_is_version_scoped_and_never_confirms_human_review():
    source=HEADER+'def use(NHI):\n    logger.info("value",NHI)\n'
    definition='NHI means a project-local transaction reference.\n'
    mapping={'repository':'fixture/repo','revision':'a'*40,'module':'app.py','scope':'use','field':'NHI',
             'meaning':'transaction_reference','category':'QID','subtype':'transaction_identifier',
             'definition_path':'glossary.md','definition_sha256':digest(definition),'definition_quote':definition}
    result=analyze(source,'use',{'glossary.md':definition},vocabulary=[mapping])
    assert result['review']['status']=='ambiguous'
    assert result['review']['human_confirmed'] is False
    assert not classify(result)['types']
    other={**mapping,'repository':'different/repo'}
    assert analyze(source,'use',{'glossary.md':definition},vocabulary=[other])['proposal']==[]
    stale={**mapping,'definition_sha256':'0'*64}
    assert analyze(source,'use',{'glossary.md':definition},vocabulary=[stale])['review']['status']=='unsupported'


def test_review_does_not_accept_candidate_claim_instead_of_raw_contract():
    source=HEADER+'def use(data:EmailStr):\n    logger.info("value",data)\n'
    proof=analyze(source,'use')['proof']
    proof['children'][0]['proposed']['meaning']='not_email'
    assert review({'app.py':source},'fixture/repo','a'*40,proof)['status']=='unsupported'


def test_call_argument_is_read_before_that_call_can_mutate_it():
    source=HEADER+'''from helper import project
def use(data:EmailStr):
    value=data
    payload=project(value)
    logger.info("value",payload)
'''
    result=analyze(source,'use',{'helper.py':'def project(value):\n    return {"contact":value,"active":True}\n'})
    assert result['review']['status']=='supported',result['review']
    assert classify(result)['types']==[{'category':'PII','subtype':'email'}]


def test_imported_type_and_builtin_shadowing_stay_unknown():
    source=HEADER+'EmailStr=str\ndef use(data:EmailStr):\n    logger.info("value",data)\n'
    assert not classify(analyze(source,'use'))['types']
    source=HEADER+'''def dict(**kw):
    return {}
def use(data:EmailStr):
    logger.info("value",dict(value=data))
'''
    assert analyze(source,'use')['review']['status']=='ambiguous'
