"""Synthetic protocol/static tests. Mock responses are never real model evidence."""
import ast
from copy import deepcopy
import json
from pathlib import Path
import subprocess

import pytest

from agentlog_unified.semantic_context import HistoricalContext, safe_view
from agentlog_unified.semantic_demand import Calls, gate, validate, run_demand
from agentlog_unified.semantic_evidence import digest, loc
from agentlog_unified.semantic_scan import use_sites, scan_semantics
from agentlog_unified.config import load_config
from agentlog_unified.miner import mine_repository, snapshot_files
from agentlog_unified.storage import stable_id
from synthetic_histories import init, commit, git, HEADER


def make_context(source, files=None, index=0, sha='a'*40, scope=None, role=None):
    tree = ast.parse(source)
    calls = [n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='info']
    call = calls[index]; text = ast.get_source_segment(source,call)
    entity = {'path':'app.py','statement':text,'start_line':call.lineno,'end_line':call.end_lineno}
    sites,_ = use_sites(entity,{'app.py':source})
    site = next((s for s in sites if s['field_origin']==role),sites[0])
    row = {'id':stable_id(sha,site),'repository':'fixture/repo','sha':sha,'path':'app.py','scope':scope or 'emit',
           'language':'python','field':site['field'],'use_anchor':site['anchor'],'use_role':site['field_origin'],
           'output_expression_anchor':site.get('output_expression_anchor'),'context':{'gaps':[]}}
    case = {'id':row['id'],'result':row,'source_versions':[], 'log_start_line':call.lineno,'log_end_line':call.end_lineno,'log_statement_sha256':digest(text)}
    ctx=HistoricalContext(case,{'sha':sha,'files':{'app.py':source,**(files or {})},'backend':'synthetic_test_memory','revision_backend':'synthetic_test_memory'})
    ctx.initial();return ctx


def request(ctx,symbol,kind='symbol_definition',**kw):
    b=next(b for b in ctx.blocks if b['kind']=='enclosing_function')
    return {'request_id':'q1','case_id':ctx.case['id'],'request_kind':kind,'symbol_or_field':symbol,
            'origin_anchor':b['id'],'reason':'protocol test','expected_evidence':'definition','priority':'high',**kw}


def response(ctx,stage='extract'):
    refs=[ctx.blocks[0]['id']]
    def d(value):return {'value':value,'status':'ambiguous','meaning':'protocol test only','evidence_refs':refs,'flow_step_refs':[],'gaps':[]}
    return {'case_id':ctx.case['id'],'stage':stage,'dataset_metadata_semantics':'not_applicable_program_use',
        'program_semantics':d('unknown'),'sensitive_type':{**d('unknown'),'types':[]},
        'log_relation':d('unknown'),'privacy_risk':d('undetermined'),'context_requests':[],
        'counterevidence':[],'human_confirmed':False,'runtime_confirmed':False}


def test_scope_alias_helper_mixed_and_derived():
    source='''from pydantic import EmailStr
from helper import relay
def first(data:EmailStr):
    value=relay(data)
    logger.info("v",value)
def second(data):
    value=3
    logger.info("v",value)
'''
    ctx=make_context(source,{'helper.py':'def relay(value):\n    return value\n'})
    before=ctx.checks(); assert before['supported_flow_validity']=='unresolved'
    assert ctx.retrieve(request(ctx,'relay','function_binding'))['status']=='success'
    after=ctx.checks(); assert after['supported_flow_validity']=='supported_bounded_static'
    assert any(s['actual_to_formal'] and s['return_anchor'] for s in after['steps'])
    other=make_context(source,index=1); assert not other.checks()['independent_rule_replay']['derived_meanings'][0]['category']
    ctx=make_context('from pydantic import EmailStr\ndef emit(data:EmailStr):\n    payload={"value":data,"ok":True}\n    logger.info("v",payload["ok"])\n')
    assert ctx.checks()['log_relation']['value']=='selected_field'
    assert not ctx.checks()['independent_rule_replay']['derived_meanings'][0]['category']
    for code,relation in [('len(data)','derived_count'),('bool(data)','derived_boolean'),('data','direct_original')]:
        ctx=make_context(f'def emit(data):\n    logger.info("v",{code})\n',role='nested_expression_input')
        assert ctx.checks()['log_relation']['value']==relation


@pytest.mark.parametrize('middle',['if flag:\n        value=external()','value.update(other)','mutate(value)','value=external()'])
def test_overwrite_and_mutation_invalidate_old_path(middle):
    source='from pydantic import EmailStr\ndef emit(data:EmailStr,flag):\n    value=data\n    '+middle+'\n    logger.info("v",value)\n'
    assert make_context(source).checks()['supported_flow_validity']=='unresolved'


def test_request_schema_reinterpret_and_no_latest_docs():
    source='from jsonschema import validate\nfrom schemas import SCHEMA\ndef emit(payload):\n    validate(payload,SCHEMA)\n    logger.info("v",payload)\n'
    ctx=make_context(source,{'schemas.py':'SCHEMA={"type":"string","format":"email"}\n'})
    assert ctx.checks()['supported_flow_validity']=='unresolved'
    retrieved=ctx.retrieve(request(ctx,'SCHEMA','bound_schema'))
    assert retrieved['status']=='success'
    assert ctx.checks()['supported_flow_validity']=='supported_bounded_static'
    assert 'email' in ctx.blocks[-1]['code_view']
    assert ctx.retrieve(request(ctx,'SCHEMA','bound_schema'))['status']=='duplicate'
    mutated=make_context(source.replace('    validate(payload,SCHEMA)','    SCHEMA.update(other)\n    validate(payload,SCHEMA)'),{'schemas.py':'SCHEMA={"format":"email"}\n'})
    mutated.retrieve(request(mutated,'SCHEMA','bound_schema'))
    assert mutated.checks()['supported_flow_validity']=='unresolved'
    old=make_context(source.replace('SCHEMA)','{"$ref":"new.json"})'))
    r=old.retrieve(request(old,'payload','bound_schema'))
    assert not r['blocks_added']  # no fallback to a latest working-tree document


def test_requests_reject_fabrication_escape_version_scope_and_budget():
    source='from helper import relay\ndef emit(data):\n    value=relay(data)\n    logger.info("v",value)\n'
    files={'helper.py':'def relay(value):\n    return value\n'}
    for extra,reason in [({'symbol_or_field':'../secret'},'invalid_symbol_no_paths_or_commands'),
                         ({'origin_anchor':'made-up'},'invented_origin_anchor'),
                         ({'sha':'b'*40},'version_or_repository_mismatch'),
                         ({'case_id':'bad'},'case_mismatch'),
                         ({'request_kind':'shell'},'request_kind_not_allowed')]:
        ctx=make_context(source,files);r=ctx.retrieve(request(ctx,'relay',**extra));assert r['reason']==reason
    ctx=make_context(source,files); assert ctx.retrieve(request(ctx,'relay'),max_files=0)['status']=='truncated'
    ctx=make_context(source,files); assert ctx.retrieve(request(ctx,'relay'),budget=1)['status']=='truncated'
    ctx=make_context('def other():\n    secret=3\ndef emit(data):\n    logger.info("v",data)\n')
    assert ctx.retrieve(request(ctx,'secret'))['reason']=='symbol_not_bound_at_origin'
    ctx=make_context(source,files);q=response(ctx);q['program_semantics']['evidence_refs']=['fake']
    with pytest.raises(ValueError,match='invented_evidence'):validate(q,ctx.case['id'],'extract',ctx.payload(),ctx.checks())


def test_safe_structure_kept_synthetic_literals_keys_comments_hidden():
    secret='SYNTHETIC_CREDENTIAL_12345678901234567890'
    code=f'''# {secret}
from pydantic import EmailStr
def emit(data: EmailStr):
    schema={{"type":"string","format":"email","description":"{secret}","{secret}":"x"}}
    logger.info("{secret}", data)
'''
    text,policy=safe_view(code,'app.py')
    assert secret not in text and 'EmailStr' in text and "'email'" in text and "'format'" in text
    assert 'description' not in text and not policy['is_verbatim']
    for path,code in [('x.ts',f'const value="{secret}"; console.log(value); // {secret}'),('schema.json',json.dumps({'format':'email','description':secret,secret:secret}))]:
        assert secret not in safe_view(code,path)[0]


def test_named_sanitizer_not_proof_and_program_rejects_full_value_len_claim():
    ctx=make_context('from helper import sanitize\ndef emit(data):\n    logger.info("v",sanitize(data))\n',{'helper.py':'def sanitize(data):\n    return data\n'})
    ctx.retrieve(request(ctx,'sanitize','function_binding'))
    assert ctx.checks()['sanitization']['status']=='unverified'
    ctx=make_context('def emit(data):\n    logger.info("v",len(data))\n',role='nested_expression_input')
    r=response(ctx);r['log_relation']['value']='direct_original';r['privacy_risk']['value']='static_candidate'
    accepted,rejected=gate(r,ctx.checks())
    assert accepted['log_relation']['value']=='derived_count' and accepted['privacy_risk']['value']=='undetermined'
    assert len(rejected)==2
    r=response(ctx);r['program_semantics']['value']='structural';r['sensitive_type'].update(value='non_sensitive',status='supported')
    accepted,rejected=gate(r,ctx.checks())
    assert accepted['sensitive_type']['value']=='unknown'
    assert any(x['reason']=='derived_output_does_not_establish_input_sensitivity' for x in rejected)


@pytest.mark.parametrize('path,source',[
    ('app.ts','function emit(data: string){ const value=data; console.log(value); }'),
    ('app.go','package main\nfunc emit(data string) { value := data; log.Printf("%s",value) }'),
    ('app.js','function emit(data) { const value=data; console.log(value); }')])
def test_demand_multilanguage_anchors_and_same_scope(path,source):
    from agentlog_unified.semantic_ast import Syntax,use_sites as tree_sites
    syntax=Syntax(path,source);call=next(n for n in syntax.nodes if n.type=='call_expression')
    text=syntax.text(call);site=tree_sites({'path':path,'start_line':call.start_point.row+1,'end_line':call.end_point.row+1,'statement':text},source)[0][0]
    result={'id':'multilang','repository':'fixture/repo','sha':'a'*40,'path':path,'scope':syntax.scope(call),'field':site['field'],
            'use_anchor':site['anchor'],'output_expression_anchor':site.get('output_expression_anchor'),'use_role':site['field_origin']}
    case={'id':'multilang','result':result,'log_start_line':call.start_point.row+1,'log_end_line':call.end_point.row+1,'log_statement_sha256':digest(text)}
    ctx=HistoricalContext(case,{'sha':'a'*40,'files':{path:source}});assert ctx.initial()['status']=='success'
    assert ctx.checks()['anchor_validity']=='valid'
    assert ctx.checks()['runtime_validity']=='not_run'
    bad=deepcopy(case);bad['log_statement_sha256']='forged'
    assert HistoricalContext(bad,{'sha':'a'*40,'files':{path:source}}).initial()['status']=='log_anchor_mismatch'


def test_relative_ts_binding_and_nested_call_log_anchor():
    from agentlog_unified.semantic_ast import Syntax,use_sites as tree_sites
    source='import { relay as helper } from "./helper.js";\nfunction emit(data:string){ console.log(`${helper(data)}`); }'
    s=Syntax('app.ts',source);call=next(n for n in s.nodes if n.type=='call_expression')
    site=tree_sites({'path':'app.ts','start_line':2,'end_line':2,'statement':s.text(call)},source)[0][0]
    r={'repository':'fixture/repo','sha':'a'*40,'path':'app.ts','scope':'emit','field':site['field'],'use_anchor':site['anchor']}
    case={'id':'nested-ts','result':r,'log_start_line':2,'log_end_line':2,'log_statement_sha256':digest(s.text(call))}
    ctx=HistoricalContext(case,{'sha':'a'*40,'files':{'app.ts':source,'helper.ts':'export function relay(value:string){ return value; }'}})
    assert ctx.initial()['status']=='success'
    q=request(ctx,'helper','function_binding');answer=ctx.retrieve(q)
    assert answer['status']=='success'
    assert ctx.blocks[-1]['anchor']['path']=='helper.ts'
    assert ctx.checks()['supported_flow_validity']=='unresolved' # definition retrieval is not interprocedural proof
    py=make_context('from typing import TypeVar\nT=TypeVar("T")\ndef emit(data:T):\n    logger.info("v",data)\n')
    assert py.retrieve(request(py,'T'))['status']=='success'


def test_wrapper_argument_is_not_concrete_log_output():
    source='''import logging
logger=logging.getLogger(__name__)
def wrapper(data):
    logger.info("count",len(data))
def emit(payload):
    wrapper(payload)
'''
    call=next(n for n in ast.walk(ast.parse(source)) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='wrapper')
    result={'repository':'fixture/repo','sha':'a'*40,'path':'app.py','scope':'emit','field':'payload','use_anchor':loc('app.py',call.args[0])}
    case={'id':'wrapper','result':result,'log_start_line':call.lineno,'log_end_line':call.end_lineno,'log_statement_sha256':digest(ast.get_source_segment(source,call))}
    ctx=HistoricalContext(case,{'sha':'a'*40,'files':{'app.py':source}});ctx.initial();checks=ctx.checks()
    assert checks['log_relation']['value']=='possible'
    assert 'wrapper_argument_to_concrete_log_output_unresolved' in checks['gaps']
    proposed=response(ctx);proposed['log_relation']['value']='direct_original'
    accepted,rejected=gate(proposed,checks)
    assert accepted['log_relation']['value']=='possible' and rejected[0]['reason']=='wrapper_argument_is_not_verified_log_output'


def test_durable_budget_failures_timeout_exact_cache(tmp_path):
    calls=Calls(tmp_path/'budget.sqlite','protocol-only',3,2)
    def unavailable(*a,**kw): raise FileNotFoundError('fake executable')
    _,r=calls.call('a','test','prompt','mock',1,unavailable);assert r['status']=='failed'
    _,r=calls.call('a','test','prompt','mock',1,unavailable);assert r['cache_reused']
    def timeout(*a,**kw):raise subprocess.TimeoutExpired('mock',1)
    _,r=calls.call('a','test','different','mock',1,timeout);assert r['receipt']['reason']=='TimeoutExpired'
    assert calls.call('a','test','third','mock',1,timeout)[1]['status']=='budget_exhausted'
    calls.close();calls=Calls(tmp_path/'budget.sqlite','protocol-only',3,2)
    assert len(calls.rows())==2;calls.close()


def test_real_pydriller_history_deletion_rename_cross_file_versions_and_resume(tmp_path):
    repo=tmp_path/'repo';init(repo)
    src=HEADER+'from helper import relay\ndef emit(data):\n    value=relay(data)\n    logger.info("v",value)\n'
    first=commit(repo,{'app.py':src,'helper.py':'def relay(data):\n    return data\n'},'introduced')
    second=commit(repo,{'helper.py':'def relay(data):\n    return "SYNTHETIC_MASK"\n','latest.md':'Only latest docs'},'changed helper',actor='human',day=2)
    git(repo,'mv','app.py','renamed.py');third=commit(repo,{},'rename',day=3)
    tip=commit(repo,{'renamed.py':HEADER},'delete',day=4)
    mined=mine_repository(str(repo),tip,[first],max_commits=10)
    assert len(mined['selected_shas'])==4
    assert any(c['old_path']=='app.py' and c['new_path']=='renamed.py' for c in mined['changes'])
    assert all(c['diff_backend'].startswith('pydriller') for c in mined['changes'])
    old=snapshot_files(str(repo),first,extensions=['.py','.md']);new=snapshot_files(str(repo),second,extensions=['.py','.md'])
    assert old['revision_backend']=='pydriller.Git.get_commit' and 'latest.md' not in old['files'] and 'latest.md' in new['files']
    assert 'SYNTHETIC_MASK' not in old['files']['helper.py']
    input_path=tmp_path/'input.jsonl';input_path.write_text(json.dumps({'is_synthetic':True,'fixture_repository_id':'demand-fixture',
        'local_repo_path':str(repo),'initial_commit_shas':[first],'target_ref':tip})+'\n')
    config=load_config(Path(__file__).parents[1]/'config.example.yaml');config['semantics']={'max_fields':100,'ablations':False}
    run=tmp_path/'scan';report=scan_semantics(input_path,run,config)
    case=json.loads(next((run/'evidence').glob('*.json')).read_text());cid=case['id']
    options={'case_ids':[cid],'experiment_id':'protocol-only','budget_ledger':str(tmp_path/'calls.sqlite'),'model':'mock'}
    output=tmp_path/'demand'
    assert run_demand(run,output,options,dry_run=True)['model_calls']==0 and not output.exists()
    result=run_demand(run,output,options,offline=True); assert result['model_attempts_this_run']==0
    assert not (tmp_path/'calls.sqlite').exists()
    assert run_demand(run,output,options,offline=True,resume=True)['resumed_without_calls']
    with pytest.raises(ValueError,match='incompatible'):run_demand(run,output,{**options,'model':'different'},resume=True)
    def invalid(*a,**kw):return {'invalid':True},{'status':'mock_invalid_json_schema','usage':[]}
    result=run_demand(run,tmp_path/'invalid-model',options,offline=False,invoker=invalid)
    assert result['model_attempts_this_run']==1 and result['valid_responses_this_run']==0
    assert result['counts']['queues']['model_not_run_or_failed']==1
    protocol_calls=[]
    def scripted(text,model,timeout,**kw):
        # Protocol fixture only: no result here is a model experiment.
        payload=json.loads(text.rsplit('\n',1)[1]);e=payload['evidence'];stage=payload['stage']
        refs=[e['blocks'][0]['id']]
        def d(value):return {'status':'ambiguous','value':value,'meaning':'mock protocol only','evidence_refs':refs,'flow_step_refs':[],'gaps':[]}
        answer={'case_id':e['case_id'],'stage':stage,'dataset_metadata_semantics':'not_applicable_program_use',
            'program_semantics':d('unknown'),'sensitive_type':{**d('unknown'),'types':[]},'log_relation':d('unknown'),
            'privacy_risk':d('undetermined'),'context_requests':[],'counterevidence':[],'human_confirmed':False,'runtime_confirmed':False}
        if stage=='extract' and not any(b['anchor']['path']=='helper.py' for b in e['blocks']):
            origin=next(b for b in e['blocks'] if b['kind']=='enclosing_function')
            answer['context_requests']=[{'request_id':'mock-request','case_id':e['case_id'],'request_kind':'function_binding','symbol_or_field':'relay',
                'origin_anchor':origin['id'],'reason':'protocol fixture','expected_evidence':'function','priority':'high'}]
        protocol_calls.append(stage);return answer,{'status':'mock_protocol_fixture','usage':[]}
    options={**options,'budget_ledger':str(tmp_path/'protocol-calls.sqlite')}
    out=tmp_path/'protocol-loop';result=run_demand(run,out,options,offline=False,invoker=scripted)
    assert result['retrieval_status']['success']==1 and len(protocol_calls)==4
    assert result['global_attempts_used']==4
    assert run_demand(run,out,options,offline=False,resume=True,invoker=scripted)['resumed_without_calls']
    assert len(protocol_calls)==4
