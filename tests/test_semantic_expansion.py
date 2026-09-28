import ast
from copy import deepcopy
import json

import pytest

from agentlog_unified.semantic_evidence import analyze_use, classify, loc, review
from agentlog_unified.semantic_ast import Syntax, review as ast_review, use_sites, view
from agentlog_unified.semantic_bindings import schema_meanings


def python_use(source,files=None,**kwargs):
    call=next(n for n in ast.walk(ast.parse(source)) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='info')
    return analyze_use({'app.py':source,**(files or {})},'fixture/repo','a'*40,'app.py',loc('app.py',call.args[-1]),**kwargs)


def test_schema_ref_has_exact_code_binding_and_separate_contract_status():
    source='''from jsonschema import validate
def emit(payload):
    validate(payload, {"$ref":"schema.json#/$defs/record"})
    logger.info("value", payload["value"])
'''
    schema={'$defs':{'record':{'type':'object','properties':{'value':{'type':'string','format':'email'},'active':{'type':'boolean'}}}}}
    files={'schema.json':json.dumps(schema)}
    result=python_use(source,files)
    assert result['review']['status']=='ambiguous',result
    assert classify(result)['possible_types_pending_review']==[{'category':'PII','subtype':'email'}]
    assert 'schema_reference_base_unverified' in result['review']['reasons']
    inline=source.replace('{"$ref":"schema.json#/$defs/record"}',repr(schema['$defs']['record']))
    assert classify(python_use(inline))['types']==[{'category':'PII','subtype':'email'}]
    assert result['proof']['binding']['contract_status']=='declared_only_not_runtime_validated'
    assert python_use(source, {})['review']['status']=='ambiguous'
    changed=deepcopy(files);changed['schema.json']=json.dumps({'$defs':{'record':{'properties':{'value':{'type':'boolean'}}}}})
    assert review({'app.py':source,**changed},'fixture/repo','a'*40,result['proof'])['status']=='unsupported'
    assert not classify(python_use(source.replace('validate(payload,','validate(other,'),files))['types']


def test_schema_reassignment_shadowing_and_local_cycle():
    source='''from jsonschema import validate
def emit(data):
    validate(data, {"format":"email"})
    data = external()
    logger.info("value", data)
'''
    assert not classify(python_use(source))['types']
    assert schema_meanings({'$ref':'#'}, {}, 'schema.json')['gaps']==['schema_reference_cycle']
    assert schema_meanings({'$ref':'https://invalid.example/schema'}, {}, 'schema.json')['gaps']
    assert not schema_meanings({'type':'string'}, {}, 'schema.json')['meanings']


def test_attached_document_retains_staleness_uncertainty():
    source='''def emit(data):
    """:param data: Opaque shipment scheduling reference."""
    logger.info("value", data)
'''
    result=python_use(source)
    assert result['review']['status']=='ambiguous'
    assert result['proposal'][0]['meaning']=='documented_parameter:data'
    assert not classify(result)['types']


def test_bounded_multi_hop_await_constant_key_and_static_replacement():
    source='''from pydantic import EmailStr
from helpers import relay
async def emit(data:EmailStr):
    payload={"v":await relay(data)}
    key="v"
    logger.info("value",payload[key])
'''
    helpers='from other import identity\nasync def relay(value):\n    return identity(value)\n'
    files={'helpers.py':helpers,'other.py':'def identity(value):\n    return value\n'}
    result=python_use(source,files,max_hops=3)
    assert result['review']['status']=='supported',result['review']
    assert classify(result)['types']==[{'category':'PII','subtype':'email'}]
    assert python_use(source,files,max_hops=1)['review']['status']=='ambiguous'
    masked=python_use('from helpers import mask\ndef emit(data):\n    logger.info("value",mask(data))\n',{'helpers.py':'def mask(value):\n    return "FIXTURE_MASK"\n'})
    assert masked['transformation']['status']=='verified_static_input_independent_output'
    assert not masked['transformation']['runtime_verified']


@pytest.mark.parametrize('path,source',[
    ('app.ts','type Email = string;\ninterface Account { value: Email; active: boolean; }\nfunction emit(data: Account) { const value=data.value; console.log("v",value); }'),
    ('app.go','package main\ntype Email string\ntype Account struct { Value Email; Active bool }\nfunc emit(data Account) { value := data.Value; log.Printf("%v",value) }'),
    ('app.js','function emit(data) { const value=true; console.log("v",value); }'),
])
def test_multilanguage_ast_bindings_and_tamper(path,source):
    syntax=Syntax(path,source);call=next(n for n in syntax.nodes if n.type=='call_expression')
    entity={'path':path,'start_line':call.start_point.row+1,'end_line':call.end_point.row+1,'statement':syntax.text(call)}
    sites,gaps=use_sites(entity,source)
    assert len(sites)==1 and sites[0]['anchor']['parser']=='tree_sitter'
    result=analyze_use({path:source},'fixture/repo','a'*40,path,sites[0]['anchor'])
    assert result['review']['status']=='supported',result['review']
    assert not classify(result)['types']  # local spelling Email is not a library contract
    forged=deepcopy(result['proof']);forged['sha']='b'*40
    assert ast_review({path:source},'fixture/repo','a'*40,forged)['status']=='unsupported'
    assert 'FIXTURE_SECRET' not in view('console.log("FIXTURE_SECRET",data)',path)


def test_tree_sitter_same_name_other_function_is_unknown():
    source='function first(){ const value=true; }\nfunction second(value){ console.log("v",value); }'
    s=Syntax('app.js',source);arg=[n for n in s.nodes if n.type=='identifier' and s.text(n)=='value'][-1]
    result=analyze_use({'app.js':source},'fixture/repo','a'*40,'app.js',s.anchor(arg))
    assert result['review']['status']=='ambiguous'


def test_explicit_field_metadata_and_mutated_tree_binding():
    source='''from pydantic import Field
class Account:
    value:str=Field(json_schema_extra={"format":"email"})
def emit(data:Account):
    logger.info("value",data.value)
'''
    assert classify(python_use(source))['types']==[{'category':'PII','subtype':'email'}]
    for statement in ('if (flag) { value=false; }','value++;','change(value);'):
        source='function emit(flag){ let value=true; '+statement+' console.log(value); }'
        s=Syntax('app.js',source);arg=[n for n in s.nodes if n.type=='identifier' and s.text(n)=='value'][-1]
        assert analyze_use({'app.js':source},'fixture/repo','a'*40,'app.js',s.anchor(arg))['review']['status']=='ambiguous'


def test_template_expression_is_not_excluded_as_fixed_message():
    source='function emit(value){ console.warn(`failure ${value instanceof Error ? value.message : String(value)}`); }'
    s=Syntax('app.ts',source);call=next(n for n in s.nodes if n.type=='call_expression')
    sites,_=use_sites({'path':'app.ts','statement':s.text(call),'start_line':1,'end_line':1},source)
    assert sites[0]['anchor']['node_kind']=='ternary_expression'
    assert any(s['field']=='value' and s['field_origin']=='nested_expression_input' for s in sites)
    assert 'value.message' in view(source,'app.ts')


def test_human_coding_is_explicit_atomic_and_separate_from_models(tmp_path):
    from agentlog_unified.semantic_review import coding
    from agentlog_unified.config import sha256_file
    run=tmp_path/'run';(run/'evidence').mkdir(parents=True)
    for i,split in [('dev','category_development'),('eval','evaluation_pending_human')]:
        (run/'evidence'/(i+'.json')).write_text(json.dumps({'id':i,'result':{'split':split}}))
    (run/'manifest.json').write_text(json.dumps({'status':'complete','artifact_sha256':{str(p.relative_to(run)):sha256_file(p) for p in (run/'evidence').glob('*')}}))
    out=tmp_path/'coding';assert coding(run,out)['human_annotations']==0
    assert not (tmp_path/'dry').exists()
    row={'case_id':'dev','origin':'human','kind':'annotation','status':'submitted','evidence_sha256':sha256_file(run/'evidence/dev.json'),
         **{axis:'correct' for axis in ('semantic_correct','type_correct','log_link_correct','privacy_risk_correct')}}
    file=tmp_path/'annotations.jsonl';file.write_text(json.dumps(row)+'\n')
    assert coding(run,out,file=file,reviewer='synthetic-test-reviewer',resume=True)['human_annotations']==1
    assert coding(run,out,file=file,reviewer='synthetic-test-reviewer',resume=True)['new_records']==0
    file.write_text(json.dumps({**row,'origin':'model'})+'\n')
    with pytest.raises(ValueError):coding(run,out,file=file,reviewer='test',resume=True)
    proposal={'kind':'category_proposal','status':'submitted','origin':'human','case_ids':['eval'],
              'action':'split','categories':['old','new'],'rationale':'synthetic test only'}
    file.write_text(json.dumps(proposal)+'\n')
    with pytest.raises(ValueError):coding(run,out,file=file,reviewer='test',resume=True)
    assert coding(run,out,resume=True)['human_annotations']==1


def test_model_response_gate_and_offline_never_invoke(tmp_path,monkeypatch):
    from agentlog_unified import semantic_model as model
    monkeypatch.setattr(model,'invoke',lambda *a,**k:pytest.fail('offline model call'))
    assert model.run_models(tmp_path/'missing',tmp_path/'out',offline=True)['model_calls']==0
    assert model.run_models(tmp_path/'missing',tmp_path/'out',dry_run=True)['model_calls']==0
    assert not (tmp_path/'out').exists()
    response={'case_id':'case','stage':'review','status':'supported','meanings':[{'meaning':'declared','category':None,'subtype':None,'evidence_refs':['a']}],
              'evidence_refs':['a'],'reason':'synthetic protocol test','log_association':'unknown','privacy_risk':'undetermined',
              'human_confirmed':False,'runtime_confirmed':False}
    assert model.validate_response(response,'case','review',{'a'})==response
    with pytest.raises(ValueError):model.validate_response(response,'case','review',{'other'})
    response['human_confirmed']=True
    import jsonschema
    with pytest.raises(jsonschema.ValidationError):model.validate_response(response,'case','review',{'a'})


def test_scope_imports_schema_mutation_and_nominal_constructor_boundaries():
    source='''def unrelated():
    from pydantic import EmailStr
def emit(data:EmailStr):
    logger.info("value",data)
'''
    assert not classify(python_use(source))['types']
    mutated='''from jsonschema import validate
SCHEMA={"format":"email"}
def emit(data):
    SCHEMA["format"]="unknown"
    validate(data,SCHEMA)
    logger.info("value",data)
'''
    assert not classify(python_use(mutated))['types']
    source='''class Record:
    value:str
def emit():
    data=Record()
    logger.info("value",data)
'''
    result=python_use(source)
    assert classify(result)['queue']=='known_semantics_unmapped'
    assert result['review']['derived_meanings'][0]['interpretation_level']=='nominal_constructor_not_field_contents'
    assert python_use(source.replace('def emit():','def emit(Record):'))['review']['status']=='ambiguous'
