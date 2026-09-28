"""Real-breakpoint shapes plus counterexamples; target source is never executed."""
import json
import pytest

from agentlog_unified.semantic_dfg import build_graph
from agentlog_unified.semantic_evidence import analyze_use
from test_semantic_callers import tree_context
from test_semantic_demand import make_context


def analyze(ctx):
    return analyze_use(ctx.files,ctx.result['repository'],ctx.sha,ctx.result['path'],ctx.result['use_anchor'])


@pytest.mark.parametrize('caller', [
    'Recorder().emit(True)',
    'r=Recorder()\ns=r\ns.emit(True)',
    'Recorder.emit(Recorder(),True)',
])
def test_python_constructed_method_receiver(caller):
    ctx=make_context('class Recorder:\n    def emit(self,data):\n        logger.info(data)\n'+caller+'\n')
    graph=build_graph(ctx)
    assert len(graph['caller_evidence'])==1
    assert graph['caller_evidence'][0]['resolution']=='python_ast_bound_method'
    assert graph['caller_evidence'][0]['status']=='possible'
    assert graph['origin_counts'].get('constant')==1


def test_declared_receiver_sensitive_argument_and_static_class_methods():
    source=('from pydantic import EmailStr\nclass Recorder:\n    def emit(self,data):\n        logger.info(data)\n'
            'def entry(rec: Recorder, address:EmailStr):\n    rec.emit(address)\n')
    g=build_graph(make_context(source))
    evidence=g['caller_evidence'][0]
    assert evidence['receiver_evidence']['kind']=='annotated_receiver_possible_subclass'
    assert evidence['actual_argument_semantics']['status']=='supported'
    for deco,param in [('staticmethod','data'),('classmethod','cls,data')]:
        s=f'class Recorder:\n    @{deco}\n    def emit({param}):\n        logger.info(data)\nRecorder.emit(data=True)\n'
        assert len(build_graph(make_context(s))['caller_evidence'])==1


@pytest.mark.parametrize('suffix', [
    'class Other:\n    def emit(self,data):pass\nOther().emit(True)\n',
    'def entry(Recorder):\n    Recorder().emit(True)\n',
    'r=Recorder()\nr.emit=other\nr.emit(True)\n',
    'r=Recorder()\nmutate(r)\nr.emit(True)\n',
    'Recorder().emit(self=other,data=True)\n',
])
def test_python_receiver_counterexamples(suffix):
    g=build_graph(make_context('class Recorder:\n    def emit(self,data):\n        logger.info(data)\n'+suffix))
    assert not g['caller_evidence']


def test_same_control_arm_is_not_an_uncertain_reaching_definition():
    ctx=make_context('def emit(flag):\n    if flag:\n        data=True\n        logger.info(data)\n')
    assert analyze(ctx)['review']['status']=='supported'
    assert build_graph(ctx)['origin_counts']=={'constant':1}
    assert build_graph(ctx)['control_context'][0]['arm']=='body'
    outside=make_context('def emit(flag,data):\n    if flag:\n        data=True\n    logger.info(data)\n')
    assert build_graph(outside)['origin_counts'].get('unknown')


def test_explicit_branch_join_keeps_both_sources_and_condition():
    ctx=make_context('def emit(flag,secret):\n    if flag:\n        data=secret\n    else:\n        data=True\n    logger.info(data)\n')
    g=build_graph(ctx)
    assert any(e['kind']=='branch_merge' and e['status']=='possible' for e in g['edges'])
    assert any(n['kind']=='branch_condition' for n in g['nodes'])
    assert g['origin_counts'].get('function_parameter')==1 and g['origin_counts'].get('constant')==1
    assert analyze(ctx)['review']['status']=='ambiguous'


def test_alias_write_is_visible_and_rebinding_does_not_pollute_original():
    source='def emit(secret):\n    data={"safe":True}\n    alias=data\n    alias["safe"]=secret\n    logger.info(data["safe"])\n'
    g=build_graph(make_context(source))
    assert g['origin_counts'].get('function_parameter')==1
    assert not g['origin_counts'].get('constant')
    rebound=source.replace('    alias["safe"]','    alias={}\n    alias["safe"]')
    assert build_graph(make_context(rebound))['origin_counts']=={'constant':1}
    escaped=source.replace('    alias["safe"]=secret','    external(alias)')
    assert build_graph(make_context(escaped))['origin_counts'].get('unknown')


def test_same_branch_object_write_and_sibling_branch_do_not_mix():
    ctx=make_context('def emit(flag):\n    data={}\n    if flag:\n        alias=data\n        alias["safe"]=True\n        logger.info(data["safe"])\n')
    assert build_graph(ctx)['origin_counts']=={'constant':1}
    assert analyze(ctx)['review']['status']=='supported'
    sibling=make_context('def emit(flag):\n    if flag:\n        data=True\n    else:\n        logger.info(data)\n')
    assert analyze(sibling)['review']['status']!='supported'


def test_typescript_same_branch_binding():
    g=build_graph(tree_context('app.ts','function emit(flag:boolean){if(flag){const data=true;logger.info(data);}}'))
    assert g['origin_counts']=={'constant':1}


def test_loop_carried_write_and_container_alias_stay_unknown():
    source='def emit(secret,items):\n    data={"safe":True}\n    for item in items:\n        logger.info(data["safe"])\n        data["safe"]=secret\n'
    assert build_graph(make_context(source))['origin_counts'].get('unknown')


def test_mutually_exclusive_write_does_not_block_elif_log():
    source='def emit(flag,other):\n    data={}\n    if flag:\n        data["safe"]=False\n    elif other:\n        data["safe"]=True\n        logger.info(data["safe"])\n'
    ctx=make_context(source)
    assert build_graph(ctx)['origin_counts']=={'constant':1}
    assert analyze(ctx)['review']['status']=='supported'
    source='def emit(secret):\n    data={"safe":True}\n    box=[data]\n    box[0]["safe"]=secret\n    logger.info(data["safe"])\n'
    assert build_graph(make_context(source))['origin_counts'].get('unknown')


def test_go_explicit_struct_cross_file_import_and_external_gap():
    files={'go.mod':'module example.test/app\n','types/model.go':'package types\ntype Record struct { Data string; Hidden struct { Other string } }\n'}
    source='package app\nimport "example.test/app/types"\nfunc emit(r types.Record){logger.info(r.Data)}'
    g=build_graph(tree_context('app.go',source,files))
    binding=g['field_bindings'][0]
    assert binding['status']=='bound' and binding['field_definition']['path']=='types/model.go'
    assert binding['field_type']=='string' and binding['sensitivity_inference']=='not_performed'
    assert any(e['kind']=='metadata' and not e['carries_value'] for e in g['edges'])
    nested=build_graph(tree_context('app.go',source.replace('r.Data','r.Other'),files))
    assert nested['field_bindings'][0]['status']=='unresolved'
    external=build_graph(tree_context('app.go','package app\nimport "net/http"\nfunc emit(r *http.Request){logger.info(r.RemoteAddr)}'))
    assert external['field_bindings'][0]['reason']=='go_external_or_unavailable_module_definition'


def test_go_receiver_struct_and_other_package_not_a_definition():
    source='package app\ntype Record struct { Data bool }\nfunc (r *Record) emit(){logger.info(r.Data)}'
    assert build_graph(tree_context('app.go',source))['field_bindings'][0]['status']=='bound'
    source='package app\nfunc emit(r Record){logger.info(r.Data)}'
    g=build_graph(tree_context('app.go',source,{'test.go':'package app_test\ntype Record struct { Data bool }\n'}))
    assert g['field_bindings'][0]['status']=='unresolved'
    imported=tree_context('app.go','package app\nimport "example.test/app/types"\nfunc emit(r types.Record){logger.info(r.Data)}',
        {'go.mod':'module example.test/app\n','types/model_test.go':'package types_test\ntype Record struct { Data bool }\n'})
    assert build_graph(imported)['field_bindings'][0]['status']=='unresolved'


def test_new_binding_shapes_from_actual_pydriller_history(tmp_path):
    from synthetic_histories import init,commit
    from agentlog_unified.miner import mine_repository
    repo=tmp_path/'repo';init(repo)
    before='class Recorder:\n    def emit(self,data):\n        logger.info(data)\nRecorder().emit(True)\n'
    first=commit(repo,{'app.py':before},'synthetic method receiver')
    after='def emit(secret,flag):\n    data={}\n    if flag:\n        alias=data\n        alias["safe"]=secret\n        logger.info(data["safe"])\n'
    second=commit(repo,{'app.py':after},'synthetic conditional alias write',actor='human',day=3)
    history=mine_repository(str(repo),second,[first])
    assert history['metrics']['pydriller_commits']==2 and history['metrics']['pydriller_diff_parsed_calls']>0
    change=next(c for c in history['changes'] if c['sha']==second)
    old=build_graph(make_context(change['before_source'],sha=first))
    new=build_graph(make_context(change['after_source'],sha=second))
    assert old['caller_evidence'] and new['origin_counts'].get('function_parameter')
    assert all(n['sha']==second for n in new['nodes'])
