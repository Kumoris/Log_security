"""Bounded data-origin checks; fixtures never execute application source."""
import json
from pathlib import Path
from xml.etree import ElementTree

import pytest

from agentlog_unified.config import load_config
from agentlog_unified.semantic_context import HistoricalContext
from agentlog_unified.semantic_dfg import build_graph, export_dfg, svg
from agentlog_unified.semantic_evidence import digest
from agentlog_unified.semantic_scan import scan_semantics, use_sites
from agentlog_unified.semantic_ast import Syntax
from synthetic_histories import init, commit, git, HEADER
from test_semantic_demand import make_context


def test_cross_file_actual_formal_return_and_versioned_identity():
    source='from helper import identity\ndef emit(data):\n    value=identity(data)\n    logger.info(value)\n'
    files={'helper.py':'def identity(payload):\n    return payload\n'}
    graph=build_graph(make_context(source,files))
    assert graph['origin_counts']=={'function_parameter':1}
    assert {'actual_to_formal','return_value','call_return','assignment'} <= {e['kind'] for e in graph['edges']}
    assert len(graph['functions'])==2
    assert all(f['parameter_anchors'] for f in graph['functions'])
    assert {n['sha'] for n in graph['nodes']}=={'a'*40}
    new=build_graph(make_context(source,files,sha='b'*40))
    assert {f['id'] for f in graph['functions']}.isdisjoint(f['id'] for f in new['functions'])
    assert not graph['complete_external_origin'] and not graph['sensitivity_verdict_changed']
    ElementTree.fromstring(svg(graph))


def test_scope_shadowing_and_unknown_dynamic_write():
    source='def first(value):\n    logger.info(value)\ndef second(value):\n    value=True\n    logger.info(value)\n'
    first=build_graph(make_context(source,index=0));second=build_graph(make_context(source,index=1))
    assert first['origin_counts']=={'function_parameter':1}
    assert second['origin_counts']=={'constant':1}
    mutated='def emit(value,flag):\n    if flag:\n        value=other()\n    logger.info(value)\n'
    g=build_graph(make_context(mutated))
    assert g['origin_counts'].get('unknown') and not g['origin_counts'].get('function_parameter')


def test_field_slice_does_not_treat_unselected_object_member_as_source():
    source='def emit(secret):\n    payload={"safe":True,"private":secret}\n    logger.info(payload["safe"])\n'
    graph=build_graph(make_context(source))
    assert graph['origin_counts']=={'constant':1}
    assert graph['pruned_object_branches']==1
    assert all(n['kind']!='parameter_input' for n in graph['nodes'])


def test_fixed_helper_return_has_no_actual_argument_flow():
    source='from helper import mask\ndef emit(data):\n    logger.info(mask(data))\n'
    graph=build_graph(make_context(source,{'helper.py':'def mask(value):\n    return "PRIVATE_FIXTURE_LITERAL"\n'}))
    assert graph['origin_counts']=={'constant':1}
    assert not any(e['kind']=='actual_to_formal' for e in graph['edges'])
    assert 'PRIVATE_FIXTURE_LITERAL' not in json.dumps(graph)
    assert graph['input_independent_output']['input_independent'] is True
    assert graph['runtime_verified'] is False


def test_type_evidence_and_external_call_dependencies_are_not_value_origins():
    typed='from pydantic import EmailStr\ndef emit(data:EmailStr):\n    logger.info(data)\n'
    graph=build_graph(make_context(typed))
    assert graph['origin_counts']=={'function_parameter':1}
    assert any(e['kind']=='metadata' and e['carries_value'] is False for e in graph['edges'])
    unknown=build_graph(make_context('def emit(payload):\n    logger.info(external(payload))\n'))
    assert unknown['origin_counts']=={'unknown':1}
    assert all(not e['carries_value'] for e in unknown['edges'] if e['kind']=='call_argument_dependency')
    assert unknown['complete_external_origin'] is False
    missing=build_graph(make_context('def emit():\n    logger.info(missing_value)\n'))
    assert missing['origin_counts']=={'unknown':1}


def test_java_generic_parameter_has_structural_origin_without_sensitive_label():
    source='class App { void other(Object value){} void emit(Object value) { logger.info("FIXTURE",value); } }'
    syntax=Syntax('App.java',source);call=next(n for n in syntax.nodes if n.type=='method_invocation')
    statement=syntax.text(call);entity={'path':'App.java','statement':statement,'start_line':1,'end_line':1}
    site=use_sites(entity,{'App.java':source})[0][0]
    result={'id':'java','repository':'fixture/java','sha':'a'*40,'path':'App.java','field':'value','scope':'emit',
        'use_anchor':site['anchor'],'use_role':site['field_origin'],'language':'java'}
    case={'id':'java','result':result,'log_start_line':1,'log_end_line':1,'log_statement_sha256':digest(statement)}
    graph=build_graph(HistoricalContext(case,{'files':{'App.java':source},'sha':'a'*40}))
    assert graph['origin_counts']=={'function_parameter':1}
    assert graph['semantic_review_status']=='ambiguous'
    assert not graph['sensitivity_verdict_changed']
    bounded=build_graph(HistoricalContext(case,{'files':{'App.java':source},'sha':'a'*40}),max_nodes=1)
    assert 'graph_node_budget_exceeded' in bounded['gaps']
    assert len(bounded['nodes'])<=2
    with pytest.raises(ValueError,match='snapshot_sha_mismatch'):
        HistoricalContext(case,{'files':{'App.java':source},'sha':'b'*40})


def test_real_pydriller_history_then_offline_dfg_resume_and_hash_checks(tmp_path):
    repo=tmp_path/'repo';init(repo)
    source=HEADER+'from helper import relay\ndef emit(data):\n    value=relay(data)\n    logger.info(value)\ndef entry(payload):\n    emit(payload)\nentry(False)\n'
    initial=commit(repo,{'app.py':source,'helper.py':'def relay(payload):\n    return payload\n'},'synthetic original')
    commit(repo,{'helper.py':'def relay(payload):\n    return "FIXTURE_MASK"\n'},'synthetic cross-file masking',actor='human',day=3)
    git(repo,'mv','app.py','renamed.py');commit(repo,{},'synthetic rename',actor='unknown',day=4)
    tip=commit(repo,{'renamed.py':HEADER+'def emit(data):\n    pass\n'},'synthetic log deletion',actor='agent',day=5)
    inp=tmp_path/'input.jsonl';inp.write_text(json.dumps({'is_synthetic':True,'fixture_repository_id':'dfg-fixture',
        'local_repo_path':str(repo),'initial_commit_shas':[initial],'target_ref':tip})+'\n')
    cfg=load_config(Path(__file__).parents[1]/'config.example.yaml');cfg['semantics'].update(max_fields=100,ablations=False)
    scan=tmp_path/'scan';coverage=scan_semantics(inp,scan,cfg)
    assert coverage['metrics']['pydriller_commits']==4
    assert coverage['metrics']['pydriller_diff_parsed_calls']>0
    assert coverage['metrics']['pydriller_source_reads']>0
    out=tmp_path/'dfg'
    assert export_dfg(scan,out,dry_run=True)['files_written'] is False
    assert not out.exists()
    report=export_dfg(scan,out,max_cases=100)
    assert report['graphs']>0 and report['unresolved_cases']==0
    assert report['resolved_caller_bindings']>0
    graphs=[json.loads(p.read_text()) for p in (out/'graphs').glob('*.json')]
    assert any(g['origin_counts'].get('constant') for g in graphs)
    assert any(g['origin_counts'].get('function_parameter') for g in graphs)
    assert any(g['side']=='before' for g in graphs)
    assert export_dfg(scan,out,max_cases=100,resume=True)['resumed_without_reprocessing']
    next((out/'graphs').glob('*.json')).write_text('{}')
    with pytest.raises(ValueError,match='integrity_mismatch'):export_dfg(scan,out,max_cases=100,resume=True)
