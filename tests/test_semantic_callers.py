"""Caller edges must identify a historical binding, not just a matching name."""
import json

import pytest

from agentlog_unified.semantic_ast import Syntax
from agentlog_unified.semantic_context import HistoricalContext
from agentlog_unified.semantic_dfg import build_graph
from agentlog_unified.semantic_evidence import digest
from agentlog_unified.semantic_scan import use_sites
from test_semantic_demand import make_context


def tree_context(path, source, files=None):
    syntax = Syntax(path, source)
    call = next(n for n in syntax.nodes if n.type in {'call_expression', 'method_invocation'}
                and syntax.text(n).startswith('logger.info('))
    statement = syntax.text(call)
    entity = {'path': path, 'statement': statement, 'start_line': call.start_point.row+1,
              'end_line': call.end_point.row+1}
    site = use_sites(entity, {path: source})[0][0]
    row = {'id': 'fixture', 'repository': 'fixture/repo', 'sha': 'a'*40, 'path': path,
           'scope': 'emit', 'field': site['field'], 'use_anchor': site['anchor'],
           'use_role': site['field_origin'], 'language': syntax.language}
    case = {'id': 'fixture', 'result': row, 'log_start_line': entity['start_line'],
            'log_end_line': entity['end_line'], 'log_statement_sha256': digest(statement)}
    return HistoricalContext(case, {'sha': 'a'*40, 'files': {path: source, **(files or {})}})


def test_python_alias_import_and_independent_argument_review():
    source = 'def emit(data):\n    logger.info(data)\n'
    caller = ('from app import emit as record\nfrom pydantic import EmailStr\n'
              'def entry(address: EmailStr):\n    payload=address\n    record(payload)\n')
    ctx = make_context(source, {'entry.py': caller})
    baseline = build_graph(ctx, max_caller_hops=0)
    graph = build_graph(ctx)
    assert not baseline['caller_evidence']
    evidence = graph['caller_evidence'][0]
    assert evidence['resolution'] == 'explicit_import_static_target'
    assert evidence['actual_argument_semantics']['status'] == 'supported'
    assert any(m['subtype'] == 'email' for m in evidence['actual_argument_semantics']['derived_meanings'])
    assert evidence['log_type_inference'] == 'not_performed'
    assert not graph['sensitivity_verdict_changed']


@pytest.mark.parametrize('call,kind', [('emit(data=True)', 'keyword'), ('emit()', 'default')])
def test_keyword_and_default_binding(call, kind):
    g = build_graph(make_context('def emit(data=False):\n    logger.info(data)\n'+call+'\n'))
    assert g['caller_evidence'][0]['binding_kind'] == kind
    assert g['origin_counts'].get('constant') == 1


@pytest.mark.parametrize('tail', [
    'def entry(emit):\n    emit(True)\n',
    'def entry():\n    def emit(x): pass\n    emit(True)\n',
    'def entry():\n    emit(True)\n    emit=other\n',
    'emit(*items)\n', 'emit(**items)\n', 'emit(True,False)\n',
    'def emit(data): pass\nemit(True)\n',
])
def test_shadowing_duplicate_or_unpack_is_not_a_caller(tail):
    g = build_graph(make_context('def emit(data):\n    logger.info(data)\n'+tail))
    assert not g['caller_evidence']


def test_multiple_callers_depth_cycle_and_literal_redaction():
    source = ('def emit(data):\n    logger.info(data)\n'
              'def relay(payload):\n    emit(payload)\n'
              'relay("NEVER_EXPORT_LITERAL")\nemit(False)\n')
    shallow = build_graph(make_context(source), max_caller_hops=1)
    deep = build_graph(make_context(source), max_caller_hops=2)
    assert len(shallow['caller_evidence']) == 2
    assert len(deep['caller_evidence']) == 3
    assert 'NEVER_EXPORT_LITERAL' not in json.dumps(deep)
    recursive = build_graph(make_context('def emit(data):\n    logger.info(data)\n    emit(data)\n'))
    assert 'recursive_caller_boundary' in recursive['gaps']


def test_caller_budget_and_historical_per_file_provenance():
    ctx = make_context('def emit(data):\n    logger.info(data)\n'+'emit(True)\n'*12)
    ctx.snapshot['fallback_reason'] = 'whole_tree_auxiliary'
    ctx.snapshot['file_provenance'] = {'app.py': {'backend': 'pydriller.ModifiedFile.source_code', 'fallback_reason': None}}
    g = build_graph(ctx)
    assert len(g['caller_evidence']) == 8
    assert 'caller_callsite_budget_exceeded' in g['gaps']
    assert all(e['callsite_evidence']['fallback_reason'] is None for e in g['caller_evidence'])
    assert all(e['callsite_evidence']['sha'] == 'a'*40 for e in g['caller_evidence'])


def test_javascript_nested_function_and_later_lexical_shadow_are_unresolved():
    for tail in ['function entry(){function emit(x){}; emit(true);}',
                 'function entry(){emit(true);let emit=other;}']:
        source = 'function emit(data){logger.info(data);}\n'+tail
        assert not build_graph(tree_context('app.js',source))['caller_evidence']


@pytest.mark.parametrize('path,source', [
    ('app.js', 'function emit(data) { logger.info(data); }\nemit(true);'),
    ('app.ts', 'function emit(data: boolean) { logger.info(data); }\nemit(true);'),
    ('app.go', 'package app\nfunc emit(data bool) { logger.info(data) }\nfunc entry() { emit(true) }'),
    ('App.java', 'class App { private void emit(Object data) { logger.info(data); } void entry(){emit(true);} }'),
])
def test_tree_language_direct_callers(path, source):
    graph = build_graph(tree_context(path, source))
    assert len(graph['caller_evidence']) == 1
    assert graph['origin_counts'].get('constant') == 1


@pytest.mark.parametrize('source', [
    'class App { void emit(Object data){logger.info(data);} void entry(){emit(true);} }',
    'class App { private void emit(Object data){logger.info(data);} private void emit(boolean data){} void entry(){emit(true);} }',
    'class App { private void emit(Object data){logger.info(data);} void entry(App other){other.emit(true);} }',
])
def test_java_dispatch_or_overload_not_guessed(source):
    assert not build_graph(tree_context('App.java', source))['caller_evidence']


def test_go_grouped_parameters_and_same_package_other_file():
    source = 'package app\nfunc emit(safe, data bool) { logger.info(data) }'
    g = build_graph(tree_context('app.go', source, {'caller.go': 'package app\nfunc entry(){emit(false,true)}'}))
    assert len(g['caller_evidence']) == 1
    assert g['caller_evidence'][0]['actual_anchor']['path'] == 'caller.go'


def test_projection_does_not_promote_other_member_sensitive_type():
    g = build_graph(make_context('def emit(data):\n    logger.info(data["safe"])\n'
                                'def entry(secret):\n    emit({"safe":True,"private":secret})\n'))
    assert g['caller_evidence'][0]['projection_applied']
    assert g['origin_counts'].get('constant') == 1
    assert not any(n['kind'] == 'parameter_input' and n['anchor']['line'] == 3 for n in g['nodes'])
