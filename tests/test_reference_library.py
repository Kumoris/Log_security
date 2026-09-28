"""Small source-bound checks: no inherited field gold or lost array input."""
from copy import deepcopy

import pytest

from agentlog_unified.reference_library import (apply_answers, evidence_digest, group_references,
    make_case, norm, sites_for_call, target_call)


def example():
    source='void emit(Config configuration) { log.info("x", new Object[]{configuration.getPassword(), count}); }'
    target='log.info("x", new Object[]{configuration.getPassword(), count});'
    syntax,call=target_call(source,target+' unrelated();','Demo.java')
    entity={'path':'Demo.java','statement':syntax.text(call),'start_line':1,'end_line':1}
    sites,gaps=sites_for_call(entity,source)
    site=next(s for s in sites if s['field']=='configuration.getPassword()')
    case=make_case('fixture/repo',None,'Demo.java',source,entity,site,
                   {'fix_commit_sha':'a'*40},['defects4log:0'])
    return case,sites


def test_array_and_scope_preserve_unknown_until_explicit_field_answer():
    case,sites=example()
    assert case['result']['use_role']=='array_log_element'
    assert any(s['field']=='count' for s in sites)
    rows,checks=apply_answers({case['id']:case},[])
    assert rows[0]['semantic_status']=='unknown'
    assert rows[0]['sensitive_types']==[] and rows[0]['human_confirmed'] is False
    assert checks[0]['semantic_correctness_verified'] is False
    decision={'case_id':case['id'],'evidence_sha256':evidence_digest(case),'origin':'assistant_source_adjudication',
        'human_confirmed':False,'status':'submitted','semantic_status':'supported','meaning':'该配置的密码读取值',
        'type_status':'known','sensitive_types':[{'concept':'password'}],
        'log_relation':'direct','privacy_risk':'static_candidate','evidence_refs':['use','log','context:0'],
        'evidence_guards':[{'ref':'context:0','contains':'Config configuration'}]}
    rows,_=apply_answers({case['id']:case},[decision])
    assert rows[0]['type_status']=='known' and rows[0]['semantic_gold_eligible'] is False
    for key,value in [('human_confirmed',True),('evidence_sha256','bad'),('evidence_refs',['missing']),
                      ('evidence_guards',[{'ref':'context:0','contains':'Invented field definition'}])]:
        bad=deepcopy(decision);bad[key]=value
        with pytest.raises(ValueError):apply_answers({case['id']:case},[bad])


def test_source_families_not_independent_and_literal_spaces_not_ignored():
    refs=[{'id':'issue:K-1','issue_keys':['K-1']},
          {'id':'d:1','issue_keys':['K-1','Z-2'],'commit_sha':'a'},
          {'id':'issue:Z-2','issue_keys':['Z-2']},
          {'id':'d:2','issue_keys':[],'commit_sha':'a'},
          {'id':'unrelated','issue_keys':[]}]
    group_references(refs)
    assert len({r['split_group'] for r in refs[:4]})==1
    assert refs[4]['split_group']!=refs[0]['split_group']
    assert norm('log.info("a b", x)')!=norm('log.info("ab",x)')
    assert norm('log.info("a b", x)')==norm('log.info( "a b",x )')
    with pytest.raises(ValueError):target_call('void f(){ log.info("ab",x); }','log.info("a b",x);','X.java')
