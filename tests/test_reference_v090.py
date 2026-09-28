import json
from pathlib import Path

import pytest

from agentlog_unified.config import sha256_file
from agentlog_unified.issue_reference import run_references,validate_selection
from agentlog_unified.semantic_ast import Syntax,view
from agentlog_unified.semantic_evidence import analyze_use
from agentlog_unified.semantic_review import blind_case,coding
from agentlog_unified.semantic_scan import use_sites
from agentlog_unified.semantic_scan import scan_semantics
from agentlog_unified.config import load_config
from agentlog_unified.semantic_demand import run_demand
from synthetic_histories import commit,init


def test_issue_pair_uses_real_pydriller_and_resumes_offline(tmp_path):
    cache=tmp_path/'cache';cache.mkdir();repo=cache/'fixture--repo';init(repo)
    commit(repo,{'app.py':'import logging\ndef emit(value):\n    logging.info(value)\n'},'synthetic initial')
    sha=commit(repo,{'app.py':'import logging\ndef emit(value):\n    logging.info("WITHHELD")\n'},'FIXTURE-1 synthetic removal',actor='human',day=2)
    source=tmp_path/'source';(source/'private').mkdir(parents=True)
    snapshot={'issue':'FIXTURE-1','complete':True,'issue_payload':{'fields':{'description':'Synthetic commit '+sha}},'comments':[]}
    (source/'private/FIXTURE-1.json').write_text(json.dumps(snapshot))
    selection=tmp_path/'selection.jsonl';selection.write_text(json.dumps({'issue':'FIXTURE-1','repository':'fixture/repo','commit_sha':sha})+'\n')
    out=tmp_path/'out'
    assert run_references(selection,source,out,cache,dry_run=True)['files_written'] is False
    assert not out.exists()
    result=run_references(selection,source,out,cache)
    assert result['counts']=={'code_pair_extracted':1}
    assert result['pydriller_commits']==1
    mined=json.loads((out/'private/FIXTURE-1.mined.json').read_text())
    assert mined['metrics']['pydriller_diff_parsed_calls']>0
    assert mined['metrics']['pydriller_source_reads']>=2
    assert mined['changes'][0]['before_source']!=mined['changes'][0]['after_source']
    assert run_references(selection,source,out,cache,resume=True)['new_attempts']==0
    (out/'private/FIXTURE-1.mined.json').write_text('{}')
    with pytest.raises(ValueError,match='integrity'):
        run_references(selection,source,out,cache,resume=True)
    with pytest.raises(ValueError):validate_selection({'issue':'../escape'},snapshot)
    # Previously exposed real-source material must never become a held-out set.
    scan_input=tmp_path/'scan.jsonl'
    scan_input.write_text(''.join(json.dumps({'repository':name,'pr_number':1,'local_repo_path':str(repo),
        'initial_commit_shas':[sha],'target_ref':sha,'is_synthetic':False})+'\n' for name in ('fixture/one','fixture/two')))
    cfg=load_config(Path(__file__).parents[1]/'config.example.yaml')
    cfg['semantics'].update(development_only=True,ablations=False)
    report=scan_semantics(scan_input,tmp_path/'scan',cfg)
    assert report['by_split']=={'category_development':2}
    assert report['repository_split_disjoint'] is False


def test_java_statement_alias_projection_and_scope_gap():
    source='class App { void first(){ boolean value=true; } void emit(Account data){ boolean value=false; logger.info("PRIVATE_LITERAL", value, data.value); } }'
    s=Syntax('App.java',source);call=next(n for n in s.nodes if n.type=='method_invocation')
    entity={'path':'App.java','statement':s.text(call),'start_line':1,'end_line':1}
    sites,gaps=use_sites(entity,{'App.java':source})
    assert not [g for g in gaps if g['reason']!='fixed_log_message_template']
    value=next(v for v in sites if v['field']=='value')
    result=analyze_use({'App.java':source},'fixture/repo','a'*40,'App.java',value['anchor'])
    assert result['review']['status']=='supported'
    assert result['review']['derived_meanings'][0]['supported_non_sensitive']
    projected=next(v for v in sites if v['field']=='data.value')
    assert analyze_use({'App.java':source},'fixture/repo','a'*40,'App.java',projected['anchor'])['review']['status']=='ambiguous'
    assert 'PRIVATE_LITERAL' not in view(source+' // ANOTHER_PRIVATE_LITERAL','App.java')
    multiline='/* PRIVATE\nCOMMENT */\n'+source
    assert view(multiline,'App.java').count('\n')==multiline.count('\n')
    changed=source.replace('boolean value=false;','')
    s2=Syntax('App.java',changed);arg=[n for n in s2.nodes if n.type=='identifier' and s2.text(n)=='value'][-2]
    assert analyze_use({'App.java':changed},'fixture/repo','a'*40,'App.java',s2.anchor(arg))['review']['status']=='ambiguous'


def test_blind_reference_is_independent_and_does_not_auto_confirm(tmp_path):
    case={'id':'dev','result':{'id':'dev','split':'category_development','sha':'a'*40,
          'path':'app.py','use_anchor':{'path':'app.py','line':2},'program_semantics':'MACHINE_ANSWER','privacy_risk':'MACHINE_ANSWER'},
          'proposal':['MACHINE_ANSWER'],'review':{'status':'MACHINE_ANSWER'},
          'log_statement_sha256':'b'*64,'log_statement_view':'log.info(value)',
          'source_versions':[{'path':'app.py','sha':'a'*40,'source_sha256':'c'*64}]}
    assert 'MACHINE_ANSWER' not in json.dumps(blind_case(case))
    run=tmp_path/'run';(run/'evidence').mkdir(parents=True);pack=run/'evidence/dev.json';pack.write_text(json.dumps(case))
    (run/'manifest.json').write_text(json.dumps({'status':'complete','artifact_sha256':{'evidence/dev.json':sha256_file(pack)}}))
    output=tmp_path/'coding';assert coding(run,output)['human_reference_annotations']==0
    template=[json.loads(l) for l in (output/'reference_template.jsonl').read_text().splitlines()]
    file=tmp_path/'filled.jsonl';row={**template[0],'status':'submitted','meaning':'Not enough contract evidence.',
         'semantic_status':'unknown','type_status':'unknown','log_relation':'direct','privacy_risk':'undetermined','evidence_refs':['use','log']}
    file.write_text(json.dumps(row)+'\n')
    assert coding(run,output,file=file,reviewer='synthetic-reviewer',resume=True)['human_reference_annotations']==1
    assert coding(run,output,file=file,reviewer='synthetic-reviewer',resume=True)['new_records']==0
    for patch in [{'origin':'model'},{'evidence_refs':['invented']},{'type_status':'non_sensitive','sensitive_types':[{'concept':'password'}]}]:
        file.write_text(json.dumps({**row,**patch})+'\n')
        with pytest.raises(ValueError):coding(run,output,file=file,reviewer='synthetic-reviewer',resume=True)
    file.write_text(json.dumps({**row,'meaning':'A different interpretation of this synthetic field.'})+'\n')
    report=coding(run,output,file=file,reviewer='synthetic-reviewer-2',resume=True)
    assert report['human_reference_annotations']==2
    assert report['unresolved_disagreements']==1


def test_new_experiment_budget_does_not_call_model_during_dry_run(tmp_path):
    options={'case_ids':['a'*24],'total_calls':300,'per_case_calls':6}
    assert run_demand(tmp_path/'unused',tmp_path/'out',options,dry_run=True)['model_calls']==0
    assert not (tmp_path/'out').exists()
    with pytest.raises(ValueError,match='invalid_budget:total_calls'):
        run_demand(tmp_path/'unused',tmp_path/'out',{**options,'total_calls':301},dry_run=True)
