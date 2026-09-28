"""Doc-derived rules are proposals; only user-asserted excerpt sensitivity is human."""
from copy import deepcopy
import json

import pytest

from agentlog_unified.issue_knowledge import extract, review_anchors, retrieve, run_knowledge, load_knowledge, target_symbols
from agentlog_unified.semantic_demand import prompt, validate
from test_semantic_demand import make_context, response


def document(*texts):
    elements=[]; start=1
    for text in texts:
        end=start+len(text.encode('utf-16-le'))//2
        elements.append({'startIndex':start,'endIndex':end,'paragraph':{'elements':[{'textRun':{'content':text}}]}})
        start=end
    return {'documentId':'synthetic-document','revisionId':'fixture-revision','tabs':[{'tabId':'t.0','body':{'content':elements}}]}


def test_group_dedup_scoped_generic_and_utf16_replay():
    doc=document('header\n', 'https://issues.apache.org/jira/browse/KAFKA-1?search=x key and value\n',
        'https://issues.apache.org/jira/browse/KAFKA-1?search=y 😀 name of the partitions\n',
        'https://issues.apache.org/jira/browse/OTHER-1 key and value\n',
        'https://issues.apache.org/jira/browse/OTHER-2\n')
    rows,outside,counts=extract(doc,'source-hash','fixture-user')
    assert len(rows)==3 and counts['issue_link_occurrences']==4 and len(outside)==1
    assert {t['concept'] for t in rows[0]['type_proposals']}=={'record_key_value','partition_name'}
    assert not rows[1]['type_proposals'] and rows[2]['human_annotation']['label']=='evidence_missing'
    assert all(review_anchors(doc,r)['status']!='unsupported' for r in rows)
    forged=deepcopy(rows[0]); forged['type_proposals'][0]['evidence'][0]['match_end_utf16']+=1
    assert review_anchors(doc,forged)['status']=='unsupported'
    doc['tabs'].append({'tabId':'t.1','body':{'content':document('password\n')['tabs'][0]['body']['content']}})
    rows,outside,_=extract(doc,'source-hash','fixture-user')
    assert len(outside)==2  # no source issue association across tabs


def test_sensitive_values_not_exported_resume_integrity_and_unknown(tmp_path):
    sentinel='SYNTHETIC_DO_NOT_PUBLISH_9f01b'
    doc=document('https://issues.apache.org/jira/browse/CAMEL-1\n',f"record's payload password={sentinel}\n",
        'https://issues.apache.org/jira/browse/OTHER-1 custom business abbreviation: zqv\n')
    source=tmp_path/'private.json';source.write_text(json.dumps(doc));out=tmp_path/'out'
    assert run_knowledge(source,out,reviewer='test',dry_run=True)['files_written'] is False
    assert not out.exists()
    report=run_knowledge(source,out,reviewer='test')
    assert report['human_sensitive_excerpt_groups']==2 and report['groups_with_type_proposals']==1
    assert report['program_human_truth']==0 and report['human_subtype_truth']==0
    assert report['accuracy'] is None and not report['held_out_evaluation']
    assert all(sentinel not in p.read_text() for p in out.rglob('*') if p.is_file())
    assert run_knowledge(source,out,reviewer='test',resume=True)['resumed_without_calls']
    assert any(q['reason']=='semantic_unknown' for q in map(json.loads,(out/'review_queue.jsonl').read_text().splitlines()))
    (out/'issue_annotations.jsonl').write_text('[]')
    with pytest.raises(ValueError,match='integrity'):load_knowledge(out)


def test_generic_names_do_not_trigger_and_examples_are_not_program_evidence():
    doc=document('https://issues.apache.org/jira/browse/KAFKA-1 key and value\n',
        "https://issues.apache.org/jira/browse/CAMEL-1 record's payload\n")
    rows,_,_=extract(doc,'source-hash','fixture-user')
    ctx=make_context('def emit(data):\n    value=data\n    payload=value\n    logger.info("event",payload)\n')
    assert not retrieve(ctx.payload(),ctx.checks(),rows)['suggestions']
    ctx=make_context('def emit(data: ConsumerRecord):\n    value=data\n    logger.info("event",value)\n')
    hints=retrieve(ctx.payload(),ctx.checks(),rows,subjects=target_symbols(ctx,ctx.checks()))
    assert {s['concept'] for s in hints['suggestions']}=={'record_key_value','record_payload'}
    assert all(s['selection_basis']=='lexical_context_retrieval_only' for s in hints['suggestions'])
    assert not hints['source_human_labels_are_target_truth']
    assert not retrieve(ctx.payload(),ctx.checks(),rows,max_chars=1)['suggestions']
    unrelated=make_context('def emit(data,err:ConsumerRecord):\n    logger.info("event",data)\n')
    assert not retrieve(unrelated.payload(),unrelated.checks(),rows,subjects=target_symbols(unrelated,unrelated.checks()))['suggestions']
    q=response(ctx);q['sensitive_type']['evidence_refs']=[hints['suggestions'][0]['id']]
    with pytest.raises(ValueError,match='invented_evidence'):validate(q,ctx.case['id'],'extract',ctx.payload(),ctx.checks())
    for stage in ('extract','review'):
        text=prompt(stage,ctx.payload(),ctx.checks(),knowledge=hints)
        assert 'issue_knowledge' in text and 'not human type gold' in text


def test_multilink_fails_closed():
    doc=document('https://issues.apache.org/jira/browse/A-1 https://issues.apache.org/jira/browse/B-1 password\n')
    with pytest.raises(ValueError,match='segmentation'):extract(doc,'source-hash','fixture-user')


def test_explicit_human_confirmation_keeps_link_only_reference_and_evidence_gap(tmp_path):
    from agentlog_unified.cli import main
    doc = document('https://issues.apache.org/jira/browse/CASE-1 password\n',
                   'https://issues.apache.org/jira/browse/CASE-2\n')
    source = tmp_path/'source.json'; source.write_text(json.dumps(doc)); out = tmp_path/'out'
    args = ['issue-knowledge', '--input', str(source), '--output', str(out),
            '--reviewer', 'fixture-user', '--confirm-all-issues', '--offline']
    assert main(args + ['--dry-run']) == 0 and not out.exists()
    assert main(args) == 0
    report = json.loads((out/'coverage.json').read_text())
    assert report['human_sensitive_reference_groups'] == report['unique_issue_groups'] == 2
    assert report['missing_description_groups'] == 1
    rows = load_knowledge(out)
    assert all(r['human_annotation']['label'] == 'sensitive_information' for r in rows)
    assert all(r['human_annotation']['origin'] == 'human' for r in rows)
    assert all(r['human_annotation']['basis'] == 'explicit_human_confirmation_all_issue_groups' for r in rows)
    missing = next(r for r in rows if r['issue_url'].endswith('/CASE-2'))
    assert missing['description_status'] == 'missing' and not missing['type_proposals']
    queue = [json.loads(s) for s in (out/'review_queue.jsonl').read_text().splitlines()]
    assert next(q for q in queue if q['annotation_id'] == missing['id'])['reason'] == 'context_missing'
    assert all(not r['human_annotation']['subtype_confirmed'] and r['program_field_semantics'] == 'not_bound' for r in rows)
    assert main(args + ['--resume']) == 0
    with pytest.raises(ValueError, match='incompatible_run'):
        run_knowledge(source, out, reviewer='fixture-user', resume=True)
    assert run_knowledge(source, tmp_path/'default', reviewer='fixture-user')['human_sensitive_reference_groups'] == 1
