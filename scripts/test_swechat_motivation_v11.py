import sys,hashlib,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import agent_log_motivation_v11 as m
from test_agent_log_motivation_io import run_fixture,write,Guard

def dependency_fixture(tmp_path):
    data,f=run_fixture(tmp_path)
    fc=json.loads((data/'file_changes.jsonl').read_text())
    fc.update(old_path='helper.py',new_path='helper.py',before_source='LIMIT=1\n',after_source='LIMIT=2\n')
    write(data/'file_changes.jsonl',[fc]); anchors=[]
    for sha,source in [('a'*40,"print('old')\n"),('b'*40,"print('new')\n")]:
        b=source.encode();anchors.append(dict(repository_id='r',sha=sha,path='app.py',source=source,
            source_sha256=hashlib.sha256(b).hexdigest(),git_blob_id=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),source_locator='local exact blob'))
    write(data/'log_source_anchors.jsonl',anchors)
    return data,anchors

def test_dependency_diff_can_use_exact_separate_log_source(tmp_path):
    dependency_fixture(tmp_path)
    events,details,gaps,_=m.normalize_trace(tmp_path,Guard())
    assert len(events)==1 and len(details)==1 and not gaps
    assert len(events[0]['source_anchors'])==2

def test_wrong_commit_anchor_does_not_link(tmp_path):
    data,anchors=dependency_fixture(tmp_path);anchors[0]['sha']='c'*40
    write(data/'log_source_anchors.jsonl',anchors)
    events,details,gaps,_=m.normalize_trace(tmp_path,Guard())
    assert not details and len(events)==1
    assert 'log_statement_anchor_mismatch' in {g['reason'] for g in gaps}

def test_tampered_anchor_remains_unknown(tmp_path):
    data,anchors=dependency_fixture(tmp_path);anchors[0]['source_sha256']='invalid'
    write(data/'log_source_anchors.jsonl',anchors)
    events,details,gaps,_=m.normalize_trace(tmp_path,Guard())
    assert not details and events[0]['motive_status']=='unknown'


def test_new_dependency_file_has_no_before_source_but_log_anchor_does(tmp_path):
    data,anchors=dependency_fixture(tmp_path)
    fc=json.loads((data/'file_changes.jsonl').read_text())
    fc.update(old_path=None,before_source=None)
    write(data/'file_changes.jsonl',[fc])
    events,details,gaps,_=m.normalize_trace(tmp_path,Guard())
    assert len(details)==1 and not gaps and len(events)==1


def test_comment_namespaces_do_not_merge_numeric_id_collisions():
    e=dict(event_id='e',repository='fixture/repo',modification_sha='b'*40,file_path='app.py')
    store=m.EvidenceStore()
    for subtype in ['inline','review_summary','pr_conversation']:
        store.add(e,'review_comment','123','same body',url='https://example.invalid/'+subtype,
            method='fixture_verified_association',basis={'sha':'b'*40},source_subtype=subtype)
    assert len(store.evidence)==3 and len(store.links)==3


def test_stage_one_denominator_includes_unmapped_candidates(tmp_path):
    data,f=run_fixture(tmp_path)
    write(data/'candidate_ledger.jsonl',[{'log_id':'mapped'},{'log_id':'unmapped'}])
    write(data/'log_changes.jsonl',[dict(case_id='c',sha='a'*40,repository='fixture/repo',stage1_log_ids=['mapped'])])
    events,details,gaps,upstream=m.normalize_trace(tmp_path,Guard())
    assert upstream['stage1_rows']==2 and upstream['trace_origin_rows']==1
    assert upstream['stage2_initial_logs_with_changes']==1


def test_commit_message_does_not_require_valid_prompt_checkpoint(tmp_path):
    import pyarrow as pa
    import pyarrow.parquet as pq
    event=dict(event_id='e',repository='fixture/repo',modification_sha='b'*40,file_path='app.py')
    pq.write_table(pa.Table.from_pylist([dict(repo_id='fixture/repo',checkpoint_pk='cp',session_pks='["s"]',commit_shas=json.dumps(['a'*40]))]),tmp_path/'checkpoints.parquet')
    pq.write_table(pa.Table.from_pylist([dict(repo_id='fixture/repo',checkpoint_pk='cp',commit_sha='b'*40,commit_message='Exact modification message',commit_date='2026-01-01')]),tmp_path/'commits.parquet')
    pq.write_table(pa.Table.from_pylist([dict(repo_id='fixture/repo')]),tmp_path/'conversations.parquet')
    store=m.EvidenceStore();m.collect_prompts([event],tmp_path,store)
    assert [r['source_type'] for r in store.evidence.values()]==['commit_message']
    assert 'checkpoint_membership_missing_or_conflicting' in {r['reason'] for r in store.missing}


def test_missing_primary_timestamp_enriched_without_losing_locators():
    event=dict(event_id='e',repository='fixture/repo',modification_sha='b'*40,file_path='app.py')
    store=m.EvidenceStore()
    for timestamp in [None,'2026-01-01']:
        store.add(event,'commit_message','b'*40,'same message',local_path='fixture.json',timestamp=timestamp,
                  method='exact_sha',basis={'sha':'b'*40})
    record=next(iter(store.evidence.values()))
    assert record['source_time']=='2026-01-01' and record['source_time_status']=='available'
    assert len(record['source_locators'])==2


def test_left_or_missing_side_cannot_assume_modification_parent():
    e=dict(modification_sha='b'*40,parent_sha='a'*40,file_path='app.py',old_path='app.py',new_path='app.py',
           observed_change={'before_lines':[4,4],'after_lines':[4,4]})
    for side in ['LEFT',None]:
        c=dict(path='app.py',commit_id='b'*40,line=4,side=side)
        assert m.inline_relation(e,c)=='same_file_context'


def test_cross_side_range_does_not_create_false_overlap():
    e=dict(modification_sha='b'*40,parent_sha='a'*40,file_path='app.py',
           observed_change={'before_lines':[4,4],'after_lines':[4,4]})
    c=dict(path='app.py',commit_id='b'*40,start_line=1,line=9,start_side='LEFT',side='RIGHT')
    assert m.inline_relation(e,c)=='same_file_context'
    assert m.inline_relation(e,{**c,'start_side':'RIGHT'})=='direct_log_location'


def test_review_path_must_match_the_referenced_version_after_rename():
    e=dict(modification_sha='b'*40,parent_sha='a'*40,file_path='new.py',old_path='old.py',new_path='new.py',
           observed_change={'before_lines':[4,4],'after_lines':[4,4]})
    c=dict(path='old.py',commit_id='b'*40,line=4,side='RIGHT')
    assert m.inline_relation(e,c)=='same_file_context'
    assert m.inline_relation(e,{**c,'commit_id':'a'*40})=='direct_parent_log_location'
