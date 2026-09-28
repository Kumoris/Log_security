"""Real synthetic Parquet + parent export + repair; no real source values."""
import csv
import fcntl
import hashlib
import json
import sqlite3
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from agentlog_unified import content_scan, content_types, content_repair as repair


def parent_run(tmp_path, values, *, prefix=64, max_matches=1):
    source=tmp_path/'source';source.mkdir()
    imported=tmp_path/'import';imported.mkdir()
    path=source/'all_pull_request.parquet';pq.write_table(pa.table({'body':values,'author_login':['plain actor']*len(values)}),path,row_group_size=2)
    manifest={'status':'complete','source_signature':{'source_dir':str(source),'inputs':[{'path':path.name,'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}]},'outputs':{'aidev.sqlite':'fixture only'}}
    (imported/'manifest.json').write_text(json.dumps(manifest))
    parent=tmp_path/'parent';content_scan.scan_content(imported,parent,max_source_chars=prefix,max_matches=max_matches)
    return parent,path


def rows(output,name):
    return [json.loads(line) for line in (output/'scan'/(name+'.jsonl')).read_text().splitlines()]


def db_snapshot(output):
    with sqlite3.connect(output/'scan'/'repair.sqlite') as db:
        return {t:db.execute('SELECT * FROM '+t+' ORDER BY 1').fetchall() for t in ('cells','matches','gaps')}


def test_fixed_selection_dry_run_and_parent_writer_lock(tmp_path):
    parent,source=parent_run(tmp_path,['x'*100,'plain'])
    output=tmp_path/'repair'
    result=repair.run_content_repair(parent,output,dry_run=True)
    assert result['selected_cells']==1 and result['source_status']=='truncated'
    assert result['source_values_decoded'] is False and not output.exists()
    with (parent/'.content.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(RuntimeError,match='writer is active'):
            repair.run_content_repair(parent,output,dry_run=True)
    assert not output.exists()


def test_full_cell_rescan_recovers_cap_prefix_unicode_offsets_and_safe_exports(tmp_path):
    token='ghp_'+'0123456789'*3
    value='中文🙂 early-person@example.invalid\n'+('\n'+token)*1005
    parent,source=parent_run(tmp_path,[value,'safe'],prefix=1048576,max_matches=1000)
    parent_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in parent.iterdir() if p.is_file()}
    output=tmp_path/'repair';result=repair.run_content_repair(parent,output,core_chars=4096,page_matches=17)
    repaired=rows(output,'repair_type_occurrences')+rows(output,'repair_excluded')
    expected=content_types.classify_text(value,max_matches=10000)['matches']
    assert result['all_selected_cells_all_rules_finished'] and len(repaired)==len(expected)==1006
    assert sum(r['subtype']=='email' for r in repaired)==1
    assert {(r['start'],r['end'],r['category'],r['subtype']) for r in repaired}=={(r['start'],r['end'],r['category'],r['subtype']) for r in expected}
    assert all(r['observation_scope']=='dataset_text_cell_rescan' and r['human_review_status']=='pending' and not r['runtime_confirmed'] for r in repaired)
    assert result['parent_and_repair_counts_additive'] is False
    assert len(rows(output,'repair_unknown_type_review_queue'))==1
    for name in ('repair_type_occurrences','repair_excluded','repair_unknown_type_review_queue','repair_data_gaps','repair_type_summary'):
        with (output/'scan'/(name+'.csv')).open() as f:
            assert len(list(csv.DictReader(f)))==len(rows(output,name))
    for path in output.rglob('*'):
        if path.is_file():
            payload=path.read_bytes()
            assert token.encode() not in payload and b'early-person@example.invalid' not in payload
    assert parent_hashes=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in parent.iterdir() if p.is_file()}


def test_page_budget_resume_exact_once_and_selection_does_not_grow(tmp_path):
    parent,source=parent_run(tmp_path,['password="'+'a'*100+'"','short'])
    output=tmp_path/'repair'
    first=repair.run_content_repair(parent,output,max_pages=2,core_chars=32,page_matches=1)
    assert first['stop_reason']=='page_budget' and first['committed_pages']==2
    selection=(output/'selection'/'selection.jsonl').read_bytes()
    # New parent exports are not consulted when repairing the already-frozen selection.
    with (parent/'content_unknown_type_review_queue.jsonl').open('a') as f:
        f.write(json.dumps({'status':'future unselected source'})+'\n')
    final=repair.run_content_repair(parent,output,resume=True,core_chars=32,page_matches=1)
    assert final['all_selected_cells_all_rules_finished']
    before=db_snapshot(output)
    repeat=repair.run_content_repair(parent,output,resume=True,core_chars=32,page_matches=1)
    assert repeat['pages_this_invocation']==0 and db_snapshot(output)==before
    assert (output/'selection'/'selection.jsonl').read_bytes()==selection


def test_page_candidate_error_rolls_back_cursor_and_rows(tmp_path,monkeypatch):
    parent,source=parent_run(tmp_path,['password="'+'a'*100+'"'])
    output=tmp_path/'repair'
    repair.run_content_repair(parent,output,max_pages=0)
    before=db_snapshot(output);original=repair.content_cursor.page
    def poisoned(*args,**kwargs):
        result,state,gaps=original(*args,**kwargs)
        good={'start':0,'end':1,'category':'PII','subtype':'email','rule':'email_shape','basis':'literal_shape','confidence':'low','value_status':'unverified','candidate_status':'literal_candidate'}
        return [good,{**good,'body':'SYNTHETIC_MUST_NOT_PERSIST'}],state,gaps
    monkeypatch.setattr(repair.content_cursor,'page',poisoned)
    with pytest.raises(ValueError,match='Unapproved'):
        repair.run_content_repair(parent,output,resume=True,max_pages=1)
    assert db_snapshot(output)==before
    assert b'SYNTHETIC_MUST_NOT_PERSIST' not in (output/'scan'/'repair.sqlite').read_bytes()


def test_source_hmac_key_and_fingerprint_changes_rejected(tmp_path):
    parent,source=parent_run(tmp_path,['password="'+'a'*100+'"'])
    output=tmp_path/'repair';repair.run_content_repair(parent,output,max_pages=1)
    before=db_snapshot(output)
    with pytest.raises(ValueError,match='identical frozen'):
        repair.run_content_repair(parent,output,resume=True,core_chars=32)
    key=(parent/'.fingerprint-key').read_bytes();(parent/'.fingerprint-key').write_bytes(b'k'*32)
    with pytest.raises(ValueError,match='key is missing or changed'):
        repair.run_content_repair(parent,output,resume=True)
    (parent/'.fingerprint-key').write_bytes(key)
    payload=bytearray(source.read_bytes());payload[len(payload)//2]^=1;source.write_bytes(payload)
    with pytest.raises(ValueError,match='Parquet changed'):
        repair.run_content_repair(parent,output,resume=True)
    assert db_snapshot(output)==before


def test_selected_cell_hmac_mismatch_blocks_before_any_page(tmp_path):
    parent,source=parent_run(tmp_path,['password="'+'a'*100+'"'])
    queue=parent/'content_unknown_type_review_queue.jsonl'
    data=[json.loads(line) for line in queue.read_text().splitlines()]
    for row in data:
        if row['status']=='truncated': row['text_hmac_sha256']='0'*64
    queue.write_text(''.join(json.dumps(row)+'\n' for row in data))
    output=tmp_path/'repair'
    with pytest.raises(ValueError,match='HMAC'):
        repair.run_content_repair(parent,output)
    with sqlite3.connect(output/'scan'/'repair.sqlite') as db:
        assert db.execute('SELECT SUM(pages) FROM cells').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM matches').fetchone()[0]==0


def test_long_pem_boundary_and_unicode_tail_from_real_parquet(tmp_path):
    opening='-----BEGIN PRIVATE KEY-----';closing='-----END PRIVATE KEY-----'
    value='汉🙂 '*360000+'tail-person@example.invalid\n'+opening+'\n'+'x'*25+' dummysuffix\n'+closing
    parent,source=parent_run(tmp_path,[value])
    output=tmp_path/'repair';result=repair.run_content_repair(parent,output,core_chars=65536)
    all_rows=rows(output,'repair_type_occurrences')+rows(output,'repair_excluded')
    assert result['all_selected_cells_all_rules_finished']
    email=next(r for r in all_rows if r['subtype']=='email')
    assert value[email['start']:email['end']]=='tail-person@example.invalid'
    assert next(r for r in all_rows if r['subtype']=='private_key')['candidate_status']=='literal_candidate'
    assert result['unknown_type_review_cells']==1 and result['exit_code']==2


def test_time_budget_preserves_pending_selection_and_resumes(tmp_path):
    parent,source=parent_run(tmp_path,['x'*100])
    output=tmp_path/'repair';result=repair.run_content_repair(parent,output,max_seconds=0.0000001)
    assert result['stop_reason']=='time_budget' and result['committed_pages']==0
    assert repair.run_content_repair(parent,output,resume=True)['all_selected_cells_all_rules_finished']


def test_unclosed_pem_gap_and_output_isolation(tmp_path):
    parent,source=parent_run(tmp_path,['-----BEGIN PRIVATE KEY-----\n'+'x'*100])
    output=tmp_path/'repair';result=repair.run_content_repair(parent,output)
    assert result['data_gap_records']==1 and result['all_selected_cells_all_rules_finished']
    assert rows(output,'repair_data_gaps')[0]['reason']=='unclosed_private_key_envelope'
    with pytest.raises(ValueError,match='independent'):
        repair.run_content_repair(parent,parent/'overwrite',dry_run=True)
    with pytest.raises(ValueError,match='offline'):
        repair.run_content_repair(parent,tmp_path/'online',offline=False,dry_run=True)


def test_completed_resume_still_verifies_selected_source_and_classifier(tmp_path,monkeypatch):
    parent,source=parent_run(tmp_path,['x'*100])
    output=tmp_path/'repair';repair.run_content_repair(parent,output)
    before=db_snapshot(output);original=repair._digest
    monkeypatch.setattr(repair,'_digest',lambda path,*args: 'changed' if Path(path).name=='content_types.py' else original(path,*args))
    with pytest.raises(ValueError,match='identical frozen'):
        repair.run_content_repair(parent,output,resume=True)
    monkeypatch.setattr(repair,'_digest',original)
    payload=bytearray(source.read_bytes());payload[len(payload)//2]^=1;source.write_bytes(payload)
    with pytest.raises(ValueError,match='Parquet changed'):
        repair.run_content_repair(parent,output,resume=True)
    assert db_snapshot(output)==before


def test_fixed_selection_hash_and_parent_input_are_enforced(tmp_path):
    parent,source=parent_run(tmp_path,['x'*100])
    output=tmp_path/'repair';repair.run_content_repair(parent,output,max_pages=0)
    other=tmp_path/'other';other.mkdir()
    with pytest.raises(ValueError,match='input differs'):
        repair.run_content_repair(other,output,resume=True)
    with (output/'selection'/'selection.jsonl').open('a') as f: f.write('\n')
    with pytest.raises(ValueError,match='selection changed'):
        repair.run_content_repair(parent,output,resume=True)


@pytest.mark.parametrize('budget',[float('nan'),float('inf'),True,-1])
def test_invalid_time_budget_is_rejected_before_source_io(tmp_path,budget):
    with pytest.raises(ValueError,match='time budget'):
        repair.repair_content(tmp_path/'missing',tmp_path/'out',max_seconds=budget)


def test_pem_example_boundary_and_pending_envelope_survive_resume(tmp_path):
    opening='-----BEGIN PRIVATE KEY-----';closing='-----END PRIVATE KEY-----'
    negative=opening+'\n'+'x'*25+' dummysuffix\n'+closing
    positive=opening+'\n'+'x'*25+' dummy \n'+closing
    long_value=opening+'\n'+'a'*150000+'\nSYNTHETIC\n'+'b'*150000+'\n'+closing
    parent,source=parent_run(tmp_path,[negative,positive,long_value])
    # First run only the small-page delimiter regressions via the pure staged
    # cursor; the end-to-end large cell persists an open envelope separately.
    for value,wanted in ((negative,'literal_candidate'),(positive,'placeholder_or_example')):
        state={'rule_index':6,'search_offset':0};found=[]
        while state['rule_index']==6:
            page,state,gaps=repair.content_cursor.page(value,state,core=32,max_rows=1);found+=page
        assert len(found)==1 and found[0]['candidate_status']==wanted
    output=tmp_path/'repair'
    first=repair.run_content_repair(parent,output,max_pages=64,core_chars=65536)
    assert first['stop_reason']=='page_budget'
    with sqlite3.connect(output/'scan'/'repair.sqlite') as db:
        pending=[json.loads(row[0]) for row in db.execute("SELECT cursor FROM cells WHERE status='partial'")]
    assert any('pending_open' in state for state in pending)
    final=repair.run_content_repair(parent,output,resume=True,core_chars=65536)
    assert final['all_selected_cells_all_rules_finished']
    assert len(rows(output,'repair_excluded'))==2 and len(rows(output,'repair_type_occurrences'))==1


@pytest.mark.parametrize('damage',['dropped_queue_row','missing_queue','missing_counter','range_mismatch'])
def test_interrupted_parent_export_is_not_silently_selected(tmp_path,damage):
    parent,source=parent_run(tmp_path,['x'*100,'y'*100])
    source_before=hashlib.sha256(source.read_bytes()).hexdigest()
    queue=parent/'content_unknown_type_review_queue.jsonl';data=[json.loads(line) for line in queue.read_text().splitlines()]
    coverage_path=parent/'content_coverage.json'
    if damage=='dropped_queue_row': queue.write_text(''.join(json.dumps(r)+'\n' for r in data[1:]))
    elif damage=='missing_queue': queue.unlink()
    elif damage=='missing_counter':
        coverage=json.loads(coverage_path.read_text());del coverage['counts']['truncated_cells'];coverage_path.write_text(json.dumps(coverage))
    else:
        data[0]['row_count']+=1;queue.write_text(''.join(json.dumps(r)+'\n' for r in data))
    output=tmp_path/'repair'
    with pytest.raises(ValueError,match='queue|range|completeness'):
        repair.run_content_repair(parent,output,dry_run=True)
    assert not output.exists() and hashlib.sha256(source.read_bytes()).hexdigest()==source_before


@pytest.mark.parametrize('budgets',[{'core_chars':0},{'page_matches':1001},{'max_pages':-1},{'max_seconds':float('nan')}])
def test_wrapper_dry_run_checks_same_budgets_before_source_io(tmp_path,budgets):
    with pytest.raises(ValueError,match='budget|threshold'):
        repair.run_content_repair(tmp_path/'missing',tmp_path/'out',dry_run=True,**budgets)
    assert not (tmp_path/'out').exists()


def test_type_summary_preserves_reference_named_and_carrier_evidence(tmp_path):
    parent,source=parent_run(tmp_path,['password=user.password\npassword="123abc"\nrequest_body="hello"'],prefix=16)
    output=tmp_path/'repair';result=repair.run_content_repair(parent,output)
    summary=rows(output,'repair_type_summary');lookup={r['subtype']:r for r in summary}
    assert lookup['password']['candidate_status_counts']=={'identifier_reference':1,'named_value_candidate':1}
    assert lookup['request_body']['candidate_status_counts']=={'carrier_candidate':1}
    assert result['type_summary']==summary
    assert result['new_type_status']=='not_established' and result['taxonomy_version']=='1.2.0'
    for path in (output/'selection'/'selection_manifest.json',output/'scan'/'manifest.json'):
        document=json.loads(path.read_text())
        assert document['taxonomy_version']=='1.2.0' and document['new_type_status']=='not_established'


def test_completed_resume_is_partial_when_source_verification_exhausts_budget(tmp_path):
    parent,source=parent_run(tmp_path,['x'*100])
    output=tmp_path/'repair'
    complete=repair.run_content_repair(parent,output)
    assert complete['status']=='complete_with_semantic_gaps' and complete['source_verification_complete']
    before=db_snapshot(output)
    limited=repair.run_content_repair(parent,output,resume=True,max_seconds=0.0000001)
    assert limited['stop_reason']=='time_budget' and limited['status']=='partial'
    assert not limited['source_verification_complete'] and not limited['all_selected_cells_all_rules_finished']
    assert limited['recorded_completed_cells']==complete['recorded_completed_cells']==1
    assert limited['cell_status_counts']==complete['cell_status_counts']
    assert limited['pages_this_invocation']==0 and db_snapshot(output)==before
    persisted=json.loads((output/'scan'/'repair_coverage.json').read_text())
    assert persisted['status']=='partial' and not persisted['all_selected_cells_all_rules_finished']
    verified=repair.run_content_repair(parent,output,resume=True)
    assert verified['status']=='complete_with_semantic_gaps' and verified['all_selected_cells_all_rules_finished']
    assert verified['source_verification_complete'] and db_snapshot(output)==before


def test_coverage_total_is_not_last_type_status_group_count(tmp_path):
    value='password=user.password\npassword="a1b2c3"\nrequest_body="hello"\nclient_ip=192.0.2.1\nclient_ip=192.0.2.2\nemail="review@example.invalid"'
    parent,source=parent_run(tmp_path,[value],prefix=16)
    output=tmp_path/'repair';result=repair.run_content_repair(parent,output)
    summary=rows(output,'repair_type_summary')
    with sqlite3.connect(output/'scan'/'repair.sqlite') as db:
        db_count=db.execute('SELECT COUNT(*) FROM matches WHERE excluded=0').fetchone()[0]
    assert result['candidate_occurrences']==len(rows(output,'repair_type_occurrences'))==db_count==6
    assert sum(r['occurrence_count'] for r in summary)==6
    assert sum(sum(r['candidate_status_counts'].values()) for r in summary)==6
    assert result['excluded_occurrences']==len(rows(output,'repair_excluded'))==1
    assert {r['subtype'] for r in summary}=={'password','request_body','business_object','network_identifier'}
    assert {state for r in summary for state in r['candidate_status_counts']}=={'identifier_reference','named_value_candidate','carrier_candidate','literal_candidate'}
