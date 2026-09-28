"""Synthetic acceptance and pending-population checks."""
import csv
import json
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from continue_agent_log_pipeline import snapshot, validate_repository
from agent_log_motivation_v11 import file_hash


def test_pending_repository_preserves_candidate_and_null_final_rate(tmp_path):
    w=tmp_path/'workspace';src=w/'upstream';src.mkdir(parents=True)
    f=w/'outputs/swechat_log_alignment_20260921/final/changed_logs.csv';f.parent.mkdir(parents=True)
    row=dict(log_id='l1',repo_id='fixture/repo',commit_sha='a'*40,path='app.py',start_line='1',end_line='1',attribution_grade='file_attribution_only',file_attribution_labels='["mixed"]')
    with f.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(row));writer.writeheader();writer.writerow(row)
    (src/'inventory.json').write_text(json.dumps(dict(input_sha256=file_hash(f),repositories=[{'repository':'fixture/repo','candidates':1}])))
    out=w/'new_result';snapshot(w,src,out,[])
    s=json.loads((out/'summary.json').read_text());ledger=json.loads((out/'candidate_ledger.jsonl').read_text())
    assert s['stage2_final_filter_fraction'] is None and s['pending_candidates']==1
    assert s['stage2_event_links']==0 and s['full_stage2_complete'] is False
    assert ledger['log_id']=='l1' and ledger['file_attribution_labels']=='["mixed"]'
    assert ledger['status']=='pending_upstream_execution'
    with pytest.raises(FileExistsError):snapshot(w,src,out,[])


def test_inaccessible_history_is_not_deleted_and_duplicate_candidate_rejected(tmp_path):
    row=dict(log_id='l1',repo_id='fixture/repo',commit_sha='a'*40,path='app.py',start_line='1',end_line='1',attribution_grade='file_attribution_only',file_attribution_labels='[]',status='history_unavailable',followup_ids=[])
    (tmp_path/'summary.json').write_text(json.dumps({'status':'history_unavailable','events':0}))
    p=tmp_path/'candidate_ledger.jsonl';p.write_text(json.dumps(row)+'\n')
    ledger,cases,events,checks=validate_repository(tmp_path,{'l1':row})
    assert len(ledger)==1 and not events and all(checks.values())
    p.write_text((json.dumps(row)+'\n')*2)
    with pytest.raises(ValueError,match='repository_validation_failed'):validate_repository(tmp_path,{'l1':row})
