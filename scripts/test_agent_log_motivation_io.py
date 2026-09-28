"""Boundary tests using only small synthetic upstream exports and Parquet tables."""
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"outputs/swechat_log_alignment_20260921/dependencies"))
import agent_log_motivation as m
import pytest


def write(path, values):
    path.write_text("".join(json.dumps(r)+"\n" for r in values),encoding="utf-8")


class Guard:
    def check(self,*args):return "allowed"


def run_fixture(root):
    data=root/"data";data.mkdir()
    write(data/"repositories.jsonl",[{"id":"r","repository":"fixture/repo"}])
    write(data/"commits.jsonl",[{"repository_id":"r","sha":"b"*40,"message":"change"}])
    write(data/"log_changes.jsonl",[{"case_id":"c","sha":"a"*40,"repository":"fixture/repo"}])
    before={"path":"app.py","statement":"print('old')","start_line":1,"end_line":1}
    after={"path":"app.py","statement":"print('new')","start_line":1,"end_line":1}
    write(data/"file_changes.jsonl",[{"id":"f","repository_id":"r","sha":"b"*40,"old_path":"app.py","new_path":"app.py",
        "before_source":"print('old')\n","after_source":"print('new')\n","diff_basis_sha":"a"*40,"diff_target_sha":"b"*40}])
    f={"id":"event","case_id":"c","repository_id":"r","sha":"b"*40,"parent_sha":"a"*40,"before":before,"after":after,"file_change_ids":["f"],"behavior_confidence":"supported"}
    write(data/"followups.jsonl",[f]);return data,f


def test_trace_adapter_preserves_duplicates_and_malformed_rows(tmp_path):
    data,f=run_fixture(tmp_path)
    with (data/"followups.jsonl").open("a") as out:out.write(json.dumps(f)+"\nnot json\n")
    events,details,gaps,upstream=m.normalize_trace(tmp_path,Guard())
    assert len(events)==3 and len({e["event_id"] for e in events})==3 and len(details)==2
    assert "invalid_json_or_nonobject" in {r["reason"] for r in gaps}
    assert upstream["stage2_unique_upstream_ids"]==2


def test_bad_source_anchor_is_retained_without_external_collection(tmp_path):
    data,f=run_fixture(tmp_path);f["before"]["statement"]="print('unrelated')"
    write(data/"followups.jsonl",[f])
    events,details,gaps,_=m.normalize_trace(tmp_path,Guard())
    assert len(events)==1 and not details and events[0]["observed_change"] is None
    assert "log_statement_anchor_mismatch" in {r["reason"] for r in gaps}


def test_guard_blocked_retains_anonymous_event(tmp_path):
    run_fixture(tmp_path)
    class Blocked:
        def check(self,*args):return "guard_protected"
    events,details,gaps,_=m.normalize_trace(tmp_path,Blocked())
    assert len(events)==1 and not details and events[0]["repository"] is None and events[0]["file_path"] is None
    assert events[0]["motive_status"]=="unknown"


def test_same_commit_is_not_silently_treated_as_followup(tmp_path):
    data,f=run_fixture(tmp_path)
    write(data/"log_changes.jsonl",[{"case_id":"c","sha":"b"*40,"repository":"fixture/repo"}])
    events,details,gaps,_=m.normalize_trace(tmp_path,Guard())
    assert len(events)==1 and not details and "not_a_later_commit" in {r["reason"] for r in gaps}


def test_prompt_join_excludes_other_repos_checkpoints_tools_and_initial_prompt(tmp_path):
    pa=pytest.importorskip("pyarrow");import pyarrow.parquet as pq
    event={"event_id":"e","repository":"fixture/repo","modification_sha":"b"*40,"file_path":"app.py"}
    pq.write_table(pa.Table.from_pylist([{"repo_id":"fixture/repo","checkpoint_pk":"cp","session_pks":'["s"]',"commit_shas":json.dumps(["b"*40])}]),tmp_path/"checkpoints.parquet")
    pq.write_table(pa.Table.from_pylist([{"repo_id":"fixture/repo","checkpoint_pk":"cp","commit_sha":"b"*40,"commit_message":"change logs","commit_date":"2026-01-01"}]),tmp_path/"commits.parquet")
    r={"repo_id":"fixture/repo","checkpoint_pk":"cp","session_id":"s","turn_id":"t","role":"user","is_conversational":True,
       "content":"Reduce repeated debug logging.","timestamp":"2026-01-01","tool_name":None,"turn_number":1}
    turns=[r,{**r,"turn_id":"other_repo","repo_id":"other/repo"},{**r,"turn_id":"old","checkpoint_pk":"intro"},
           {**r,"turn_id":"tool","tool_name":"Edit"},{**r,"turn_id":"assistant","role":"assistant"},
           {**r,"turn_id":"not_conversation","is_conversational":False}]
    pq.write_table(pa.Table.from_pylist(turns),tmp_path/"conversations.parquet")
    s=m.EvidenceStore();m.collect_prompts([event],tmp_path,s)
    prompts=[r for r in s.evidence.values() if r["source_type"]=="prompt"]
    assert len(prompts)==1 and prompts[0]["turn_id"]=="t"
    assert m.judge(event,s,[])["motive_status"]=="unknown"


def test_same_evidence_retains_both_verified_source_locations():
    e={"event_id":"e","repository":"fixture/repo","modification_sha":"b"*40,"file_path":"app.py"}
    s=m.EvidenceStore()
    for local,url in [("/local/message.json",None),("/cache/response.json","https://example.invalid/commit")]:
        s.add(e,"commit_message","b"*40,"same text",local_path=local,url=url,method="exact_sha",basis={"sha":"b"*40})
    r=next(iter(s.evidence.values()));assert len(s.evidence)==1 and len(r["source_locators"])==2 and r["source_url"]


def test_parent_revision_review_requires_exact_log_lines():
    e={"modification_sha":"b"*40,"parent_sha":"a"*40,"file_path":"app.py","old_path":"app.py","new_path":"app.py",
       "observed_change":{"before_lines":[4,4],"after_lines":[4,4]}}
    c={"path":"app.py","commit_id":"a"*40,"line":4,"side":"RIGHT"}
    assert m.inline_relation(e,c)=="direct_parent_log_location"
    assert m.inline_relation(e,{**c,"line":8})=="same_file_context"


def test_paginated_comment_points_to_actual_page(tmp_path):
    class Client:
        cache_dir=tmp_path
        def _url(self,p):return 'https://api.github.com/'+p
    endpoint='repos/fixture/repo/pulls/2/comments'
    first={'url':'https://api.github.com/'+endpoint+'?per_page=100','data':[{'id':1}]}
    second={'url':'https://api.github.com/'+endpoint+'?per_page=100&page=2','data':[{'id':2}]}
    (tmp_path/'one.json').write_text(json.dumps(first))
    (tmp_path/'two.json').write_text(json.dumps(second))
    c=m.Collector(Client(),m.EvidenceStore())
    assert Path(c.cache_path(endpoint,True,2)).name=='two.json'
    assert c.cache_path(endpoint,True,3) is None


def test_missing_source_locator_records_gap_without_stopping():
    e={'event_id':'e','repository':'fixture/repo','modification_sha':'b'*40,'file_path':'app.py'}
    s=m.EvidenceStore()
    assert s.add(e,'review_comment','None','text',method='review',basis={'sha':'b'*40}) is None
    assert not s.evidence and s.missing[0]['reason']=='source_locator_or_identifier_or_basis_missing'
