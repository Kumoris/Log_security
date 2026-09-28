"""Synthetic-only regression checks: no study records or sealed sources."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import agent_log_motivation as m
import pytest


def event(**kwargs):
    return {"event_id":"e1","repository":"example/project","modification_sha":"b"*40,"file_path":"app.py",
            "old_path":"app.py","new_path":"app.py","upstream_confidence":"supported",
            "observed_change":{"before_lines":[4,5],"after_lines":[4,5]},**kwargs}


def evidence(store,e,text="Remove this debug log to reduce noise.",relation="direct_log_location"):
    return store.add(e,"review_comment","comment:1",text,local_path="synthetic://review/1",timestamp="2026-01-01T00:00:00Z",
                     method="synthetic_exact_location",basis={"sha":e["modification_sha"],"line":4},relation=relation)


def claim(eid,**kwargs):
    return {"event_id":"e1","status":"explicit","annotator":"synthetic_test_not_human","labels":["noise_control"],
            "rationale":"Review text names the deleted log.","direct_correspondence":"The review is on app.py line 4 at the modifying SHA.",
            "target_anchor":{"modification_sha":"b"*40,"file_path":"app.py","line":4,"side":"before"},
            "stated_purpose":"reduce noise","citations":[{"evidence_id":eid,"quote":"reduce noise"}],
            "claim_key":"remove_debug_for_noise","position":"supports",**kwargs}


def test_identical_evidence_and_edge_deduplicate():
    s=m.EvidenceStore();e=event();evidence(s,e);evidence(s,e)
    assert len(s.evidence)==len(s.links)==1 and s.duplicate_attempts==1


def test_same_evidence_multiple_events_and_comment_revisions():
    s=m.EvidenceStore();evidence(s,event());evidence(s,event(event_id="e2"));evidence(s,event(),text="Revised review")
    assert len(s.evidence)==2 and len(s.links)==3


def test_no_evidence_kept_unknown_with_left_join(tmp_path):
    s=m.EvidenceStore();e=event();summary=m.export(tmp_path,[e],s,[],{"stage2_event_rows":1},{})
    assert summary["motive_distribution"]["unknown"]==1
    r=list(m.rows(tmp_path/"modifications_with_evidence.jsonl"))[0][1]
    assert r["event_id"]=="e1" and r["evidence_id"] is None


def test_same_commit_metadata_is_not_a_motive():
    s=m.EvidenceStore();e=event();evidence(s,e)
    assert m.judge(e,s,[])["motive_status"]=="unknown"


def test_explicit_quote_and_inferred_are_separate():
    s=m.EvidenceStore();e=event();eid=evidence(s,e)
    assert m.judge(e,s,[claim(eid)])["motive_status"]=="explicit"
    a=claim(eid,status="inferred",inference="May reduce console volume.")
    r=m.judge(e,s,[a]);assert r["motive_status"]=="inferred" and r["stated_purposes"]==[]


def test_opposing_claims_conflict_compatible_labels_do_not():
    s=m.EvidenceStore();e=event();eid=evidence(s,e)
    other=evidence(s,e,text="Keep the debug log despite noise.")
    opposing=claim(other,position="opposes",citations=[{"evidence_id":other,"quote":"Keep the debug log"}])
    assert m.judge(e,s,[claim(eid),opposing])["motive_status"]=="conflicting"
    assert m.judge(e,s,[claim(eid),claim(eid,position="opposes")])["motive_status"]=="unknown"
    assert m.judge(e,s,[claim(eid),claim(eid,claim_key="format",labels=["format_consistency"])])["motive_status"]=="explicit"


@pytest.mark.parametrize("change",[
    {"citations":[{"evidence_id":"invented","quote":"reduce noise"}]},
    {"citations":[]},{"direct_correspondence":""},{"labels":["invented"]},{"annotator":""}])
def test_invalid_claim_cannot_promote(change):
    s=m.EvidenceStore();e=event();eid=evidence(s,e)
    assert m.judge(e,s,[claim(eid,**change)])["motive_status"]=="unknown" and s.missing


def test_initial_prompt_cannot_explain_later_change():
    s=m.EvidenceStore();e=event();eid=evidence(s,e,relation="introduction_background")
    assert m.judge(e,s,[claim(eid)])["motive_status"]=="unknown"


def test_ambiguous_lineage_cannot_be_explicit():
    s=m.EvidenceStore();e=event(upstream_confidence="possible");eid=evidence(s,e)
    assert m.judge(e,s,[claim(eid)])["motive_status"]=="unknown"


@pytest.mark.parametrize("changes,expected",[
    ({},"direct_log_location"),({"path":"other.py"},"pr_context"),
    ({"commit_id":"c"*40},"same_file_context"),({"line":25},"same_file_context"),
    ({"line":None,"position":1},"same_file_context")])
def test_inline_comments_require_sha_path_and_line(changes,expected):
    c={"path":"app.py","commit_id":"b"*40,"line":4,"side":"RIGHT",**changes}
    assert m.inline_relation(event(),c)==expected


def test_issue_reference_edges_not_similarity():
    assert m.issue_refs("Fixes #3; see other/repo#7 and https://github.com/x/y/issues/9", "example/project")==[("example/project",3),("other/repo",7),("x/y",9)]
    assert m.issue_refs("similar topic yesterday", "example/project")==[]


class FakeClient:
    def __init__(self,tmp_path):self.cache_dir=tmp_path;self.failures=[];self.calls=[]
    def _url(self,p):return "https://api.github.com/"+p
    def get(self,p):
        self.calls.append(p)
        if "/commits/" in p:return {"sha":"b"*40,"html_url":"synthetic://commit", "commit":{"message":"change logs","committer":{"date":"2026-01-01"}}}
        if p.endswith("/pulls/2"):return {"number":2,"title":"Update logs", "body":"Fixes #3", "html_url":"synthetic://pr"}
        if p.endswith("/issues/3"):return {"number":3,"title":"Log noise","body":"Please reduce repeated output.","html_url":"synthetic://issue"}
        return None
    def paginate(self,p):
        self.calls.append(p)
        if p.endswith("/pulls"):return [{"number":2,"base":{"repo":{"full_name":"example/project"}}}]
        if p.endswith("/pulls/2/comments"):return [{"id":1,"path":"app.py","commit_id":"b"*40,"line":4,"side":"RIGHT","body":"Reduce noise","html_url":"synthetic://inline"}]
        if p.endswith("/pulls/2/reviews"):return [{"id":2,"body":"Looks good","html_url":"synthetic://summary"}]
        if p.endswith("/issues/3/comments"):return [{"id":3,"body":"Still repeated","html_url":"synthetic://discussion"}]
        return []


def test_complete_commit_pr_review_issue_chain(tmp_path):
    s=m.EvidenceStore();client=FakeClient(tmp_path);m.Collector(client,s).collect(event(),{})
    assert {e["source_type"] for e in s.evidence.values()}=={"commit_message","pr_description","review_comment","issue"}
    assert {e.get("source_subtype") for e in s.evidence.values()} >= {"inline","review_summary","body","discussion"}
    assert all(r["association_basis"] for r in s.links.values())
    assert m.judge(event(),s,[])["motive_status"]=="unknown"


def test_network_failure_is_missing_not_fake_evidence(tmp_path):
    class Broken(FakeClient):
        def get(self,p):self.failures.append({"error_type":"HTTP_404","reason":"not accessible"});return None
        def paginate(self,p):self.failures.append({"error_type":"HTTP_403","reason":"rate limit"});return []
    s=m.EvidenceStore();m.Collector(Broken(tmp_path),s).collect(event(),{})
    assert not s.evidence and {r["reason"] for r in s.missing}>={"HTTP_404","HTTP_403"}


def test_zero_denominator_is_null(tmp_path):
    summary=m.export(tmp_path,[],m.EvidenceStore(),[],{"stage2_event_rows":0},{})
    assert all(c["fraction"] is None for c in summary["source_coverage"].values())
