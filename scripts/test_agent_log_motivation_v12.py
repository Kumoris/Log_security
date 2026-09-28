"""Synthetic regressions for the incremental continuation; no corpus cases."""
import json
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent_log_motivation_v11 as old
import agent_log_motivation_v12 as new
from test_agent_log_motivation import event, evidence, claim, FakeClient


def test_failed_pr_query_is_not_reported_as_empty(tmp_path):
    class Failed(FakeClient):
        def paginate(self, p):
            self.failures.append({'error_type': 'HTTP_403', 'reason': 'access denied'})
            return []
    store = old.EvidenceStore()
    new.Collector(Failed(tmp_path), store).collect(event(), {})
    reasons = {g['reason'] for g in store.missing}
    assert 'HTTP_403' in reasons
    assert 'no_pr_returned_for_exact_commit' not in reasons


def test_successfully_empty_pr_query_is_reported_as_empty(tmp_path):
    class Empty(FakeClient):
        def paginate(self, p):
            return []
    store = old.EvidenceStore()
    new.Collector(Empty(tmp_path), store).collect(event(), {})
    assert 'no_pr_returned_for_exact_commit' in {g['reason'] for g in store.missing}


@pytest.mark.parametrize('mode', ['unknown', 'explicit', 'inferred', 'conflicting'])
def test_indexed_judgment_matches_original_for_all_statuses(tmp_path, mode):
    store = old.EvidenceStore()
    e = event()
    eid = evidence(store, e)
    claims = [] if mode == 'unknown' else [claim(eid)]
    if mode == 'inferred':
        claims = [claim(eid, status='inferred', inference='Context suggests noise reduction.')]
    if mode == 'conflicting':
        other = evidence(store, e, text='Keep the debug log despite noise.')
        claims.append(claim(other, position='opposes', citations=[{'evidence_id': other, 'quote': 'Keep the debug log'}]))
    expected = old.judge(e, store, claims)
    result = new.export(tmp_path, [e, event(event_id='no-evidence')], store, claims, {'stage2_event_rows': 2}, {})
    actual = [r for _, r in old.rows(tmp_path / 'motives.jsonl')]
    assert actual[0] == expected
    assert actual[1]['motive_status'] == 'unknown'
    assert result['motive_distribution'][mode] >= 1
    assert json.loads((tmp_path / 'validation.json').read_text())['status'] == 'PASS'


def test_new_collector_preserves_multiple_evidence_and_source_types(tmp_path):
    store = old.EvidenceStore()
    c = new.Collector(FakeClient(tmp_path), store)
    c.collect(event(), {})
    n = len(store.evidence)
    c.collect(event(event_id='second'), {})
    assert len(store.evidence) == n
    assert {l['event_id'] for l in store.links.values()} == {'e1', 'second'}
    assert {r['source_type'] for r in store.evidence.values()} == {'commit_message', 'pr_description', 'review_comment', 'issue'}


def test_invalid_citation_is_still_unknown_after_indexing(tmp_path):
    store = old.EvidenceStore()
    eid = evidence(store, event())
    new.export(tmp_path, [event()], store, [claim(eid, citations=[{'evidence_id': eid, 'quote': 'invented quotation'}])], {'stage2_event_rows': 1}, {})
    assert [r for _, r in old.rows(tmp_path / 'motives.jsonl')][0]['motive_status'] == 'unknown'
    assert any(g['reason'] == 'invalid_or_unassociated_quote' for g in store.missing)
