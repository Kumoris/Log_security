"""Synthetic contract: a left join keeps both code observations and evidence."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent_log_motivation_v11 as m


def test_join_keeps_code_fields_for_multiple_and_missing_sources(tmp_path):
    common = dict(repository='fixture/repo', modification_sha='b' * 40,
                  file_path='fixture.py', observed_change={'before_statement': 'log.info(old)',
                  'after_statement': 'log.info(new)'}, stage1_log_ids=['initial-fixture'])
    first, second = dict(common, event_id='with-evidence'), dict(common, event_id='without-evidence')
    store = m.EvidenceStore()
    for kind in ('commit_message', 'prompt'):
        store.add(first, kind, 'fixture-' + kind, 'Fixture context only.',
                  local_path=str(tmp_path / (kind + '.json')), method='fixture_exact_sha',
                  basis={'sha': 'b' * 40})
    m.export(tmp_path, [first, second], store, [], {'stage2_event_rows': 2}, {})
    joined = [r for _, r in m.rows(tmp_path / 'modifications_with_evidence.jsonl')]
    assert len(joined) == 3
    assert all(r['observed_change'] == common['observed_change'] for r in joined)
    assert all(r['stage1_log_ids'] == ['initial-fixture'] for r in joined)
    assert sum(r['evidence_id'] is None for r in joined) == 1
    assert all(r['motive_status'] == 'unknown' for r in joined)
