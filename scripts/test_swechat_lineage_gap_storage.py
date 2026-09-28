"""Full-output equivalence on guarded synthetic Git history, never heldout data."""
import json
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'tests'))
from agentlog_unified import lineage
from align_swechat_agent_logs import Guard
from swechat_lineage_gap_storage import TraceGapStorage
import synthetic_histories as fixtures


@pytest.fixture
def trace_arguments(tmp_path, monkeypatch):
    guard = Guard(ROOT)
    variants = [fixtures.SAFE,
                fixtures.SAFE.replace('user=%s', 'user state=%s'),
                fixtures.SAFE.replace('logger.info', 'logger.debug')]
    for source in variants:
        assert guard.check('synthetic-lineage-gap-storage', 'app.py', source) == 'allowed'
    fixtures.init(tmp_path)
    first = fixtures.commit(tmp_path, {'app.py': variants[0]}, 'synthetic first log', day=2)
    second = fixtures.commit(tmp_path, {'app.py': variants[1]}, 'synthetic message edit', day=3)
    last = fixtures.commit(tmp_path, {'app.py': variants[2]}, 'synthetic level edit', actor='human', day=4)
    captured = []
    def record(*args, **kwargs):
        captured.append(args)
        return lineage.trace_logs(*args, **kwargs)
    monkeypatch.setattr(fixtures, 'trace_logs', record)
    fixtures.pipeline(tmp_path, last, [first, second])
    return captured[0]


@pytest.mark.parametrize('stage', ['mine', 'collect', 'detect'])
def test_complete_output_order_duplicates_and_repeated_calls(trace_arguments, stage):
    args = list(trace_arguments)
    rid = args[0][0]['id']
    extras = [dict(repository_id=rid, stage=stage, error_type='synthetic_gap'),
              dict(repository=rid, stage='detect', error_type='synthetic_name_match'),
              dict(repository_id='unrelated', stage='mine', error_type='unrelated')]
    gaps = tuple(args[7] + extras * 1000)
    args[7] = gaps
    before = json.dumps(gaps, sort_keys=True)
    expected = lineage.trace_logs(*args)
    runner = TraceGapStorage(lineage, gaps)
    actual = runner(*args)
    repeated = runner(*args)
    assert actual == expected == repeated
    assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)
    rows = actual['log_changes'] + repeated['log_changes']
    assert len(rows) >= 4
    assert len({id(row['coverage_gaps']) for row in rows}) == 1
    assert all(row['coverage_gaps'] == [g for g in gaps if g.get('repository_id') == rid or g.get('repository') == rid] for row in rows)
    assert json.dumps(gaps, sort_keys=True) == before
    preserved = list(rows[1]['coverage_gaps'])
    rows[0]['coverage_gaps'] = [dict(stage='summary', count=len(preserved))]
    assert rows[1]['coverage_gaps'] == preserved
    assert runner.statistics()['repository_views'] == 1


def test_cache_rejects_a_different_gap_sequence_and_preserves_repo_predicate(trace_arguments):
    args = list(trace_arguments)
    gaps = tuple(args[7])
    runner = TraceGapStorage(lineage, gaps)
    args[7] = list(gaps)
    with pytest.raises(ValueError, match='same frozen'):
        runner(*args)
    rows = (dict(repository_id='a', n=1), dict(repository='b', n=2),
            dict(repository_id='c', n=3), dict(repository_id='a', n=1))
    runner = TraceGapStorage(lineage, rows)
    assert runner._view('a', 'b') == [rows[0], rows[1], rows[3]]
    assert runner._view('c', 'd') == [rows[2]]
    assert runner.statistics()['repository_views'] == 2
