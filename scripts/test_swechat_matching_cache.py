import sys,copy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agentlog_unified import analysis,matching,detector
from swechat_matching_cache import install,CandidateIndex


def test_caches_preserve_semantics_and_ambiguous_candidate_order():
    versions=[{'app.py':s} for s in [
        'import logging\nlogging.info("same")\nlogging.info("same")\nlogging.debug("other")\n',
        'import logging\nlogging.info("same")\nlogging.warning("other")\n',
        'import logging\nlogging.info("same")\nlogging.info("same")\nlogging.debug("other")\n']]
    versions=[{p:source.replace('import logging\n','import logging\nlogger = logging.getLogger(__name__)\n').replace('logging.info','logger.info').replace('logging.debug','logger.debug').replace('logging.warning','logger.warning') for p,source in v.items()} for v in versions]
    snapshots=[detector.detect_snapshot(v)['entities'] for v in versions]
    expected=[matching.match_entities(a,b,'app.py','app.py') for a,b in zip(snapshots,snapshots[1:])]
    keys=[matching.entity_key(e) for batch in snapshots for e in batch]
    behaviors=[matching.behavior(e) for batch in snapshots for e in batch]
    finish=install(analysis,matching)
    try:
        assert [matching.entity_key(e) for batch in snapshots for e in batch]==keys
        assert [matching.behavior(e) for batch in snapshots for e in batch]==behaviors
        assert [matching.match_entities(a,b,'app.py','app.py') for a,b in zip(snapshots,snapshots[1:])]==expected
        rows=[dict(before=a,after=b) for a in snapshots[0] for b in [*snapshots[1],None]]
        rows.extend(copy.deepcopy(rows[:2]))
        index=CandidateIndex(matching.entity_key)
        for before in [*snapshots[0],None]:
            for after in [*snapshots[1],None]:
                exact=[p for p in rows if (before and matching.entity_key(p['before'])==matching.entity_key(before)) or (after and p['after'] and matching.entity_key(p['after'])==matching.entity_key(after))]
                assert index(rows,before,after)==exact
    finally:stats=finish()
    assert stats['entity_key']['hits']>0 and stats['semantic_code']['hits']>0
