"""Real Git/PyDriller checks for conservative unified history matching."""
import pytest

from agentlog_unified.analysis import detect_history
from agentlog_unified.matching import entity_key, resolve_match
from synthetic_histories import HEADER, RISK, SAFE, commit, init, pipeline
import synthetic_histories


def test_format_only_call_and_dependency_edit_is_not_behavior_change(tmp_path):
    init(tmp_path)
    intro = commit(tmp_path, {'app.py': RISK}, 'initial', day=2)
    formatted = RISK.replace('payload = {"active": True, "password": "DUMMY_RESEARCH_SECRET_NOT_VALID"}',
                             'payload = {\n "active": True,\n "password": "DUMMY_RESEARCH_SECRET_NOT_VALID",\n}')
    formatted = formatted.replace('logger.info("user=%s", payload)', 'logger.info(\n    "user=%s",\n    payload,\n)')
    end = commit(tmp_path, {'app.py': formatted}, 'format only', actor='human', day=3)
    result = pipeline(tmp_path, end, [intro])
    assert result['mined']['metrics']['pydriller_commits'] == 2
    assert result['followups'] == []
    assert not any(e['sha'] == end for e in result['detected']['events'])


def test_unique_function_move_to_existing_file_then_fix(tmp_path):
    init(tmp_path)
    function = 'def handle():\n    logger.info("received", extra={"password": "DUMMY_RESEARCH_SECRET_NOT_VALID"})\n'
    intro = commit(tmp_path, {'a.py': HEADER + function + '\ndef stay():\n    return 1\n',
                              'b.py': HEADER + 'def existing():\n    return 2\n'}, 'initial', day=2)
    moved = commit(tmp_path, {'a.py': HEADER + 'def stay():\n    return 1\n',
                              'b.py': HEADER + 'def existing():\n    return 2\n\n' + function}, 'move function', day=3)
    fixed = commit(tmp_path, {'b.py': (HEADER + 'def existing():\n    return 2\n\n' + function).replace('"password"', '"token_count"')},
                   'remove sensitive field', actor='human', day=4)
    result = pipeline(tmp_path, fixed, [intro])
    move = next(f for f in result['followups'] if f['sha'] == moved)
    assert move['behavior_match_status'] == 'unique_cross_file_semantic'
    assert move['before']['path'] == 'a.py' and move['after']['path'] == 'b.py'
    assert result['candidates'][0]['fix_sha'] == fixed


def test_duplicate_cross_file_destinations_stay_ambiguous(tmp_path):
    init(tmp_path)
    function = 'def handle():\n    logger.info("received", extra={"password": "DUMMY_RESEARCH_SECRET_NOT_VALID"})\n'
    source = HEADER + 'def stay():\n    return 1\n'
    intro = commit(tmp_path, {'a.py': source + function, 'b.py': source, 'c.py': source}, 'initial', day=2)
    end = commit(tmp_path, {'a.py': source, 'b.py': source + function, 'c.py': source + function}, 'duplicate movement', actor='human', day=3)
    result = pipeline(tmp_path, end, [intro])
    changed = [e for e in result['detected']['events'] if e['sha'] == end]
    assert len(changed) == 3
    assert all(e['behavior_match_status'] == 'ambiguous' for e in changed)
    assert all(r['fix_sha'] is None for r in result['candidates'])


@pytest.mark.parametrize('restored', [SAFE, RISK])
def test_parse_gap_resumes_without_inventing_deletion_or_precise_fix(tmp_path, restored):
    init(tmp_path)
    intro = commit(tmp_path, {'app.py': RISK}, 'initial', day=2)
    broken = commit(tmp_path, {'app.py': RISK + '\ndef broken(:\n'}, 'syntax break', actor='human', day=3)
    end = commit(tmp_path, {'app.py': restored}, 'parse again', actor='human', day=4)
    result = pipeline(tmp_path, end, [intro])
    events = result['detected']['events']
    assert not any(e['sha'] == broken and e['change_kind'] == 'deleted' for e in events)
    opened = next(f for f in result['followups'] if f['sha'] == broken)
    resumed = next(f for f in result['followups'] if f['sha'] == end)
    assert opened['change_kind'] == 'coverage_gap'
    assert resumed['change_kind'] == 'gap_resumed'
    assert resumed['gap_interval'] == {'last_observed_sha': intro, 'start_sha': broken, 'end_sha': end}
    assert resumed['fix_effect'] == 'unknown' and resumed['fix_executor_type'] == 'unknown'
    assert resumed['effective_target_sha'] is None
    assert resumed['time_source'] == 'interval_censored'
    assert result['candidates'][0]['fix_sha'] is None
    assert result['candidates'][0]['screening_bucket'] == 'NEEDS_CONTEXT'


def test_broken_dependency_does_not_become_sanitizer_fix(tmp_path):
    init(tmp_path)
    code = HEADER + 'from serialization import serialize\ndef handle():\n    value = {"password": "DUMMY_RESEARCH_SECRET_NOT_VALID"}\n    logger.info("value=%s", serialize(value))\n'
    intro = commit(tmp_path, {'app.py': code, 'serialization.py': 'def serialize(value):\n    return value\n'}, 'initial', day=2)
    broken = commit(tmp_path, {'serialization.py': 'def serialize(value):\n    return value\ndef broken(:\n'}, 'break dependency', day=3)
    end = commit(tmp_path, {'serialization.py': 'def serialize(value):\n    return {"token_count": 1}\n'}, 'restore narrow serializer', day=4)
    result = pipeline(tmp_path, end, [intro])
    assert any(f['sha'] == broken and f['change_kind'] == 'coverage_gap' for f in result['followups'])
    assert any(f['sha'] == end and f['change_kind'] == 'gap_resumed' for f in result['followups'])
    assert result['candidates'][0]['fix_sha'] is None


def test_csharp_broken_string_is_history_gap_not_deleted_log(tmp_path):
    init(tmp_path)
    source = 'class App { void Run() { logger.LogInformation("value={Password}", user.Password); } }\n'
    intro = commit(tmp_path, {'App.cs': source}, 'initial C# log', day=2)
    broken = commit(tmp_path, {'App.cs': 'class App { string text = "unterminated\n' + source},
                    'break string boundary', actor='human', day=3)
    end = commit(tmp_path, {'App.cs': 'class App { void Run() {} }\n'}, 'restore source', actor='human', day=4)
    result = pipeline(tmp_path, end, [intro])
    assert not any(e['sha'] == broken and e['change_kind'] == 'deleted' for e in result['detected']['events'])
    opened = next(f for f in result['followups'] if f['sha'] == broken)
    resumed = next(f for f in result['followups'] if f['sha'] == end)
    assert opened['change_kind'] == 'coverage_gap'
    assert resumed['change_kind'] == 'gap_resumed'
    assert resumed['gap_interval'] == {'last_observed_sha': intro, 'start_sha': broken, 'end_sha': end}
    assert resumed['fix_effect'] == 'unknown' and resumed['effective_target_sha'] is None


def test_verified_human_pair_can_be_replayed_without_confirming_privacy(tmp_path, monkeypatch):
    init(tmp_path)
    duplicate = HEADER + '''def handle():
    logger.info("received", extra={"password": "DUMMY_RESEARCH_SECRET_NOT_VALID"})
    logger.info("received", extra={"access_token": "DUMMY_RESEARCH_SECRET_NOT_VALID"})
'''
    remaining = HEADER + '''def handle():
    logger.info("received", extra={"refresh_token": "DUMMY_RESEARCH_SECRET_NOT_VALID"})
'''
    intro = commit(tmp_path, {'app.py': duplicate}, 'initial duplicates', day=2)
    end = commit(tmp_path, {'app.py': remaining}, 'one remaining', day=3)
    result = pipeline(tmp_path, end, [intro])
    event = next(e for e in result['detected']['events'] if e['sha'] == end and e.get('match_candidates'))
    choice = next(c for c in event['match_candidates'] if c['after_key'])
    snapshots = {s['sha']: s for s in result['detected']['snapshots']}
    old = next(e for e in snapshots[intro]['entities'] if entity_key(e) == choice['before_key'])
    new = next(e for e in snapshots[end]['entities'] if entity_key(e) == choice['after_key'])
    resolved = resolve_match(snapshots[intro], snapshots[end], choice['before_key'], choice['after_key'],
                             [{'before': old, 'after': new}], 'human-reviewer')
    assert resolved['match_review']['scope'] == 'entity_pair_only'
    with pytest.raises(ValueError, match='not among'):
        resolve_match(snapshots[intro], snapshots[end], choice['before_key'], choice['after_key'], [], 'human-reviewer')
    override = {**choice, 'repository_id': 'synthetic-repository', 'before_sha': intro,
                'after_sha': end, 'reviewer': 'human-reviewer'}
    monkeypatch.setattr(synthetic_histories, 'detect_history', lambda repo, mined, cfg:
                        detect_history(repo, mined, cfg, match_overrides=[override]))
    reviewed = pipeline(tmp_path, end, [intro])
    replay = next(e for e in reviewed['detected']['events'] if e.get('match_review'))
    assert replay['machine_match_status'] == 'ambiguous'
    assert replay['behavior_match_status'] == 'human_confirmed_pair'
    assert all(r['human_review_status'] == 'pending' for r in reviewed['candidates'])
    assert all(r['runtime_leak_claim'] is False for r in reviewed['candidates'])
    monkeypatch.setattr(synthetic_histories, 'detect_history', lambda repo, mined, cfg:
                        detect_history(repo, mined, cfg, match_overrides=[override, override]))
    with pytest.raises(ValueError, match='one-to-one'):
        pipeline(tmp_path, end, [intro])
