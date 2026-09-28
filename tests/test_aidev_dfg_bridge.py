import importlib.util
import json
from pathlib import Path

import pytest

from agentlog_unified.batch_mine import repository_cache_path
from agentlog_unified.config import sha256_file
from agentlog_unified.detector import detect_snapshot
from agentlog_unified.export import write_json, write_jsonl
from agentlog_unified.semantic_dfg import export_dfg
from synthetic_histories import init, commit, HEADER

spec = importlib.util.spec_from_file_location('aidev_dfg_bridge', Path(__file__).parents[1]/'examples/trace_aidev_reference_dfg.py')
bridge = importlib.util.module_from_spec(spec); spec.loader.exec_module(bridge)


def test_synthetic_reference_coordinates_to_pydriller_to_caller_graph(tmp_path):
    cache = tmp_path/'cache'; cache.mkdir(); repo = repository_cache_path(cache, 'fixture/repo'); init(repo)
    source = HEADER+'def emit(data):\n    logger.info(data)\nemit(True)\n'
    sha = commit(repo, {'app.py': source}, 'synthetic caller')
    entity = detect_snapshot({'app.py': source})['entities'][0]
    row = {**entity, 'id': 'source', 'repository': 'fixture/repo', 'snapshot_sha': sha,
           'event_references': [{'id': 'event', 'sha': sha, 'side': 'after', 'snapshot_sha': sha}]}
    original = tmp_path/'original.jsonl'; write_jsonl(original, [row])
    example = {k: row[k] for k in ('repository','snapshot_sha','path','start_line','end_line')}
    example.update(id='example', source_record_id='source', source_record_line=1, source_file=str(original),
        source_file_sha256=sha256_file(original), human_sensitive_reference_ids=['reference'],
        reference_concepts=['test'], category='QID', subtype='test')
    audit = tmp_path/'audit'; write_jsonl(audit/'aidev_reference_examples.jsonl', [example, {'id': 'unbound'}])
    write_json(audit/'manifest.json', {'artifacts': {'aidev_reference_examples.jsonl': sha256_file(audit/'aidev_reference_examples.jsonl')}})
    out = tmp_path/'frozen'
    assert bridge.freeze(audit, out, cache, dry_run=True)['files_written'] is False
    assert not out.exists()
    report = bridge.freeze(audit, out, cache)
    assert report['use_cases'] == 1 and report['code_examples_with_uses'] == 1
    assert report['metrics']['pydriller_commits'] == 1
    assert report['metrics']['pydriller_diff_parsed_calls'] > 0
    assert report['metrics']['pydriller_source_reads'] > 0
    assert (out/'checkpoint.sqlite').stat().st_mode & 0o777 == 0o600
    graph = export_dfg(out, tmp_path/'dfg')
    assert graph['resolved_caller_bindings'] == 1
    assert bridge.freeze(audit, out, cache, resume=True)['resumed_without_reprocessing']
    next((out/'evidence').glob('*.json')).write_text('{}')
    with pytest.raises(ValueError, match='integrity_mismatch'):
        bridge.freeze(audit, out, cache, resume=True)
