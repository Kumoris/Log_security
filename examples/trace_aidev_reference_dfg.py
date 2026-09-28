"""Freeze exact historical use sites from the existing AIDev reference audit.

Reuse the miner, log detector, use-site extractor and DFG exporter. Dataset text
without a code coordinate is retained as unbound, never turned into a log use.
Raw history is stored only in the mode-0600 local checkpoint.
"""
import argparse
from collections import Counter
import json
from pathlib import Path

from agentlog_unified.batch_mine import repository_cache_path
from agentlog_unified.config import now, sha256_file
from agentlog_unified.detector import detect_snapshot, LANGUAGES
from agentlog_unified.export import write_csv, write_json, write_jsonl
from agentlog_unified.miner import mine_repository, snapshot_files
from agentlog_unified.semantic_evidence import digest
from agentlog_unified.semantic_scan import use_sites
from agentlog_unified.storage import Store, redact, stable_id


def freeze(audit, output, cache, *, dry_run=False, resume=False, max_cases=100, repo_map=None):
    audit, output, cache = Path(audit), Path(output), Path(cache)
    if not 1 <= max_cases <= 100:
        raise ValueError('case_budget_1_to_100')
    if dry_run:
        return {'status': 'dry_run', 'files_written': False, 'network_calls': 0}
    manifest = json.loads((audit/'manifest.json').read_text())
    for name, expected in manifest['artifacts'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts or sha256_file(audit/name) != expected:
            raise ValueError('input_audit_integrity_mismatch')
    repo_map = {k: str(Path(v).resolve()) for k, v in (repo_map or {}).items()}
    fingerprint = {'audit_manifest': sha256_file(audit/'manifest.json'), 'max_cases': max_cases, 'repo_map': repo_map,
                   'cache': str(cache.resolve()), 'runner': sha256_file(Path(__file__)),
                   'sources': {p.name: sha256_file(p) for p in Path(__file__).resolve().parents[1].joinpath('src/agentlog_unified').glob('*.py')}}
    if output.exists() and any(output.iterdir()):
        old = json.loads((output/'manifest.json').read_text())
        if not resume or old['fingerprint'] != fingerprint:
            raise ValueError('input_or_code_changed_use_new_output')
        if any(sha256_file(output/p) != h for p, h in old['artifact_sha256'].items()):
            raise ValueError('output_integrity_mismatch')
        return {**json.loads((output/'coverage.json').read_text()), 'resumed_without_reprocessing': True}
    examples = [json.loads(x) for x in (audit/'aidev_reference_examples.jsonl').read_text().splitlines()]
    source_files = {}; records = []; excluded = []; gaps = []; units = {}; links = []; evidence = {}
    metrics = Counter(); extraction = []
    for example in examples:
        if not example.get('snapshot_sha'):
            excluded.append({'id': example['id'], 'reason': 'dataset_observation_without_historical_log_binding'})
            continue
        p = Path(example['source_file'])
        if p not in source_files:
            if sha256_file(p) != example['source_file_sha256']:
                raise ValueError('source_record_file_integrity_mismatch')
            source_files[p] = [json.loads(x) for x in p.read_text().splitlines()]
        original = source_files[p][example['source_record_line']-1]
        if original['id'] != example['source_record_id'] or any(original[k] != example[k] for k in ('repository','snapshot_sha','path','start_line','end_line')):
            raise ValueError('source_record_coordinate_mismatch')
        records.append((example, original))
    mined_cache = {}; snapshot_cache = {}; detections = {}
    store = Store(output/'checkpoint.sqlite')
    try:
        for example, original in records:
            repository = example['repository']; revision = example['snapshot_sha']; path = example['path']
            key = (repository, revision); local = Path(repo_map.get(repository) or repository_cache_path(cache, repository))
            if not local.is_dir():
                gaps.append({'id': example['id'], 'reason': 'local_repository_missing'}); continue
            unit = units.setdefault(repository, {'id': stable_id(repository), 'repository': repository, 'snapshots': {}, 'mined': []})
            events = [e for e in original['event_references'] if e['snapshot_sha'] == revision]
            if not events:
                gaps.append({'id': example['id'], 'reason': 'historical_event_link_missing'}); continue
            for event in events:
                mining_key = (repository, event['sha'])
                if mining_key not in mined_cache:
                    mined = mine_repository(str(local), event['sha'], [event['sha']], max_commits=1)
                    mined_cache[mining_key] = mined; unit['mined'].append(mined)
                    metrics.update(mined['metrics'])
                    gaps.extend(dict(g, repository=repository) for g in mined['gaps'])
                    for change in mined['changes']:
                        extraction.append({'id': change['change_id'], 'repository': repository,
                            **{k: v for k, v in change.items() if k not in {'before_source','after_source','added','deleted','diff'}}})
                mined = mined_cache[mining_key]
                if key not in snapshot_cache:
                    raw = snapshot_files(str(local), revision, max_files=500)
                    # Prefer actual PyDriller ModifiedFile source on changed files.
                    for change in mined['changes']:
                        for side, version, file_path in [('before', change['parent_sha'], change['old_path']),
                                                          ('after', change['sha'], change['new_path'])]:
                            if version == revision and file_path and change.get(side+'_source') is not None:
                                raw['files'][file_path] = change[side+'_source']
                                raw.setdefault('file_provenance', {})[file_path] = {
                                    'backend': change['source_backends'][side],
                                    'fallback_reason': change.get('source_fallback_reasons', {}).get(side),
                                    'change_id': change['change_id'], 'side': side}
                    snapshot_cache[key] = raw; unit['snapshots'][revision] = raw
                    gaps.extend(dict(g, repository=repository) for g in raw['gaps'])
            raw = snapshot_cache[key]
            if path not in raw['files']:
                gaps.append({'id': example['id'], 'reason': 'historical_source_missing'}); continue
            if key not in detections:
                detections[key] = detect_snapshot(raw['files'])
                metrics['snapshot_log_entities_detected'] += len(detections[key]['entities'])
                gaps.extend(dict(g, repository=repository, sha=revision) for g in detections[key]['gaps'])
            matches = [e for e in detections[key]['entities'] if e['path'] == path
                       and e['start_line'] == example['start_line'] and e['end_line'] == example['end_line']
                       and redact(e['statement']) == original['statement']]
            if len(matches) != 1:
                gaps.append({'id': example['id'], 'reason': 'exact_historical_log_statement_not_unique_or_not_reproduced'}); continue
            entity = matches[0]; sites, omitted = use_sites(entity, raw['files'])
            for item in omitted:
                excluded.append({'id': stable_id(example['id'], item), 'example_id': example['id'], 'details': item})
            if not sites:
                gaps.append({'id': example['id'], 'reason': 'no_use_sites_in_log'}); continue
            for site in sites:
                case_id = stable_id(repository, revision, path, entity['identity'], site)
                if not site.get('anchor'):
                    gaps.append({'id': case_id, 'example_id': example['id'], 'reason': 'ast_use_anchor_unavailable'}); continue
                if case_id not in evidence and len(evidence) >= max_cases:
                    excluded.append({'id': case_id, 'example_id': example['id'], 'reason': 'case_budget'}); continue
                row = {'id': case_id, 'repository': repository, 'sha': revision, 'path': path,
                       'field': site['field'], 'scope': entity['symbol'], 'language': LANGUAGES[Path(path).suffix],
                       'use_anchor': site['anchor'], 'use_role': site['field_origin'], 'side': events[0]['side'],
                       'output_expression_anchor': site.get('output_expression_anchor'), 'context': {'gaps': []}}
                evidence[case_id] = {'id': case_id, 'result': row, 'source_versions': [
                    {'path': path, 'sha': revision, 'source_sha256': digest(raw['files'][path])}],
                    'log_start_line': entity['start_line'], 'log_end_line': entity['end_line'],
                    'log_statement_sha256': digest(entity['statement']), 'history_event_id': events[0]['id']}
                links.append({'id': stable_id(example['id'], case_id), 'example_id': example['id'],
                    'case_id': case_id, 'reference_ids': example['human_sensitive_reference_ids'],
                    'reference_concepts': example['reference_concepts'],
                    'inherited_candidate_type': [example['category'], example['subtype']],
                    'label_scope': 'original_log_candidate_not_every_argument',
                    'target_human_confirmed': False, 'type_inference': 'not_performed'})
        store.replace('mined_units', list(units.values())); store.db.commit()
    finally:
        store.close()
    for key, case in evidence.items():
        write_json(output/'evidence'/(key+'.json'), case)
    for name, rows in [('reference_links', links), ('exclusions', excluded), ('gaps', gaps), ('extraction_audit', extraction)]:
        write_jsonl(output/(name+'.jsonl'), rows); write_csv(output/(name+'.csv'), rows)
    coverage = {'input_examples': len(examples), 'code_examples': len(records),
                'code_examples_with_uses': len({r['example_id'] for r in links}), 'use_cases': len(evidence),
                'repositories': len(units), 'historical_snapshots': len(snapshot_cache), 'metrics': dict(metrics),
                'exclusions': len(excluded), 'gap_records': len(gaps),
                'missing_code_examples': sorted({r['id'] for r, _ in records}-{r['example_id'] for r in links}),
                'selection': 'all_arguments_of_existing_purposive_code_examples_not_a_recall_sample',
                'network_calls': 0, 'target_code_executed': False, 'model_calls': 0,
                'history_scope': 're_read_selected_event_commits_and_snapshots_not_full_history',
                'max_snapshot_files': 500, 'max_source_bytes': 2097152}
    write_json(output/'coverage.json', coverage)
    write_json(output/'manifest.json', {'status': 'complete', 'created_at': now(), 'fingerprint': fingerprint,
        'artifact_sha256': {str(p.relative_to(output)): sha256_file(p) for p in output.rglob('*') if p.is_file()}})
    return coverage


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache-dir', type=Path, required=True)
    parser.add_argument('--offline', action='store_true', help='always offline; documents the execution policy')
    parser.add_argument('--dry-run', action='store_true'); parser.add_argument('--resume', action='store_true')
    parser.add_argument('--max-cases', type=int, default=100)
    parser.add_argument('--repo-map', type=Path, help='JSON object mapping repository IDs to existing local caches')
    args = parser.parse_args()
    print(json.dumps(freeze(args.input, args.output, args.cache_dir, dry_run=args.dry_run,
                           resume=args.resume, max_cases=args.max_cases,
                           repo_map=json.loads(args.repo_map.read_text()) if args.repo_map else None), ensure_ascii=False))
