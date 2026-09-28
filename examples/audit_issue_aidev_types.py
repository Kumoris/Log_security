"""Link human issue references to frozen AIDev observations; never transfer gold.

Reuses the existing inventory, type candidates and PyDriller exports. Only safe
coordinates and finite labels are exported, never source text or credential values.
"""
import argparse
from collections import Counter, defaultdict
import gzip
import json
from pathlib import Path

from agentlog_unified.config import now, sha256_file
from agentlog_unified.export import write_csv, write_json, write_jsonl
from agentlog_unified.issue_knowledge import load_knowledge
from agentlog_unified.storage import stable_id


def records(path):
    path = Path(path)
    with (gzip.open(path, 'rt') if path.suffix == '.gz' else path.open()) as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def link_types(references, inventory):
    """An exact catalog-pair overlap is a retrieval link, not semantic proof."""
    concepts = {}
    for row in references:
        if row['human_annotation']['origin'] != 'human' or row['human_annotation']['label'] != 'sensitive_information':
            raise ValueError('reference_not_human_sensitive')
        for proposal in row['type_proposals']:
            concept = proposal['concept']; pair = (proposal['category'], proposal['subtype'])
            if concept in concepts and concepts[concept]['pair'] != pair:
                raise ValueError('conflicting_reference_mapping')
            entry = concepts.setdefault(concept, {'concept': concept, 'pair': pair, 'reference_ids': []})
            entry['reference_ids'].append(row['id'])
    links = []
    for row in inventory:
        if row['dataset'] != 'aidev':
            raise ValueError('non_aidev_inventory')
        matches = [c for c in concepts.values() if c['pair'][1] is not None and c['pair'] == (row['category'], row['subtype'])]
        links.append({**row, 'reference_concepts': sorted(c['concept'] for c in matches),
                      'human_sensitive_reference_ids': sorted({rid for c in matches for rid in c['reference_ids']}),
                      'reference_alignment': 'catalog_pair_overlap_only' if matches else 'no_mapped_reference',
                      'target_human_confirmed': False})
    return links, list(concepts.values())


def safe_sample(row, label, path, line, source_run, source_sha256):
    keep = ('table_path', 'source_row', 'column_name', 'start', 'end', 'document_id',
            'document_index', 'source_start', 'source_end', 'decoded_start', 'decoded_end',
            'repository', 'snapshot_sha', 'path', 'start_line', 'end_line', 'parser_status',
            'log_detection_status', 'analysis_method', 'analysis_depth')
    return {k: row[k] for k in keep if k in row} | {
        'id': stable_id(str(path), row['id'], label['category'], label['subtype']),
        'source_record_id': row['id'], 'source_record_line': line,
        'source_file': str(path), 'source_file_sha256': source_sha256, 'source_run': source_run,
        'category': label['category'], 'subtype': label['subtype'],
        'candidate_status': label.get('evidence_status', row.get('candidate_status', 'unknown')),
        'evidence_basis': label.get('evidence_basis', row.get('basis', 'unknown')),
        'observation_scope': row['observation_scope'],
        'target_human_confirmed': False, 'runtime_confirmed': False,
        'history_read': 'reused_pydriller_export' if 'snapshot_sha' in row else 'not_git_evidence',
    }


def observation_labels(row):
    if row['observation_scope'] != 'dataset_commit_changes':
        return [row]
    grouped = defaultdict(list)
    for label in row['taxonomy_labels']:
        grouped[(label['category'], label['subtype'])].append(label)
    result = []
    for (category, subtype), labels in grouped.items():
        statuses = {label['evidence_status'] for label in labels}
        result.append({'category': category, 'subtype': subtype,
                       'evidence_status': next(iter(statuses)) if len(statuses) == 1 else 'mixed_evidence',
                       'evidence_basis': sorted({b for label in labels for b in label['evidence_basis']})})
    return result


def run(base, knowledge, output, *, offline=True, dry_run=False, resume=False):
    base, knowledge, output = (Path(p).resolve() for p in (base, knowledge, output))
    if not offline:
        raise ValueError('this_audit_is_offline_only')
    if dry_run:
        return {'status': 'dry_run', 'files_written': False, 'model_calls': 0}
    references = load_knowledge(knowledge)
    inventory_path = base/'docs/aidev_observed_types_v050.jsonl'
    provenance_path = base/'docs/aidev_observed_types_v050_provenance.json'
    provenance = json.loads(provenance_path.read_text())
    if provenance['dataset'] != 'aidev' or sha256_file(inventory_path) != provenance['output_sha256'][str(inventory_path)]:
        raise ValueError('inventory_provenance_mismatch')
    all_rows = list(records(inventory_path))
    inventory = [r for r in all_rows if r['observation_scope'] == 'dataset_commit_changes' or r['source_run'] == 'aidev-v050']
    links, concepts = link_types(references, inventory)
    inputs = {inventory_path, provenance_path, knowledge/'manifest.json', Path(__file__).resolve()}
    sources = []
    grouped = defaultdict(list)
    for row in links:
        grouped[(row['observation_scope'], row['source_run'])].append(row)
        path = Path(row['source_path']); inputs.add(path)
        if sha256_file(path) != row['source_sha256']:
            raise ValueError('inventory_summary_changed')
    for (scope, name), summary in sorted(grouped.items()):
        if scope == 'dataset_commit_changes':
            folder = base/'outputs/batches'/name/'exports'; path = folder/'type_occurrences.jsonl'
            coverage_path = folder/'summary.json'; coverage = json.loads(coverage_path.read_text())
            if not coverage['actual_extraction_metrics'].get('pydriller_commits'):
                raise ValueError('missing_pydriller_provenance')
        elif scope == 'dataset_text_reconciled':
            folder = base/'outputs/reconciled-runs'/name; path = folder/'merged_type_occurrences.jsonl.gz'
            coverage_path = folder/'merged_coverage.json'
            manifest_path = folder/'manifest.json'; inputs.add(manifest_path)
            manifest = json.loads(manifest_path.read_text())
            if manifest['status'] != 'complete' or sha256_file(path) != manifest['outputs'][path.name]['sha256']:
                raise ValueError('text_snapshot_changed_or_incomplete')
        elif scope == 'dataset_structured_text':
            folder = base/'outputs/structured-runs'/name; path = folder/'structured_type_occurrences.jsonl.gz'
            coverage_path = folder/'structured_coverage.json'
            state_path = folder/'export_state.json'; inputs.add(state_path)
            state = json.loads(state_path.read_text())
            if state['status'] != 'complete' or sha256_file(path) != state['outputs'][path.name]['sha256']:
                raise ValueError('structured_snapshot_changed_or_incomplete')
        else:
            raise ValueError('unsupported_inventory_scope')
        inputs.update((path, coverage_path))
        sources.append((scope, name, path, coverage_path, summary))
    inputs.add(base/'outputs/schema-runs/aidev-v047/schema_coverage.json')
    hashes = {str(p): sha256_file(p) for p in sorted(inputs)}
    fingerprint = {'inputs': hashes, 'examples_per_type_and_scope': 2}
    if (output/'manifest.json').exists():
        manifest = json.loads((output/'manifest.json').read_text())
        if not resume or manifest['fingerprint'] != fingerprint:
            raise ValueError('incompatible_run_use_new_directory')
        for name, expected in manifest['artifacts'].items():
            if Path(name).is_absolute() or '..' in Path(name).parts or sha256_file(output/name) != expected:
                raise ValueError('audit_output_integrity_mismatch')
        return {**json.loads((output/'coverage.json').read_text()), 'resumed_without_scan': True}
    if output.exists() and any(output.iterdir()):
        raise ValueError('output_directory_not_empty')
    by_pair = {(r['category'], r['subtype']): r for r in links if r['reference_concepts']}
    samples = defaultdict(list); audits = []
    # ponytail: replay frozen candidate exports; broader semantics needs new source analysis, not more labels here.
    rank = {'named_value_candidate': 0, 'literal_candidate': 1, 'sensitive_value_candidate': 0,
            'identifier_reference': 2, 'carrier_candidate': 3}
    for scope, name, path, coverage_path, summary in sources:
        counts = Counter(); statuses = Counter(); processed = 0
        for line, row in enumerate(records(path), 1):
            processed += 1
            if row['observation_scope'] != scope:
                raise ValueError('occurrence_scope_mismatch')
            labels = observation_labels(row)
            for label in labels:
                pair = (label['category'], label['subtype']); counts[pair] += 1
                status = label.get('evidence_status', row.get('candidate_status', 'unknown')); statuses[status] += 1
                if pair not in by_pair:
                    continue
                group = samples[(scope, *pair)]
                if len(group) == 2 and rank.get(status, 2) >= group[-1][0]:
                    continue
                sample = safe_sample(row, label, path, line, name, hashes[str(path)])
                sample.update(reference_concepts=by_pair[pair]['reference_concepts'],
                              human_sensitive_reference_ids=by_pair[pair]['human_sensitive_reference_ids'],
                              reference_alignment='catalog_pair_overlap_only')
                # Keep at most two distinct source positions for each type/scope.
                location = (sample.get('repository'), sample.get('snapshot_sha'), sample.get('path'), sample.get('start_line'),
                            sample.get('table_path'), sample.get('source_row'), sample.get('column_name'))
                if any(item[1] == location for item in group):
                    continue
                group.append((rank.get(status, 2), location, sample))
                group.sort(key=lambda item: (item[0], item[2]['id'])); del group[2:]
        for row in summary:
            actual = counts[(row['category'], row['subtype'])]
            expected = row.get('candidate_variant_count')
            if expected is None:
                expected = row['count_within_processed_scope']
            if expected is not None and actual != expected:
                raise ValueError(f'candidate_summary_mismatch:{scope}:{name}:{row["subtype"]}')
        coverage = json.loads(coverage_path.read_text())
        audits.append({'scope': scope, 'source_run': name, 'candidate_export_rows_read': processed,
                       'type_labels_observed': len([p for p, n in counts.items() if n and p[1] is not None]),
                       'reference_aligned_type_labels': sum(bool(counts[p]) for p in by_pair),
                       'candidate_status_counts': dict(statuses),
                       'outside_catalog_observations': counts[(None, None)],
                       'source_coverage_file': str(coverage_path), 'source_coverage_sha256': hashes[str(coverage_path)],
                       'source_limitations': coverage.get('limitations', []),
                       'upstream_processed_rows': coverage.get('processed_rows'),
                       'upstream_unknown_review_records': coverage.get('unknown_review_range_records', coverage.get('unknown_type_review_cells')),
                       'upstream_data_gap_records': coverage.get('data_gap_records', coverage.get('repair_data_gap_records'))})
    if any(sha256_file(Path(p)) != digest for p, digest in hashes.items()):
        raise ValueError('input_changed_during_audit')
    examples = [item[2] for group in samples.values() for item in group]
    mapping = [{**c, 'category': c['pair'][0], 'subtype': c['pair'][1],
                'mapping_status': 'existing_rule_mapping' if c['pair'][1] else 'unmapped_or_split_pending',
                'type_origin': 'existing_rule_proposal', 'human_label_scope': 'issue_group_sensitivity'} for c in concepts]
    queue = [{'issue_reference_id': r['id'], 'reason': 'reference_type_unknown', 'human_sensitive_reference': True}
             for r in references if not r['type_proposals']]
    queue += [{'concept': c['concept'], 'reference_ids': c['reference_ids'], 'reason': 'unmapped_or_split_pending'}
              for c in mapping if c['subtype'] is None]
    schema = json.loads((base/'outputs/schema-runs/aidev-v047/schema_coverage.json').read_text())
    report = {'status': 'complete', 'created_at': now(), 'human_sensitive_references_retained': len(references),
              'references_with_concepts': sum(bool(r['type_proposals']) for r in references),
              'reference_concepts': len(concepts), 'mapped_reference_concepts': sum(c['pair'][1] is not None for c in concepts),
              'reference_types_with_aidev_observations': len({(r['category'], r['subtype']) for r in links if r['reference_concepts'] and r['observed_within_processed_scope']}),
              'inventory_rows_checked': len(links), 'historical_inventory_rows_not_combined': len(all_rows)-len(links),
              'sources': audits, 'evidence_examples': len(examples), 'unknown_reference_queue_records': len(queue),
              'schema_context': {'scope': 'dataset_metadata_only_not_reanalysed',
                                 'unresolved_field_records': schema['unresolved_field_records'],
                                 'account_reference_coverage': schema['account_reference_coverage']},
              'cross_scope_or_cross_run_counts_additive': False, 'new_type_detections': 0,
              'new_git_history_reads': 0, 'model_calls': 0, 'target_code_executed': False,
              'aidev_target_human_confirmations': 0, 'accuracy': None, 'recall': None,
              'interpretation': 'reference-linked existing candidates, not new detections or sensitivity confirmation of target data'}
    tables = {'human_sensitive_references': references, 'reference_type_crosswalk': mapping,
              'aidev_type_links': links, 'reference_review_queue': queue, 'aidev_reference_examples': examples}
    for name, rows in tables.items():
        write_jsonl(output/(name+'.jsonl'), rows); write_csv(output/(name+'.csv'), rows)
    for row in examples:
        write_json(output/'evidence'/(row['id']+'.json'), row)
    write_json(output/'coverage.json', report)
    write_json(output/'manifest.json', {'status': 'complete', 'fingerprint': fingerprint,
               'artifacts': {str(p.relative_to(output)): sha256_file(p) for p in output.rglob('*') if p.is_file()}})
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--knowledge', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--dry-run', action='store_true'); parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    print(json.dumps(run(args.base, args.knowledge, args.output, offline=args.offline,
                         dry_run=args.dry_run, resume=args.resume), ensure_ascii=False, indent=2))
