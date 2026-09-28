#!/usr/bin/env python3
"""Append the separate structured-text scope to the frozen AIDev v047 inventory."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import json
from pathlib import Path

import build_type_inventory_v046 as shared


def collect(base):
    base = Path(base).resolve(); docs = base / 'docs'; shared.READS.clear()
    prior_path = docs / 'aidev_observed_types_v047_provenance.json'
    prior = shared.read(prior_path)
    for path, expected in prior['output_sha256'].items():
        shared.blob(path)
        if shared.READS[str(Path(path).resolve())] != expected: raise ValueError('Frozen v047 inventory changed')
    rows = shared.records(docs / 'aidev_observed_types_v047.jsonl')
    outside = shared.records(docs / 'aidev_observed_types_v047_outside_catalog.jsonl')
    if len(rows) != 294 or any(r['dataset'] != 'aidev' for r in rows + outside):
        raise ValueError('Expected the complete AIDev-only v047 inventory')
    catalog = {(r['category'], r['subtype']): r['subtype_label'] for r in rows}
    if len(catalog) != 42 or prior['taxonomy_version'] != '1.0.0': raise ValueError('Catalog differs')
    run = base / 'structured-runs/aidev-v048'
    with (run / '.structured.lock').open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        state = shared.read(run / 'export_state.json'); manifest = shared.read(run / 'manifest.json')
        coverage = shared.read(run / 'structured_coverage.json')
        if (state['status'] != 'complete' or state['fingerprint'] != manifest['fingerprint']
                or manifest['dataset'] != 'aidev' or manifest['fingerprint']['taxonomy_version'] != '1.0.0'
                or coverage['source_manifest_sha256'] != manifest['source_manifest_sha256']
                or not coverage['all_source_rows_visited'] or coverage['status'] != 'complete_with_semantic_gaps'):
            raise ValueError('Structured run must have a complete, consistent export and all rows visited')
        path = run / 'structured_type_summary.jsonl.gz'; summary = shared.records(path)
        for file in (path, run / 'structured_coverage.json'):
            if shared.READS[str(file)] != state['outputs'][file.name]['sha256']:
                raise ValueError('Structured summary differs from its export snapshot')
        if any(s['source_manifest_sha256'] != manifest['source_manifest_sha256'] for s in prior['sources'] if 'source_manifest_sha256' in s):
            raise ValueError('AIDev sources refer to different frozen imports')
        index = {}
        for row in summary:
            key = row['category'], row['subtype']; shared.number(row['candidate_occurrences'])
            if (key in index or key not in set(catalog) | {(None, None)} or row['observation_scope'] != 'dataset_structured_text'
                    or row['human_review_status'] != 'pending' or row['runtime_confirmed'] is not False
                    or row['application_log_evidence'] is not False or row['full_dataset_coverage_claim'] is not False):
                raise ValueError('Structured summary labels or evidence scope differ')
            index[key] = row['candidate_occurrences']
        if set(index) != set(catalog) | {(None, None)} or sum(index.values()) != coverage['candidate_occurrences']:
            raise ValueError('Structured summary omits zero labels or differs from coverage')
        source = shared.source_metadata(path, 'aidev', 'dataset_structured_text',
            'source_cell_document_ordinal_node_decoded_span_and_finite_match_details', coverage['status'],
            'unavailable_per_type_in_structured_summary')
        source.update(source_manifest_sha256=manifest['source_manifest_sha256'],
            manifest_sha256=shared.READS[str(run/'manifest.json')], export_state_sha256=shared.READS[str(run/'export_state.json')],
            implementation_sha256=manifest['fingerprint']['source_sha256'], limits=manifest['fingerprint']['limits'],
            source_snapshot_counts={k: coverage[k] for k in ('processed_rows', 'documents', 'candidate_occurrences', 'excluded_occurrences', 'data_gap_records', 'unknown_review_source_cells')})
        rows += [shared.source_row(source, key, label, index[key]) for key, label in sorted(catalog.items())]
        outside.append(shared.source_row(source, (None, None), 'Unclassified JSON values; zero does not establish absence', index[(None, None)], controlled=False))
        for file, expected in shared.READS.items():
            if hashlib.sha256(Path(file).read_bytes()).hexdigest() != expected: raise ValueError('Summary input changed while building')
    observed = {(r['category'], r['subtype']) for r in rows if r['count_within_processed_scope']}
    counts = Counter(r['observation_scope'] for r in rows)
    if len(rows) != 336 or len({(r['source_run'],r['observation_scope'],r['category'],r['subtype']) for r in rows}) != 336:
        raise ValueError('Expected eight separate sources and every controlled type')
    provenance = {'recorded_utc': datetime.now(timezone.utc).isoformat(), 'dataset': 'aidev',
        'taxonomy_version': '1.0.0', 'catalog_subtypes': 42, 'row_count': len(rows),
        'sources': prior['sources'] + [source], 'historical_source_rows_preserved': 294,
        'historical_rows_recomputed': False, 'input_summary_sha256': dict(shared.READS),
        'observed_catalog_type_union': sorted(observed), 'observed_catalog_type_union_count': len(observed),
        'inventory_rows_by_scope': dict(counts), 'counts_additive_across_scopes_or_runs': False,
        'new_observation_does_not_mean_new_cell_type': True,
        'candidate_status_counts_note': 'Empty status maps on structured rows mean per-type status counts are unavailable in the summary, not zero candidates.',
        'zero_means': 'No observed candidate in the processed source scope; not absence in the complete dataset.',
        'source_values_or_value_hashes_read': False, **shared.SCOPE}
    return rows, outside, provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-dir', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--check-only', action='store_true'); args = parser.parse_args()
    rows, outside, provenance = collect(args.base_dir)
    if not args.check_only:
        targets = [args.base_dir.resolve()/'docs'/f'aidev_observed_types_v048{s}' for s in ('.csv','.jsonl','_outside_catalog.csv','_outside_catalog.jsonl','_provenance.json')]
        if any(p.exists() for p in targets): raise FileExistsError('Preserve the existing v048 inventory')
        for path, items in zip(targets[:-1], (rows,rows,outside,outside)): shared.write_grid(path, items)
        provenance['builder_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        provenance['helper_sha256'] = hashlib.sha256(Path(shared.__file__).read_bytes()).hexdigest()
        provenance['output_sha256'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in targets[:-1]}
        targets[-1].write_text(json.dumps(provenance, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'rows':len(rows),'sources':8,'observed_labels':provenance['observed_catalog_type_union_count'],
                      'files_written':not args.check_only,'counts_additive':False}))


if __name__ == '__main__': main()
