#!/usr/bin/env python3
"""Build the v046 type-label inventory from terminal, metadata-only summaries.

Run only after both reconciliations stop. No SQLite, occurrence body, or target
source is read. Existing v045 snapshots are never rewritten. Counts across
scopes/runs are not additive; only the set of observed controlled labels is unioned.
"""
from collections import defaultdict
from contextlib import ExitStack
from datetime import datetime, timezone
import argparse
import csv
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path

LOG_RUNS = ('aidev-full-v5', 'swechat-full-v5', 'aidev-anchors-v3', 'aidev-prior-cache-v042',
            'aidev-expansion-v043-final', 'csharp-swechat-v043-final', 'aidev-expansion-v044')
STATUSES = {'literal_candidate', 'named_value_candidate', 'identifier_reference', 'carrier_candidate',
            'placeholder_or_example', 'unknown_named_value', 'schema_context_candidate'}
SCOPE = {'human_review_status': 'pending', 'runtime_confirmed': False,
         'new_type_status': 'not_established', 'full_dataset_coverage_claim': False}
COLUMNS = ['observation_scope', 'dataset', 'source_run', 'count_unit', 'coverage_status',
           'category', 'subtype', 'subtype_label', 'catalog_membership', 'count_within_processed_scope',
           'observed_within_processed_scope', 'candidate_variant_count', 'candidate_status_counts',
           'candidate_status_count_unit', 'excluded_identity_count', 'excluded_variant_count',
           'distinct_candidate_cells', *SCOPE, 'source_path', 'source_sha256']
READS = {}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def blob(path):
    path = Path(path).resolve(); data = path.read_bytes(); digest = hashlib.sha256(data).hexdigest()
    if str(path) in READS and READS[str(path)] != digest:
        raise ValueError('Input summary changed during inventory build')
    READS[str(path)] = digest
    return data


def read(path):
    return json.loads(blob(path))


def records(path):
    data = blob(path)
    if str(path).endswith('.gz'):
        data = gzip.decompress(data)
    return [json.loads(line) for line in data.decode('utf-8').splitlines() if line.strip()]


def number(value):
    if type(value) is not int or value < 0:
        raise ValueError('Summary count must be a nonnegative integer')
    return value


def labels_status(value):
    if not isinstance(value, dict) or not set(value) <= STATUSES:
        raise ValueError('Unexpected candidate-status labels')
    return {key: number(count) for key, count in value.items()}


def source_row(source, key, label, count, *, statuses=None, variants=None,
               excluded_identities=None, excluded_variants=None, distinct_cells=None, controlled=True):
    return {**{key: source[key] for key in ('observation_scope', 'dataset', 'source_run', 'count_unit', 'coverage_status')},
            'category': key[0], 'subtype': key[1], 'subtype_label': label,
            'catalog_membership': 'controlled' if controlled else 'outside_catalog',
            'count_within_processed_scope': number(count), 'observed_within_processed_scope': count > 0,
            'candidate_variant_count': variants, 'candidate_status_counts': statuses or {},
            'candidate_status_count_unit': source['candidate_status_count_unit'],
            'excluded_identity_count': excluded_identities, 'excluded_variant_count': excluded_variants,
            'distinct_candidate_cells': distinct_cells, **SCOPE,
            'source_path': source['path'], 'source_sha256': source['sha256']}


def expand(source, summary, catalog):
    """Identity counts and evidence-variant status counts deliberately differ."""
    indexed = {}; outside = []
    for item in summary:
        if item.get('observation_scope') != source['observation_scope'] or any(item.get(key) != SCOPE[key] for key in ('human_review_status', 'runtime_confirmed', 'new_type_status')) or item.get('application_log_evidence') is not False or item.get('full_dataset_coverage_claim', False) is not False:
            raise ValueError('Summary evidence scope or review status differs')
        key = (item['category'], item['subtype'])
        if key in indexed:
            raise ValueError('Duplicate category/subtype summary row')
        if source['observation_scope'] == 'dataset_text_reconciled':
            count = number(item['candidate_identity_count']); variants = number(item['candidate_variant_count'])
            statuses = labels_status(item['candidate_status_variant_counts'])
            if sum(statuses.values()) != variants or variants < count:
                raise ValueError('Variant/status or identity counts disagree')
            extras = {'statuses': statuses, 'variants': variants,
                      'excluded_identities': number(item['excluded_identity_count']),
                      'excluded_variants': number(item['excluded_variant_count']),
                      'distinct_cells': number(item['distinct_candidate_cells'])}
            if extras['excluded_variants'] < extras['excluded_identities'] or extras['distinct_cells'] > count:
                raise ValueError('Excluded variants or distinct-cell counts disagree')
        else:
            count = number(item['candidate_source_cells'])
            if item.get('candidate_status') != 'schema_context_candidate':
                raise ValueError('Unexpected schema candidate status')
            extras = {'statuses': {'schema_context_candidate': count}}
        indexed[key] = (count, extras)
        if key not in catalog:
            outside.append(source_row(source, key, '目录外／细类待定', count, controlled=False, **extras))
    rows = []
    for key, label in sorted(catalog.items()):
        count, extras = indexed.get(key, (0, {}))
        if source['observation_scope'] == 'dataset_text_reconciled' and key not in indexed:
            extras = {'variants': 0, 'excluded_identities': 0, 'excluded_variants': 0, 'distinct_cells': 0}
        rows.append(source_row(source, key, label, count, **extras))
    return rows, outside


def source_metadata(path, dataset, scope, unit, status, status_unit):
    return {'path': str(path.resolve()), 'sha256': READS[str(path.resolve())], 'dataset': dataset,
            'source_run': path.parent.name, 'observation_scope': scope, 'count_unit': unit,
            'coverage_status': status, 'candidate_status_count_unit': status_unit}


def collect(base):
    READS.clear(); base = Path(base).resolve(); docs = base / 'docs'
    historical_paths = [docs / ('observed_types_v045' + suffix) for suffix in ('.csv', '.jsonl', '_provenance.json')]
    for path in historical_paths:
        blob(path)
    history = read(historical_paths[-1])
    old_sources = {s['source_run']: s for s in history['sources'] if s['observation_scope'] == 'dataset_commit_changes'}
    if set(old_sources) != set(LOG_RUNS) or history['taxonomy_version'] != '1.0.0':
        raise ValueError('Historical batch selection or taxonomy differs')
    catalog_path = docs / 'observed_type_inventory_v044.csv'
    old_rows = list(csv.DictReader(io.StringIO(blob(catalog_path).decode('utf-8'))))
    catalog = {(r['category'], r['subtype']): r['subtype_label'] for r in old_rows}
    if len(old_rows) != len(catalog) or len(catalog) != 42:
        raise ValueError('Expected 42 unique controlled taxonomy labels')
    rows = []; outside = []; sources = []
    for run in LOG_RUNS:
        previous = old_sources[run]
        if previous['sha256'] != READS[str(catalog_path.resolve())]:
            raise ValueError('Historical log inventory changed; refusing to recalculate historical counts')
        source = {**previous, 'dataset': 'swe-chat' if previous['dataset'] in {'swe-chat', 'swechat'} else previous['dataset'],
                  'candidate_status_count_unit': 'unavailable_in_historical_log_summary'}
        sources.append(source)
        for item in old_rows:
            count = int(item[run]); number(count); key = item['category'], item['subtype']
            rows.append(source_row(source, key, catalog[key], count))
    with ExitStack() as stack:
        for dataset, folder_name in (('aidev', 'aidev-v046'), ('swe-chat', 'swechat-v046')):
            for folder, lock_name in ((base / 'reconciled-runs' / folder_name, '.reconcile.lock'),
                                      (base / 'schema-runs' / folder_name, '.schema.lock')):
                lock = stack.enter_context((folder / lock_name).open('rb'))
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        for dataset, folder_name in (('aidev', 'aidev-v046'), ('swe-chat', 'swechat-v046')):
            folder = base / 'reconciled-runs' / folder_name
            manifest = read(folder / 'manifest.json'); coverage = read(folder / 'merged_coverage.json')
            path = folder / 'merged_type_summary.jsonl.gz'; summary = records(path)
            if manifest.get('status') != 'complete' or not manifest.get('source_verification_complete') or not coverage.get('source_verification_complete'):
                raise ValueError('Reconciliation must be terminal and source-verified')
            if manifest.get('taxonomy_version') != '1.0.0' or coverage.get('taxonomy_version') != '1.0.0' or any(r.get('taxonomy_version') != '1.0.0' for r in summary):
                raise ValueError('Reconciled taxonomy version differs from the fixed catalog')
            if coverage['fingerprint'] != manifest['fingerprint'] or manifest['outputs'][path.name]['sha256'] != READS[str(path.resolve())]:
                raise ValueError('Reconciled summary/fingerprint differs from its completed manifest')
            if sum(number(r['candidate_identity_count']) for r in summary) != coverage['candidate_identities'] or sum(number(r['candidate_variant_count']) for r in summary) != coverage['candidate_occurrence_variants']:
                raise ValueError('Reconciled summary candidate counts differ from coverage')
            if sum(number(r['excluded_identity_count']) for r in summary) != coverage['excluded_identities'] or sum(number(r['excluded_variant_count']) for r in summary) != coverage['excluded_occurrence_variants']:
                raise ValueError('Reconciled excluded counts differ from coverage')
            if coverage['parent_and_repair_counts_additive'] is not False or coverage['full_dataset_coverage_claim'] is not False:
                raise ValueError('Reconciled evidence boundary changed')
            source = source_metadata(path, dataset, 'dataset_text_reconciled', 'reconciled_candidate_identity_per_type',
                                     coverage['status'], 'reconciled_candidate_evidence_variant')
            source.update(manifest_path=str(folder/'manifest.json'), manifest_sha256=READS[str((folder/'manifest.json').resolve())],
                          coverage_path=str(folder/'merged_coverage.json'), coverage_sha256=READS[str((folder/'merged_coverage.json').resolve())],
                          parent_run=manifest['parent_run'], repair_run=manifest['repair_run'],
                          source_manifest_sha256=manifest['fingerprint']['source_manifest_sha256'],
                          source_file_hashes_verified_by_reconciler=manifest['fingerprint']['verified_source_files'],
                          implementation_sha256=manifest['fingerprint']['implementation_sha256'],
                          source_snapshot_counts={key: coverage.get(key) for key in ('candidate_identities','candidate_occurrence_variants','excluded_identities','excluded_occurrence_variants','unknown_type_review_cells','unknown_type_review_export_records','parent_all_selected_text_rows_visited','repair_cell_status_counts','repair_data_gap_records')},
                          identity_unit=coverage['identity_unit'], variant_unit=coverage['variant_unit'])
            emitted, unknown = expand(source, summary, catalog); rows.extend(emitted); outside.extend(unknown); sources.append(source)
            folder = base / 'schema-runs' / folder_name
            manifest = read(folder/'manifest.json'); coverage = read(folder/'schema_coverage.json')
            path = folder/'schema_type_summary.json'; document = read(path); summary = document['summary']
            if document.get('taxonomy_version') != '1.0.0' or manifest['fingerprint']['taxonomy_version'] != '1.0.0' or coverage['source_manifest_sha256'] != manifest['source_manifest_sha256']:
                raise ValueError('Schema taxonomy or source manifest differs')
            if not coverage['all_selected_fields_visited'] or coverage['all_dataset_values_classified'] is not False or coverage['status'] != 'complete_with_schema_gaps':
                raise ValueError('Selected schema fields must be terminal with explicit unresolved scope')
            if sum(number(r['candidate_source_cells']) for r in summary) != coverage['counts']['schema_context_candidate']:
                raise ValueError('Schema summary differs from source-cell coverage')
            source = source_metadata(path, dataset, 'dataset_schema_context', 'candidate_source_cell',
                                     coverage['status'], 'candidate_source_cell')
            source.update(manifest_path=str(folder/'manifest.json'), manifest_sha256=READS[str((folder/'manifest.json').resolve())],
                          coverage_path=str(folder/'schema_coverage.json'), coverage_sha256=READS[str((folder/'schema_coverage.json').resolve())],
                          source_manifest_sha256=manifest['source_manifest_sha256'], implementation_source_sha256=manifest['fingerprint']['source_sha256'],
                          frozen_source_inputs=manifest['fingerprint']['inputs'],
                          source_snapshot_counts={key: coverage[key] for key in ('all_fields','selected_fields','unresolved_field_records','counts')})
            emitted, unknown = expand(source, summary, catalog); rows.extend(emitted); outside.extend(unknown); sources.append(source)
        # Record as-of drift only; never rewrite v045 observations from mutable sources.
        as_of = []
        for source in history['sources']:
            path = Path(source['path']).resolve()
            if not path.is_relative_to(base):
                raise ValueError('Historical summary reference escapes project')
            current = None
            if path.exists():
                blob(path); current = READS[str(path)]
            as_of.append({'source_run': source['source_run'], 'original_dataset_label': source['dataset'],
                          'observation_scope': source['observation_scope'], 'path': str(path),
                          'v045_source_sha256': source['sha256'], 'current_source_sha256': current,
                          'state': 'missing_now' if current is None else 'still_matches_v045_snapshot' if current == source['sha256'] else 'mutable_source_differs_from_v045_snapshot',
                          'historical_observations_recomputed': False})
        for path, digest in list(READS.items()):
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
                raise ValueError('Input changed during inventory build')
    rows.sort(key=lambda r: (r['observation_scope'],r['dataset'],r['source_run'],r['category'],r['subtype']))
    if len(rows) != 11*42 or len({(r['observation_scope'],r['dataset'],r['source_run'],r['category'],r['subtype']) for r in rows}) != len(rows):
        raise ValueError('Expected eleven independent sources with all 42 controlled labels')
    by_scope = defaultdict(set)
    for row in rows:
        if row['observed_within_processed_scope']:
            by_scope[row['observation_scope']].add((row['category'],row['subtype']))
    observed = set().union(*by_scope.values())
    provenance = {'recorded_utc':datetime.now(timezone.utc).isoformat(),'taxonomy_version':'1.0.0','catalog_subtypes':42,
                  'catalog_source':str(catalog_path),'row_count':len(rows),'sources':sources,'input_summary_sha256':dict(READS),
                  'observed_type_sets_by_scope':{key:[list(pair) for pair in sorted(value)] for key,value in by_scope.items()},
                  'observed_catalog_type_union':[list(pair) for pair in sorted(observed)],'observed_catalog_type_union_count':len(observed),
                  'candidate_records_outside_catalog_rows':outside,'outside_catalog_count_unit_note':'Same per-source count units as the main grid; never sum these counts across scopes.',
                  'counts_additive_across_scopes_or_runs':False,'parent_and_repair_counts_added':False,'parent_repair_reconciliation_performed':True,
                  'parent_repair_individual_scopes_counted_in_label_union':False,
                  'candidate_status_counts_unit_note':'Reconciled rows use evidence variants; count_within_processed_scope uses logical identities. These differ when conflicting details are preserved. Schema rows count source cells. Historical log statuses are unavailable.',
                  'observed_definition':'At least one non-example candidate in that source processed scope; static label evidence only.',
                  'zero_means':'No recorded non-example candidate in that processed source scope; not absence in the complete dataset.',
                  'historical_v045_recorded_utc':history['recorded_utc'],'historical_v045_files_preserved':True,'historical_sources_as_of_build':as_of,
                  'unknown_queue_exhausted':False,'full_dataset_coverage_claim':False,'human_review_status':'pending','runtime_confirmed':False,
                  'application_log_provenance':str(docs/'type_inventory_v044_provenance.json'),
                  'source_bodies_or_shared_databases_read':False,'original_values_or_value_hashes_exported':False,
                  'raw_source_hashes_recomputed':False,'frozen_source_hash_evidence_origin':'Copied from terminal reconciliation/schema manifests; this inventory only rehashes small metadata summaries.'}
    return rows, outside, provenance


def csv_cell(value):
    if isinstance(value,(dict,list)):
        return canonical(value)
    if value is None:
        return ''
    if isinstance(value,str) and value.lstrip().startswith(('=','+','-','@','\t','\r')):
        return "'"+value
    return value


def write_grid(path, rows):
    temporary = path.with_name(path.name+'.tmp')
    with temporary.open('w',encoding='utf-8',newline='') as stream:
        if path.suffix == '.jsonl':
            for row in rows:
                stream.write(canonical(row)+'\n')
        else:
            writer=csv.DictWriter(stream,fieldnames=COLUMNS);writer.writeheader()
            for row in rows:
                writer.writerow({key:csv_cell(row.get(key)) for key in COLUMNS})
    os.replace(temporary,path)


def self_test():
    catalog={('QID','user_identifier'):'账户标识',('PII','email'):'邮箱'}
    source={'observation_scope':'dataset_text_reconciled','dataset':'fixture','source_run':'fixture',
            'count_unit':'reconciled_candidate_identity_per_type','coverage_status':'reconciled_with_semantic_gaps',
            'candidate_status_count_unit':'reconciled_candidate_evidence_variant','path':'fixture-summary','sha256':'synthetic'}
    summary=[{'category':'QID','subtype':'user_identifier','candidate_identity_count':1,'candidate_variant_count':2,
              'candidate_status_variant_counts':{'identifier_reference':1,'named_value_candidate':1},
              'excluded_identity_count':0,'excluded_variant_count':0,'distinct_candidate_cells':1},
             {'category':None,'subtype':None,'candidate_identity_count':3,'candidate_variant_count':3,
              'candidate_status_variant_counts':{'unknown_named_value':3},'excluded_identity_count':0,'excluded_variant_count':0,'distinct_candidate_cells':2}]
    summary=[{**item, **SCOPE, 'observation_scope':'dataset_text_reconciled', 'application_log_evidence':False} for item in summary]
    rows,outside=expand(source,summary,catalog)
    assert len(rows)==2 and len(outside)==1
    positive=next(r for r in rows if r['subtype']=='user_identifier')
    assert positive['count_within_processed_scope']==1 and positive['candidate_variant_count']==2 and sum(positive['candidate_status_counts'].values())==2
    assert next(r for r in rows if r['subtype']=='email')['observed_within_processed_scope'] is False
    assert outside[0]['count_within_processed_scope']==3 and outside[0]['catalog_membership']=='outside_catalog'
    try:
        expand(source,[{**summary[0],'candidate_variant_count':1}],catalog)
    except ValueError:
        pass
    else:
        raise AssertionError('Variant/status mismatch accepted')
    print(canonical({'synthetic_self_test':'passed','real_sources_read':False,'files_written':False}))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-dir',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--check-only',action='store_true',help='Validate terminal summaries without writing the inventory')
    parser.add_argument('--self-test',action='store_true',help='Run bounded synthetic count/identity tests only')
    args=parser.parse_args()
    if args.self_test:
        self_test();return
    rows,outside,provenance=collect(args.base_dir)
    if not args.check_only:
        docs=args.base_dir.resolve()/'docs'
        targets=[docs/f'observed_types_v046{suffix}' for suffix in ('.csv','.jsonl','_outside_catalog.csv','_outside_catalog.jsonl','_provenance.json')]
        if any(p.exists() for p in targets):
            raise FileExistsError('v046 inventory already exists; preserve this snapshot before rebuilding')
        write_grid(targets[0],rows);write_grid(targets[1],rows);write_grid(targets[2],outside);write_grid(targets[3],outside)
        provenance['builder_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        provenance['output_sha256']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in targets[:-1]}
        targets[-1].write_text(json.dumps(provenance,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(canonical({'rows':len(rows),'sources':len(provenance['sources']),'catalog_subtypes':42,
                     'observed_catalog_label_union':provenance['observed_catalog_type_union_count'],
                     'outside_catalog_summary_rows':len(outside),'files_written':not args.check_only,
                     'counts_additive_across_scopes':False,'full_sensitive_type_coverage_claim':False}))


if __name__=='__main__':
    main()
