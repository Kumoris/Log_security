#!/usr/bin/env python3
"""AIDev-only inventory: six preserved v046 sources plus terminal v047 schema.

Metadata only. Historical log versions, reconciled identities and schema cells
stay in separate source rows; their counts are never added across sources.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import argparse
import copy
import fcntl
import hashlib
import json
from pathlib import Path

import build_type_inventory_v046 as previous

LOG_RUNS = {'aidev-full-v5', 'aidev-anchors-v3', 'aidev-prior-cache-v042',
            'aidev-expansion-v043-final', 'aidev-expansion-v044'}
HISTORY_KEYS = {('dataset_commit_changes', name) for name in LOG_RUNS} | {('dataset_text_reconciled', 'aidev-v046')}
UNITS = {'dataset_commit_changes': ('observed_log_version_per_type_in_one_batch', 'unavailable_in_historical_log_summary'),
         'dataset_text_reconciled': ('reconciled_candidate_identity_per_type', 'reconciled_candidate_evidence_variant'),
         'dataset_schema_context': ('candidate_source_cell', 'candidate_source_cell')}


def source_key(row):
    return row['observation_scope'], row['source_run']


def validate_rows(rows, outside, sources, catalog):
    indexed = {source_key(s): s for s in sources}
    if len(indexed) != len(sources):
        raise ValueError('Duplicate source identity')
    seen = set()
    for row in rows + outside:
        source = indexed[source_key(row)]
        if row['dataset'] != 'aidev' or source['dataset'] != 'aidev':
            raise ValueError('Non-AIDev observation selected')
        if (row['count_unit'], row['candidate_status_count_unit']) != UNITS[row['observation_scope']]:
            raise ValueError('Incompatible source count units')
        if any(row.get(k) != v for k, v in previous.SCOPE.items()):
            raise ValueError('Candidate evidence boundary changed')
        for key in ('dataset', 'coverage_status', 'count_unit', 'candidate_status_count_unit'):
            if row[key] != source[key]:
                raise ValueError('Grid/source metadata differs')
        if row['source_path'] != source['path'] or row['source_sha256'] != source['sha256']:
            raise ValueError('Grid/source hash reference differs')
        count = previous.number(row['count_within_processed_scope'])
        if row['observed_within_processed_scope'] is not (count > 0):
            raise ValueError('Observed flag differs from count')
        key = row['category'], row['subtype']
        identity = (*source_key(row), *key)
        if identity in seen or (row['catalog_membership'] == 'controlled') != (key in catalog):
            raise ValueError('Duplicate or inconsistent catalog row')
        seen.add(identity)
        statuses = previous.labels_status(row['candidate_status_counts'])
        if row['observation_scope'] == 'dataset_text_reconciled':
            variants = previous.number(row['candidate_variant_count'])
            if sum(statuses.values()) != variants or variants < count or previous.number(row['distinct_candidate_cells']) > count:
                raise ValueError('Reconciled identity/variant counts differ')
            if previous.number(row['excluded_variant_count']) < previous.number(row['excluded_identity_count']):
                raise ValueError('Excluded identity/variant counts differ')
        elif row['observation_scope'] == 'dataset_schema_context' and (sum(statuses.values()) != count or set(statuses) - {'schema_context_candidate'}):
            raise ValueError('Schema cell/status counts differ')
        elif row['observation_scope'] == 'dataset_commit_changes' and (statuses or row['candidate_variant_count'] is not None):
            raise ValueError('Historical unavailable status counts were invented')
    for key in indexed:
        if { (r['category'], r['subtype']) for r in rows if source_key(r) == key } != set(catalog):
            raise ValueError('Every source must preserve all 42 labels including zeros')


def historical_selection(history, old_rows):
    if history['taxonomy_version'] != '1.0.0' or history['row_count'] != len(old_rows):
        raise ValueError('Historical taxonomy or row count differs')
    sources = [s for s in history['sources'] if s['dataset'] == 'aidev' and source_key(s) in HISTORY_KEYS]
    if {source_key(s) for s in sources} != HISTORY_KEYS or len(sources) != 6:
        raise ValueError('Expected exactly five AIDev Git sources and one reconciled source')
    rows = [r for r in old_rows if r['dataset'] == 'aidev' and source_key(r) in HISTORY_KEYS]
    outside = [r for r in history['candidate_records_outside_catalog_rows'] if r['dataset'] == 'aidev' and source_key(r) in HISTORY_KEYS]
    catalog = {}
    for row in rows:
        key = row['category'], row['subtype']
        if key in catalog and catalog[key] != row['subtype_label']:
            raise ValueError('Historical catalog label differs between sources')
        catalog[key] = row['subtype_label']
    if len(catalog) != 42 or len(rows) != 6*42:
        raise ValueError('Expected six historical 42-label grids')
    validate_rows(rows, outside, sources, catalog)
    text = next(s for s in sources if s['observation_scope'] == 'dataset_text_reconciled')
    if text['coverage_status'] != 'reconciled_with_semantic_gaps':
        raise ValueError('Historical reconciliation was not terminal')
    text_rows = [r for r in rows + outside if source_key(r) == source_key(text)]
    for column, total in (('count_within_processed_scope', 'candidate_identities'), ('candidate_variant_count', 'candidate_occurrence_variants'), ('excluded_identity_count', 'excluded_identities'), ('excluded_variant_count', 'excluded_occurrence_variants')):
        if sum(previous.number(r[column]) for r in text_rows) != text['source_snapshot_counts'][total]:
            raise ValueError('Historical reconciliation totals differ from provenance')
    return rows, outside, sources, catalog


def schema_guard(manifest, coverage, document, expected_source):
    if manifest['dataset'] != 'aidev' or coverage['dataset'] != 'aidev':
        raise ValueError('Schema dataset is not AIDev')
    if document['taxonomy_version'] != '1.0.0' or manifest['fingerprint']['taxonomy_version'] != '1.0.0':
        raise ValueError('Schema taxonomy differs')
    if {manifest['source_manifest_sha256'], coverage['source_manifest_sha256'], manifest['fingerprint']['source_manifest_sha256']} != {expected_source}:
        raise ValueError('Schema and historical text use different frozen inputs')
    if coverage['status'] != 'complete_with_schema_gaps' or coverage['all_selected_fields_visited'] is not True or coverage['all_dataset_values_classified'] is not False:
        raise ValueError('Schema must be terminal with explicit unresolved scope')
    for value in (manifest, coverage, document):
        if value.get('observation_scope') != 'dataset_schema_context' or value.get('application_log_evidence') is not False or any(value.get(k) != previous.SCOPE[k] for k in ('human_review_status', 'runtime_confirmed', 'new_type_status')):
            raise ValueError('Schema scope or review status changed')
    fields = {f['field_id']: f for f in manifest['fields']}
    if len(fields) != 160 or coverage['all_fields'] != 160 or len(coverage['fields']) != 160 or len(manifest['fingerprint']['inputs']) != 18:
        raise ValueError('Expected frozen AIDev 18-table / 160-field schema')
    total = Counter(); selected = 0; seen = set()
    for row in coverage['fields']:
        f = fields[row['field_id']]
        if row['field_id'] in seen or any(row[k] != value for k, value in f.items()):
            raise ValueError('Coverage field differs from manifest')
        seen.add(row['field_id']); counts = {k: previous.number(v) for k, v in row['counts'].items()}; total.update(counts)
        if f['selected_for_value_scan']:
            selected += 1
            if row['state'] != 'complete' or row['next_row'] != f['source_rows'] or counts.get('cells_decoded', 0) != f['source_rows'] or sum(v for k, v in counts.items() if k != 'cells_decoded') != f['source_rows']:
                raise ValueError('Selected field is partial or quality totals differ')
        elif counts or row['next_row']:
            raise ValueError('Unselected source field unexpectedly classified')
    if dict(total) != coverage['counts'] or selected != coverage['selected_fields'] or 160-selected != coverage['unresolved_field_records']:
        raise ValueError('Schema field/count totals differ')
    if sum(previous.number(r['candidate_source_cells']) for r in document['summary']) != total['schema_context_candidate']:
        raise ValueError('Schema summary differs from candidate source cells')


def collect(base):
    previous.READS.clear(); base = Path(base).resolve(); docs = base/'docs'
    history_path = docs/'observed_types_v046_provenance.json'; old_path = docs/'observed_types_v046.jsonl'
    history = previous.read(history_path); old_rows = previous.records(old_path)
    if history['output_sha256'][str(old_path)] != previous.READS[str(old_path)]:
        raise ValueError('v046 JSONL hash differs from its provenance')
    rows, outside, sources, catalog = historical_selection(history, old_rows)
    text = next(s for s in sources if s['observation_scope'] == 'dataset_text_reconciled')
    folder = base/'schema-runs/aidev-v047'
    with (folder/'.schema.lock').open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        manifest_path=folder/'manifest.json'; coverage_path=folder/'schema_coverage.json'; path=folder/'schema_type_summary.json'
        manifest=previous.read(manifest_path); coverage=previous.read(coverage_path); document=previous.read(path)
        schema_guard(manifest, coverage, document, text['source_manifest_sha256'])
        if {r['path']: r['sha256'] for r in manifest['fingerprint']['inputs']} != {Path(p).name: sha for p,sha in text['source_file_hashes_verified_by_reconciler'].items()}:
            raise ValueError('Schema and historical text list different frozen source files')
        source=previous.source_metadata(path, 'aidev', 'dataset_schema_context', 'candidate_source_cell', coverage['status'], 'candidate_source_cell')
        source.update(manifest_path=str(manifest_path), manifest_sha256=previous.READS[str(manifest_path)], coverage_path=str(coverage_path), coverage_sha256=previous.READS[str(coverage_path)], source_manifest_sha256=manifest['source_manifest_sha256'], implementation_source_sha256=manifest['fingerprint']['source_sha256'], frozen_source_inputs=manifest['fingerprint']['inputs'], source_snapshot_counts={k:coverage[k] for k in ('all_fields','selected_fields','unresolved_field_records','counts')}, account_reference_coverage=manifest.get('account_reference_coverage'))
        emitted, unknown=previous.expand(source, document['summary'], catalog)
        rows=rows+emitted; outside=outside+unknown; sources=sources+[source]
        validate_rows(rows, outside, sources, catalog)
        for p, sha in list(previous.READS.items()):
            if hashlib.sha256(Path(p).read_bytes()).hexdigest()!=sha:
                raise ValueError('Input changed during inventory build')
    if len(rows)!=294 or len(sources)!=7:
        raise ValueError('Expected seven independent sources and 294 controlled rows')
    rows.sort(key=lambda r:(r['observation_scope'],r['source_run'],r['category'],r['subtype']))
    by_scope=defaultdict(set)
    for row in rows:
        if row['observed_within_processed_scope']:by_scope[row['observation_scope']].add((row['category'],row['subtype']))
    observed=set().union(*by_scope.values())
    provenance={k:history[k] for k in ('observed_definition','zero_means','candidate_status_counts_unit_note')}
    provenance.update(recorded_utc=datetime.now(timezone.utc).isoformat(), dataset='aidev', taxonomy_version='1.0.0', catalog_subtypes=42, row_count=len(rows), sources=sources, input_summary_sha256=dict(previous.READS), historical_inventory_path=str(old_path), historical_inventory_sha256=previous.READS[str(old_path)], historical_provenance_path=str(history_path), historical_provenance_sha256=previous.READS[str(history_path)], historical_source_rows_preserved=252, historical_rows_recomputed=False, old_schema_replaced_not_added=True, observed_type_sets_by_scope={s:[list(k) for k in sorted(keys)] for s,keys in by_scope.items()}, observed_catalog_type_union=[list(k) for k in sorted(observed)], observed_catalog_type_union_count=len(observed), candidate_records_outside_catalog_rows=outside, counts_additive_across_scopes_or_runs=False, outside_catalog_count_unit_note='Per-source units only; source cells, log versions and reconciled identities must not be summed.', parent_and_repair_counts_added=False, unknown_queue_exhausted=False, full_dataset_coverage_claim=False, human_review_status='pending', runtime_confirmed=False, source_bodies_or_shared_databases_read=False, raw_source_hashes_recomputed=False, original_values_or_value_hashes_exported=False, swe_sources_reopened=False, inherited_source_hash_evidence='Historical source fingerprints and totals are copied from the hashed v046 inventory; original mutable summaries are not reopened.', helper_sha256=hashlib.sha256(Path(previous.__file__).read_bytes()).hexdigest())
    return rows,outside,provenance


def self_test():
    catalog={('SYNTHETIC',f'type_{i}'):f'type_{i}' for i in range(42)}
    sources=[];rows=[]
    for scope,run in sorted(HISTORY_KEYS | {('dataset_schema_context','aidev-v046'),('dataset_commit_changes','swechat-fixture')}):
        unit,statusunit=UNITS[scope]
        source={'dataset':'swe-chat' if run=='swechat-fixture' else 'aidev','observation_scope':scope,'source_run':run,'path':'synthetic','sha256':'synthetic','count_unit':unit,'candidate_status_count_unit':statusunit,'coverage_status':'reconciled_with_semantic_gaps' if scope=='dataset_text_reconciled' else 'complete_with_schema_gaps' if scope=='dataset_schema_context' else 'incomplete_or_gaps'}
        source['source_snapshot_counts']={'candidate_identities':42,'candidate_occurrence_variants':84,'excluded_identities':0,'excluded_occurrence_variants':0};sources.append(source)
        for key,label in catalog.items():
            extras={'variants':2,'statuses':{'identifier_reference':2},'excluded_identities':0,'excluded_variants':0,'distinct_cells':1} if scope=='dataset_text_reconciled' else {'statuses':{'schema_context_candidate':1}} if scope=='dataset_schema_context' else {}
            rows.append(previous.source_row(source,key,label,1,**extras))
    history={'taxonomy_version':'1.0.0','row_count':len(rows),'sources':sources,'candidate_records_outside_catalog_rows':[]}
    selected, outside, kept, labels=historical_selection(history,rows)
    assert len(selected)==252 and len(kept)==6 and all(r['dataset']=='aidev' for r in selected)
    assert not any(r['observation_scope']=='dataset_schema_context' for r in selected)
    assert next(r for r in selected if r['observation_scope']=='dataset_text_reconciled')['candidate_variant_count']==2
    broken=copy.deepcopy(selected);broken[0]['count_unit']='candidate_source_cell'
    try:validate_rows(broken,[],kept,labels)
    except ValueError:pass
    else:raise AssertionError('Mixed unit accepted')
    try:validate_rows(selected[:-1],[],kept,labels)
    except ValueError:pass
    else:raise AssertionError('Missing zero/catalog label accepted')
    source={'dataset':'aidev','observation_scope':'dataset_schema_context','source_run':'fixture','path':'synthetic','sha256':'synthetic','count_unit':'candidate_source_cell','candidate_status_count_unit':'candidate_source_cell','coverage_status':'complete_with_schema_gaps'}
    zero,extra=previous.expand(source,[],catalog)
    assert len(zero)==42 and not extra and all(r['count_within_processed_scope']==0 for r in zero)
    common={**previous.SCOPE,'observation_scope':'dataset_schema_context','application_log_evidence':False,'dataset':'aidev','source_manifest_sha256':'synthetic'}
    fields=[{'field_id':str(i),'selected_for_value_scan':i==0,'source_rows':2 if i==0 else 0} for i in range(160)]
    counts={'cells_decoded':2,'schema_context_candidate':1,'null':1}
    manifest={**common,'fields':fields,'fingerprint':{'taxonomy_version':'1.0.0','source_manifest_sha256':'synthetic','inputs':[{} for _ in range(18)]}}
    coverage={**common,'all_fields':160,'selected_fields':1,'unresolved_field_records':159,'status':'complete_with_schema_gaps','all_selected_fields_visited':True,'all_dataset_values_classified':False,'counts':counts,
              'fields':[{**f,'state':'complete' if f['selected_for_value_scan'] else 'unselected','next_row':f['source_rows'],'counts':counts if f['selected_for_value_scan'] else {}} for f in fields]}
    document={**common,'taxonomy_version':'1.0.0','summary':[{'candidate_source_cells':1}]}
    schema_guard(manifest,coverage,document,'synthetic')
    for replacement in ({'all_selected_fields_visited':False},{'source_manifest_sha256':'different'},{'counts':{'cells_decoded':3,'schema_context_candidate':1,'null':2}}):
        try:schema_guard(manifest,{**coverage,**replacement},document,'synthetic')
        except ValueError:pass
        else:raise AssertionError('Invalid schema terminal/source/count accepted')
    print(previous.canonical({'synthetic_self_test':'passed','assertions':10,'real_sources_read':False,'files_written':False}))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-dir',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--check-only',action='store_true')
    parser.add_argument('--self-test',action='store_true')
    args=parser.parse_args()
    if args.self_test:self_test();return
    rows,outside,provenance=collect(args.base_dir)
    if not args.check_only:
        targets=[args.base_dir.resolve()/'docs'/f'aidev_observed_types_v047{s}' for s in ('.csv','.jsonl','_outside_catalog.csv','_outside_catalog.jsonl','_provenance.json')]
        if any(p.exists() for p in targets):raise FileExistsError('Preserve the existing v047 snapshot')
        for path,items in zip(targets[:-1],(rows,rows,outside,outside)):previous.write_grid(path,items)
        provenance['builder_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        provenance['output_sha256']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in targets[:-1]}
        targets[-1].write_text(json.dumps(provenance,ensure_ascii=False,indent=2)+'\n')
    print(previous.canonical({'rows':len(rows),'sources':len(provenance['sources']),'catalog_subtypes':42,'observed_catalog_label_union':provenance['observed_catalog_type_union_count'],'outside_catalog_summary_rows':len(outside),'files_written':not args.check_only,'dataset':'aidev','counts_additive_across_scopes':False}))


if __name__=='__main__':
    main()
