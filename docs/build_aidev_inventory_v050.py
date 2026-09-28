#!/usr/bin/env python3
"""Version-aware AIDev inventory from frozen history and terminal summaries.

Old source fields remain unchanged. Newly introduced types are unevaluated in
old runs, with null counts; source cells, spans and log versions never add up.
"""
import argparse
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
import csv
import fcntl
import hashlib
import json
from pathlib import Path
import tempfile

import build_type_inventory_v046 as shared
from agentlog_unified.taxonomy import TAXONOMY_VERSION, taxonomy_catalog

EXTRA = ['catalog_version', 'source_taxonomy_version', 'evaluation_status']
COLUMNS = shared.COLUMNS + EXTRA


def versioned(row, version, evaluated=True):
    return {**row, 'catalog_version': '1.2.0', 'source_taxonomy_version': version,
            'evaluation_status': 'evaluated_under_source_rules' if evaluated else 'not_evaluated'}


def preserve_history(rows, catalog):
    """Already-versioned history is an immutable observation, including nulls."""
    if {(r['category'], r['subtype']) for r in rows} != set(catalog):
        raise ValueError('The 49-label catalog changed; this build adds sources only')
    return [dict(r) for r in rows]


def check_scope(row, scope):
    if row.get('observation_scope') != scope or any(row.get(k) != v for k, v in shared.SCOPE.items()):
        raise ValueError('Candidate evidence scope changed')
    if row.get('application_log_evidence') is not False: raise ValueError('Dataset text is not Git log evidence')


def new_source_rows(source, summary, catalog, total, structured):
    indexed = {}; outside = []
    for item in summary:
        if not structured and item['summary_level'] == 'category': continue
        check_scope(item, source['observation_scope'])
        key = item['category'], item['subtype']
        if key in indexed or key not in catalog and not (structured and key == (None, None)):
            raise ValueError('Unexpected or duplicated summary label')
        count = shared.number(item['candidate_occurrences' if structured else 'occurrence_count'])
        extras = {}
        if not structured:
            statuses = shared.labels_status(item['evidence_status_counts'])
            cells = shared.number(item['distinct_cell_count'])
            if sum(statuses.values()) != count or cells > count: raise ValueError('Text type/status counts differ')
            extras = {'statuses': statuses, 'distinct_cells': cells}
        indexed[key] = count, extras
    expected = set(catalog) | ({(None, None)} if structured else set())
    if set(indexed) != expected: raise ValueError('Summary omits zero labels')
    known = sum(count for key, (count, _) in indexed.items() if key in catalog)
    unknown = shared.number(total - known)
    if structured and unknown != indexed[(None, None)][0]: raise ValueError('Structured total differs from summary')
    rows = [versioned(shared.source_row(source, key, label, indexed[key][0], **indexed[key][1]), '1.2.0')
            for key, label in sorted(catalog.items())]
    unknown_source = {**source, 'candidate_status_count_unit': 'unavailable_outside_controlled_summary'}
    outside.append(versioned(shared.source_row(unknown_source, (None, None),
        'Unclassified candidates; zero does not establish absence', unknown, controlled=False), '1.2.0'))
    return rows, outside


def reconciled_guard(manifest, coverage, summary, expected_source):
    if (manifest.get('status')!='complete' or not manifest.get('source_verification_complete')
            or not coverage.get('source_verification_complete') or coverage.get('status')!='reconciled_with_semantic_gaps'):
        raise ValueError('Final reconciled source must be terminal and source verified; no raw fallback')
    if manifest['fingerprint']!=coverage['fingerprint'] or manifest['fingerprint']['source_manifest_sha256']!=expected_source:
        raise ValueError('Reconciled source fingerprint differs')
    for document in (manifest,coverage,*summary):
        check_scope(document,'dataset_text_reconciled')
        if document['taxonomy_version']!='1.2.0':raise ValueError('Reconciled taxonomy differs')
    for key,total in (('candidate_identity_count','candidate_identities'),('candidate_variant_count','candidate_occurrence_variants'),
                      ('excluded_identity_count','excluded_identities'),('excluded_variant_count','excluded_occurrence_variants')):
        if sum(shared.number(r[key]) for r in summary)!=coverage[total]:raise ValueError('Reconciled identity/variant totals differ')
    if coverage['parent_and_repair_counts_additive'] is not False:raise ValueError('Raw and repaired counts cannot be added')


def reconciled_source(base, catalog, expected_source):
    run=base/'reconciled-runs/aidev-v050';manifest=shared.read(run/'manifest.json');coverage=shared.read(run/'merged_coverage.json')
    path=run/'merged_type_summary.jsonl.gz';summary=shared.records(path)
    reconciled_guard(manifest,coverage,summary,expected_source)
    if manifest['outputs'][path.name]['sha256']!=shared.READS[str(path)]:raise ValueError('Reconciled summary snapshot changed')
    parent_path=base/'content-runs/aidev-v050/manifest.json';parent=shared.read(parent_path);fp=manifest['fingerprint']
    if (manifest['parent_run']!=str(parent_path.parent) or parent['dataset']!='aidev'
            or parent['source_manifest_sha256']!=expected_source
            or fp['input_files'][str(parent_path)]!=shared.READS[str(parent_path)]):
        raise ValueError('Reconciled parent is not this AIDev advanced snapshot')
    implementation={'content_reconcile.py':fp['implementation_sha256'],**fp['execution_dependency_sha256']}
    for name,sha in implementation.items():
        if hashlib.sha256(shared.blob(base/'src/agentlog_unified'/name)).hexdigest()!=sha:raise ValueError('Reconciled execution implementation differs')
    source=shared.source_metadata(path,'aidev','dataset_text_reconciled','reconciled_candidate_identity_per_type',
        coverage['status'],'reconciled_candidate_evidence_variant')
    source.update(source_taxonomy_version='1.2.0',source_manifest_sha256=expected_source,
        manifest_sha256=shared.READS[str(run/'manifest.json')],coverage_sha256=shared.READS[str(run/'merged_coverage.json')],
        implementation_sha256=implementation,actual_execution_fingerprint=fp,parent_run=manifest['parent_run'],repair_run=manifest['repair_run'],
        source_snapshot_counts={k:coverage[k] for k in ('candidate_identities','candidate_occurrence_variants','excluded_identities','excluded_occurrence_variants',
            'unknown_type_review_cells','repair_data_gap_records','repair_cell_status_counts','parent_all_selected_text_rows_visited')},
        all_selected_rows_visited=coverage['parent_all_selected_text_rows_visited'],identity_unit=coverage['identity_unit'],variant_unit=coverage['variant_unit'])
    rows,outside=shared.expand(source,summary,catalog)
    return [versioned(r,'1.2.0') for r in rows],[versioned(r,'1.2.0') for r in outside],source


def collect(base):
    base = Path(base).resolve(); docs = base / 'docs'; shared.READS.clear()
    prior = shared.read(docs / 'aidev_observed_types_v049_provenance.json')
    for path, expected in prior['output_sha256'].items():
        if hashlib.sha256(shared.blob(path)).hexdigest() != expected: raise ValueError('Frozen v049 output changed')
    old = shared.records(docs / 'aidev_observed_types_v049.jsonl')
    old_outside = shared.records(docs / 'aidev_observed_types_v049_outside_catalog.jsonl')
    catalog = {(c['category'], s['subtype']): s['label'] for c in taxonomy_catalog()['categories'] for s in c['subtypes']}
    if TAXONOMY_VERSION != '1.2.0' or len(catalog) != 49 or prior['catalog_version'] != '1.1.0':
        raise ValueError('Expected historical taxonomy1.1 catalog and current taxonomy1.2')
    if len(old) != 490 or len(prior['sources']) != 10:
        raise ValueError('Expected ten historical 49-type sources')
    if any(r['dataset'] != 'aidev' for r in old + old_outside): raise ValueError('AIDev only')
    sources = [dict(s) for s in prior['sources']]
    rows = preserve_history(old, catalog); outside = [dict(r) for r in old_outside]
    source_sha = {s['source_manifest_sha256'] for s in sources if 'source_manifest_sha256' in s}
    if len(source_sha) != 1: raise ValueError('Historical frozen sources disagree')
    expected_source = source_sha.pop()
    with ExitStack() as stack:
        for folder, lock_name in ((base/'reconciled-runs/aidev-v050', '.reconcile.lock'),
                                  (base/'structured-runs/aidev-v050', '.structured.lock')):
            lock = stack.enter_context((folder / lock_name).open('rb'))
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        new, unknown, source = reconciled_source(base, catalog, expected_source)
        rows.extend(new); outside.extend(unknown); sources.append(source)
        run = base/'structured-runs/aidev-v050'
        manifest = shared.read(run/'manifest.json'); coverage_path = run/'structured_coverage.json'
        coverage = shared.read(coverage_path); state_path = run/'export_state.json'; state = shared.read(state_path)
        path = run/'structured_type_summary.jsonl.gz'; summary = shared.records(path); fp = manifest['fingerprint']
        if manifest['dataset']!='aidev' or coverage['dataset']!='aidev' or {manifest['source_manifest_sha256'],coverage['source_manifest_sha256']}!={expected_source}:
            raise ValueError('Structured source identity differs')
        check_scope(coverage,'dataset_structured_text')
        if state['status']!='complete' or state['fingerprint']!=fp or fp['taxonomy_version']!='1.2.0':
            raise ValueError('Structured snapshot is not terminal or has the wrong classifier')
        for file in (path,coverage_path):
            if state['outputs'][file.name]['sha256']!=shared.READS[str(file)]: raise ValueError('Structured snapshot hash differs')
        implementation=fp['source_sha256']
        for name,sha in implementation.items():
            if hashlib.sha256(shared.blob(base/'src/agentlog_unified'/name)).hexdigest()!=sha:
                raise ValueError('Structured producer implementation differs')
        source=shared.source_metadata(path,'aidev','dataset_structured_text',
            'source_cell_document_ordinal_node_decoded_span_and_finite_match_details',coverage['status'],'unavailable_per_type_in_structured_summary')
        source.update(source_taxonomy_version='1.2.0',source_manifest_sha256=expected_source,
            manifest_sha256=shared.READS[str(run/'manifest.json')],coverage_sha256=shared.READS[str(coverage_path)],
            export_state_sha256=shared.READS[str(state_path)],implementation_sha256=implementation,actual_execution_fingerprint=fp,
            source_snapshot_counts={k:coverage[k] for k in ('source_rows','processed_rows','candidate_occurrences','excluded_occurrences','counts')},
            all_selected_rows_visited=coverage['all_source_rows_visited'])
        new,unknown=new_source_rows(source,summary,catalog,coverage['candidate_occurrences'],True)
        rows.extend(new);outside.extend(unknown);sources.append(source)
        for path, sha in shared.READS.items():
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != sha: raise ValueError('Input changed during inventory build')
    if len(rows) != 588 or len({(r['observation_scope'],r['source_run'],r['category'],r['subtype']) for r in rows}) != 588:
        raise ValueError('Expected twelve independent 49-type grids')
    source_keys={(s['observation_scope'],s['source_run']) for s in sources}
    if len(source_keys)!=12 or any({(r['category'],r['subtype']) for r in rows if (r['observation_scope'],r['source_run'])==key}!=set(catalog) for key in source_keys):
        raise ValueError('Each independent source must retain all 49 catalog labels')
    if rows[:490] != old or outside[:len(old_outside)] != old_outside or sources[:10] != prior['sources']:
        raise ValueError('Historical fields, versions, nulls, or source fingerprints changed')
    pending = [r for r in rows if r['evaluation_status']=='not_evaluated']
    if len(pending)!=56 or any(r['count_within_processed_scope'] is not None or r['observed_within_processed_scope'] is not None for r in pending):
        raise ValueError('Historical new labels must have null counts and observations')
    observed = {(r['category'],r['subtype']) for r in rows if r['observed_within_processed_scope'] is True}
    provenance = {'recorded_utc':datetime.now(timezone.utc).isoformat(),'dataset':'aidev','catalog_version':'1.2.0',
        'source_taxonomy_versions':['1.0.0','1.1.0','1.2.0'],'catalog_subtypes':49,'row_count':len(rows),'sources':sources,
        'historical_rows_original_fields_preserved':490,'historical_new_type_not_evaluated_rows':56,
        'new_version_evaluated_rows':98,'historical_rows_recomputed':False,
        'catalog_subtypes_added_this_version':0,'historical_catalog_versions_preserved':True,
        'historical_source_validation':'Frozen v049 inventory export SHA; old implementation hashes are provenance, not current-code requirements.','input_summary_sha256':dict(shared.READS),
        'observed_catalog_type_union':sorted(observed),'observed_catalog_type_union_count':len(observed),
        'inventory_rows_by_scope':dict(Counter(r['observation_scope'] for r in rows)),
        'candidate_records_outside_catalog_rows':outside,'counts_additive_across_scopes_or_runs':False,
        'null_means':'Not evaluated under the historical source taxonomy, never zero or absence.',
        'zero_means':'No recorded candidate in the processed source scope under that source taxonomy; not dataset-wide absence.',
        'new_plaintext_source':'final_reconciled_snapshot_only','advanced_raw_source_in_final_grid':False,
        'source_values_or_value_hashes_read':False,'body_and_structure_counts_added':False,**shared.SCOPE}
    return rows,outside,provenance


def write_grid(path,rows):
    with path.open('w',encoding='utf-8',newline='') as stream:
        if path.suffix=='.jsonl':
            for row in rows:stream.write(shared.canonical(row)+'\n')
        else:
            writer=csv.DictWriter(stream,fieldnames=COLUMNS);writer.writeheader()
            for row in rows:writer.writerow({key:shared.csv_cell(row.get(key)) for key in COLUMNS})


def self_test():
    source={'observation_scope':'dataset_text_cells','dataset':'aidev','source_run':'old','count_unit':'source_cell_span_rule_type','coverage_status':'partial','candidate_status_count_unit':'candidate_occurrence','path':'synthetic','sha256':'synthetic'}
    catalog={('PII','email'):'email',('PII','new_type'):'new'}
    old={**shared.source_row(source,('PII','email'),'email',0),
         'catalog_version':'1.1.0','source_taxonomy_version':'1.0.0','evaluation_status':'evaluated_under_source_rules'}
    unknown={**shared.source_row(source,('PII','new_type'),'new',0),
         'catalog_version':'1.1.0','source_taxonomy_version':'1.0.0','evaluation_status':'not_evaluated',
         'count_within_processed_scope':None,'observed_within_processed_scope':None}
    rows=preserve_history([old,unknown],catalog)
    assert rows==[old,unknown] and rows[0] is not old
    assert rows[1]['evaluation_status']=='not_evaluated' and rows[1]['count_within_processed_scope'] is None and rows[1]['observed_within_processed_scope'] is None
    assert rows[0]['catalog_version']=='1.1.0' and rows[0]['count_within_processed_scope']==0 and rows[0]['observed_within_processed_scope'] is False
    try:preserve_history([old],catalog)
    except ValueError:pass
    else:raise AssertionError('Changed historical catalog not rejected')
    item={'summary_level':'subtype','category':'PII','subtype':'email','occurrence_count':0,'distinct_cell_count':0,'evidence_status_counts':{},'observation_scope':'dataset_text_cells','application_log_evidence':False,**shared.SCOPE}
    new,outside=new_source_rows(source,[item],{('PII','email'):'email'},0,False)
    assert new[0]['source_taxonomy_version']=='1.2.0' and new[0]['count_within_processed_scope']==0 and outside[0]['count_within_processed_scope']==0
    try:new_source_rows(source,[item,item],{('PII','email'):'email'},0,False)
    except ValueError:pass
    else:raise AssertionError('Duplicate summary not rejected')
    try:new_source_rows(source,[{**item,'occurrence_count':1}],{('PII','email'):'email'},0,False)
    except ValueError:pass
    else:raise AssertionError('Inconsistent summary not rejected')
    scope={**shared.SCOPE,'observation_scope':'dataset_text_reconciled','application_log_evidence':False,'taxonomy_version':'1.2.0'}
    manifest={**scope,'status':'complete','source_verification_complete':True,'fingerprint':{'source_manifest_sha256':'source'}}
    coverage={**manifest,'status':'reconciled_with_semantic_gaps','candidate_identities':1,'candidate_occurrence_variants':2,
        'excluded_identities':0,'excluded_occurrence_variants':0,'parent_and_repair_counts_additive':False}
    summary=[{**scope,'category':'PII','subtype':'email','candidate_identity_count':1,'candidate_variant_count':2,
        'excluded_identity_count':0,'excluded_variant_count':0,'distinct_candidate_cells':1,
        'candidate_status_variant_counts':{'named_value_candidate':1,'identifier_reference':1}}]
    reconciled_guard(manifest,coverage,summary,'source')
    merged,_=shared.expand({**source,'observation_scope':'dataset_text_reconciled'},summary,catalog)
    assert merged[0]['count_within_processed_scope']==1 and merged[0]['candidate_variant_count']==2 and merged[1]['count_within_processed_scope']==0
    for bad_manifest,bad_coverage in (({**manifest,'status':'building'},coverage),(manifest,{**coverage,'candidate_occurrence_variants':3})):
        try:reconciled_guard(bad_manifest,bad_coverage,summary,'source')
        except ValueError:pass
        else:raise AssertionError('Incomplete or inconsistent reconciliation accepted')
    with tempfile.TemporaryDirectory() as folder:
        p=Path(folder)/'grid.csv';write_grid(p,rows)
        with p.open() as stream:out=list(csv.DictReader(stream))
        assert out[0]['count_within_processed_scope']=='0' and out[1]['count_within_processed_scope']==''
        p=Path(folder)/'grid.jsonl';write_grid(p,rows)
        assert [json.loads(x) for x in p.read_text().splitlines()]==rows
    print(json.dumps({'self_test':'passed','checks':13,'real_outputs_read':False,'raw_fallback_supported':False}))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base-dir',type=Path,default=Path(__file__).resolve().parents[1]);p.add_argument('--check-only',action='store_true');p.add_argument('--self-test',action='store_true');a=p.parse_args()
    if a.self_test:self_test();return
    rows,outside,provenance=collect(a.base_dir)
    if not a.check_only:
        paths=[a.base_dir.resolve()/'docs'/f'aidev_observed_types_v050{s}' for s in ('.csv','.jsonl','_outside_catalog.csv','_outside_catalog.jsonl','_provenance.json')]
        if any(path.exists() for path in paths):raise FileExistsError('Preserve existing v050 inventory')
        for path,data in zip(paths[:-1],(rows,rows,outside,outside)):write_grid(path,data)
        provenance.update(builder_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),helper_sha256=hashlib.sha256(Path(shared.__file__).read_bytes()).hexdigest(),output_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths[:-1]})
        paths[-1].write_text(json.dumps(provenance,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'rows':len(rows),'sources':len(provenance['sources']),'not_evaluated_rows':56,'observed_labels':provenance['observed_catalog_type_union_count'],'files_written':not a.check_only,'counts_additive':False}))


if __name__=='__main__':main()
