"""Independent metadata-only comparison of the final versioned AIDev grid."""
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import time

BASE=Path(__file__).resolve().parents[1]
EXTRA={'catalog_version','source_taxonomy_version','evaluation_status'}


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text())
def records(path):
    with (gzip.open(path,'rt',encoding='utf-8') if path.suffix=='.gz' else path.open()) as stream:
        return [json.loads(line) for line in stream]
def cell(v):
    if v is None:return ''
    if isinstance(v,(dict,list)):return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'))
    if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@','\t','\r')):return "'"+v
    return str(v)
def key(row):return row['observation_scope'],row['source_run']


def run():
    started=datetime.now(timezone.utc).isoformat();clock=time.monotonic();docs=BASE/'docs';checks={}
    def check(name,value):checks[name]=bool(value)
    path=docs/'aidev_observed_types_v049_provenance.json';provenance=read(path)
    prior=read(docs/'aidev_observed_types_v048_provenance.json')
    rows=records(docs/'aidev_observed_types_v049.jsonl');outside=records(docs/'aidev_observed_types_v049_outside_catalog.jsonl')
    old=records(docs/'aidev_observed_types_v048.jsonl');oldoutside=records(docs/'aidev_observed_types_v048_outside_catalog.jsonl')
    for name,expected in provenance['output_sha256'].items():check('output_sha_'+Path(name).name,sha(Path(name))==expected)
    check('all_frozen_input_hashes',all(sha(Path(p))==v for p,v in provenance['input_summary_sha256'].items()))
    check('all_old_v048_output_hashes',all(sha(Path(p))==v for p,v in prior['output_sha256'].items()))
    check('builder_and_reused_helper_hashes',sha(docs/'build_aidev_inventory_v049.py')==provenance['builder_sha256'] and sha(docs/'build_type_inventory_v046.py')==provenance['helper_sha256'])
    for suffix,data in (('',rows),('_outside_catalog',outside)):
        with (docs/f'aidev_observed_types_v049{suffix}.csv').open() as stream:csvrows=list(csv.DictReader(stream))
        check('csv_jsonl_fields'+suffix,len(csvrows)==len(data) and all({k:cell(v) for k,v in row.items()}==csvrow for row,csvrow in zip(data,csvrows)))
    check('old336_original_fields_preserved',len(old)==336 and [{k:v for k,v in r.items() if k not in EXTRA} for r in rows[:336]]==old)
    check('old_outside_fields_preserved',[{k:v for k,v in r.items() if k not in EXTRA} for r in outside[:len(oldoutside)]]==oldoutside)
    oldlabels={(r['category'],r['subtype']) for r in old};catalog={(r['category'],r['subtype']) for r in rows}
    sources={key(s):s for s in provenance['sources']}
    check('490_unique_rows_10_sources_49_labels',len(rows)==490 and len(sources)==10 and len(catalog)==49 and len({(*key(r),r['category'],r['subtype']) for r in rows})==490)
    check('every_source_all49',all({(r['category'],r['subtype']) for r in rows if key(r)==s}==catalog for s in sources))
    check('aidev_only',all(r['dataset']=='aidev' for r in rows+outside+list(sources.values())))
    check('row_source_provenance',all(r['source_path']==sources[key(r)]['path'] and r['source_sha256']==sources[key(r)]['sha256'] and r['count_unit']==sources[key(r)]['count_unit'] and r['source_taxonomy_version']==sources[key(r)]['source_taxonomy_version'] for r in rows+outside))
    pending=[r for r in rows if r['evaluation_status']=='not_evaluated'];evaluated=[r for r in rows if r['evaluation_status']=='evaluated_under_source_rules']
    check('56_not_evaluated_null_not_zero',len(pending)==56 and all(r['count_within_processed_scope'] is None and r['observed_within_processed_scope'] is None and r['source_taxonomy_version']=='1.0.0' and (r['category'],r['subtype']) not in oldlabels for r in pending))
    check('evaluated_counts_and_flags',len(evaluated)==434 and all(type(r['count_within_processed_scope']) is int and r['count_within_processed_scope']>=0 and r['observed_within_processed_scope'] is (r['count_within_processed_scope']>0) for r in evaluated))
    check('catalog_version_and_old_source_taxonomy',all(r['catalog_version']=='1.1.0' for r in rows+outside) and all(r['source_taxonomy_version']=='1.0.0' for r in rows[:336]))
    new=[r for r in rows if r['source_taxonomy_version']=='1.1.0'];newoutside=[r for r in outside if r['source_taxonomy_version']=='1.1.0']
    check('98_new_evaluated_rows_no_advanced_slot',len(new)==98 and {r['observation_scope'] for r in new}=={'dataset_text_reconciled','dataset_structured_text'} and all(r['evaluation_status']=='evaluated_under_source_rules' for r in new))
    merged=records(BASE/'reconciled-runs/aidev-v049/merged_type_summary.jsonl.gz');coverage=read(BASE/'reconciled-runs/aidev-v049/merged_coverage.json');index={(r['category'],r['subtype']):r for r in merged}
    mr=[r for r in new+newoutside if r['observation_scope']=='dataset_text_reconciled'];valid=True
    mapping={'count_within_processed_scope':'candidate_identity_count','candidate_variant_count':'candidate_variant_count','excluded_identity_count':'excluded_identity_count','excluded_variant_count':'excluded_variant_count','distinct_candidate_cells':'distinct_candidate_cells'}
    for row in mr:
        expected=index.get((row['category'],row['subtype']),{})
        valid &= all(row[k]==expected.get(v,0) for k,v in mapping.items())
        valid &= row['candidate_status_counts']==expected.get('candidate_status_variant_counts',{})
    check('reconciled_each_type_identity_variant_status_exact',valid)
    check('reconciled_only_its_own_totals',all(sum(r[column] for r in mr)==coverage[total] for column,total in (('count_within_processed_scope','candidate_identities'),('candidate_variant_count','candidate_occurrence_variants'),('excluded_identity_count','excluded_identities'),('excluded_variant_count','excluded_occurrence_variants'))))
    structured=records(BASE/'structured-runs/aidev-v049/structured_type_summary.jsonl.gz');sc=read(BASE/'structured-runs/aidev-v049/structured_coverage.json');si={(r['category'],r['subtype']):r['candidate_occurrences'] for r in structured};sr=[r for r in new+newoutside if r['observation_scope']=='dataset_structured_text']
    check('structured_each_type_and_unknown_exact',len(si)==50 and all(r['count_within_processed_scope']==si[(r['category'],r['subtype'])] for r in sr))
    check('structured_only_its_own_total',sum(r['count_within_processed_scope'] for r in sr)==sc['candidate_occurrences'])
    check('structured_per_type_status_unavailable_not_invented',all(not r['candidate_status_counts'] and r['candidate_variant_count'] is None and r['candidate_status_count_unit'].startswith('unavailable') for r in sr))
    check('outside_catalog_records_retained',len(outside)==4 and all(r['catalog_membership']=='outside_catalog' and r['category'] is None and r['subtype'] is None for r in outside))
    observed={(r['category'],r['subtype']) for r in rows if r['observed_within_processed_scope'] is True}
    check('label_union_recomputed',sorted(observed)==[tuple(x) for x in provenance['observed_catalog_type_union']] and len(observed)==provenance['observed_catalog_type_union_count'])
    check('nonadditive_and_pending_boundaries',provenance['counts_additive_across_scopes_or_runs'] is False and provenance['advanced_raw_source_in_final_grid'] is False and all(r['human_review_status']=='pending' and r['runtime_confirmed'] is False and r['new_type_status']=='not_established' and r['full_dataset_coverage_claim'] is False for r in rows+outside))
    result={'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-clock,'checks':checks,'passed':sum(checks.values()),'total':len(checks),'all_checks_passed':all(checks.values()),'grid_rows':len(rows),'independent_sources':len(sources),'historical_rows_original_fields_preserved':len(old),'not_evaluated_rows':len(pending),'evaluated_rows':len(evaluated),'evaluated_zero_rows':sum(r['count_within_processed_scope']==0 for r in evaluated),'observed_catalog_type_union_count':len(observed),'new_version_sources':[{'scope':k[0],'source_run':k[1],'unit':s['count_unit']} for k,s in sources.items() if s['source_taxonomy_version']=='1.1.0'],'new_controlled_types':[{'scope':r['observation_scope'],'subtype':r['subtype'],'count':r['count_within_processed_scope']} for r in new if (r['category'],r['subtype']) not in oldlabels],'reconciled_candidate_identities':coverage['candidate_identities'],'reconciled_candidate_variants':coverage['candidate_occurrence_variants'],'structured_candidate_occurrences':sc['candidate_occurrences'],'outside_rows':len(outside),'provenance_sha256':sha(path),'output_sha256':provenance['output_sha256'],'verifier_sha256':sha(Path(__file__)),'source_values_or_databases_read':False,'cross_scope_totals_computed':False,'new_true_sensitive_type_claim':False}
    target=docs/'aidev_inventory_v049_verification.json'
    if target.exists():raise FileExistsError('Preserve prior verification')
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'report':str(target),'passed':result['passed'],'total':result['total'],'all_checks_passed':result['all_checks_passed'],'failed':[k for k,v in checks.items() if not v],'rows':len(rows),'observed_labels':len(observed)}))
    return 0 if result['all_checks_passed'] else 1


if __name__=='__main__':raise SystemExit(run())
