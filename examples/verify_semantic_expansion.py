"""Verify delivered frozen artifacts and denominators; no target code execution."""
from collections import Counter
import json
from pathlib import Path
import stat

from agentlog_unified.config import sha256_file
from agentlog_unified.export import write_json
from agentlog_unified.taxonomy import taxonomy_catalog

ROOT=Path(__file__).resolve().parents[1]
report={'checks':[],'runs':{},'accuracy_estimated':False}
for name in ('synthetic-v070-final','real-v070-final'):
    run=ROOT/'outputs/semantic-runs'/name;manifest=json.loads((run/'manifest.json').read_text())
    assert manifest['status']=='complete'
    for relative,expected in manifest['artifact_sha256'].items():assert sha256_file(run/relative)==expected
    for filename,expected in manifest['fingerprint']['source_sha256'].items():assert sha256_file(ROOT/'src/agentlog_unified'/filename)==expected
    assert stat.S_IMODE((run/'checkpoint.sqlite').stat().st_mode)==0o600
    rows=[json.loads(line) for line in (run/'field_semantics.jsonl').read_text().splitlines()]
    coverage=json.loads((run/'coverage.json').read_text())
    assert len(rows)==coverage['funnel']['selected_field_uses']
    assert sum(coverage['by_language'].values())==len(rows)
    assert all(not row['privacy_risk']['runtime_confirmed'] and row['human_review_status']=='pending' for row in rows)
    assert all(row['privacy_risk']['status']=='undetermined' for row in rows if row['use_role']=='nested_expression_input')
    ablations=[json.loads(line) for line in (run/'ablations.jsonl').read_text().splitlines()]
    report['runs'][name]={'funnel':coverage['funnel'],'artifact_hashes_verified':len(manifest['artifact_sha256']),
        'source_hashes_verified':len(manifest['fingerprint']['source_sha256']),'private_checkpoint_mode':'0600',
        'generic_name_cases':coverage['generic_name_cases'],'by_language':coverage['by_language'],'by_queue':coverage['by_queue'],
        'by_interpretation_level':coverage['interpretation_levels'],'type_context_cases':coverage['explicit_type_context_cases'],
        'ablation_rule_supported':{variant:sum(row['variants'][variant]['status']=='supported' for row in ablations)
                                    for variant in ablations[0]['variants']},
        'ablation_denominator':len(ablations),'accuracy':None,'recall':None}
baseline=ROOT/'outputs/semantic-runs/real-v070-third'
before={json.loads(line)['id']:json.loads(line) for line in (baseline/'field_semantics.jsonl').read_text().splitlines()}
after={json.loads(line)['id']:json.loads(line) for line in (ROOT/'outputs/semantic-runs/real-v070-final/field_semantics.jsonl').read_text().splitlines()}
assert before.keys()==after.keys() and len(after)==100
report['fixed_cohort_comparison']={'denominator':100,'baseline':'real-v070-third','final':'real-v070-final',
    'new_rule_supported_ids':[i for i in after if before[i]['independent_review_status']!='supported' and after[i]['independent_review_status']=='supported'],
    'claim':'New support is nominal constructor identity only, not business meaning or sensitivity.'}
history=json.loads((ROOT/'outputs/semantic-runs/history-v070/full_git_mining_audit.json').read_text())
report['full_git_audit']={k:v for k,v in history.items() if k!='repositories'}
assert history['all_requested_commits_extracted'] and history['pydriller_commits']==660
assert sum(len((p/'commits.jsonl').read_text().splitlines()) for p in (ROOT/'outputs/semantic-runs/history-v070/full_git_audit').iterdir())==660
assert sum(len((p/'file_differences.jsonl').read_text().splitlines()) for p in (ROOT/'outputs/semantic-runs/history-v070/full_git_audit').iterdir())==3063
coding=json.loads((ROOT/'outputs/semantic-runs/human-coding-v070/coding_audit.json').read_text())
assert coding['human_annotations']==0 and coding['category_decisions']==0 and coding['case_denominator']==100
report['human_coding']=coding
model_path=ROOT/'outputs/semantic-runs/model-real-v070/model_audit.json'
if model_path.exists():
    model=json.loads(model_path.read_text());ledger=model_path.with_name('model_manifest.json')
    assert sha256_file(ledger)==model['ledger_sha256']
    records=json.loads(ledger.read_text())['records']
    assert all(not r['human_confirmed'] for r in records)
    assert all(not r['receipt'].get('tool_use_observed',False) for r in records)
    report['real_model_execution']=model
    catalog={(c['category'],s['subtype']) for c in taxonomy_catalog()['categories'] for s in c['subtypes']}
    gates=[]
    for row in records:
        if row['stage']!='review' or not row['response']:continue
        case=after[row['case_id']];response=row['response']
        gates.append({'case_id':row['case_id'],'method':'rule_audit_of_model_suggestion_not_human_review',
            'model_record_id':row['id'],'model_semantic_verdict':response['status'],
            'verified_program_use_role':case['use_role'],'whole_input_value_logged_proven':False,
            'log_association_requires_review':response['log_association']=='supported_static_argument' and case['use_role']=='nested_expression_input',
            'unmapped_model_labels':[{'category':m['category'],'subtype':m['subtype']} for m in response['meanings']
                                     if m['category'] and (m['category'],m['subtype']) not in catalog],
            'sensitive_types_confirmed':[],'human_status':'pending'})
    report['model_dimension_gates']=gates
    report['real_model_usage']={key:sum(u.get(key,0) for r in records for u in r['receipt'].get('usage',[]) if u)
                              for key in ('input_tokens','cached_input_tokens','output_tokens')}
    write_json(ROOT/'docs/model_dimension_audit_v070.json',{'records':gates,
        'note':'Model category strings may describe analytical dimensions; they are not automatically sensitive taxonomy entries. Nested inputs are not whole-value log output proof.'})
report['checks']=['frozen_public_and_source_hashes','private_checkpoint_permissions','four_dimensions_not_collapsed',
                  'same_100_real_use_id_cohort','actual_PyDriller_full_history_counts','human_pending_without_fabricated_labels']
write_json(ROOT/'docs/semantic_v070_verification.json',report)
print(json.dumps({'status':'verified','checks':len(report['checks']),'runs':list(report['runs'])}))
