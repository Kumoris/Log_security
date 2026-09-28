"""Metadata-only verification of the terminal fixed-alias discovery report."""
from collections import Counter
from pathlib import Path
import hashlib
import json

DOCS = Path(__file__).resolve().parent
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    report = json.loads((DOCS / 'plaintext_alias_probe_v050.json').read_text())
    execution = json.loads((DOCS / 'plaintext_alias_probe_v050_execution.json').read_text())
    prior = json.loads((DOCS / 'json_key_alias_probe_v050.json').read_text())
    snapshot = json.loads((DOCS / 'plaintext_alias_probe_v050_source_snapshot.json').read_text())
    evidence = [json.loads(line) for line in (DOCS / report['evidence_path']).open()]
    checks = []
    def check(name, condition):
        checks.append({'check': name, 'passed': bool(condition)})
        if not condition: raise AssertionError(name)
    check('terminal_execution_success_and_frozen_sources_unchanged', execution['exit_code'] == 0 and execution['frozen_source_and_helper_unchanged'])
    check('report_uses_recorded_v049_implementation', report['source_code_sha256'] == snapshot['source_sha256'])
    check('frozen_module_hashes_still_match', all(digest(Path(snapshot['frozen_package']) / Path(k).name) == h for k, h in report['source_code_sha256'].items()))
    check('single_bounded_attempt', report['full_scan_attempts'] == 1 and report['time_budget_seconds'] == 300)
    check('exact_prior_alias_set', {r['predeclared_alias']: r['canonical_hint'] for r in report['alias_catalog']} == prior['proposed_aliases'])
    check('exact_98_unique_alias_ids', len(report['alias_catalog']) == len({r['alias_id'] for r in report['alias_catalog']}) == 98)
    check('prior_source_relationship', report['source_manifest_sha256'] == prior['source_manifest_sha256'] and report['frozen_source_inputs'] == prior['frozen_source_inputs'])
    check('evidence_hash_and_count', digest(DOCS / report['evidence_path']) == report['evidence_sha256'] and len(evidence) == report['field_assignment_count'])
    check('coverage_all_source_tables', len(report['coverage']) == report['table_denominator'] == len(report['frozen_source_inputs']))
    check('source_row_denominator', sum(t['source_rows'] for t in report['coverage']) == report['source_row_denominator'])
    check('string_column_and_cell_denominators', sum(len(t['fields']) for t in report['coverage']) == report['string_column_denominator'] and sum(t['source_rows'] * len(t['fields']) for t in report['coverage']) == report['text_cell_denominator'])
    check('visited_rows_partition_and_gap_boundary', all(0 <= t['visited_rows'] <= t['source_rows'] and t['complete'] == (t['visited_rows'] == t['source_rows']) and t['first_unvisited_source_row'] == (t['visited_rows'] + 1 if not t['complete'] else None) for t in report['coverage']))
    stats = report['scan_stats']
    fields = {(t['table_path'], f['column_name']): (t, f) for t in report['coverage'] for f in t['fields']}
    check('all_fields_cover_same_committed_row_prefix', all(f.get('source_cells_visited', 0) == t['visited_rows'] for t, f in fields.values()))
    check('per_field_null_empty_nonempty_partition', all(sum(f.get(k, 0) for k in ('null_cells', 'empty_cells', 'nonempty_cells')) == f.get('source_cells_visited', 0) for _, f in fields.values()))
    check('global_null_empty_nonempty_partition', sum(stats.get(k, 0) for k in ('null_cells', 'empty_cells', 'nonempty_cells')) == stats['text_cells_visited'])
    check('field_stats_equal_global_counts', all(sum(f.get(k, 0) for _, f in fields.values()) == stats.get(k, 0) for k in ('null_cells', 'empty_cells', 'nonempty_cells', 'characters_seen', 'characters_examined', 'source_prefix_truncated_cells', 'source_cells_with_alias_assignments')))
    check('logical_rows_and_cells_match_coverage', stats['processed_source_rows'] == sum(t['visited_rows'] for t in report['coverage'] if t['fields']) and stats['text_cells_visited'] == sum(t['visited_rows'] * len(t['fields']) for t in report['coverage']))
    if report['all_selected_source_rows_visited']:
        check('complete_counts_match_previous_frozen_full_corpus', stats['nonempty_cells'] == report['historical_complete_nonempty_text_cell_denominator'] and stats['text_cells_visited'] == report['text_cell_denominator'])
    catalog = {r['alias_id']: r for r in report['alias_catalog']}
    allowed = {'table_path', 'column_name', 'source_row', 'alias_id', 'key_start', 'key_end', 'value_start', 'value_end', 'value_quality', 'expected_types', 'baseline_key_types', 'within_prior_successful_json_document', 'baseline_replayed', 'human_review_status', 'personal_ownership_confirmed', 'sensitivity_confirmed', 'runtime_confirmed', 'baseline_same_value_span_types', 'baseline_expected_type_found'}
    check('no_unexpected_evidence_fields', all(set(e) <= allowed for e in evidence))
    check('evidence_coordinates_and_fixed_alias_types', all(e['alias_id'] in catalog and e['expected_types'] == catalog[e['alias_id']]['expected_types'] and 1 <= e['source_row'] <= fields[e['table_path'], e['column_name']][0]['visited_rows'] and 0 <= e['key_start'] < e['key_end'] <= e['value_start'] <= e['value_end'] <= 1048576 for e in evidence))
    check('quality_and_alias_counts', dict(Counter(e['value_quality'] for e in evidence)) == report['value_quality_counts'] and all(sum(e['alias_id'] == r['alias_id'] for e in evidence) == r['field_assignment_count'] for r in report['alias_catalog']))
    check('prior_json_overlap_counts', dict(Counter('within_prior_successful_json_document' if e['within_prior_successful_json_document'] else 'outside_prior_successful_json_document' for e in evidence)) == report['prior_json_overlap_counts'])
    replayed = [e for e in evidence if e['baseline_replayed']]
    check('bounded_purposive_baseline_counts', len({(e['table_path'], e['column_name'], e['source_row']) for e in replayed}) == report['baseline_source_cells_replayed'] <= 32 and len(replayed) == report['baseline_counts'].get('field_assignments_replayed', 0))
    check('baseline_expected_type_counts', sum(e['baseline_expected_type_found'] for e in replayed) == report['baseline_counts'].get('expected_type_found', 0) and sum(not e['baseline_expected_type_found'] for e in replayed) == report['baseline_counts'].get('expected_type_not_found', 0))
    check('review_and_confirmation_boundaries', all(e['human_review_status'] == 'pending' and not any(e[k] for k in ('personal_ownership_confirmed', 'sensitivity_confirmed', 'runtime_confirmed')) for e in evidence))
    check('no_exported_values_or_new_sensitive_type_claim', not any(report[k] for k in ('source_values_exported', 'dynamic_keys_exported', 'value_hashes_exported', 'formal_source_or_tests_modified', 'network_accessed', 'new_sensitive_types_established')))
    result = {'all_passed': True, 'check_count': len(checks), 'checks': checks, 'report_sha256': digest(DOCS / 'plaintext_alias_probe_v050.json'),
              'execution_sha256': digest(DOCS / 'plaintext_alias_probe_v050_execution.json'), 'evidence_records': len(evidence),
              'raw_source_values_read_for_verification': False, 'frozen_source_modules': len(snapshot['source_sha256'])}
    (DOCS / 'plaintext_alias_probe_v050_verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'all_passed': True, 'check_count': len(checks), 'evidence_records': len(evidence)}))


if __name__ == '__main__': main()
