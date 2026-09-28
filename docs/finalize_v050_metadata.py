"""Update the current index only after all v050 data audits pass."""
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DOCS = BASE / 'docs'
read = lambda p: json.loads(Path(p).read_text())
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
write = lambda p, v: Path(p).write_text(json.dumps(v, ensure_ascii=False, indent=2) + '\n')
reports = {
    'structured_export_verification': 'aidev_structured_v050_verification_attempt02.json',
    'content_export_verification': 'aidev_content_v050_verification.json',
    'repair_export_verification': 'aidev_repair_v050_verification.json',
    'content_reconcile_verification': 'aidev_reconcile_v050_verification.json',
    'type_inventory_verification': 'aidev_inventory_v050_verification.json',
}
for name in reports.values():
    audit = read(DOCS / name)
    assert audit['checks'] and all(v is True for v in audit['checks'].values()), name
content = read(BASE / 'content-runs/aidev-v050/content_coverage.json')
structured = read(BASE / 'structured-runs/aidev-v050/structured_coverage.json')
repair = read(BASE / 'repair-runs/aidev-v050/scan/repair_coverage.json')
merged = read(BASE / 'reconciled-runs/aidev-v050/merged_coverage.json')
inventory = read(DOCS / 'aidev_observed_types_v050_provenance.json')
assert content['all_selected_text_rows_visited'] and structured['all_source_rows_visited']
assert repair['all_selected_cells_all_rules_finished'] and merged['source_verification_complete']
executions = []
for path in sorted(DOCS.glob('aidev_v050_*_execution.json')):
    record = read(path)
    if not all(k in record for k in ('command', 'finished_at', 'source_before', 'source_after')):
        continue
    assert record['source_unchanged'] and record['source_before'] == record['source_after']
    executions.append({'path': str(path), 'sha256': sha(path), **{k: record[k] for k in
        ('command', 'exit_code', 'elapsed_seconds', 'started_at', 'finished_at', 'source_unchanged')}})
commands_path = DOCS / 'aidev_v050_commands.json'
if commands_path.exists():
    raise FileExistsError(commands_path)
write(commands_path, {'recorded_utc': datetime.now(timezone.utc).isoformat(),
    'dataset_scope': 'aidev_only', 'executions': executions,
    'probe_summary': str(DOCS / 'alias_discovery_v050_summary.md'),
    'structured_first_failed_audit_preserved': str(DOCS / 'aidev_structured_v050_verification.json')})
progress = read(DOCS / 'datasets_progress_pre_v050_snapshot.json')
for key, value in list(progress.items()):
    if isinstance(value, str) and 'v049' in value and key not in ('active_work', 'synthetic_execution_note'):
        progress[key] = value.replace('v049', 'v050')
progress.update(recorded_utc=datetime.now(timezone.utc).isoformat(), tool_version='0.5.0',
    installed_tool_version='0.5.0', taxonomy_version='1.2.0', latest_completed_report_version='0.5.0',
    historical_progress_snapshot=str(DOCS / 'datasets_progress_pre_v050_snapshot.json'),
    observed_controlled_type_label_union=inventory['observed_catalog_type_union_count'],
    structured_scan=structured, content_scan=content,
    structured_resume_verification=str(DOCS / 'aidev_structured_v050_resume_verification.json'),
    content_reconciled={'aidev': {k: merged[k] for k in (
        'status', 'parent_all_selected_text_rows_visited', 'candidate_identities', 'candidate_occurrence_variants',
        'excluded_identities', 'unknown_type_review_cells', 'unknown_type_review_export_records',
        'repair_data_gap_records', 'full_dataset_coverage_claim')}},
    tests_completed=722, test_record=str(DOCS / 'aidev_v050_tests_stdout.txt'),
    test_execution_record=str(DOCS / 'aidev_v050_tests_execution.json'),
    type_inventory_scope='Twelve separate AIDev sources, 49 types each; all 490 historical rows preserved, including 56 not_evaluated/null entries. Units are not additive.',
    active_work='v050 scans, repair, reconciliation and inventory are complete. Unknown semantics, schema mapping and Git-history coverage remain unresolved.',
    environment_blocked_this_version=False, free_disk_gib_at_recording=round(shutil.disk_usage(BASE).free / 2**30, 3),
    synthetic_execution_note='722 pytest cases include real local synthetic Git/PyDriller and Parquet-to-reconciliation checks; no separate v050 seven-stage CLI run.',
    completed_v050={'all_data_writers_terminal': True, 'taxonomy_version': '1.2.0', 'catalog_size': 49,
        'tests_passed': 722, 'content_rows': content['processed_rows'], 'structured_rows': structured['processed_rows'],
        'reconciled_candidate_identities': merged['candidate_identities'],
        'observed_union_labels': inventory['observed_catalog_type_union_count']},
    structured_v050_delta=read(DOCS / reports['structured_export_verification'])['previous_v049_comparison'],
    alias_discovery_report=str(DOCS / 'alias_discovery_v050_summary.md'))
progress.update({k: str(DOCS / v) for k, v in reports.items()})
progress['current_remaining'] = [
    '138 schema fields and 485812 account-reference cells retain the prior unresolved status; schema mapping was not recomputed.',
    f"{content['counts']['nonempty_cells']} nonempty text cells remain semantically reviewable; overlapping queues are not additive.",
    f"{structured['data_gap_records']} structured syntax/decode gaps remain recorded.",
    '49 finite catalog types do not establish discovery of all sensitive types; parent context does not cross arrays, decoding boundaries or ancestors.',
    'The full-text alias probe produced pending syntax clues, not confirmed values or newly established types.',
    'Most real Git-history coverage remains incomplete; this version adds no real repository mining.',
    'No human confirmation, valid-credential verification, runtime leakage or exhaustion of unknown cases is claimed.',
]
write(DOCS / 'datasets_progress.json', progress)
print(json.dumps({'execution_records': len(executions), 'tool_version': '0.5.0',
    'inventory_rows': inventory['row_count'], 'goal_complete': progress['goal_complete']}))
