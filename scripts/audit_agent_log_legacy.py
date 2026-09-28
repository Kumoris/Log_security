"""Recount the fixed legacy frame; preserve isolation and all parent artifacts."""
import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from agent_log_motivation_v11 import rows, file_hash, table, write_json
from run_swechat_followups import resolve_path


def audit(workspace, output):
    w, out = Path(workspace), Path(output)
    out.mkdir(parents=True, exist_ok=False)
    project = w
    protocol = project / 'research/swechat-independent-holdout-20260914'
    checked = subprocess.run([sys.executable, '-B', str(protocol / 'guard.py'), '--batch', str(protocol / 'development_allowed_ids.jsonl')], capture_output=True, text=True, check=True)
    guard = json.loads(checked.stdout)
    assert guard['allowed']
    write_json(out / 'development_guard.json', guard)
    allowed = {r['log_version_id'] for _, r in rows(protocol / 'development_allowed_ids.jsonl')}
    prior = w / 'outputs/swechat_motivation_20260921/delivery'
    baseline = json.loads((prior / 'audit/input_integrity.json').read_text(encoding='utf-8'))['input_sha256']
    integrity = []
    for old_path, expected in baseline.items():
        p = resolve_path(old_path, project=w)
        actual = file_hash(p)
        integrity.append(dict(path=str(p.resolve()), expected=expected, actual=actual, matches=actual == expected))
    view = project / 'research/swechat-common-flow-605-20260914'
    statuses, ids, field_ids, missing, gaps, schema_keys = Counter(), Counter(), Counter(), Counter(), Counter(), set()
    refs, repos, locators, source_keys, semantic_unknown, completed = set(), set(), set(), Counter(), set(), set()
    unresolved = []
    field_counts = Counter()
    for line, r in rows(view / 'current_log_coverage.jsonl'):
        lid = r['log_version_id']
        ids[lid] += 1
        statuses[r['status']] += 1
        repos.add(r['repository'])
        refs.update(x['observation_id'] for x in r.get('observation_references', []))
        locators.add(tuple(r.get(k) for k in ('repository', 'snapshot_sha', 'path', 'start_line', 'end_line', 'target_statement_sha256')))
        if r.get('same_source_log_key'):
            source_keys[r['same_source_log_key']] += 1
        if lid not in allowed:
            continue
        schema_keys.update(r)
        if r['status'] == 'completed':
            completed.add(lid)
        absent = [k for k in ('repository', 'snapshot_sha', 'path', 'source_sha256', 'git_blob_id', 'observation_ids') if not r.get(k)]
        missing.update(absent)
        gaps.update(r.get('gaps', []))
        unresolved.append(dict(log_version_id=lid, repository=r['repository'], snapshot_sha=r['snapshot_sha'], file_path=r['path'],
            source_path=str((view / 'current_log_coverage.jsonl').resolve()), source_row=line, extraction_status=r['status'],
            missing_locator_fields=absent, extraction_gaps=r.get('gaps', []),
            modification_motive_status='not_an_event_requires_stage2', session_definition='not_in_this_legacy_view'))
    for _, r in rows(view / 'current_fields.jsonl'):
        field_ids[r['field_occurrence_id']] += 1
        field_counts['rows'] += 1
        field_counts['countable' if r.get('count_in_field_summary') else 'noncountable_parent'] += 1
        if r.get('count_in_field_summary') and (r.get('language_type') or 'unknown') == 'unknown':
            field_counts['countable_unknown_language_type'] += 1
        if r['log_version_id'] not in ids:
            field_counts['orphan_log_reference'] += 1
        if r['log_version_id'] in allowed and 'semantic_type_undetermined' in r.get('unresolved', []):
            semantic_unknown.add(r['log_version_id'])
    n = sum(ids.values())
    summary = dict(rows=n, repositories=len(repos), unique_observations=len(refs), extraction_status=dict(statuses),
        completed_fraction=statuses['completed']/n, partial_fraction=statuses['partial']/n,
        duplicate_primary_key_rows=sum(v-1 for v in ids.values()), duplicate_field_id_rows=sum(v-1 for v in field_ids.values()),
        coarse_locator_excess_rows=n-len(locators), same_source_excess_rows=sum(v-1 for v in source_keys.values()),
        development_rows=len(unresolved), withheld_rows=n-len(unresolved), development_missing_locator_fields=dict(missing),
        development_semantic_undetermined_logs=len(semantic_unknown), completed_but_semantic_undetermined=len(completed & semantic_unknown),
        extraction_gaps=dict(gaps), fields=dict(field_counts), source_meaning_completion_fraction=None, motivation_completion_fraction=None,
        interpretation='completed/partial are extraction states, not known source/meaning/motive rates',
        duplicate_policy='audit only; preserve original IDs, rows and filters', evaluated_holdout=False)
    table(out, 'unresolved_legacy_logs', unresolved, ['log_version_id', 'extraction_status', 'missing_locator_fields', 'extraction_gaps'])
    write_json(out / 'summary.json', summary)
    write_json(out / 'input_integrity.json', {'files': integrity, 'all_match_accepted_parent': all(r['matches'] for r in integrity)})
    for name in ('field_dictionary', 'raw_field_provenance', 'source_types', 'unresolved_field_definitions'):
        for ext in ('csv', 'jsonl'):
            shutil.copyfile(prior / (name + '.' + ext), out / (name + '.' + ext))
    if not all(r['matches'] for r in integrity):
        raise ValueError('legacy_parent_changed')
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--workspace', type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument('--output', type=Path, required=True)
    args=ap.parse_args()
    audit(args.workspace, args.output)
