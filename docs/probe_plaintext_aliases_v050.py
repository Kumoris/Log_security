"""Single bounded discovery pass over frozen AIDev string cells; no classifier edits."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import json
import sys
import time

import pyarrow.parquet as pq
from agentlog_unified import content_scan, content_repair, content_types, taxonomy
import probe_personal_attribute_fields_v049 as personal
from probe_json_key_aliases_v050 import ALIASES

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'
FROZEN = Path('/private/tmp/aidev_alias_plaintext_v050_frozen/src/agentlog_unified')
MAX_SECONDS = 300
BASELINE_CELLS = 32
BASELINE_CELLS_PER_ALIAS = 2
ALIAS_IDS = {name: f'alias_{i:03d}' for i, name in enumerate(sorted(ALIASES), 1)}
TYPES = {name: sorted({r[:2] for r in taxonomy._matches(value)}) for name, value in ALIASES.items()}


def fingerprints():
    return {'src/agentlog_unified/' + p.name: content_repair._digest(p) for p in FROZEN.glob('*.py')}


def assignments(text):
    for match in personal.KEY.finditer(text):
        alias = match['key'].casefold()
        if alias not in ALIASES:
            continue
        raw = match['value']; start, end = match.span('value')
        quoted = len(raw) > 1 and raw[0] in '\"\'' and raw[-1] == raw[0]
        value = raw[1:-1] if quoted else raw.rstrip('}])')
        if quoted:
            start += 1; end -= 1
        else:
            end = start + len(value)
        if not value.strip(): quality = 'empty_value'
        elif not quoted and value.lower() in {'none', 'null', 'nil'}: quality = 'null_value'
        elif content_types._example(text, start, end) or value.lower() in {'yyyy-mm-dd', 'yyyy/mm/dd', 'dd/mm/yyyy', 'mm/dd/yyyy'}: quality = 'placeholder_or_example'
        elif value.startswith(('{', '[', '(', '${', '$')) or content_types._TEMPLATE.search(value): quality = 'container_not_scalar' if value.startswith(('{', '[')) else 'reference_or_expression'
        elif value.lower() in personal.TYPE_WORDS: quality = 'type_declaration'
        elif quoted: quality = 'explicit_literal_value'
        elif personal.NUMBER.fullmatch(value) or personal.DATE.fullmatch(value) or value in {'true', 'false', 'True', 'False'}: quality = 'unquoted_literal_value'
        elif content_types._REFERENCE.fullmatch(value): quality = 'unquoted_identifier_ambiguous' if '.' not in value else 'reference_or_expression'
        else: quality = 'reference_or_expression'
        yield {'alias_id': ALIAS_IDS[alias], 'key_start': match.start('key'), 'key_end': match.end('key'),
               'value_start': start, 'value_end': end, 'value_quality': quality,
               'expected_types': [{'category': a, 'subtype': b} for a, b in TYPES[alias]],
               'baseline_key_types': [{'category': r[0], 'subtype': r[1]} for r in taxonomy._matches(match['key'])]}


def self_test():
    cases = [('IPAddr="redacted"', 'placeholder_or_example'), ('用户ID=17', 'unquoted_literal_value'),
             ('密码=""', 'empty_value'), ('性别=null', 'null_value'), ('姓名=string', 'type_declaration'),
             ('api密钥=user.key', 'reference_or_expression'), ('学历="graduate"', 'explicit_literal_value'),
             ('民族=value', 'unquoted_identifier_ambiguous'), ('请求体={}', 'container_not_scalar')]
    for text, quality in cases:
        rows = list(assignments(text)); assert len(rows) == 1 and rows[0]['value_quality'] == quality
    for text in ['password="value"', 'APIKey=17', 'Discuss 密码', '密码 == value', '密码 => value', '密码数量=4', '对象.密码="x"']:
        assert not list(assignments(text))
    assert len(ALIASES) == 98 and ALIASES == json.loads((DOCS / 'json_key_alias_probe_v050.json').read_text())['proposed_aliases']
    assert all(Path(m.__file__).parent == FROZEN for m in (content_scan, content_repair, content_types, taxonomy))
    assert fingerprints() == json.loads((DOCS / 'plaintext_alias_probe_v050_source_snapshot.json').read_text())['source_sha256']
    print(json.dumps({'synthetic_checks': 19, 'all_passed': True, 'real_source_values_read': False}), flush=True)


def main():
    start = time.monotonic(); started = datetime.now(timezone.utc).isoformat(); deadline = start + MAX_SECONDS
    output = DOCS / 'plaintext_alias_probe_v050.json'; evidence_path = DOCS / 'plaintext_alias_probe_v050_evidence.jsonl'
    if output.exists() or evidence_path.exists(): raise FileExistsError('Preserve previous probe evidence')
    self_test(); source_before = fingerprints()
    helpers = [Path(__file__), Path(personal.__file__), DOCS / 'probe_json_key_aliases_v050.py',
               DOCS / 'json_key_alias_probe_v050.json', DOCS / 'json_key_alias_probe_v050_selection.jsonl']
    helper_before = {p.name: content_repair._digest(p) for p in helpers}
    dataset, manifest_sha, tables = content_scan._inventory(ROOT / 'inputs/aidev-full-v2')
    assert dataset == 'aidev'
    old = json.loads((DOCS / 'json_key_alias_probe_v050.json').read_text())
    assert old['source_manifest_sha256'] == manifest_sha and old['all_selected_documents_replayed']
    assert old['frozen_source_inputs'] == [{k: t[k] for k in ('path', 'bytes', 'sha256')} for t in tables]
    assert old['selection_sha256'] == helper_before['json_key_alias_probe_v050_selection.jsonl']
    parsed = defaultdict(list)
    for line in (DOCS / old['selection_path']).open():
        row = json.loads(line)
        parsed[row['table_path'], row['column_name'], row['source_row']].append((row['source_start'], row['source_end']))
    historical = json.loads((ROOT / 'content-runs/aidev-v049/content_coverage.json').read_text())
    assert historical['source_manifest_sha256'] == manifest_sha and historical['all_selected_text_rows_visited']
    historical_sha = content_repair._digest(ROOT / 'content-runs/aidev-v049/content_coverage.json')
    stats = Counter(); qualities = Counter(); alias_counts = Counter(); overlap = Counter(); coverage = []; evidence_count = 0
    baseline_aliases = Counter(); baseline_cells = 0; baseline_counts = Counter(); stop = None
    with evidence_path.open('w') as evidence:
        for table in tables:
            columns = [f['column'] for f in table['columns'] if f['selected']]
            fields = {column: Counter() for column in columns}; seen = 0
            if columns and not stop:
                parquet = pq.ParquetFile(table['absolute_path'])
                for batch in parquet.iter_batches(batch_size=256, columns=columns, use_threads=False):
                    if time.monotonic() >= deadline: stop = 'time_budget'; break
                    for raw in batch.to_pylist():
                        if time.monotonic() >= deadline: stop = 'time_budget'; break
                        seen += 1
                        for column in columns:
                            field = fields[column]; value = raw[column]; field['source_cells_visited'] += 1; stats['text_cells_visited'] += 1
                            if value is None:
                                field['null_cells'] += 1; stats['null_cells'] += 1; continue
                            if not value.strip():
                                field['empty_cells'] += 1; stats['empty_cells'] += 1; continue
                            field['nonempty_cells'] += 1; stats['nonempty_cells'] += 1
                            for counter in (field, stats):
                                counter['characters_seen'] += len(value); counter['characters_examined'] += min(len(value), personal.MAX_CHARS)
                                counter['source_prefix_truncated_cells'] += int(len(value) > personal.MAX_CHARS)
                            prefix = value[:personal.MAX_CHARS]; hits = list(assignments(prefix))
                            if not hits: continue
                            field['source_cells_with_alias_assignments'] += 1; stats['source_cells_with_alias_assignments'] += 1
                            ids = {h['alias_id'] for h in hits}
                            replay = baseline_cells < BASELINE_CELLS and any(baseline_aliases[a] < BASELINE_CELLS_PER_ALIAS for a in ids)
                            baseline = content_types.classify_text(prefix) if replay else None
                            if replay:
                                baseline_cells += 1; baseline_aliases.update(ids); baseline_counts['truncated_classifier_cells'] += int(baseline['truncated'])
                            for hit in hits:
                                key = table['path'], column, seen
                                in_parsed = any(a <= hit['key_start'] and hit['value_end'] <= b for a, b in parsed.get(key, []))
                                result = {'table_path': table['path'], 'column_name': column, 'source_row': seen, **hit,
                                          'within_prior_successful_json_document': in_parsed, 'baseline_replayed': replay,
                                          'human_review_status': 'pending', 'personal_ownership_confirmed': False,
                                          'sensitivity_confirmed': False, 'runtime_confirmed': False}
                                if replay:
                                    matched = [m for m in baseline['matches'] if m['start'] == hit['value_start'] and m['end'] == hit['value_end']]
                                    result['baseline_same_value_span_types'] = [{k: m[k] for k in ('category', 'subtype', 'value_status', 'candidate_status')} for m in matched]
                                    result['baseline_expected_type_found'] = any({'category': m['category'], 'subtype': m['subtype']} in hit['expected_types'] for m in matched)
                                    baseline_counts['field_assignments_replayed'] += 1
                                    baseline_counts['expected_type_found' if result['baseline_expected_type_found'] else 'expected_type_not_found'] += 1
                                evidence.write(json.dumps(result, sort_keys=True, ensure_ascii=False) + '\n')
                                evidence_count += 1; alias_counts[hit['alias_id']] += 1; qualities[hit['value_quality']] += 1
                                overlap['within_prior_successful_json_document' if in_parsed else 'outside_prior_successful_json_document'] += 1
                        stats['processed_source_rows'] += 1
                    if stop: break
            elif not columns:
                seen = table['rows']; stats['source_rows_without_text_columns_footer_only'] += seen
            coverage.append({'table_path': table['path'], 'source_rows': table['rows'], 'visited_rows': seen,
                             'row_completion_semantics': 'all_selected_columns_in_each_visited_row', 'complete': seen == table['rows'],
                             'first_unvisited_source_row': seen + 1 if seen < table['rows'] else None,
                             'fields': [{'column_name': c, 'source_cell_denominator': table['rows'], **dict(fields[c])} for c in columns]})
            assert content_scan._stat(Path(table['absolute_path'])) == tuple(table['source_stat'])
            print(json.dumps({'table_path': table['path'], 'visited_rows': seen, 'source_rows': table['rows'],
                              'alias_assignments': evidence_count, 'alias_counts': dict(alias_counts),
                              'elapsed_seconds': round(time.monotonic() - start, 3), 'stop_reason': stop}), flush=True)
    assert all(content_scan._stat(Path(t['absolute_path'])) == tuple(t['source_stat']) for t in tables)
    assert content_repair._digest(ROOT / 'inputs/aidev-full-v2/manifest.json') == manifest_sha
    assert source_before == fingerprints() and helper_before == {p.name: content_repair._digest(p) for p in helpers}
    complete = all(t['complete'] for t in coverage)
    report = {'started_utc': started, 'completed_utc': datetime.now(timezone.utc).isoformat(), 'elapsed_seconds': time.monotonic() - start,
              'time_budget_seconds': MAX_SECONDS, 'full_scan_attempts': 1, 'stop_reason': stop,
              'selection_rule': 'All frozen AIDev string/large_string columns and rows, then exact 98 fixed casefold aliases in Unicode key:value/key=value syntax; no content-based row filter.',
              'source_manifest_sha256': manifest_sha, 'frozen_source_inputs': [{k: t[k] for k in ('path', 'bytes', 'sha256')} for t in tables],
              'source_code_sha256': source_before, 'helper_sha256': helper_before, 'frozen_package': str(FROZEN),
              'source_inputs_and_frozen_implementation_unchanged': True, 'table_denominator': len(tables),
              'string_column_denominator': sum(len(t['fields']) for t in coverage), 'source_row_denominator': sum(t['rows'] for t in tables),
              'text_cell_denominator': sum(t['rows'] * sum(f['selected'] for f in t['columns']) for t in tables),
              'historical_complete_nonempty_text_cell_denominator': historical['counts']['nonempty_cells'],
              'historical_complete_coverage_sha256': historical_sha, 'scan_stats': dict(stats), 'coverage': coverage,
              'all_selected_source_rows_visited': complete, 'field_assignment_count': evidence_count, 'value_quality_counts': dict(qualities),
              'prior_json_overlap_counts': dict(overlap), 'baseline_source_cells_replayed': baseline_cells, 'baseline_counts': dict(baseline_counts),
              'baseline_source_cell_budget': BASELINE_CELLS, 'baseline_source_cell_per_alias_target': BASELINE_CELLS_PER_ALIAS,
              'alias_catalog': [{'alias_id': ALIAS_IDS[a], 'predeclared_alias': a, 'canonical_hint': ALIASES[a],
                                 'expected_types': [{'category': x, 'subtype': y} for x, y in TYPES[a]], 'field_assignment_count': alias_counts[ALIAS_IDS[a]]} for a in sorted(ALIASES)],
              'evidence_path': evidence_path.name, 'evidence_sha256': content_repair._digest(evidence_path),
              'source_values_exported': False, 'dynamic_keys_exported': False, 'value_hashes_exported': False,
              'formal_source_or_tests_modified': False, 'network_accessed': False, 'new_sensitive_types_established': False,
              'limitations': ['Finite explicit assignments only; ordinary mentions and unrecognized keys remain outside this probe.',
                              'A key hint or quoted value is not confirmed personal data, a real credential, or an application log finding.',
                              'The baseline is purposive and capped at 32 source cells; no-hit cells never call the classifier.',
                              'Prior JSON document overlap uses the previously verified 5422-document source spans and does not newly parse other formats.',
                              'Character positions are Python string offsets; each cell is capped at a 1MiB prefix and the reused recognizer bounds quoted values to 4096 and unquoted values to 256 characters.',
                              'Arrow may decode a prefetched batch beyond the last committed source row; reported visited rows are complete all-field logical observations.',
                              'Source cells, field assignments, and type hints have different denominators and cannot be added into counts of people or secrets.']}
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'report': str(output), 'all_selected_source_rows_visited': complete, 'stats': dict(stats),
                      'field_assignments': evidence_count, 'alias_counts': dict(alias_counts), 'baseline_counts': dict(baseline_counts)}), flush=True)


if __name__ == '__main__':
    self_test() if sys.argv[1:] == ['--self-test'] else main()
