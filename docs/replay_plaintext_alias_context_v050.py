"""Bounded reread of the already chosen 11 cells; export fixed syntax labels only."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import ipaddress
import json
import re
import time

from agentlog_unified import content_scan, content_repair, content_types
from probe_plaintext_aliases_v050 import DOCS, ROOT, assignments, fingerprints

LOGGER = re.compile(r'\b(?:log(?:ger|ging)?\.(?:debug|info|warn|warning|error|critical|exception)|console\.(?:log|info|debug|warn|error))\s*\(', re.I)
INTERPOLATION = re.compile(r'\$\{|\{[A-Za-z_][\w.\[\]]*\}|%[sdv]')
REFERENCE = re.compile(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|\[[^\n]{1,128}\])+')


def value_role(value, prior_quality):
    if not value.strip(): return 'empty'
    if prior_quality == 'type_declaration': return 'type_declaration'
    try:
        return 'ipv4_literal_shape' if ipaddress.ip_address(value).version == 4 else 'ipv6_literal_shape'
    except ValueError:
        pass
    if INTERPOLATION.search(value): return 'interpolation_syntax'
    if REFERENCE.search(value): return 'member_or_index_reference_syntax'
    if re.search(r'[A-Za-z_]\w*\s*\(', value): return 'call_expression_syntax'
    if re.search(r'[\u3400-\u9fff]', value): return 'non_ascii_prose_or_unresolved_syntax'
    if value.startswith(('<', '[', '`')): return 'markup_or_quote_syntax'
    return 'other_unresolved_syntax'


def main():
    started = time.monotonic(); start_utc = datetime.now(timezone.utc).isoformat(); deadline = started + 90
    source_before = fingerprints(); helper_before = content_repair._digest(Path(__file__))
    report = json.loads((DOCS / 'plaintext_alias_probe_v050.json').read_text())
    assert source_before == report['source_code_sha256']
    evidence = [json.loads(line) for line in (DOCS / report['evidence_path']).open()]
    selected = [e for e in evidence if e['baseline_replayed']]
    grouped = defaultdict(list)
    for e in selected: grouped[e['table_path'], e['column_name'], e['source_row']].append(e)
    assert len(grouped) == report['baseline_source_cells_replayed'] == 11
    cells = [dict(zip(('table_path', 'column_name', 'source_row'), key)) for key in grouped]
    dataset, source_sha, tables = content_scan._inventory(ROOT / 'inputs/aidev-full-v2')
    assert dataset == 'aidev' and source_sha == report['source_manifest_sha256']
    assert report['frozen_source_inputs'] == [{k: t[k] for k in ('path', 'bytes', 'sha256')} for t in tables]
    table_map = {t['path']: t for t in tables}; stats = {t['path']: tuple(t['source_stat']) for t in tables}
    rows = []; decoded = 0
    for cell, text, _, _ in content_repair._selected_values(cells, table_map, deadline, stats):
        decoded += 1; key = cell['table_path'], cell['column_name'], cell['source_row']
        current = list(assignments(text[:1048576])); baseline = content_types.classify_text(text[:1048576])
        assert not baseline['truncated']
        for item in grouped[key]:
            match = next(m for m in current if (m['alias_id'], m['key_start'], m['value_start'], m['value_end']) == (item['alias_id'], item['key_start'], item['value_start'], item['value_end']))
            assert match['value_quality'] == item['value_quality'] and match['expected_types'] == item['expected_types']
            begin = text.rfind('\n', 0, item['key_start']) + 1; end = text.find('\n', item['value_end'])
            line = text[begin:end if end >= 0 else len(text)]
            before_key = text[begin:item['key_start']]
            value = text[item['value_start']:item['value_end']]
            fence = None
            for previous in text[:begin].splitlines():
                marker = re.match(r'^\s*(`{3,}|~{3,})', previous)
                if marker:
                    char = marker[1][0]
                    if fence is None: fence = char
                    elif fence == char: fence = None
            same_span = [m for m in baseline['matches'] if m['start'] == item['value_start'] and m['end'] == item['value_end']]
            check_projection = [{k: m[k] for k in ('category', 'subtype', 'value_status', 'candidate_status')} for m in same_span]
            assert check_projection == item['baseline_same_value_span_types']
            expected = {(m['category'], m['subtype']) for m in item['expected_types']}
            present = {(m['category'], m['subtype']) for m in baseline['matches'] if m['candidate_status'] != 'placeholder_or_example'}
            rows.append({k: item[k] for k in ('table_path', 'column_name', 'source_row', 'alias_id', 'key_start', 'key_end', 'value_start', 'value_end', 'value_quality', 'expected_types', 'baseline_expected_type_found')} | {
                'value_syntax_role': value_role(value, item['value_quality']),
                'source_column_role': 'patch' if cell['column_name'] == 'patch' else 'pull_request_body',
                'patch_line_role': ('added' if line.startswith('+') else 'deleted' if line.startswith('-') else 'context_or_unresolved') if cell['column_name'] == 'patch' else 'not_patch',
                'inside_markdown_fence_by_line_markers': fence is not None,
                'logger_call_syntax_before_key_same_line': bool(LOGGER.search(before_key)),
                'quote_or_backtick_before_key_same_line': bool(re.search(r'[\"\x27`]', before_key)),
                'expected_type_elsewhere_or_same_position_in_baseline_cell': bool(expected & present),
                'human_review_status': 'pending', 'personal_ownership_confirmed': False, 'sensitivity_confirmed': False, 'application_log_evidence_confirmed': False})
    assert decoded == len(cells) and len(rows) == len(selected) == 14
    assert source_before == fingerprints() and helper_before == content_repair._digest(Path(__file__))
    assert all(content_scan._stat(Path(t['absolute_path'])) == stats[t['path']] for t in tables)
    out = DOCS / 'plaintext_alias_context_v050_evidence.jsonl'
    if out.exists(): raise FileExistsError('Preserve prior context evidence')
    out.write_text(''.join(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n' for r in rows))
    summary = {'started_utc': start_utc, 'completed_utc': datetime.now(timezone.utc).isoformat(), 'elapsed_seconds': time.monotonic() - started,
               'selected_source_cells': len(cells), 'decoded_source_cells': decoded, 'selected_field_assignments': len(rows),
               'selection_rule': 'Exactly the fixed, previously replayed 11 cells / 14 field assignments; no new source selection or corpus scan.',
               'syntax_role_counts': dict(Counter(r['value_syntax_role'] for r in rows)),
               'logger_syntax_before_key_count': sum(r['logger_call_syntax_before_key_same_line'] for r in rows),
               'baseline_same_value_span_expected_type_found': sum(r['baseline_expected_type_found'] for r in rows),
               'baseline_same_source_cell_expected_type_found': sum(r['expected_type_elsewhere_or_same_position_in_baseline_cell'] for r in rows),
               'source_manifest_sha256': source_sha, 'source_code_sha256': source_before, 'helper_sha256': helper_before,
               'discovery_report_sha256': content_repair._digest(DOCS / 'plaintext_alias_probe_v050.json'),
               'evidence_sha256': content_repair._digest(out), 'source_inputs_and_frozen_implementation_unchanged': True,
               'source_values_exported': False, 'dynamic_keys_exported': False, 'value_hashes_exported': False,
               'limitations': ['Syntax labels are deterministic observations only; source code/prose and log-like calls do not establish runtime application logging or sensitive values.',
                               'The original coarse reference_or_expression quality includes address-shaped and markup-shaped values; this bounded supplement preserves and refines it without editing the full scan.',
                               'The frozen canonical request_id hint returns both request_identifier and a coarse request_body overlap; these are existing-rule hints, not two verified meanings.',
                               'Counts are purposive field assignments, not unique people, secrets, new types, or a full-population error rate.']}
    (DOCS / 'plaintext_alias_context_v050.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: summary[k] for k in ('selected_source_cells', 'selected_field_assignments', 'syntax_role_counts', 'logger_syntax_before_key_count', 'baseline_same_value_span_expected_type_found', 'baseline_same_source_cell_expected_type_found', 'source_inputs_and_frozen_implementation_unchanged')}))


if __name__ == '__main__': main()
