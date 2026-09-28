"""Human-selected issue excerpts as scoped examples, never program-use gold.

Only canonical concepts and source anchors leave the private document snapshot.
Phrase extraction is rule annotation; the user's sensitivity assertion is human.
"""
from __future__ import annotations

from collections import Counter
import ast
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from .config import now, sha256_file
from .export import write_csv, write_json, write_jsonl
from .semantic_evidence import digest
from .storage import stable_id
from .taxonomy import taxonomy_catalog

VERSION = 'issue-knowledge-2'
# concept, category/subtype proposal, explicit description, retrieval cues.
# These phrases classify issue descriptions, NOT arbitrary program field names.
CONCEPTS = (
    ('password', 'AUTH', 'password', r'passwords?|passphrase|simple authentication', r'password|passwd|passphrase|SecretStr'),
    ('access_token', 'AUTH', 'access_token', r'\btokens?\b', r'access_token|auth_token|bearer'),
    ('service_key', 'AUTH', 'api_key', r'api ?keys?|secret ?keys?|cloud storage keys', r'api_key|secret_key|client_secret'),
    ('private_key', 'AUTH', 'private_key', r'private keys?|SSH keys?', r'private_key|SSH|keystore'),
    ('credential_container', 'AUTH', 'credential_bundle', r'credentials?|AuthenticationInfo|keystore contents', r'AuthenticationInfo|credentials|keystore'),
    ('authorization_header', 'AUTH', 'authorization_header', r'Authorization:\s*Basic|UsernameToken', r'Authorization|UsernameToken'),
    ('account_name', 'QID', None, r'usernames?', r'username|user_name'),
    ('user_identifier', 'QID', 'user_identifier', r'userid|Android can be linked by uid', r'user_id|Android'),
    ('person_name', 'PII', 'person_name', r'masking of passwords and names', r'full_name|person_name'),
    ('government_identifier', 'PII', 'government_identifier', r'social security number', r'SSN|social_security'),
    ('payment_card', 'PII', 'financial', r'credit cards?|credit card number', r'credit_card|card_number'),
    ('network_address', 'QID', 'network_identifier', r'ip addresses?|\bIP\b|private/public IPs', r'ip_address|RemoteAddr|SplitHostPort|client_ip'),
    ('hostname', 'CFG', None, r'hostnames?', r'hostname|host_name|SplitHostPort'),
    ('network_port', 'CFG', None, r'username/ip/port', r'SplitHostPort|RemoteAddr|extractPort'),
    ('filesystem_path', 'CFG', 'filesystem_path', r'jar:file:/', r'file_path|working_directory'),
    ('filename', 'CFG', None, r'filenames', r'filename|file_name'),
    ('file_content', 'BIZ', 'document_content', r'partial file content', r'file_content|document_content'),
    ('partition_name', 'CFG', None, r'name of the partitions', r'TopicPartition|partition_name'),
    ('record_key_value', 'BIZ', None, r'key[ /]value|key and value', r'ConsumerRecord|ProducerRecord|KeyValue'),
    ('record_payload', 'BIZ', None, r"record.s payload", r'ConsumerRecord|ProducerRecord|Message|Record'),
    ('table_schema', 'CFG', None, r'table schema details', r'TableSchema|table_schema'),
    ('row_key', 'BIZ', None, r'Row key', r'RowKey|row_key|GetRow'),
    ('mutation_content', 'BIZ', None, r'whole mutation', r'RowMutation|Mutation'),
    ('uri_parameters', 'BIZ', None, r'sensitive query parameters|URIs having options|credential is included in a URL', r'query_params|RawQuery|URL|URI'),
    ('configuration', 'CFG', 'deployment_configuration', r'config(?:uration)? (?:properties|file)|sensitive configs|logConf|clear text from conf', r'Configuration|config|logConf'),
    ('soap_message', 'BIZ', None, r'SOAP requests and responses|Payload:\s*<soap:Envelope', r'SOAP|Soap|Envelope'),
    ('database_statement', 'BIZ', None, r'\(Prepared\)Statements|DCL audit log statements', r'PreparedStatement|query|statement'),
    ('crash_dump', 'DIAG', None, r'crash report and minidump', r'minidump|crash_report'),
    ('error_message', 'DIAG', 'exception_message', r'leaked through error message', r'error|exception|err'),
    ('encrypted_key', 'AUTH', None, r'Encrypted user key', r'userKey|encrypted_key'),
    ('initialization_vector', 'AUTH', None, r'IV is|initVector', r'initVector|initialization_vector'),
)
DEFINITIONS = {c: {'concept': c, 'category': cat, 'subtype': sub,
    'classification_origin': 'rule_proposal_pending_human_type_review',
    'scope': 'reported_issue_context_only', 'target_human_confirmed': False}
    for c, cat, sub, _, _ in CONCEPTS}
ISSUE = re.compile(r'https://(?:issues\.apache\.org/jira/browse/[A-Z][A-Z0-9]*-\d+|github\.com/[\w.-]+/[\w.-]+/issues/\d+)(?:\?[^\s]*)?')


def paragraphs(document):
    """Retain native UTF-16 anchors, including paragraphs in tables and tabs."""
    def walk(content, tab):
        for element in content:
            if 'paragraph' in element:
                runs = element['paragraph'].get('elements', [])
                text = ''.join(r.get('textRun', {}).get('content', '') for r in runs)
                yield {'tab_id': tab, 'start': element.get('startIndex'), 'end': element.get('endIndex'), 'text': text}
            for row in element.get('table', {}).get('tableRows', []):
                for cell in row.get('tableCells', []): yield from walk(cell.get('content', []), tab)
    tabs = document.get('tabs') or [{'tabId': None, 'body': document.get('body')}]
    for tab in tabs:
        body = tab.get('body') or tab.get('documentTab', {}).get('body') or {}
        yield from walk(body.get('content', []), tab.get('tabId', tab.get('tabProperties', {}).get('tabId')))
        if tab.get('childTabs'): yield from paragraphs({'tabs': tab['childTabs']})


def extract(document, source_hash, reviewer, *, confirm_all_issues=False):
    units = {}; current = None; outside = []; occurrences = 0; nonempty = 0; previous_tab = None
    for p in paragraphs(document):
        if p['tab_id'] != previous_tab: current = None
        previous_tab = p['tab_id']
        if not p['text'].strip(): continue
        nonempty += 1
        if type(p['start']) is not int or type(p['end']) is not int or p['end'] <= p['start']:
            raise ValueError('document_paragraph_anchor_missing')
        urls = list(ISSUE.finditer(p['text']))
        if len(urls) > 1: raise ValueError('multiple_issue_links_in_paragraph_require_explicit_segmentation')
        if urls:
            u = urlsplit(urls[0].group()); current = 'https://' + u.netloc + u.path
            occurrences += 1
            units.setdefault(current, {'url': current, 'paragraphs': [], 'has_description': False, 'concepts': {}})
        anchor = {'tab_id': p['tab_id'], 'start_utf16': p['start'], 'end_utf16': p['end'], 'text_sha256': digest(p['text'])}
        if not current:
            outside.append({'anchor': anchor, 'reason': 'no_preceding_issue_link'}); continue
        unit = units[current]; unit['paragraphs'].append(anchor)
        # Spaces preserve Python character offsets before conversion to UTF-16.
        text = re.sub(r'https?://\S+', lambda m: ' ' * len(m.group()), p['text'])
        unit['has_description'] |= bool(text.strip())
        for concept, _, _, pattern, _ in CONCEPTS:
            for match in re.finditer(pattern, text, re.I):
                if concept in {'record_key_value', 'partition_name'} and '/KAFKA-' not in current: continue
                start = p['start'] + len(p['text'][:match.start()].encode('utf-16-le')) // 2
                end = p['start'] + len(p['text'][:match.end()].encode('utf-16-le')) // 2
                unit['concepts'].setdefault(concept, []).append({**anchor, 'match_start_utf16': start, 'match_end_utf16': end,
                    'match_sha256': digest(p['text'][match.start():match.end()])})
    records = []
    for url, u in units.items():
        project = url.rsplit('/', 1)[-1].rsplit('-', 1)[0] if 'issues.apache.org' in url else '/'.join(urlsplit(url).path.split('/')[1:3])
        records.append({'id': stable_id(source_hash, url), 'issue_url': url, 'issue_project': project,
            'source_sha256': source_hash, 'document_id': document['documentId'], 'revision_id': document.get('revisionId'),
            'paragraph_anchors': u['paragraphs'], 'link_association': 'nearest_preceding_document_link_unverified',
            'human_annotation': {'origin': 'human', 'annotator': reviewer, 'identity': 'self_declared_user',
                'label': 'sensitive_information' if confirm_all_issues or u['has_description'] else 'evidence_missing',
                'granularity': 'user_selected_issue_group_not_exact_redacted_span',
                'basis': ('explicit_human_confirmation_all_issue_groups' if confirm_all_issues else
                          'explicit_import_of_user_asserted_sensitive_issue_material'), 'subtype_confirmed': False},
            'description_status': 'present' if u['has_description'] else 'missing',
            'type_proposals': [{**DEFINITIONS[c], 'evidence': anchors} for c, anchors in sorted(u['concepts'].items())],
            'program_field_semantics': 'not_bound', 'dataset_metadata_semantics': 'not_applicable_issue_excerpt',
            'application_log_relation': 'reported_context_not_independently_verified', 'privacy_risk': 'not_runtime_confirmed',
            'source_issue_fetched': False, 'split': 'development_only_all_document_read',
            'redacted_values_reconstructed': False})
    return records, outside, {'nonempty_paragraphs': nonempty, 'issue_link_occurrences': occurrences}


def review_anchors(document, record):
    """Reopen original spans, not the extractor's explanation. No type gold claim."""
    original = {(p['tab_id'], p['start'], p['end']): p['text'] for p in paragraphs(document)}
    failures = []
    for t in record['type_proposals']:
        pattern = next(c[3] for c in CONCEPTS if c[0] == t['concept'])
        for a in t['evidence']:
            text = original.get((a['tab_id'], a['start_utf16'], a['end_utf16']))
            if text is None or digest(text) != a['text_sha256']:
                failures.append('paragraph_missing_or_changed'); continue
            try:
                fragment = text.encode('utf-16-le')[(a['match_start_utf16']-a['start_utf16'])*2:(a['match_end_utf16']-a['start_utf16'])*2].decode('utf-16-le')
            except UnicodeError: fragment = ''
            if digest(fragment) != a['match_sha256'] or not re.fullmatch(pattern, fragment, re.I): failures.append('span_mismatch')
            if t['concept'] in {'record_key_value','partition_name'} and '/KAFKA-' not in record['issue_url']:
                failures.append('source_project_scope_mismatch')
    return {'annotation_id': record['id'], 'origin': 'independent_source_span_replay_rule',
        'status': 'unsupported' if failures else 'supported' if record['type_proposals'] else 'ambiguous',
        'verified_dimension': 'literal_phrase_presence_and_anchor_integrity_only', 'reasons': failures,
        'source_issue_association': 'document_layout_unverified', 'human_type_review': 'pending'}


def load_knowledge(folder):
    folder = Path(folder); m = json.loads((folder/'manifest.json').read_text())
    if m['status'] != 'complete': raise ValueError('incomplete_issue_knowledge')
    for name, expected in m['artifacts'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts or sha256_file(folder/name) != expected:
            raise ValueError('issue_knowledge_integrity_mismatch')
    rows = [json.loads(line) for line in (folder/'issue_annotations.jsonl').read_text().splitlines()]
    for row in rows:
        for t in row['type_proposals']:
            if any(t.get(k) != v for k, v in DEFINITIONS[t['concept']].items()): raise ValueError('changed_concept_definition')
    return rows


def target_symbols(ctx, checks):
    """Only the anchored use and visible proof nodes, not neighboring variables."""
    from .semantic_context import contains
    anchors = [ctx.result['use_anchor']]
    for s in checks['steps']:
        anchors += [s[k] for k in ('anchor','definition_anchor') if s.get(k)]
    result = []
    for a in anchors:
        refs = [b['id'] for b in ctx.blocks if contains(b['anchor'], a)]
        if not refs: continue
        n = ctx.node(a); nodes = [n]
        if isinstance(n, ast.arg): nodes = list(ast.walk(n.annotation)) if n.annotation else []
        elif isinstance(n, ast.AnnAssign): nodes = list(ast.walk(n.annotation))
        elif isinstance(n, ast.Assign): nodes = [n.value]
        for node in nodes:
            symbol = None
            if isinstance(node, (ast.Name, ast.Attribute)): symbol = ast.unparse(node)
            elif isinstance(node, ast.Call): symbol = ast.unparse(node.func)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)): symbol = node.name
            elif node is not None and not isinstance(node, ast.AST):
                if node.type in {'identifier','selector_expression','member_expression'}: symbol = ctx.raw(a)
            if symbol and re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', symbol):
                result.append({'symbol': symbol, 'evidence_refs': refs})
    return result


def retrieve(context, checks, knowledge, limit=4, max_chars=4000, subjects=None):
    """Cues select analogies only; these are deliberately NOT code evidence IDs."""
    suggestions = []; meanings = checks.get('independent_rule_replay', {}).get('derived_meanings', [])
    for concept, cat, sub, _, cue in CONCEPTS:
        examples = [r for r in knowledge if any(t['concept'] == concept for t in r['type_proposals'])]
        if not examples: continue
        refs = sorted({ref for s in (subjects or []) if re.search(r'\b(?:' + cue + r')\b', s['symbol'], re.I) for ref in s['evidence_refs']})
        typed = sub is not None and any(m.get('category') == cat and m.get('subtype') == sub for m in meanings)
        if not refs and not typed: continue
        suggestions.append({**DEFINITIONS[concept], 'id': stable_id(concept, [r['id'] for r in examples]),
            'selection_basis': 'independent_rule_type' if typed else 'lexical_context_retrieval_only',
            'target_code_refs': refs, 'target_binding_status': 'requires_independent_code_evidence',
            'source_examples': [{'annotation_id': r['id'], 'issue_url': r['issue_url'], 'source_sha256': r['source_sha256'],
                'human_label_scope': r['human_annotation']['granularity']} for r in examples[:2]],
            'matching_source_examples': len(examples)})
    suggestions.sort(key=lambda s: (s['selection_basis'] != 'independent_rule_type', s['concept']))
    selected = []
    for s in suggestions[:limit]:
        if len(json.dumps(selected+[s], ensure_ascii=False)) <= max_chars: selected.append(s)
    return {'suggestions': selected, 'eligible_concepts': len(suggestions), 'omitted_by_budget': len(suggestions)-len(selected),
        'example_chars': len(json.dumps(selected, ensure_ascii=False)), 'example_char_budget': max_chars,
        'source_human_labels_are_target_truth': False, 'role': 'analogy_and_type_proposal_only'}


def run_knowledge(source, output, *, reviewer, analysis_run=None, max_cases=100, offline=True, dry_run=False, resume=False,
                  confirm_all_issues=False):
    if not reviewer or not reviewer.strip(): raise ValueError('explicit_self_declared_human_annotator_required')
    if not 1 <= max_cases <= 100: raise ValueError('case_budget_must_be_1_to_100')
    if dry_run: return {'status': 'dry_run', 'files_written': False, 'model_calls': 0, 'exit_code': 0}
    source = Path(source); output = Path(output)
    fingerprint = {'source_sha256': sha256_file(source), 'reviewer': reviewer, 'version': VERSION, 'max_cases': max_cases,
        'confirm_all_issues': confirm_all_issues,
        'sources': {p.name: sha256_file(p) for p in Path(__file__).parent.glob('*.py')},
        'analysis_manifest': sha256_file(Path(analysis_run)/'manifest.json') if analysis_run else None,
        'analysis_checkpoint': sha256_file(Path(analysis_run)/'checkpoint.sqlite') if analysis_run else None}
    if (output/'manifest.json').exists():
        manifest = json.loads((output/'manifest.json').read_text())
        if not resume or manifest['fingerprint'] != fingerprint: raise ValueError('incompatible_run_use_new_directory')
        if manifest['status'] == 'complete':
            load_knowledge(output); return {**json.loads((output/'coverage.json').read_text()), 'resumed_without_calls': True}
    elif output.exists() and any(output.iterdir()): raise ValueError('output_directory_not_empty')
    document = json.loads(source.read_text()); document = document.get('document', document)
    rows, exclusions, counts = extract(document, fingerprint['source_sha256'], reviewer.strip(),
                                     confirm_all_issues=confirm_all_issues)
    reviews = [review_anchors(document, r) for r in rows]
    if any(r['status'] == 'unsupported' for r in reviews): raise ValueError('source_projection_failed_independent_replay')
    mapped_pairs = {(c['category'], s['subtype']) for c in taxonomy_catalog()['categories'] for s in c['subtypes']}
    for r in rows:
        for t in r['type_proposals']: t['mapping_status'] = 'existing_catalog_proposal' if (t['category'],t['subtype']) in mapped_pairs else 'new_or_split_type_pending_human'
    queues = [{'annotation_id': r['id'], 'reason': 'type_mapping_pending_human' if r['type_proposals'] else
               'context_missing' if r['description_status'] == 'missing' else 'semantic_unknown',
               'concepts': [t['concept'] for t in r['type_proposals']]} for r in rows]
    programs = []
    if analysis_run:
        from .semantic_context import HistoricalContext, load_run
        cases, snapshots, _ = load_run(analysis_run)
        for cid, case in sorted(cases.items()):
            if len(programs) >= max_cases:
                exclusions.append({'case_id': cid, 'reason': 'program_case_budget'}); continue
            r = case['result']; raw = snapshots.get((r['repository'], r['sha']))
            row = {'case_id': cid, 'repository': r['repository'], 'sha': r['sha'], 'language': r['language'],
                   'field': r['field'], 'human_confirmed': False, 'target_code_executed': False, 'model_run': False}
            if raw:
                ctx = HistoricalContext(case, raw); initial = ctx.initial()
                checks = ctx.checks()
                row.update(context_status=initial['status'], knowledge=retrieve(ctx.payload(), checks, rows, subjects=target_symbols(ctx,checks)),
                    program_field_semantics='unchanged_pending_review', log_relation=ctx.log_relation(),
                    privacy_risk='unchanged_pending_review')
            else: row.update(context_status='historical_snapshot_missing', knowledge={'suggestions': []})
            programs.append(row)
    report = {'status': 'complete', 'exit_code': 0, 'created_at': now(), **counts,
        'unique_issue_groups': len(rows), 'duplicate_link_occurrences': counts['issue_link_occurrences']-len(rows),
        'human_sensitive_excerpt_groups': sum(r['human_annotation']['label']=='sensitive_information' for r in rows),
        'human_sensitive_reference_groups': sum(r['human_annotation']['label']=='sensitive_information' for r in rows),
        'human_confirmation_scope': 'all_issue_groups' if confirm_all_issues else 'described_issue_groups',
        'missing_description_groups': sum(r['description_status']=='missing' for r in rows),
        'groups_with_type_proposals': sum(bool(r['type_proposals']) for r in rows),
        'type_proposal_occurrences': sum(len(r['type_proposals']) for r in rows),
        'concept_counts': dict(Counter(t['concept'] for r in rows for t in r['type_proposals'])),
        'mapping_counts': dict(Counter(t['mapping_status'] for r in rows for t in r['type_proposals'])),
        'issue_project_counts': dict(Counter(r['issue_project'] for r in rows)),
        'program_cases_processed': len(programs), 'program_cases_with_analogies': sum(bool(r['knowledge']['suggestions']) for r in programs),
        'program_repository_counts': dict(Counter(r['repository'] for r in programs)),
        'program_language_counts': dict(Counter(r['language'] for r in programs)),
        'program_context_counts': dict(Counter(r['context_status'] for r in programs)),
        'program_human_truth': 0, 'human_subtype_truth': 0, 'model_calls': 0, 'paid_api_calls': 0,
        'accuracy': None, 'recall': None, 'held_out_evaluation': False,
        'annotation_boundary': 'human issue-group sensitivity; rule-generated concepts pending review; no exact span or negative gold',
        'raw_document_exported': False, 'remote_issue_verification': 'not_run', 'taxonomy_changed': False}
    report['funnel'] = {k: report[k] for k in ('nonempty_paragraphs','issue_link_occurrences','unique_issue_groups',
        'human_sensitive_reference_groups','human_sensitive_excerpt_groups','missing_description_groups','groups_with_type_proposals','type_proposal_occurrences',
        'program_cases_processed','program_cases_with_analogies','program_human_truth')}
    manifest = {'status': 'running', 'fingerprint': fingerprint}
    write_json(output/'manifest.json', manifest)
    tables = {'issue_annotations': rows, 'independent_source_reviews': reviews, 'review_queue': queues, 'exclusions': exclusions, 'program_knowledge_candidates': programs,
        'category_proposals': [{**DEFINITIONS[c], 'status': 'pending_human_decision', 'action': 'new_or_split',
            'source_annotation_ids': [r['id'] for r in rows if any(t['concept']==c for t in r['type_proposals'])]}
            for c in report['concept_counts'] if DEFINITIONS[c]['subtype'] is None]}
    for name, records in tables.items():
        write_jsonl(output/(name+'.jsonl'), records); write_csv(output/(name+'.csv'), records)
    for r in rows: write_json(output/'evidence'/(r['id']+'.json'), r)
    write_json(output/'coverage.json', report)
    manifest.update(status='complete', artifacts={str(p.relative_to(output)): sha256_file(p) for p in output.rglob('*') if p.is_file() and p.name != 'manifest.json'})
    write_json(output/'manifest.json', manifest)
    return report
