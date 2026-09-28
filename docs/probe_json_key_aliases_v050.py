"""Bounded existing-parser replay of a fixed JSON document cohort; labels only."""
from collections import Counter, defaultdict
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
import fcntl
import hashlib
import json
import re
import sqlite3
import sys
import time

from agentlog_unified import content_repair, content_scan, structured_scan
from agentlog_unified import structured_types as parser, taxonomy

ROOT = Path(__file__).resolve().parents[1]
LIMIT_SECONDS = 180
LIMIT_DOCUMENTS = 6000
# Fixed aliases proposed before reading keys. Generic ID/name/UID/race remain untouched.
ALIASES = {
    'ipaddr': 'ip_address', 'clientipaddr': 'client_ip', 'remoteipaddr': 'remote_addr',
    '密码': 'password', '用户密码': 'password', '访问令牌': 'access_token', '刷新令牌': 'refresh_token',
    '认证令牌': 'auth_token', 'api密钥': 'api_key', '接口密钥': 'api_key', '服务密钥': 'api_key',
    '私钥': 'private_key', '认证cookie': 'auth_cookie', '认证头': 'authorization', '授权头': 'authorization',
    '凭证': 'credentials', '电子邮箱': 'email', '邮箱': 'email', '邮件地址': 'email',
    '电话号码': 'phone_number', '手机号': 'mobile_number', '手机号码': 'mobile_number',
    '个人姓名': 'person_name', '用户姓名': 'user_name', '姓名': 'person_name',
    '邮寄地址': 'postal_address', '家庭住址': 'home_address', '收货地址': 'shipping_address', '通信地址': 'postal_address',
    '身份证号': 'national_id', '护照号码': 'passport_number', '社保号码': 'social_security_number',
    '医疗记录': 'medical_record', '健康记录': 'health_record', '诊断': 'diagnosis', '处方': 'prescription',
    '银行卡号': 'card_number', '银行账号': 'bank_account', '个人收入': 'income', '薪资': 'salary',
    '精确位置': 'precise_location', '纬度': 'latitude', '经度': 'longitude',
    '指纹模板': 'fingerprint_template', '面部特征向量': 'face_embedding', '虹膜模板': 'iris_template',
    '用户编号': 'user_id', '用户id': 'user_id', '账户id': 'account_id', '账号id': 'account_id', '客户编号': 'customer_number',
    '会话id': 'session_id', '会话编号': 'session_id', '设备id': 'device_id', '设备编号': 'device_id',
    'ip地址': 'ip_address', '客户端ip': 'client_ip', '远程ip地址': 'remote_addr',
    '请求id': 'request_id', '请求编号': 'request_id', '跟踪id': 'trace_id',
    '订单id': 'order_id', '交易id': 'transaction_id', '付款id': 'payment_id', '租户id': 'tenant_id', '租户编号': 'tenant_id',
    '出生日期': 'birth_date', '生日': 'birth_date', '个人年龄': 'person_age', '用户年龄': 'user_age',
    '性别': 'gender', '性别认同': 'gender_identity', '民族': 'ethnicity', '族裔': 'ethnicity', '种族属性': 'racial_identity',
    '宗教信仰': 'religious_belief', '宗教归属': 'religious_affiliation',
    '学历': 'education_level', '教育经历': 'education_history', '最高学位': 'highest_degree',
    '就业状况': 'employment_status', '个人职业': 'occupation', '雇主名称': 'employer_name',
    '请求体': 'request_body', '响应体': 'response_body', '请求头': 'headers', '文档内容': 'document_content',
    '消息内容': 'message_content', '业务对象': 'business_object', '数据库连接串': 'connection_string',
    '数据库地址': 'database_url', '内部端点': 'internal_endpoint', '内部路径': 'internal_path',
    '环境变量': 'environment', '部署配置': 'deployment_config', '异常信息': 'exception',
    '堆栈跟踪': 'stack_trace', '错误响应': 'error_response',
}
TYPE_ROWS = {(r[0], r[1]): r for r in taxonomy.RULES}


def types(rows):
    return {r[:2] for r in rows}


def variants(name):
    normalized = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name)
    original = taxonomy._matches(name)
    normalized_rows = taxonomy._matches(normalized)
    canonical = ALIASES.get(name.casefold())
    alias_rows = taxonomy._matches(canonical) if canonical else []
    combined = {r[:2]: r for r in original + normalized_rows + alias_rows}
    return original, normalized_rows, alias_rows, list(combined.values())


def proposed(name):
    return variants(name)[3]


def self_test():
    controls = [('APIKey', ('AUTH', 'api_key')), ('userID', ('QID', 'user_identifier'))]
    for key, expected in controls:
        assert expected in types(taxonomy._matches(key)) and types(proposed(key)) == types(taxonomy._matches(key))
    for key, expected in [('HTTPHeaders', ('BIZ', 'http_headers')), ('IDToken', ('AUTH', 'access_token')),
                          ('IPAddr', ('QID', 'network_identifier')), ('密码', ('AUTH', 'password')),
                          ('用户ID', ('QID', 'user_identifier')), ('出生日期', ('PII', 'birth_date'))]:
        assert expected in types(proposed(key)) - types(taxonomy._matches(key))
    for key in ['id', 'name', 'UID', 'age', 'race', 'class', 'HTTPHeadersCount', '密码数量']:
        assert not proposed(key)
    assert all(types(taxonomy._matches(value)) <= set(TYPE_ROWS) for value in ALIASES.values())
    old, new, keys = key_capture('{"HTTPHeaders":{"nested":"fixture"},"IPAddr":null,"用户ID":7}', {})
    assert len(keys) == old['counts']['keyed_nodes'] == 4
    assert {relation(m) for m in new['matches']} - {relation(m) for m in old['matches']} == {
        (0, (0,), 'BIZ', 'http_headers'), (0, (2,), 'QID', 'user_identifier')}
    print(json.dumps({'synthetic_checks': 19, 'all_passed': True, 'real_source_values_read': False}))


def shape(value):
    kind = parser._kind(value)
    if kind == 'string':
        return 'empty_string' if not value else 'whitespace_string' if not value.strip() else 'nonempty_string'
    if kind in {'array', 'object'} and not value:
        return 'empty_' + kind
    return kind


def key_capture(text, limits):
    """Observe the existing parser's object-child positions without exporting keys."""
    current = {'document_index': None}; keys = {}
    original_documents, original_children = parser._documents, parser._children
    def documents(text, counts):
        for index, item in enumerate(original_documents(text, counts)):
            current['document_index'] = index
            yield item
    def children(value, path, depth, layers):
        for item in original_children(value, path, depth, layers):
            child, child_path, _, name, _ = item
            if name is not None:
                keys[current['document_index'], tuple(child_path)] = (name, shape(child))
            yield item
    with patch.object(parser, '_documents', documents), patch.object(parser, '_children', children):
        baseline = parser.classify_structured(text, **limits)
    with patch.object(parser, '_matches', proposed):
        proposed_result = parser.classify_structured(text, **limits)
    return baseline, proposed_result, keys


def relation(match):
    return match['document_index'], tuple(match['node_path']), match['category'], match['subtype']


def main():
    started = time.monotonic(); started_utc = datetime.now(timezone.utc).isoformat()
    docs = ROOT / 'docs'; run = ROOT / 'structured-runs/aidev-v049'
    output = docs / 'json_key_alias_probe_v050.json'
    if output.exists():
        raise FileExistsError('Preserve prior probe artifacts')
    with ExitStack() as stack:
        lock = stack.enter_context((run / '.structured.lock').open('rb'))
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        manifest = json.loads((run / 'manifest.json').read_text())
        state = json.loads((run / 'export_state.json').read_text())
        coverage = json.loads((run / 'structured_coverage.json').read_text())
        assert state['status'] == 'complete' and coverage['all_source_rows_visited']
        assert state['fingerprint'] == manifest['fingerprint'] and manifest['fingerprint']['source_sha256'] == structured_scan._sources()
        dataset, source_sha, tables_list = content_scan._inventory(Path(manifest['fingerprint']['source_import']))
        assert dataset == 'aidev' and source_sha == manifest['source_manifest_sha256']
        assert [{k: t[k] for k in ('path', 'sha256', 'bytes')} for t in tables_list] == manifest['fingerprint']['inputs']
        paths = [run / name for name in ('manifest.json', 'export_state.json', 'structured_coverage.json', 'structured.sqlite')]
        paths.append(Path(manifest['fingerprint']['source_import']) / 'manifest.json')
        modules = [Path(m.__file__) for m in (content_scan, content_repair, structured_scan, parser, taxonomy)]
        before = {str(p): {'sha256': content_repair._digest(p), 'stat': content_repair._stat(p)} for p in paths + modules}
        db = stack.enter_context(sqlite3.connect((run / 'structured.sqlite').as_uri() + '?mode=ro&immutable=1', uri=True))
        db.row_factory = sqlite3.Row
        db.set_progress_handler(lambda: int(time.monotonic() - started > LIMIT_SECONDS), 10000)
        unclosed = {r[0] for r in db.execute("SELECT document_id FROM gaps WHERE reason='unclosed_json_fence'")}
        available = [dict(r) for r in db.execute("SELECT * FROM documents WHERE status!='invalid_json' ORDER BY table_path,source_row,column_name,document_index") if r['id'] not in unclosed]
        grouped = defaultdict(list)
        for row in available:
            grouped[row['table_path'], row['column_name'], row['source_row']].append(row)
        selected = []; cells = []
        for key, rows in grouped.items():
            if len(selected) + len(rows) > LIMIT_DOCUMENTS:
                break
            selected.extend(rows); cells.append(dict(zip(('table_path', 'column_name', 'source_row'), key)))
        selection_file = docs / 'json_key_alias_probe_v050_selection.jsonl'
        selection_file.write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in selected))
        limits = manifest['fingerprint']['limits']
        tables = {t['path']: t for t in tables_list}; verified = {t['path']: tuple(t['source_stat']) for t in tables_list}
        evidence = []; counts = Counter(); mechanisms = Counter(); deltas = Counter(); quality = Counter(); cell_audit = []
        node_pairs = set(); cell_pairs = set(); nonexcluded_cell_pairs = set(); observed_documents = set(); stop = None
        try:
            for cell, text, _, _ in content_repair._selected_values(cells, tables, started + LIMIT_SECONDS, verified):
                baseline, proposal, keys = key_capture(text, limits)
                valid = {r['document_index']: r for r in grouped[cell['table_path'], cell['column_name'], cell['source_row']]}
                actual_docs = {d['document_index']: d for d in baseline['documents']}
                for index, prior in valid.items():
                    assert all(actual_docs[index][k] == prior[k] for k in ('document_index', 'format', 'source_start', 'source_end', 'status'))
                    observed_documents.add(prior['id'])
                old_relations = {relation(m) for m in baseline['matches'] if m['document_index'] in valid}
                old_cell_types = {(r[2], r[3]) for r in old_relations}
                old_nonexcluded_cell_types = {(m['category'], m['subtype']) for m in baseline['matches'] if m['document_index'] in valid and m['candidate_status'] != 'placeholder_or_example'}
                new_relations = {relation(m): m for m in proposal['matches'] if m['document_index'] in valid}
                visited_keys = [(coord, data) for coord, data in keys.items() if coord[0] in valid]
                assert len(visited_keys) == baseline['counts']['keyed_nodes']
                counts['source_cells_read'] += 1; counts['source_characters_materialized'] += len(text)
                counts['documents_replayed'] += len(valid); counts['keys_visited'] += len(visited_keys)
                counts['nodes_visited'] += baseline['counts']['nodes_visited']
                counts['baseline_candidate_observations'] += sum(m['candidate_status'] != 'placeholder_or_example' for m in baseline['matches'] if m['document_index'] in valid)
                counts['proposal_match_budget_gaps'] += sum(g['reason'] == 'match_budget' for g in proposal['gaps'])
                for (doc_index, path), (key, value_shape) in visited_keys:
                    old, normalized, aliased, combined = variants(key)
                    counts['non_ascii_keys'] += not key.isascii()
                    counts['acronym_boundary_keys'] += bool(re.search(r'[A-Z]+[A-Z][a-z]', key))
                    counts['explicit_alias_keys'] += key.casefold() in ALIASES
                    added = types(combined) - types(old)
                    for category, subtype in sorted(added):
                        relation_key = doc_index, path, category, subtype
                        detail = new_relations.get(relation_key)
                        new_observation = detail is not None and relation_key not in old_relations
                        reason = []
                        if (category, subtype) in types(normalized): reason.append('ascii_acronym_boundary')
                        if (category, subtype) in types(aliased): reason.append('explicit_ascii_alias' if key.isascii() else 'explicit_chinese_alias')
                        assert reason
                        document = valid[doc_index]
                        rec = {**cell, 'source_document_id': document['id'], 'document_index': doc_index,
                               'source_start': document['source_start'], 'source_end': document['source_end'],
                               'format': document['format'], 'node_path': list(path), 'value_shape': value_shape,
                               'category': category, 'subtype': subtype, 'mechanisms': reason,
                               'new_key_type_hint': True, 'new_emitted_node_type_relation': new_observation,
                               'new_source_cell_type_relation': new_observation and (category, subtype) not in old_cell_types,
                               'new_nonexcluded_source_cell_type_relation': new_observation and detail['candidate_status'] != 'placeholder_or_example' and (category, subtype) not in old_nonexcluded_cell_types,
                               'already_observed_by_other_rule': relation_key in old_relations,
                               'candidate_status': detail['candidate_status'] if detail else 'not_emitted_by_existing_value_gates',
                               'value_status': detail['value_status'] if detail else None,
                               'decoded_start': detail['decoded_start'] if detail else None,
                               'decoded_end': detail['decoded_end'] if detail else None,
                               'human_review_status': 'pending', 'personal_ownership_confirmed': False,
                               'sensitivity_confirmed': False, 'runtime_confirmed': False}
                        evidence.append(rec); counts['additional_key_type_hints'] += 1; quality[value_shape] += 1
                        mechanisms.update(reason)
                        if new_observation:
                            counts['new_emitted_node_type_relations'] += 1
                            excluded = detail['candidate_status'] == 'placeholder_or_example'
                            counts['new_placeholder_relations' if excluded else 'new_nonexcluded_relations'] += 1
                            deltas[category, subtype, 'placeholder_or_example' if excluded else 'candidate'] += 1
                            node_pairs.add((document['id'], path, category, subtype))
                            cell_type = cell['table_path'], cell['column_name'], cell['source_row'], category, subtype
                            if (category, subtype) not in old_cell_types: cell_pairs.add(cell_type)
                            if not excluded and (category, subtype) not in old_nonexcluded_cell_types: nonexcluded_cell_pairs.add(cell_type)
                cell_audit.append({**cell, 'selected_documents': len(valid), 'keyed_nodes': len(visited_keys),
                    'nodes_visited': baseline['counts']['nodes_visited'], 'baseline_gap_count': len(baseline['gaps']),
                    'proposal_gap_count': len(proposal['gaps'])})
                if counts['source_cells_read'] % 500 == 0:
                    print(json.dumps({'source_cells_read': counts['source_cells_read'], 'documents_replayed': counts['documents_replayed'],
                                      'keys_visited': counts['keys_visited'], 'additional_key_type_hints': counts['additional_key_type_hints'],
                                      'new_emitted_node_type_relations': counts['new_emitted_node_type_relations']}), flush=True)
        except content_repair._BudgetExpired:
            stop = 'time_budget'
        assert all(content_repair._stat(Path(t['absolute_path'])) == verified[t['path']] for t in tables_list)
        assert all(content_repair._stat(Path(p)) == record['stat'] for p, record in before.items())
        assert manifest['fingerprint']['source_sha256'] == structured_scan._sources()
        evidence_file = docs / 'json_key_alias_probe_v050_evidence.jsonl'
        evidence_file.write_text(''.join(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n' for r in evidence))
        report = {'started_utc': started_utc, 'completed_utc': datetime.now(timezone.utc).isoformat(),
            'elapsed_seconds': round(time.monotonic() - started, 3), 'time_budget_seconds': LIMIT_SECONDS,
            'document_budget': LIMIT_DOCUMENTS, 'helper_sha256': content_repair._digest(Path(__file__)),
            'selection_rule': 'All previously successful top-level JSON documents, including valid top-level documents with inner decoding gaps; no key/type filter. Fixed source order, whole-cell groups, at most 6000 documents.',
            'available_documents': len(available), 'available_source_cells': len(grouped), 'selected_documents': len(selected),
            'selected_source_cells': len(cells), 'selected_table_columns': len({(r['table_path'], r['column_name']) for r in selected}),
            'full_dataset_source_rows': coverage['source_rows'], 'full_dataset_nonempty_text_cells': coverage['counts']['nonempty_cells'],
            'all_selected_documents_replayed': len(observed_documents) == len(selected), 'stop_reason': stop,
            'counts': dict(counts), 'mechanism_hint_counts': dict(mechanisms), 'new_hint_value_shapes': dict(quality),
            'new_node_type_pairs': len(node_pairs), 'new_source_cell_type_pairs': len(cell_pairs),
            'new_nonexcluded_source_cell_type_pairs': len(nonexcluded_cell_pairs),
            'by_type_status': [{'category': c, 'subtype': s, 'status': status, 'count': n} for (c, s, status), n in sorted(deltas.items())],
            'source_manifest_sha256': source_sha, 'frozen_source_inputs': manifest['fingerprint']['inputs'],
            'checked_inputs_and_implementation': before, 'inputs_and_implementation_unchanged': True,
            'selection_path': selection_file.name, 'selection_sha256': content_repair._digest(selection_file),
            'evidence_path': evidence_file.name, 'evidence_sha256': content_repair._digest(evidence_file),
            'cell_coverage': cell_audit, 'proposed_aliases': ALIASES,
            'source_values_exported': False, 'dynamic_keys_exported': False, 'value_hashes_exported': False,
            'package_or_tests_modified': False, 'new_taxonomy_types_added': False, 'new_true_sensitive_types_established': False,
            'limitations': ['This is a bounded replay of documents recognized by v049, not all dataset text or unsupported formats.',
                'A new named key hint or emitted node-type relationship is low-confidence evidence, not a confirmed real person, secret, credential or leak.',
                'Aliases are an exact finite dictionary; no transliteration, arbitrary-language discovery, parent-role inference or global id/name classification.',
                'Null, boolean, empty/container and example gates are reused from the existing parser; emitted and non-emitted hints remain separate.',
                'All object keys of replayed documents, including decoded nested objects, are visited; dynamic key names are kept only in process memory.',
                'Selected scalar values are materialized once per source cell; Arrow can also decode intervening rows while reaching selected indices.']}
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({k: report[k] for k in ('available_documents', 'selected_documents', 'selected_source_cells', 'all_selected_documents_replayed', 'counts', 'by_type_status', 'stop_reason', 'inputs_and_implementation_unchanged')}, ensure_ascii=False))


if __name__ == '__main__':
    self_test() if sys.argv[1:] == ['--self-test'] else main()
