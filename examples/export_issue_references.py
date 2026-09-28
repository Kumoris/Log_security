"""Validate source-backed issue adjudications and export a bounded reference set.

No network/model calls. This checks provenance, not semantic accuracy.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from agentlog_unified.config import sha256_file
from agentlog_unified.export import write_csv, write_json, write_jsonl
from agentlog_unified.storage import atomic_write


KINDS = {
    'reported_sensitive_value': '来源报告具体敏感值',
    'reported_sensitive_carrier': '来源报告敏感内容载体',
    'reported_log_field': '审计字段语义，未证实不当泄露',
    'potential_sensitive_carrier': '可能承载敏感内容',
    'protective_feature': '保护功能或扩展点',
    'protective_advice': '条件性保护建议',
    'redacted_support_material': '支持材料删改或私发声明',
    'rejected_feature_risk': '未采纳提案的风险讨论',
    'out_of_application_log_scope': '应用日志范围外',
}
CARRIERS = set('configuration configuration_value response_body error_message uri_parameters command_arguments record_payload mutation_content soap_message database_statement query_predicate database_row function_arguments message_payload record_key property_value repository_structure authentication_trace query_literals uri file_content keystore_metadata credential_container'.split())
CONDITIONAL = {'potential_sensitive_carrier', 'protective_feature', 'protective_advice', 'rejected_feature_risk'}
# Explicit case exceptions prevent a feature title/status from deciding log linkage.
LOG_RELATIONS = {
    'JSPWIKI-736': 'out_of_scope_page_access',
    'ZEPPELIN-828': 'credential_persistence_not_log_evidence',
    'CONTINUUM-2505': 'redacted_configuration_not_bound_to_log',
    'QPID-8460': 'exception_message_sink_log_sink_untraced',
    'CASSANDRA-10580': 'discussed_full_payload_path_contradicted_for_2_1',
    'HBASE-14443': 'proposed_path_not_present_in_original_warning',
    'DERBY-3676': 'proposed_toString_path_not_adopted',
    'KAFKA-7015': 'proposed_readable_value_path_not_adopted',
    'OAK-943': 'client_exception_to_server_log_boundary',
    'WSS-195': 'client_exception_to_server_log_boundary',
    'SVN-1051': 'client_error_sanitized_original_retained_in_server_log',
}


def evidence(source, reference):
    """Resolve to frozen text, never synthesize missing source references."""
    payload = source['issue_payload']
    if reference == 'D':
        pointer = '/issue_payload/fields/description' if 'fields' in payload else '/issue_payload/body'
        value = payload['fields'].get('description') if 'fields' in payload else payload.get('body')
        url = source['issue_url']
        timestamp = (payload.get('fields') or payload).get('updated', payload.get('updated_at'))
    else:
        matches = [(i, c) for i, c in enumerate(source['comments']) if 'C'+str(c['id']) == reference]
        if len(matches) != 1:
            raise ValueError(f"unresolved evidence: {source['issue']} {reference}")
        i, comment = matches[0]
        pointer = f'/comments/{i}/body'
        value = comment.get('body')
        url = comment.get('html_url') or source['issue_url']+'?focusedCommentId='+str(comment['id'])+'#comment-'+str(comment['id'])
        timestamp = comment.get('updated', comment.get('updated_at'))
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'empty evidence: {reference}')
    return {'reference': reference, 'json_pointer': pointer, 'source_url': url,
            'text_sha256': hashlib.sha256(value.encode()).hexdigest(),
            'text_characters': len(value), 'source_updated_at': timestamp,
            'raw_text_exported': False}


def validate(annotations, decisions, sources):
    ids = [r['id'] for r in annotations]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate input annotation')
    keys = [r['issue'] for r in decisions]
    if len(keys) != len(set(keys)) or set(keys) != set(sources):
        raise ValueError('adjudications must match every collected issue exactly once')
    if {s['source_annotation_id'] for s in sources.values()} != set(ids):
        raise ValueError('source/input coverage mismatch')
    if len(sources) != len(annotations):
        raise ValueError('source/input cardinality mismatch')
    for row in decisions:
        source = sources[row['issue']]
        if not source.get('complete'):
            raise ValueError('incomplete issue collection')
        payload = source['issue_payload']
        expected = payload['fields']['comment']['total'] if 'fields' in payload else payload['comments']
        comments = source['comments']
        if len(comments) != expected or len({str(c['id']) for c in comments}) != expected:
            raise ValueError(f"incomplete/duplicate comments: {row['issue']}")
        if row['kind'] not in KINDS or not row['reference_answer_zh'].strip():
            raise ValueError('missing decision')
        if row['review_origin'] != 'assistant_source_adjudication_not_human_expert':
            raise ValueError('unattested review origin')
        if not row['evidence_refs']:
            raise ValueError('missing evidence')
        for ref in row['evidence_refs']:
            evidence(source, ref)
        for negative in row.get('contextual_negative_examples', []):
            if not negative['scope']:
                raise ValueError('unscoped negative example')
            for ref in negative['evidence_refs']:
                evidence(source, ref)


def export(root, input_path):
    annotations = [json.loads(line) for line in input_path.read_text().splitlines() if line]
    decisions = json.loads((root/'adjudications.json').read_text())
    sources = {p.stem: json.loads(p.read_text()) for p in (root/'private').glob('*.json')}
    validate(annotations, decisions, sources)
    collection = json.loads((root/'collection.json').read_text())
    if collection['input_sha256'] != sha256_file(input_path):
        raise ValueError('input changed since collection')
    old = {r['id']: r for r in annotations}
    output = root/'reference'
    results, corrections, types, negatives, templates = [], [], [], [], []
    for decision in sorted(decisions, key=lambda r: r['issue']):
        key = decision['issue']; source = sources[key]; previous = old[source['source_annotation_id']]
        fields = source['issue_payload'].get('fields', source['issue_payload'])
        refs = [evidence(source, ref) for ref in decision['evidence_refs']]
        relation = LOG_RELATIONS.get(key)
        if relation is None:
            relation = ('conditional_or_design_discussion' if decision['kind'] in CONDITIONAL else
                        'support_material_statement' if decision['kind'] == 'redacted_support_material' else
                        'source_reports_log_output_not_independently_reproduced')
        concrete = [c for c in decision['concepts'] if c not in CARRIERS]
        type_scope = ('conditional_examples_not_observed_values' if decision['kind'] in CONDITIONAL else
                      'issue_context_not_general_field_rule')
        status = ('specific_sensitive_type_not_established' if not concrete else type_scope)
        row = dict(decision, id=key, issue_url=source['issue_url'], project=previous['issue_project'],
                   reference_status='source_checked_assistant_adjudicated',
                   dataset_metadata_semantics='issue_tracker_evidence_not_target_program_data',
                   type_status=status, application_log_relation=relation,
                   privacy_risk_status=('excluded_from_application_log_defect_reference' if decision['kind']=='out_of_application_log_scope'
                                        else 'see_case_answer_no_runtime_confirmation'),
                   reference_use='source_comprehension_and_scoped_case_analysis',
                   sensitive_detection_gold_eligible=False, human_expert_review='pending',
                   original_human_annotation=previous['human_annotation'],
                   source_annotation_id=previous['id'], document_revision=previous['revision_id'],
                   original_document_sha256=previous['source_sha256'],
                   original_paragraph_anchors=previous['paragraph_anchors'],
                   source_snapshot_sha256=sha256_file(root/'private'/f'{key}.json'),
                   source_status=(fields.get('status') or {}).get('name', fields.get('state')),
                   source_resolution=(fields.get('resolution') or {}).get('name'),
                   source_fix_versions=[v['name'] for v in fields.get('fixVersions', [])],
                   fix_verification='issue_metadata_and_discussion_only_no_runtime_reproduction',
                   runtime_confirmed=False, agent_attribution='not_established',
                   git_history='not_collected_in_this_source_audit',
                   source_comments_collected=len(source['comments']),
                   source_attachments_not_read=len(fields.get('attachment', [])),
                   evidence=refs)
        results.append(row)
        evidence_row = {k: row[k] for k in ('id','issue_url','reference_answer_zh','source_snapshot_sha256','evidence','source_comments_collected','source_attachments_not_read')}
        evidence_row.update(source_receipts=source['receipts'], private_source_relative_path='../private/'+key+'.json',
                            coverage='all_comment_pages_collected_relevant_claims_reviewed_attachments_not_read')
        write_json(output/'evidence'/f'{key}.json', evidence_row)
        before = sorted({p['concept'] for p in previous['type_proposals']})
        after = sorted(decision['concepts'])
        corrections.append({'id':key, 'previous_rule_proposals':before, 'source_checked_concepts':after,
                            'removed_or_reframed':sorted(set(before)-set(after)),
                            'added_or_refined':sorted(set(after)-set(before)),
                            'concept_set_changed':before!=after,
                            'interpretation':row['reference_answer_zh'],
                            'origin':'assistant_revision_not_new_human_type_annotation'})
        for concept in after:
            types.append({'id':key+'::'+concept,'issue':key,'concept':concept,
                          'role':'carrier_or_structure' if concept in CARRIERS else 'contextual_type',
                          'case_kind':decision['kind'],'type_status':status,'evidence_refs':decision['evidence_refs'],
                          'scope':key,'human_expert_review':'pending','real_value_presence':'not_independently_verified',
                          'note':'标签用于本 issue 来源解释；无自动全局映射或日志泄露真值提升'})
        for i, negative in enumerate(decision.get('contextual_negative_examples', [])):
            negatives.append(dict(negative,id=key+'::negative::'+str(i),issue=key,
                                  origin='assistant_source_adjudication_not_human_expert'))
        templates.append({'id':key,'issue_url':source['issue_url'],'reviewer':'','decision':'pending',
                          'semantic_interpretation':'','sensitive_types':'','log_relation':'',
                          'privacy_risk':'','supporting_refs':'','contradicting_refs':'','notes':''})
    for name, rows in [('reference_answers',results),('type_reference_items',types),('corrections',corrections),
                       ('contextual_negatives',negatives),('human_review_template',templates),
                       ('unknown_type_queue',[r for r in results if r['type_status']=='specific_sensitive_type_not_established']),
                       ('application_log_exclusions',[r for r in results if r['kind']=='out_of_application_log_scope'])]:
        write_jsonl(output/f'{name}.jsonl',rows); write_csv(output/f'{name}.csv',rows)
    audit = {'denominator':len(annotations),'source_cases_collected':len(sources),
             'source_comments_collected':sum(len(s['comments']) for s in sources.values()),
             'source_requests':sum(len(s['receipts']) for s in sources.values()),
             'source_cases_adjudicated':len(results),'evidence_refs_resolved':sum(len(r['evidence']) for r in results),
             'cases_by_kind':dict(Counter(r['kind'] for r in results)),
             'cases_by_type_status':dict(Counter(r['type_status'] for r in results)),
             'type_reference_items':len(types),'concepts':len({r['concept'] for r in types}),
             'concept_set_revised_cases':sum(r['concept_set_changed'] for r in corrections),
             'contextual_negative_examples':len(negatives),
             'project_count':len({r['project'] for r in results}),
             'human_expert_adjudications':0,'runtime_confirmations':0,'external_model_api_calls':0,
             'new_accuracy_recall_estimates':None,
             'validation_scope':'identity_cardinality_comment_pagination_reference_resolution_hashes_not_semantic_accuracy',
             'missing_evidence':['unretrieved_attachments','private_email_contents','full_historical_code','independent_human_expert_review','target_runtime_reproduction'],
             'split_policy':'development_reference_only_do_not_evaluate_on_same_issues_or_related_issue_families'}
    write_json(output/'audit.json',audit)
    paragraphs = ['# Issue 来源核对参考答案\n',
        '范围：用户文档中的 67 个去重 issue。保留全部条目，按原始正文和讨论核对；链接不是敏感类型真值。此版由助手进行来源裁决，尚未取得独立人工专家复核。\n',
        f"共抓取 {audit['source_comments_collected']} 条公开评论，{audit['evidence_refs_resolved']} 个正文/评论证据引用通过定位检查。检查证明引用存在及快照完整性，不证明语义准确率。\n",
        '用途：来源文本理解、范围受限的语义案例和后续人工标注。不得直接用作真实值泄露、Agent 归因或目标程序字段分类的完整 gold set。所有类型限定当前 issue；载体、示例、已删改材料和实际值报告不能混作正例。\n',
        '修复状态取自冻结的 issue 元数据与讨论，不代表本轮复现；附件、私信、完整 Git 历史未读取。原始快照留在相邻 private 目录，分享时仅分享 reference 目录；导出不包含原始敏感值。\n',
        '同族使用限制：CXF-6824 明确重复 CXF-6262；KAFKA-3830 参考 ZOOKEEPER-2405；KAFKA-6804/7015/7510 同属记录 key/value 日志策略讨论。按项目及关联案例族隔离开发/评估，67 条不是 67 个独立缺陷。\n',
        '## 筛选分布\n']
    paragraphs.extend(f'- {KINDS[k]}：{v}/67\n' for k,v in audit['cases_by_kind'].items())
    for row in results:
        paragraphs.extend([f"\n## {row['id']}\n",f"[原始 issue]({row['issue_url']}) · {KINDS[row['kind']]}\n",
            row['reference_answer_zh']+'\n',
            '语义概念：'+('、'.join(row['concepts']) or 'unknown；不补猜类型')+'。\n',
            f"日志关联：`{row['application_log_relation']}`。类型证据范围：`{row['type_status']}`。\n",
            '核对依据：'+'、'.join(f"[{e['reference']}]({e['source_url']})" for e in row['evidence'])+'。\n',
            f"来源状态：{row['source_status']} / {row['source_resolution'] or '未列 resolution'}；独立人工专家复核：待审。\n"])
    atomic_write(output/'参考答案.md','\n'.join(paragraphs))
    manifest = {'input_sha256':sha256_file(input_path),'adjudications_sha256':sha256_file(root/'adjudications.json'),
                'exporter_sha256':sha256_file(Path(__file__)),
                'files':{str(p.relative_to(output)):sha256_file(p) for p in sorted(output.rglob('*')) if p.is_file() and p.name!='manifest.json'}}
    write_json(output/'manifest.json',manifest)
    return audit


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--input',type=Path,required=True);args=parser.parse_args()
    print(json.dumps(export(args.root,args.input),ensure_ascii=False,indent=2))
