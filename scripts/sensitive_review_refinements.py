"""Additive assistant review corrections; accepted trial/batch rows stay immutable."""
import copy,re
import sensitive_log_review as s
from annotate_sensitive_log_review import code_values,safe_excerpt

# These decisions follow the individually read target statements and exact diff/source chains.
NOTES={
 1:('pre_redacted_related_example','会话含已脱敏的配置示例；目标只传递 err，未建立凭据进入日志的值流。'),
 2:('concrete_value_in_related_material_only','关联 prompt 存在具体凭据样式内容，真实性未验证；目标错误载体与该值之间没有已核实的传播链。'),
 3:('concrete_value_in_related_material_only','关联 prompt 中的具体凭据样式内容不等于目标中的用户标识；未建立凭据写入日志。'),
 4:('concrete_value_in_related_material_only','仅共享修改会话不足以证明具体凭据进入本错误输出。'),
 8:('sanitizer_present_runtime_unverified','目标已有 scrubSecrets(error.message)，在本次前后语句未变化；评审安全意见指子进程环境继承，不能认定本次新增日志脱敏。'),
 54:('keys_only_not_payload_values','目标是 Object.keys(payload).join(...)，只显示字段名；撤销请求正文值的提示分类。字段名本身的敏感性仍未验证。'),
 55:('concept_literal_only','这是提及 secret 的固定诊断提示，没有插入 secret 变量；相邻行的签名输出由 Q491 单独审查。'),
 59:('example_context_authenticity_unverified','目标属于本地 Xtream mock 服务的连接示例 URL；不能仅凭 mock 路径确认每个字面量都是合成凭据，也不能由删除行认定隐私目的。'),
 60:('example_context_authenticity_unverified','mock 服务连接示例；固定值真实性未验证，与本次 Docker 构建调整之间的日志隐私目的未建立。'),
 61:('documented_synthetic_fixture_context','PR #1300 明确说使用本地合成测试凭据；它支持该测试上下文为示例，不能证明删除此输出就是为防泄露。'),
 62:('documented_synthetic_fixture_context','同一性能测试 PR 的合成凭据说明是背景，不是这条日志删除目的的直接说明。'),
 88:('sanitizer_present_runtime_unverified','原输出传入 scrubSecrets(refusalPayload)。refusalPayload 的业务方向无法仅凭变量名判为 request body；改记不透明对象。改动属于 runner 重构，未验证脱敏函数效果或是否迁移输出。'),
 268:('headers_carrier_contents_unverified','静态表达式输出 response.headers，但没有实际响应头值；不能认定其中包含认证头或秘密。'),
 276:('public_key_identifier_not_key_value','输出字段 apiKeyId 取 foundKey.publicId，而非 API key 原值。旁边 parseError(err) 仍是未解析载体。PR #678 说明整体 API 迁移及删除旧库文件；不是日志泄露证明。'),
 285:('identifier_normalization_not_secret_redaction','目标同时输出 sanitized 与 original，周围是 stale branch/prune/dry-run 流程；本 diff 仅替换 logger。sanitized 一词不能证明秘密脱敏，分支名实际值未取得。'),
 286:('identifier_normalization_not_secret_redaction','此组替换 log.Info 为 slog.Default().Info，仍传相同两个名字；不支持新增隐私过滤目的。'),
 287:('identifier_normalization_not_secret_redaction','分支同步场景的 sanitized 名字与 err；未验证命名规范化函数全体语义，不能当作认证秘密脱敏。'),
 288:('identifier_normalization_not_secret_redaction','同步日志与级别调整；sanitized 名称及错误参数未提供实际敏感值。'),
 289:('identifier_normalization_not_secret_redaction','slog.Default().Info 改为 slog.Info，参数保留；不是脱敏算法变更。'),
 290:('identifier_normalization_not_secret_redaction','logger 调用修正；相同 sanitized/original 参数不证明有秘密值。'),
 393:('other_target_risk_not_this_event','PR #785 的评审明确担忧 opencode export 前后缀字节经 WARN 写入日志；本目标却是 getStagedFiles 的 err.Error()，不能把另一条值流归于本事件。记录相关风险，未新增第二步候选。'),
 423:('redaction_in_related_helper_unproven_target_flow','PR #796 提议对 git fetch 诊断脱敏；本目标是 GetRemoteMetadataBranchTree 返回的 remoteErr。所读 diff 未闭合两者的值流，不能套用脱敏目的。'),
 429:('url_redaction_refactor_context','PR #989 确认集中 URL 解析/脱敏并删除旧 helper；目标输出 config.Repo 和 err。可推断参与重构，不能据此确认删除是清除真实凭据；尚未证明 URL 含 userinfo。'),
 491:('derived_authenticator_expression_unverified','删除的日志静态插入 signature 与 expected；同 diff 的 expected 来源为 HMAC digest。它们是潜在认证材料，不是原始 client secret。没有运行时值/日志实例，不能确认真实秘密已落盘。提交明确说删除诊断日志，但没有明确隐私目的。'),
 492:('presence_flag_not_signature_value','三元表达式将 signature 映射为固定 present/missing 提示；这条不输出 signature 原值。Q491 是不同事件。'),
 588:('auth_metadata_not_auth_secret','输出 auth.type 和条件性的 auth.caller，不是整个凭据对象；caller 内容及敏感性仍未验证。'),
}

def add_type(row,typ,basis):
 if typ not in {t['baseline_type'] for t in row['potential_types']}:
  row['potential_types'].append({'baseline_type':typ,'certainty':'potential_static_type','basis':basis,'expression_hint':None})

def refine(old,event,sources,links):
 r=copy.deepcopy(old);n=r['queue_index'];obs=event['current_observation'];stmt='\n'.join([obs.get('before_statement') or '',obs.get('after_statement') or ''])
 r['review_revision']='final_scoped_review_v1';r['review_scope']+='; additive exact-case corrections recorded in final_review_corrections.jsonl'
 r['value_kind']='unresolved_runtime_expression'
 r['confirmed_actual_sensitive_value_in_target_log_meaning']='False means not established in reviewed evidence, not absence or safety.'
 r['target_observation_limit']='Empty upstream after text alone is not proof the statement disappeared; consult diff classification and coordinates.'
 if r['log_entry_evidence']=='call_present_final_sink_unresolved':r['value_kind']='wrapper_input_final_sink_unresolved'
 # Correct logger names missed by the first-pass recognizer, without claiming runtime execution.
 if re.search(r'\b(?:self\._logger|self\.logger)\.(?:debug|info|warning|error|exception)\s*\(',stmt):
  r['log_entry_evidence']='static_log_argument_expression';r['value_kind']='unresolved_runtime_expression'
  r['sensitivity_assessment']='unresolved_dynamic_log_argument'
 if n in {47,51,462,463}:
  r['potential_types']=[t for t in r['potential_types'] if t['baseline_type']!='BIZ.message_content']
  add_type(r,'DIAG.exception_message','Target object property error: message is diagnostic content; not automatically business chat.')
  r['contextual_inference']+=' 复核 error: message 后改为诊断载体，不作业务消息内容。'
 if n==54:r['potential_types']=[t for t in r['potential_types'] if t['baseline_type']!='BIZ.request_body']
 if n==88:
  r['potential_types']=[t for t in r['potential_types'] if t['baseline_type']!='BIZ.request_body']
  add_type(r,'BIZ.unclassified_object','Opaque refusal payload passed through scrubSecrets; request/response direction not established.')
 if n==276:add_type(r,'QID.unspecified_linkable_identifier','foundKey.publicId identifies a credential record; not the secret itself.')
 if n==429:add_type(r,'CFG.unclassified_internal_resource','config.Repo names a remote resource; userinfo content and actual value not established.')
 if n==491:
  add_type(r,'AUTH.credential_bundle','Potential received/derived HMAC authenticators; existing baseline fallback, no actual value available.')
  r['sensitivity_assessment']='potential_type_in_static_output'
 if n in NOTES:r['value_kind'],r['contextual_inference']=NOTES[n]
 if n in {54,55,276,285,286,287,288,289,290,492,588}:
  r['false_positive_dimension']={54:'payload_values_vs_keys',55:'secret_concept_vs_value',276:'api_key_secret_vs_public_id',492:'signature_value_vs_presence_flag',588:'auth_secret_vs_auth_metadata'}.get(n,'name_normalization_vs_secret_redaction')
  r['false_positive_scope']='Only this specified keyword-to-value/privacy inference is refuted; remaining arguments may still be unresolved.'
 else:r['false_positive_dimension']=None
 # Preserve ordinary change purpose separately from the privacy-specific question.
 r['general_change_motive']={k:event.get(k) for k in ('motive_status','motive_labels','stated_purpose','contextual_inference','unknown_reason')}
 for k in ('stated_purpose','contextual_inference','unknown_reason'):
  if isinstance(r['general_change_motive'].get(k),str):r['general_change_motive'][k]=s.redact(r['general_change_motive'][k],True)
 r['privacy_purpose_inference']=None
 r['unknown_reason_codes']=['privacy_purpose_not_directly_supported','actual_values_and_runtime_write_not_observed']
 if 'prompt' not in r['source_coverage']:r['unknown_reason_codes'].append('no_linked_modification_prompt_in_parent_corpus')
 if obs['classification'] in {'no_target_span_in_attached_diff','upstream_deleted_but_target_retained_as_diff_context'}:r['unknown_reason_codes'].append(obs['classification'])
 if r['value_kind']=='wrapper_input_final_sink_unresolved':r['unknown_reason_codes'].append('final_logging_sink_unresolved')
 # Attach additional exact passages for manually inspected borderline cases.
 needles={61:'uses only local synthetic',62:'uses only local synthetic',276:'Deletes the three dead',393:'This string is logged at WARN',423:'so resume/checkRemoteMetadata can log',429:'Centralizes checkpoint remote URL',491:'Remove diagnostic logging'}
 if n in needles:
  for l in links:
   v=sources[l['evidence_id']];start=v['text'].find(needles[n])
   if start>=0:
    c={'evidence_id':v['evidence_id'],'role':'case_scope_support_not_direct_privacy_purpose',**safe_excerpt(v,start,min(len(v['text']),start+300))}
    if not any((z['evidence_id'],z['original_start'],z['original_end'])==(c['evidence_id'],c['original_start'],c['original_end']) for z in r['citations']):r['citations'].append(c)
 return r
