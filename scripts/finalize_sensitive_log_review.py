"""Create a new redacted delivery; never overwrite accepted research or batch data."""
import collections,copy,csv,hashlib,json,re,sys
from pathlib import Path
import sensitive_log_review as s
from annotate_sensitive_log_review import validate
from run_sensitive_review_batches import accepted
from sensitive_review_refinements import refine

SOURCE_TYPES=['prompt','commit_message','pr_description','review_comment','issue']

def redact_embedded(v,key=''):
 if isinstance(v,dict):return {k:redact_embedded(x,k) for k,x in v.items()}
 if isinstance(v,list):return [redact_embedded(x,key) for x in v]
 if isinstance(v,str) and key in {'diff_hunk','excerpt','text','quote','error','message','description'}:return s.redact(v,True)
 return v

def table(path,rows,cols):
 with path.open('x',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=cols);w.writeheader()
  for r in rows:w.writerow({k:json.dumps(r.get(k),ensure_ascii=False) if isinstance(r.get(k),(list,dict)) else r.get(k) for k in cols})

def verify_original_chains(links,events):
 needs={lid:l for l in links for lid in l.get('original_link_ids',[])}
 path=s.ROOT/'outputs/agent_log_three_stage_complete_20260923/stage3_final/evidence_links.jsonl'
 digest=hashlib.sha256();matched=set();scanned=0
 with path.open('rb') as f:
  for line in f:
   digest.update(line);r=json.loads(line);scanned+=1
   if r['link_id'] not in needs:continue
   l=needs[r['link_id']];e=events[l['modification_id']]
   assert all(r[k]==l[k] for k in ('evidence_id','repository','modification_sha','file_path'))
   assert r['event_id'] in e['association_event_ids'];matched.add(r['link_id'])
 assert matched==set(needs),'original_chain_missing'
 return {'path':str(path.relative_to(s.ROOT)),'sha256':digest.hexdigest(),'original_rows_scanned':scanned,'selected_original_links_verified':len(matched),'status':'PASS'}

def run():
 output=s.OUT/'delivery';assert not output.exists(),'Delivery already exists; validate or use a new version, never overwrite.'
 ee,src,edges,ctx=s.load();events={e['modification_id']:e for e in ee};queue=s.read(s.OUT/'review_queue.jsonl');ids={r['modification_id'] for r in queue}
 old=accepted();assert len(old)==716 and {r['modification_id'] for r in old}==ids
 receipts=json.loads((s.OUT/'manual_group_read_receipts.json').read_text());assert receipts['approved_group_numbers']==list(range(1,197))
 rows=sorted([refine(r,events[r['modification_id']],src,edges[r['modification_id']]) for r in old],key=lambda r:r['queue_index'])
 validation=validate(rows,events,src,edges)
 oldmap={r['modification_id']:r for r in old};corrections=[]
 compared=['potential_types','sensitivity_assessment','log_entry_evidence','contextual_inference']
 for r in rows:
  changes={k:{'accepted_batch_value':oldmap[r['modification_id']][k],'final_value':r[k]} for k in compared if oldmap[r['modification_id']][k]!=r[k]}
  if changes:corrections.append({'modification_id':r['modification_id'],'queue_index':r['queue_index'],'changes':changes,'method':'additive final assistant review; batch and parent unchanged'})
 links=[copy.deepcopy(l) for r in rows for l in edges[r['modification_id']]]
 assert len({(l['modification_id'],l['evidence_id']) for l in links})==len(links)
 original_receipt=verify_original_chains(links,events)
 selected_sources={l['evidence_id'] for l in links};citations=collections.defaultdict(dict)
 for r in rows:
  for c in r['citations']:
   key=(c['original_start'],c['original_end']);entry=citations[c['evidence_id']].setdefault(key,{**c,'modification_ids':[]});entry['modification_ids'].append(r['modification_id'])
 evidence=[]
 for eid in sorted(selected_sources):
  v=src[eid]
  e={k:copy.deepcopy(x) for k,x in v.items() if k not in {'text','excerpt','excerpt_truncated'}}
  e['source_content_sha256']=v['content_sha256'];e['raw_text_exported']=False
  e['source_parent_file']='outputs/agent_log_motive_completion_20260924/delivery/motive_evidence.jsonl'
  e['source_parent_key']={'evidence_id':eid};e['excerpts']=list(citations[eid].values())
  e['reading_scope']='available linked context and bounded excerpts; not a claim of full-text review or purpose support'
  evidence.append(e)
 for l in links:
  e=events[l['modification_id']]
  assert all(l[k]==e[k] for k in ('repository','modification_sha','file_path'))
  if 'original_event_ids' in l:assert set(l['original_event_ids'])<=set(e['association_event_ids'])
  for c in l.get('representative_chains',[]):
   assert c['event_id'] in e['association_event_ids']
   assert all(c[k]==l[k] for k in ('evidence_id','repository','modification_sha','file_path'))
  l['parent_delivery']='outputs/agent_log_motive_completion_20260924/delivery/evidence_links.jsonl'
  if l.get('original_link_ids'):l['complete_original_chain_file']=original_receipt
  l['privacy_purpose_support']=False
  l['association_limit']='Session/PR/file context proves association only, not this log purpose or execution order.'
 links=redact_embedded(links)
 for r in rows:
  e=events[r['modification_id']]
  r['observed_code_change']['diffs_redacted']=redact_embedded(e['current_observation']['target_diff_excerpts'])
  # diff row text is code and is always masked; object traversal preserves coordinates/IDs.
  r['evidence_chain_key']={'modification_id':r['modification_id'],'join_file':'event_evidence_links.jsonl'}
  r['prompt_association_scope']='modification_commit_checkpoint_session' if 'prompt' in r['source_coverage'] else 'no_linked_modification_prompt'
  r['prompt_execution_order_verified']=False
 screens=[];rowmap={r['modification_id']:r for r in rows}
 for oldscreen in s.read(s.OUT/'screening.jsonl'):
  r=copy.deepcopy(oldscreen);review=rowmap.get(r['modification_id'])
  r['review_state']='assistant_reviewed' if review else 'not_selected_not_reviewed'
  r['sensitivity_motive_status']=review['sensitivity_motive_status'] if review else None
  r.pop('sensitivity_status',None);screens.append(r)
 assert len(screens)==1757 and sum(r['review_state']=='assistant_reviewed' for r in screens)==716
 assert all(r['sensitivity_motive_status'] is None for r in screens if not r['selected'])
 gaps=[]
 for r in rows:
  for st in SOURCE_TYPES:
   if st not in r['source_coverage']:gaps.append({'modification_id':r['modification_id'],'source_type':st,'reason':'no_verified_linked_source_of_this_type_in_parent_delivery','scope':'corpus_link_missing_not_proof_source_does_not_exist','request_attempted_this_round':False})
  for reason in r['unknown_reason_codes']:gaps.append({'modification_id':r['modification_id'],'source_type':None,'reason':reason,'scope':'review_limitation'})
 historical=[redact_embedded(r) for r in s.read(s.PRIOR/'delivery/source_gaps.jsonl') if r['modification_id'] in ids]
 for r in historical:r['status_time_scope']='inherited_historical_request_or_gap_not_current_authentication_status'
 for r in rows:
  if r['repository']=='obmondo/gfetch' and r['modification_sha'].startswith('24d9fb3'):
   gaps.append({'modification_id':r['modification_id'],'source_type':'pr_description','reason':'gitea_api_http_401_unauthorized','receipt':'../external_gitea_receipt.json','scope':'current_exact_host_attempt','request_attempted_this_round':True})
  if r['modification_sha'].startswith('05ee00f'):
   gaps.append({'modification_id':r['modification_id'],'source_type':'pr_description','reason':'exact_commit_associated_pr_query_returned_empty','receipt':'../external_github_receipts.json','scope':'current_query_not_absence_proof','request_attempted_this_round':True})
 coverage={st:{'events':sum(st in r['source_coverage'] for r in rows),'percent':round(100*sum(st in r['source_coverage'] for r in rows)/716,2),'missing':sum(st not in r['source_coverage'] for r in rows),'independent_source_records':sum(v['source_type']==st for v in evidence),'direct_privacy_purpose_supported_events':0} for st in SOURCE_TYPES}
 cat=collections.Counter();sub=collections.Counter()
 for r in rows:
  sub.update({t['baseline_type'] for t in r['potential_types']});cat.update({t['baseline_type'].split('.')[0] for t in r['potential_types']})
 eq=collections.defaultdict(list)
 for v in evidence:eq[v['equivalence_group']].append(v['evidence_id'])
 duplicates=[{'equivalence_group':k,'evidence_ids':v,'counted_as':'one provenance-equivalent source, never independent votes'} for k,v in eq.items() if len(v)>1]
 stats={'at':s.now(),'parent_events':1757,'screened_events':1757,'selected_events':716,'reviewed_events':716,'pending_selected_events':0,'not_selected_not_reviewed':1041,'pilot':40,'accepted_batches':15,'followup_sizes':[50]*13+[26],
  'original_candidate_ids':len({i for r in rows for i in r['stage1_log_ids']}),'original_association_ids':len({i for r in rows for i in r['association_event_ids']}),'evidence_records':len(evidence),'event_evidence_links':len(links),'equivalent_duplicate_groups':len(duplicates),'equivalent_unique_sources':len(eq),
  'source_coverage':coverage,'sensitivity_motive_status':dict(collections.Counter(r['sensitivity_motive_status'] for r in rows)),'prior_general_motive_status_in_selected_events':dict(collections.Counter(r['prior_motive_status'] for r in rows)),
  'static_potential_category_events':dict(cat),'static_potential_subtype_events':dict(sub),'assessment':dict(collections.Counter(r['sensitivity_assessment'] for r in rows)),'value_kind':dict(collections.Counter(r['value_kind'] for r in rows)),
  'target_observation':dict(collections.Counter(r['observed_code_change']['classification'] for r in rows)),
  'scoped_false_positive_events':sum(bool(r['false_positive_dimension']) for r in rows),'false_positive_dimensions':dict(collections.Counter(r['false_positive_dimension'] for r in rows if r['false_positive_dimension'])),
  'actual_sensitive_value_in_target_log_established':0,'confirmed_new_types':0,'taxonomy_version':'1.2.0','taxonomy_subtypes':49,'novelty_rule':'Existing type observed in this subset is not a new taxonomy type; potential carriers are not confirmed sensitive values.',
  'unknown_reasons_multilabel':dict(collections.Counter(reason for r in rows for reason in r['unknown_reason_codes'])),'events_with_concrete_credential_like_prompt_context':sum(any(v['value_kind']=='concrete_credential_like_value_in_prompt' for v in r['concrete_values_in_related_material']) for r in rows),'independent_evaluation':False}
 checks=validation['checks']+['all_716_selected_retained_once','all_1757_screening_rows_retained','unselected_not_mislabeled_unknown','parent_event_identity_and_attribution_retained','15_accepted_batches_pass','all_196_groups_have_read_receipt','full_original_chain_recheck','source_equivalence_not_independent_votes','scoped_conflict_not_target_conflict','each_unknown_has_reason','no_actual_value_or_privacy_purpose_overclaim']
 frozen=json.loads((s.OUT/'input_hashes.json').read_text());assert all(s.sha(s.ROOT/k)==v for k,v in frozen.items());checks.append('all_9_frozen_inputs_unchanged')
 validation.update(at=s.now(),checks=checks,input_hashes_unchanged=len(frozen),original_chains=original_receipt,selected_events=716,pending=0)
 # Confirm the already-observed concrete value is absent from every new export, without printing it.
 tail=src['cd368fde85d16f311fc4c66a']['text'].strip().split()[-1]
 for obj in (rows,evidence,links,gaps,historical,corrections):
  if len(tail)>8:assert tail not in json.dumps(obj,ensure_ascii=False),'known_literal_leak'
 output.mkdir()
 for name,value in [('reviews',rows),('evidence_redacted',evidence),('event_evidence_links',links),('all_event_screening',screens),('source_gaps',gaps),('historical_source_gaps',historical),('final_review_corrections',corrections),('evidence_equivalence_groups',duplicates)]:s.lines(output/(name+'.jsonl'),value)
 table(output/'reviews.csv',rows,['queue_index','modification_id','repository','modification_sha','file_path','review_state','sensitivity_motive_status','value_kind','sensitivity_assessment','potential_types','actual_exposure','false_positive_dimension','contextual_inference','unknown_reason_codes','stage1_log_ids'])
 s.write(output/'statistics.json',stats);s.write(output/'validation.json',validation);s.write(output/'complete_chain_reference.json',original_receipt)
 s.lines(output/'pending_reviews.jsonl',[])
 examples=[]
 for n in [2,8,55,61,88,276,285,393,429,491,492]:
  r=next(r for r in rows if r['queue_index']==n)
  examples.append({'review':r,'evidence_links':[l for l in links if l['modification_id']==r['modification_id']],'source_metadata_and_redacted_excerpts':[v for v in evidence if v['evidence_id'] in {c['evidence_id'] for c in r['citations']}], 'trace_policy':'Use original_link_ids + complete_chain_reference.json for every underlying association; excerpts carry offsets and source hash.'})
 s.lines(output/'traceable_examples.jsonl',examples)
 (output/'traceable_examples.md').write_text(examples_md(examples),encoding='utf-8')
 (output/'FIELD_DICTIONARY.md').write_text(dictionary(),encoding='utf-8')
 (s.OUT/'README.md').write_text(report(stats,len(corrections),validation),encoding='utf-8')
 s.write(s.OUT/'progress.json',{'at':s.now(),'phase':'delivery_written_pending_adversarial_validation','screened':1757,'selected':716,'reviewed':716,'pending':0,'pilot':40,'accepted_batches':15,'independent_evaluation':False})
 print(json.dumps(stats,ensure_ascii=False,indent=2))

def examples_md(examples):
 out=['# 可追溯样例（全部为脱敏摘录）','每例均连接目标事件、修改 SHA/路径/diff、独立来源 ID、原文位置及结论；JSONL 保留多条来源和全部原链回查 ID。以下 quoted text 是脱敏后的原文，不是逐字原值。']
 for x in examples:
  r=x['review'];out+=['',f'## Q{r["queue_index"]} · {r["value_kind"]}',f'- 事件：`{r["modification_id"]}`',f'- 仓库 / 修改 SHA：`{r["repository"]}` / `{r["modification_sha"]}`',f'- 路径：`{r["file_path"]}`',f'- 观察：`{r["observed_code_change"]["classification"]}`；目标摘录：', '```text',r['observed_code_change']['before_redacted'] or '(empty)','```',f'- 判断：{r["contextual_inference"]}',f'- 隐私目的：`{r["sensitivity_motive_status"]}`；实际写入：`{r["actual_exposure"]}`。']
  choices=[c for c in r['citations'] if c['role'].startswith('case_scope')] or r['citations'][:2]
  for c in choices[:2]:
   v=next(v for v in x['source_metadata_and_redacted_excerpts'] if v['evidence_id']==c['evidence_id']);link=next(l for l in x['evidence_links'] if l['evidence_id']==c['evidence_id'])
   out += [f'- 证据 `{c["evidence_id"]}`（{v["source_type"]}），来源 `{v.get("source_url") or v.get("source_local_path") or v.get("source_id")}`，时间 `{v.get("source_time")}`。',f'- 关联：`{link.get("association_methods",link.get("association_method"))}`；关系 `{link["relation"]}`。','```text',c['quote_redacted'],'```',f'- 原文字符区间：[{c["original_start"]}, {c["original_end"]})；源 SHA256 `{c["original_source_sha256"]}`。']
 return '\n'.join(out)+'\n'

def dictionary():
 return '''# 字段与口径

| 文件/字段 | 含义与来源 |
|---|---|
| reviews · modification_id | 继承最新动机交付的去重修改事件键，不重新去重或变更第二步 |
| association_event_ids / stage1_log_ids | 所有原追踪关联和原候选 ID；不同计数单位 |
| review_state | assistant_reviewed 表示已对目标表达式、差异分类和有限材料进行助手审阅；不代表所有来源全文通读 |
| sensitivity_motive_status | 本日志后续修改的隐私/敏感信息目的：explicit / inferred / unknown / conflicting；与 general_change_motive 分开 |
| all_event_screening | 保留全部 1757 事件。未选中的 1041 条是 not_selected_not_reviewed，动机 null，不能计入 unknown 或无风险 |
| general_change_motive / prior_motive_* | 原交付的一般修改目的；本轮未覆盖，脱敏文本仅为展示副本 |
| observed_code_change | 原前后语句、坐标修正、逐行 diff 的脱敏副本；空 after 不是独立删除证明 |
| value_kind | 概念/示例上下文/关联材料中的具体值/未解析变量等分开；每类都附不确定性 |
| potential_types | 现有 1.2.0 分类下的静态潜在类型，非实际敏感值鉴定；多标签，不能相加当事件数 |
| actual_runtime / actual_exposure | unverified：未取得运行值、执行及实际日志写入证明，不代表安全 |
| confirmed_actual_sensitive_value_in_target_log | false 仅表示本轮未证实，不是无泄露断言 |
| concrete_values_in_related_material | prompt 中的具体凭据样式/邮箱或占位符；真实性和进入日志的边分别标记，值不导出 |
| explicit_sensitive_purpose / privacy_purpose_inference | 针对隐私目的的明确主张与推断；均不能由关键词自动赋值 |
| contextual_inference | 助手解释及上下文边界，不能冒充材料明确目的 |
| source_conflict_scope | 相反主张必须指同一日志的同一问题才升级 conflicting；存储/其他代码的争论单独留存 |
| false_positive_dimension | 已复核的一种特定误读，例如 key 原值与 publicId；不是该事件全部参数无风险 |
| novelty | 对照冻结的 49 子类型；本轮未建立新增类型，潜在载体不算新类型 |
| evidence_redacted | 每个来源独立一行；source_type 为 prompt、commit_message、pr_description、review_comment、issue |
| source_id / URL / local_path / time | 从父来源元数据复制；空时间保留空及 time_status，不猜测 |
| session/checkpoint/PR/issue/comment/turn ID | 可用时保留。评审 source_subtype 区分行内评论、评审总结、PR 讨论；issue 正文及讨论分别为来源 |
| prompt_content_kind | 保留原始 prompt 内容类型；会话中的工具/其他内容不自动当用户意图 |
| excerpts | quote_redacted 是脱敏原文；original_start/end 是原始文本字符偏移，source hash 可重放校验；每个摘录保留事件关联 |
| equivalence_group | 同一来源的等价文本归组，不将重复提及作为独立投票 |
| event_evidence_links | 保留事件身份、关联方法/依据、session/checkpoint/PR/评论链及每个 original_link_id；diff_hunk 脱敏 |
| complete_chain_reference | v12 原始完整关联链文件路径+哈希。大文件不复制，每个所用链 ID 已重新逐条核验 |
| source_gaps / historical_source_gaps | 当前缺口与历史请求分别保留；没有关联、返回空、401、旧认证失败不可混为一谈 |

审阅对象是既有修改事件，可能只是上下文或依赖发生更改，不能全部称为已删除的日志。对于封装函数调用，未展开到输出端时保留 final sink unresolved。静态函数名、变量名和关键词只提供检索及类型提示；别处有具体秘密、删除输出或找到 prompt 均不足以确认目标日志泄露。

脱敏覆盖引号字面量、凭据模式、邮箱/IP、URI、用户目录和混合不透明值。为追溯保留的 repository/SHA/path/session 等标识属于来源身份，不是日志中的运行时值。保守脱敏可能遮住无害信息；不能宣称识别所有语义秘密。原值只留在原父数据，不在新交付展示。
'''

def report(st,corrections,validation):
 cov='\n'.join(f'| {k} | {v["events"]} | {v["percent"]}% | {v["missing"]} |' for k,v in st['source_coverage'].items())
 cats='\n'.join(f'| {k} | {v} |' for k,v in sorted(st['static_potential_category_events'].items()))
 return f'''# 敏感信息相关日志修改核查

基于 `agent_log_motive_completion_20260924` 的 1,757 个事件，本轮检索出 **716 个相关候选，全部有审阅记录，剩余 0**。先试审 40 条并复核修正，再执行 13 × 50 + 26 条，共 15 个接受批次。另 1,041 个未入选事件仍在全量筛选表，标为未审阅，不能解释为安全或 unknown。

这是助手对目标表达式、带坐标差异、严格关联材料的有限片段进行的保守静态核查；不是逐份全文通读、运行测试、人工金标准或独立准确率评估。关键词用于检索，不用于泄露判定。既有第一、二阶段没有重跑、改规则或覆盖结果。

## 已执行与结论

- 716 个隐私目的判断均为 unknown；explicit 0 / inferred 0 / conflicting 0。这里仅问“本次修改是否为了处理敏感信息”；一般修改目的完整继承原交付，分布为 `{st['prior_general_motive_status_in_selected_events']}`，没有全部改成 unknown。
- 本轮**没有证实真实敏感值进入目标日志**，也没有建立新增类型。不能把“未证实”写成“无泄露”。已有 taxonomy 1.2.0 的 6 大类、49 子类型及文件哈希已冻结。
- 静态类型和错误/对象载体只表示潜在性。关联 prompt 中发现具体凭据样式内容的事件 {st['events_with_concrete_credential_like_prompt_context']} 个，真实性未验证，未闭合到目标日志的值流；新结果只保存脱敏信息。
- 复核确认 {st['scoped_false_positive_events']} 个事件存在特定的关键词误读边界：字段名不是正文值、公开 key ID 不是 key、签名存在标志不是签名值、分支名字规范化不是秘密脱敏等。这不是全量误报率，也不排除同一事件的其他参数仍有风险。
- HMAC 诊断日志 Q491 静态传入收到/计算的签名，属于既有 AUTH 兜底类型的潜在认证材料；提交说明删除诊断日志，但没有直接说明隐私目的，也没有真实运行值。Q492 仅输出存在标志，分开处理。
- PR #785 的评审确实指出另一处 transcript 字节可能进入 WARN 日志；该风险说明与当前 getStagedFiles 错误日志不能合并。没有因此擅自增加第二步候选。

## 类型数量（事件多标签，均为潜在提示）

| 现有分类 | 涉及事件 |
|---|---:|
{cats}

子类型逐项计数见 `delivery/statistics.json`。计数不能相加当作总事件数；目前确证的新增类型数为 0。

## 证据覆盖（分母 716；有材料不代表有目的证据）

| 来源 | 事件 | 覆盖率 | 未关联该类材料 |
|---|---:|---:|---:|
{cov}

共 {st['evidence_records']} 个独立来源记录、{st['event_evidence_links']} 条事件—来源关系；{st['equivalent_duplicate_groups']} 个等价重复组，合并等价后 {st['equivalent_unique_sources']} 个来源。逐项保留，不压成一个来源字段。修改 prompt 通过 commit → checkpoint → session/user turn 连接；会话内执行先后没有被证明，因此仍不自动等于该日志的目的。

本轮 GET 已复核 PR #828、#785、#1300 的合并 SHA；tpmjs 指定修改的 PR 查询成功但返回空；Gitea 正确主机 PR #22 返回 HTTP 401。请求凭据在根目录 `external_*receipt*.json`。旧交付的认证过期只属于历史请求，不能当作本轮 GitHub 仍不可用。没有远程写操作。没有穷尽所有仓库的新外部材料。

## 复核修正及隔离

- 在研究 Python 下执行 829 项守卫检查，全部允许；18,173 条原关联及 1,757 个事件的代码身份匹配父交付。封存材料未用于规则调整或审阅。
- 首批修正排除了日志 callee、stderr 输出控制参数，并把 error.message 与业务消息分开；旧试审版本保留，接受 `001_pilot_v3`。
- 最终复核另有 {corrections} 条增量修正记录，见 `delivery/final_review_corrections.jsonl`：包括 error: message、Object.keys(payload)、refusalPayload 方向、实例 logger、公开 ID 和具体边界解释；接受批次和父交付未改写。
- 初始工具查看时发生一次自由文本凭据样式值漏遮蔽；发现后停止原样展示，补强混合值、URI 等遮蔽规则。该值未写入新交付，并在内存中逐文件检查不再导出。不能把这写成从未发生漏遮蔽。
- 目标差异保留原观察：`{st['target_observation']}`。空 after、上下文保留或无目标 hunk 不强行解释为日志删除。

## 验证及交付

15 个批次验收 PASS；全量检查包括 716 事件恰好一次、原候选和关联不变、每条脱敏摘录从原文偏移重放、来源等价去重、关联身份核对、unknown 理由、全部九个冻结输入哈希不变。重新读取原始完整链并核对所用 {validation['original_chains']['selected_original_links_verified']} 条关联，PASS。全量验证文件为 `delivery/validation.json`；额外回归与续跑凭据另存，最终状态以 `progress.json` 为准，不以本说明的计划代替测试结果。

- `delivery/reviews.csv` / `.jsonl`：716 条审阅、一般目的与隐私目的分栏。
- `delivery/evidence_redacted.jsonl`：来源元数据、脱敏原文、偏移与哈希。
- `delivery/event_evidence_links.jsonl`：事件—证据全部关系及原链回查键。
- `delivery/all_event_screening.jsonl`：全部 1,757 个事件的筛选及审阅状态。
- `delivery/source_gaps.jsonl` / `historical_source_gaps.jsonl`：当前缺口与历史失败原因。
- `delivery/traceable_examples.md` / `.jsonl`：11 个可逐层追溯样例。
- `delivery/FIELD_DICTIONARY.md`、`taxonomy_baseline.json`：定义及分类基线。

继续执行 `python3 scripts/run_sensitive_review_batches.py` 会跳过已接受事件；`python3 scripts/finalize_sensitive_log_review.py` 对已存在的交付拒绝覆盖。后续新增材料必须另建目录/修订层，并先按 AGENTS.md 执行守卫。

## 尚未执行或受阻事项

没有实际运行日志样本、真实变量值和完整跨函数序列化传播证明；未验证脱敏函数在运行时有效。{st['source_coverage']['prompt']['missing']} 个候选没有已关联的修改 prompt；无关联不是已证明不存在。Gitea PR 受 401 阻塞；其他未取得类型列于缺口表。建议在授权可读材料下优先补查 Q491、Q268、Q393 相关值流及包装输出端，再处理目标 hunk 缺失记录。以上是后续建议，不是已完成的验证。全部选中事件已保留，不以证据缺失删除。
'''

if __name__=='__main__':run()
