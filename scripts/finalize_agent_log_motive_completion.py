"""Record completed verification, documentation and an auditable artifact manifest."""
import json,collections,subprocess,sys
from pathlib import Path
import complete_agent_log_motive_reviews as m
O=m.OUT;D=O/'delivery';V=O/'verification'

def main():
 validation=json.loads((V/'validation.json').read_text());assert validation['status']=='PASS'
 stats=json.loads((D/'statistics.json').read_text())
 protocol=json.loads((O/'protocol.json').read_text());assert protocol['rule_digest']==m.sha(m.ROOT/'scripts/motive_completion_decisions.py')
 before={str(p.relative_to(O)):m.sha(p) for p in (O/'batches').rglob('*') if p.is_file()}
 result=subprocess.run([sys.executable,str(m.ROOT/'scripts/complete_agent_log_motive_reviews.py'),'run'],cwd=m.ROOT,capture_output=True,text=True,check=True)
 after={str(p.relative_to(O)):m.sha(p) for p in (O/'batches').rglob('*') if p.is_file()}
 assert before==after
 m.write(V/'resume_idempotence.json',{'status':'PASS','at':m.now(),'batch_files_unchanged':len(before),'new_batches':0,'stdout':result.stdout,'rule_digest_matches':True})
 reviews=m.read(D/'log_modification_reviews.jsonl');gaps=m.read(D/'source_gaps.jsonl')
 issues=[{'issue':'prior_pending_mislabeled_unknown','affected_events':1646,'impact':'旧汇总将未审阅混入 unknown，不能解释为已审阅后无法判断。','action':'本轮起始 inventory 将未审阅 motive_status 设为 null；逐批审阅后才赋值。旧交付不改写。'},
 {'issue':'inherited_association_not_event_review','affected_events':1,'impact':'继承关联层推断不等于事件审阅。','action':'0295e62c02137fcddbc46b5d 已在本轮实际审阅，结论 inferred，保留原来历。'},
 {'issue':'off_by_one_upstream_span','affected_events':9,'impact':'原行号指向相邻语句，妨碍精确复核。','action':'同提交、同路径 diff 中完整语句唯一匹配；原始字段保留，另存 span_corrections；未改变筛选或动机结论。'},
 {'issue':'upstream_deleted_but_context_retained','affected_events':sum(x['current_observation']['classification']=='upstream_deleted_but_context_retained' for x in reviews),'impact':'上游 deleted 标签不能单独证明目标日志消失。','action':'逐事件记录当前观察；没有直接对应目的则 unknown，不删除事件。'},
 {'issue':'target_not_located_in_attached_diff','affected_events':sum(x['current_observation']['classification']=='no_target_span_in_attached_diff' for x in reviews),'impact':'所附 diff 不能核实目标具体变化，禁止将别处改动目的套用。','action':'保留当前证据与不足说明；建议后续在独立目录补充父/子提交的目标文件快照，尚未执行。'},
 {'issue':'wrong_host_issue_number_lookup','affected_events':len({x['modification_id'] for x in gaps if 'interpretation_correction' in x}),'impact':'Gitea PR #22 与 GitHub 同编号 issue 不是同一材料；旧失败记录不能证明 Gitea PR 不存在。','action':'保留请求历史并添加解释修正；本轮未获取 Gitea PR。'},
 {'issue':'external_authentication_expired','affected_events':len({x['modification_id'] for x in gaps if x.get('reason')=='authentication_token_expired'}),'impact':'两个修改提交的 PR 查找无法完成，不表示没有 PR。','action':'保存具体 GET 失败凭据，使用已有材料继续；连接恢复后可补查，尚未执行。'}]
 # Actual classifier names remain authoritative; derive counts without inventing labels.
 classes=collections.Counter(x['current_observation']['classification'] for x in reviews)
 for r in issues:
  if r['issue']=='upstream_deleted_but_context_retained':
   matching=[k for k in classes if 'retained' in k];r['observed_classifications']={k:classes[k] for k in matching};r['affected_events']=sum(classes[k] for k in matching)
 m.lines(D/'issues_and_impact.jsonl',issues);m.csv_table(D/'issues_and_impact.csv',issues)
 coverage='\n'.join(f"| {t} | {c['events']} | {c['fraction']:.2%} | {c['missing']} | {stats['purpose_support_coverage'][t]['events']} |" for t,c in stats['source_coverage'].items())
 reasons='\n'.join(f'- `{r}`：{n} 条。' for r,n in stats['unknown_reasons'].items())
 issue_lines='\n'.join(f"- **{r['issue']}**：影响 {r['affected_events']} 个事件。{r['impact']}{r['action']}" for r in issues)
 doc=f'''# 日志后续修改动机判读完成交付

本轮从 `agent_log_motive_review_20260924/delivery_v2` 继续，以 v12 既有去重事件键为单位完成审阅。生成时间：{m.now()}。所有结果仅写入本目录及本轮新增脚本；原始数据、接受的父交付、第一步与第二步逻辑未修改。本轮不是第一步或第二步的重跑。

## 已执行结果

共 **1,757 个目标事件，已审阅 1,757，未审阅 0**，保留 18,173 条追踪起点—修改关联和 996 个原候选 ID。复核原有 110 条；新增判读 1,647 条（原未审阅 1,646 条，加 1 条仅继承关联层结论的事件）。新增 33 批：32 × 50 + 47；另有 110 条前批复核记录。每批验证 PASS 后继续。

| 动机状态 | 事件数 | 占全部目标 |
| --- | ---: | ---: |
| explicit | 134 | {134/1757:.2%} |
| inferred | 129 | {129/1757:.2%} |
| unknown | 1,494 | {1494/1757:.2%} |
| conflicting | 0 | 0.00% |

`review_state` 与 `motive_status` 分开。起始未审阅事件的动机值为 null；最终 unknown 均有审阅记录和不足原因，不能解释为未处理。标签允许多选，标签计数不可相加当作事件数。未发现已阅读材料中成立的相反目的主张；conflicting=0 不代表全部外部材料没有冲突。

## 判读范围及前批复核

按仓库+修改 SHA 组织 363 组上下文，读取提交/PR 摘要及相关原文片段，检查逐事件目标路径、before/after、带坐标 diff，以及适用的 session/checkpoint 和评论链。对明确目的的候选深入核对原文与目标行或外围控制流的对应。全部事件均有代码核验与审阅记录；完整来源已保存，但并未对全部来源逐字人工通读。

这是保守的开发阶段**助手判读**，不是双人盲标、人工金标准或独立准确率评估。旧 110 条的摘录、关联链、代码对应和结论经复核保留（84 explicit、9 inferred、17 unknown）。本轮先审阅并验证首批 50 条，进一步核验修正 9 条行号偏移后，按同一判读规则继续。旧批次文件不改写，修正覆盖层另存。

同一提交的目的只有与目标改动对应时才用于该事件。引入日志的 prompt 只作背景；不以关键词、时间接近、同文件或找到 prompt 本身认定目的。代码观察、明确目的、上下文推断分别保存。整文件迁移可支持迁移目的的推断，但不能凭此断言噪声控制。目标字符串未变化时，若直接控制流证据说明取消后静默返回，仍可有明确目的。

## 来源覆盖与缺失

共 3,630 条来源记录；在旧 3,629 条基础上新增 1 条 issue 正文。共 16,821 条事件—证据关联，新增 13 条由修改 prompt 明确引用 issue 形成的链；13 条关联不是 13 个独立来源。88 组仅 CRLF/末尾空白差异的同源文本保留原 ID，并归入等价组，不作独立重复佐证。

| 来源 | 有关联材料的事件 | 覆盖率 | 缺少该类材料的事件 | 实際用于目的支持的事件 |
| --- | ---: | ---: | ---: | ---: |
{coverage}

分母均为 1,757；同一事件可以有多类证据，覆盖率不可相加。关联材料包含上下文/背景，不能当作目的已查明。目的支持列统计引用角色 `purpose_support`，包括 explicit 或 inferred，亦不可跨来源相加。全部事件至少有提交消息，因此完全没有任何来源的事件为 0；这不等于不存在目的材料缺失。

本轮外部仅 GET：issue 正文成功、讨论成功但为空；两个提交的 PR 补查各有一次未保留详细错误的失败，重试明确返回认证令牌过期，合计 4 条失败凭据。未绕过认证、未发布评论或改写远程资源。Gitea PR 未获取；旧 GitHub 重定向/缺失来源等具体历史原因保留在 `source_gaps.jsonl`，不能把请求失败等同于不存在材料。

审阅后 unknown 的原因分布：

{reasons}

## 系统性问题及影响

{issue_lines}

上述仅影响本轮观察、统计解释或后续补证建议；没有改变前两步准入、Agent 品牌范围、候选归因或事件去重键。问题详情和 9 个修正事件清单见 `delivery/issues_and_impact.jsonl`、`delivery/span_corrections.jsonl`。目标定位缺口可能影响第二步标签解释，应在新的核验增量中处理；本轮保留事件而非回写筛选结果。

## 三阶段对应与数量口径

以下继承 v12 已验收统计，本轮未重跑：第一步在 10,767 个原范围代码文件单元中得到 805 个含日志候选的文件单元（7.48%），共 4,128 个日志候选；第二步发现 996 个候选有后续修改（24.13%，pending=0）。18,173 条追踪起点—修改关联按既有事件键汇总为 1,757 个事件；第三步全部保留。不同单位不可直接相除作为筛选率。

旧“2 万多条/约 60% 与 40%”对应的原始记录及字段审计仍以 v12 为准，不能把其比例解释成当前动机明确率。本轮的统计单位是修改事件，不是工具操作数或原始日志语句数；仍保存原候选和每条关联 ID，不跨仓库合并 fork 或别名。

## 已执行验证

- 34 份批次验收均 PASS（原有 110 条复核 + 33 个新批次）；全部目标 ID 恰好一次、pending 为空。
- 全量验收 15 项 PASS：逐条摘录偏移、证据关联及目标身份、冲突合同、18,173 关联留存、原始事件与归因字段不变、829 项 guard 均允许、来源文本哈希、关联去重等。
- 191,672 条原始关联链逐条回查 ID、证据、仓库、修改 SHA、路径、原事件成员关系；全部通过。大原链文件不复制，保存父路径和 SHA256，凭 `original_link_ids` 回查。
- 7 个登记父输入的 SHA256 前后相同；3,629 条父来源全文和元数据原样保留。
- 21 项回归/对抗测试 PASS，覆盖不关联证据、错误摘录、错误 SHA、背景 prompt 不可充当目的、同源重复不可独立投票、冲突证据、缺失来源和错误目标行。
- 完成后实际续跑一次，新增批次 0，全部 {len(before)} 个批次文件哈希不变；规则文件与冻结摘要一致。

验证证明结构、可追溯性和判读约束符合本协议，不是独立语义准确率证明。封存材料未用于开发判读；本轮守卫凭据在 `guard_receipt.json`。

## 文件入口

- `delivery/log_modification_reviews.csv` / `.jsonl`：1,757 个事件、代码观察、目的、推断、状态、候选及关联 ID。
- `delivery/motive_evidence.jsonl`：独立来源记录及全文、时间、URL/本地路径和来源 ID。
- `delivery/evidence_links.jsonl`：事件—证据多对多关联、链和原链 ID。
- `delivery/event_evidence_citations.csv` / `.jsonl`：实际引用的必要原文、偏移、角色、来源元数据和关联依据。
- `delivery/unresolved_motives.csv` / `.jsonl`：1,494 个已审阅但动机仍未知的事件与原因；不是待处理队列。
- `delivery/pending_events.jsonl`：空文件，表示未审阅 0。
- `delivery/source_gaps.jsonl` / `external_request_outcomes.jsonl`：缺失与实际请求结果。
- `delivery/field_dictionary.csv` / `.jsonl`、`source_types.jsonl`：字段及来源类型定义；新增定义覆盖同名旧定义，原字段内容保留。
- `delivery/statistics.json`、`batch_progress.csv`：分布、覆盖率及批次进度。
- `delivery/可追溯样例.md`、`traceable_examples.jsonl`：8 个完整样例，含 prompt、行内评审、控制流、推断和 unknown。
- `verification/validation.json`、`regression_tests.json`、`resume_idempotence.json`：已执行验证凭据。
- `progress.json`、`completion_receipt.json`、`artifact_manifest.json`：完成状态、输入/输出哈希及继续入口。

## 运行与继续

在项目根目录执行（Linux Python 3；首次准备 guard 使用项目规定的研究 Python，已完成）：

```bash
python3 scripts/complete_agent_log_motive_reviews.py run
python3 scripts/deliver_agent_log_motive_completion.py verify
python3 scripts/test_motive_completion.py
```

第一条会跳过已有通过验收的批次，本交付已无待处理事件；不会再次判读。`--limit-batches 1` 可限制调试运行。生成器 `deliver_agent_log_motive_completion.py build` 只允许不存在的 delivery 目录，当前交付已生成，勿重复构建或覆盖。准备器和 initialize 仅用于本轮初始隔离准备，不应在现有输出上重跑。

可复现判读规则见 `scripts/motive_completion_decisions.py`，批次及检查见 `scripts/complete_agent_log_motive_reviews.py`，交付/校验见 `scripts/deliver_agent_log_motive_completion.py`，回归见 `scripts/test_motive_completion.py`。这些脚本只读前两步父产物。今后恢复连接后补证或补充快照，应新建下一增量目录，沿用事件 ID 并记录状态变更，先执行隔离守卫；当前全部目标事件的审阅工作已完成。

## 未完成及受阻事项

未审阅事件：0。外部材料的穷尽收集未完成：GitHub 认证过期阻止两个提交的 PR 补查；部分 prompt/session、PR、评审、issue 仍无可用关联。1494 个 unknown 的目的未确定；允许保留，已逐事件记录原因。Gitea 材料获取、缺失目标快照补证、恢复认证后的补查、独立双人盲标与评估均未执行；不将这些建议列为已完成。
'''
 (O/'README.md').write_text(doc,encoding='utf-8')
 progress=json.loads((O/'progress.json').read_text());progress.update(phase='completed',at=m.now(),global_validation='PASS',completion_scope='all 1757 target events assistant-reviewed; unknown retained with reasons',remaining_review_events=0)
 m.write(O/'progress.json',progress)
 receipt={'at':m.now(),'status':'completed','reviewed':1757,'remaining':0,'newly_reviewed':1647,'motive_distribution':stats['motive_distribution'],
 'validation':'verification/validation.json','independent_evaluation':False,'external_collection_exhaustive':False,'remaining_limitations':['1494 motives unresolved with reasons','GitHub token expired for two commit PR queries','missing source classes and some target diffs','no independent accuracy evaluation']}
 m.write(O/'completion_receipt.json',receipt)
 source={'schemaVersion':1,'items':[{'id':'review-completion','title':'日志修改事件审阅完成情况','queries':[{'id':'event-counts','source':{'label':'本轮判读交付',
 'files':[{'label':'delivery/statistics.json'},{'label':'verification/validation.json'},{'label':'verification/regression_tests.json'}],
 'metricDefinitions':[{'label':'审阅事件','definition':'沿用 v12 的去重修改事件键，共 1,757 个目标事件。'},{'label':'unknown','definition':'已审阅后证据不足，不包含未审阅事件。'}],
 'filters':['开发隔离守卫允许的目标事件'],
 'caveats':['本轮为助手判读，不是独立准确率评估。','GitHub 认证过期，部分外部材料未取得。','没有观察到已阅读材料中的成立冲突，不代表全部材料不存在冲突。'],
 'executedAt':validation['at']},'columns':['指标','数量'],'rows':[{'指标':k,'数量':v} for k,v in {'已审阅':1757,'未审阅':0,'本轮新增':1647,**stats['motive_distribution']}.items()],
 'preview':{'kind':'aggregate','note':'按目标修改事件计数；状态互斥。','totalRows':1757}}]}]}
 m.write(O/'sources_receipt.json',source)
 scripts=['prepare_agent_log_motive_completion.py','motive_completion_decisions.py','complete_agent_log_motive_reviews.py','deliver_agent_log_motive_completion.py','test_motive_completion.py','finalize_agent_log_motive_completion.py']
 manifest={'at':m.now(),'algorithm':'SHA256','artifacts':{str(p.relative_to(O)):m.sha(p) for p in sorted(O.rglob('*')) if p.is_file() and p.name!='artifact_manifest.json'},'scripts':{s:m.sha(m.ROOT/'scripts'/s) for s in scripts}}
 m.write(O/'artifact_manifest.json',manifest)
 print(json.dumps({'completed':True,'reviewed':1757,'pending':0,'resume':'PASS','artifact_files':len(manifest['artifacts']),'issues':[{k:r[k] for k in ('issue','affected_events')} for r in issues]},ensure_ascii=False))
if __name__=='__main__':main()
