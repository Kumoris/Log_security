"""Finish the verified handoff without overwriting earlier results."""
import argparse
import csv
import json
import os
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from run_swechat_followups import resolve_path
from agent_log_motivation_v11 import rows, table, file_hash, write_json


def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))


def local_path(value):
    return resolve_path(value)


def finish(root):
    root=Path(root);out=root/'delivery';w=Path(__file__).resolve().parents[1]
    if (root/'README.md').exists() or (root/'manifest.json').exists():raise FileExistsError('handoff already finalized')
    summary=read(out/'summary.json');legacy=summary['legacy'];s3=read(root/'stage3_final/summary.json')
    additional=read(root/'connector_batches/additional_source_checks.json')
    resolved={r['url'].removeprefix('https://api.github.com/'):r for r in additional if r.get('success') and r.get('data',{}).get('pull_request')}
    redirects={r['source_request_url'].removeprefix('https://api.github.com/'):r for _,r in rows(root/'redirect_source_gaps.jsonl')}
    notes=[]
    for _,r in rows(root/'stage3_final/unresolved_records.jsonl'):
        r=dict(r);endpoint=r.get('endpoint','').lstrip('/')
        if r['reason']=='offline_cache_miss' and endpoint in resolved:
            r.update(prior_reason=r['reason'],reason='reference_is_pull_request_not_issue',resolution_receipt=str((root/'connector_batches/additional_source_checks.json').resolve()))
        if r['reason']=='offline_cache_miss' and r['source_type']=='commit_message':
            r['availability_interpretation']='remote duplicate was not requested; exact local commit message is present'
            r['counts_as_missing_source_type']=False
        if endpoint in redirects:
            r['redirect_detail']=redirects[endpoint]
        notes.append(r)
    table(out,'current_source_gap_ledger',notes,['event_id','source_type','reason','endpoint','availability_interpretation'])
    raw=[]
    for r in read(root/'raw_prompt_inputs_before.json'):
        p=local_path(r['path']);h=file_hash(p)
        raw.append(dict(path=str(p.resolve()),sha256=h,matches_before=h==r['sha256'],matches_accepted_baseline=r['matches_accepted_baseline']))
    write_json(root/'raw_prompt_inputs_after.json',raw)
    assert all(r['matches_before'] and r['matches_accepted_baseline'] for r in raw)
    existing=read(out/'verification.json')
    assert existing['status']=='PASS'
    tests=(root/'verification/regression_tests.txt').read_text(encoding='utf-8')
    assert read(root/'verification/regression_execution.json')['returncode']==0
    source_dir=out/'code';source_dir.mkdir()
    names=['continue_agent_log_pipeline.py','agent_log_motivation_v12.py','audit_agent_log_legacy.py','import_agent_log_connector_receipts.py',
           'package_agent_log_three_stage.py','finish_agent_log_delivery.py','test_agent_log_motivation_v12.py','test_continue_agent_log_pipeline.py','test_import_agent_log_connector_receipts.py']
    for name in names:shutil.copyfile(w/'scripts'/name,source_dir/name)
    dependencies=['agent_log_motivation_v11.py','align_swechat_agent_logs.py','swechat_connector_cache.py','run_swechat_followups.py','package_swechat_followups.py']
    write_json(out/'code_dependencies.json',{str((w/'scripts'/n).resolve()):file_hash(w/'scripts'/n) for n in dependencies})
    pending_path=w/'outputs/swechat_followup_20260922/additional-attempts/marin-detached-shared-gap-20260923/attempt_status.json'
    write_json(out/'upstream_status_at_delivery.json',dict(checked_at=datetime.now(timezone.utc).isoformat(),
        source_path=str(pending_path.resolve()),source_sha256=file_hash(pending_path),status=read(pending_path),
        snapshot_pending_candidates=summary['pending_candidates'],interpretation='status of the existing run; this task did not start or terminate it'))
    coverage='\n'.join(f"| {r['source_type']} | {r['association_events']:,}/{r['association_denominator']:,}（{r['association_fraction']:.2%}） | {r['unique_modifications']:,}/{r['unique_denominator']:,}（{r['unique_fraction']:.2%}） | {r['evidence_rows']:,} |" for r in summary['source_coverage'])
    dist=summary['motive_distribution'];review=read(out/'review_subtype_coverage.json')
    text=f'''# Agent 日志三阶段流程：2026-09-23 增量交付

**已完成现状重核、第三步增量实现、已完成第二步产物的证据采集及交付校验。前两步筛选与归因逻辑、原数据和旧结果未改动。** 本次是明确注明范围的完成批次快照：原追踪仍有 1 个仓库、20 个候选未完成，不能把这份交付称为第二步全量最终结果。动机只完成 3 个代表样例的助手审阅，其余保留 unknown，不冒充全量人工标注。

## 1. 当前实现与三阶段的对应

| 环节 | 已有实现与口径 | 本次增量 |
|---|---|---|
| 历史底座 | SWE-chat 固定历史日志版本视图；`swechat-common-flow-605-20260914`，来源见旧字段字典与 lineage | 重新计数、核对旧验收摘要，只展开 guard 允许的开发记录 |
| 第一步 | `swechat_agent_scope_20260919/final` → `align_swechat_agent_logs.py` → `swechat_log_alignment_20260921/final/changed_logs.csv` | 原 4,128 个候选、Agent 归因等级、mixed 和 possible 原样保留；没有新增品牌限制 |
| 第二步 | `run_swechat_followups.py` / `execute_swechat_followups.py` 适配既有 `lineage.trace_logs`；冻结目标分支历史及原 first-parent、祖先、窗口/回退规则 | 仅核验已完成仓库的原事件并建立隔离快照；未重跑匹配器、未改变准入或观察窗口 |
| 第三步 | 原 `agent_log_motivation_v11.py` 的五类来源、证据表、关联表和带引文的四态判定 | 新 v1.2 增加不可变输入视图、依赖变化的精确日志 blob 锚点、读取失败/空结果区分及按事件索引的判定；旧入口保留 |

旧的 9 月 21 日交付写“第二步未找到”，已不能代表当前状态。本次接纳 69 个既有仓库回执及完成验收的 Entireio 新 attempt，另一个原进程仍保留。快照的逐仓库检查、源行映射、原输入摘要位于 [stage2_snapshot](stage2_snapshot/)。

## 2. 两万多条数据与 60%／40% 的核验

实际是 **24,685 个历史日志版本、93 个仓库、25,627 个观察引用**。completed=14,986（60.71%），partial=9,699（39.29%），这两个状态表示提取情况，不能解释为来源、含义或修改动机查明率。

48,683 条字段记录中，47,392 条可计数、1,291 条为不重复计数的父容器；可计数字段中编程类型未定 25,114 条。允许开发的 23,533 个日志版本中，18,775 个含语义未定字段，其中 **12,969 个自身仍为 completed**。因此“60% 的日志已经完全理解”不成立。

日志 ID 与字段 ID 均无重复。粗定位键有 402 条超出首条，同源辅助键有 4,944 条超出首条；它们可能代表不同实体、位置或版本，本次只报告而不删除。1,152 条隔离记录保持封存；不展示其身份、源码或预测，不进行独立评估。

开发范围检查的 repository、snapshot_sha、path、source_sha256、git_blob_id、observation_ids 没有空缺。主要未决问题是对象/语义解析（4,323 条日志）、包装器实参到输出映射（2,413）、上下文属性/初始化（1,239）和解析预算等，类别可重叠。字段定义待复核、源定位缺失、归因强度和修改动机是不同维度，不能合并成“剩余40%”。

逐条台账和重新计算结果见 [legacy_audit/summary.json](legacy_audit/summary.json)、[unresolved_legacy_logs.csv](legacy_audit/unresolved_legacy_logs.csv)。八项历史审计输入与旧验收摘要一致；四个原始会话表也已完成执行前后摘要核对。

## 3. 粒度、代码状态与字段来源

- `agent_changes` 一行是工具编辑操作；一次操作可涉及多条日志，一条日志也可多次编辑。它不是最终提交日志或后续修改事件。
- `agent_version` 是 Agent 操作快照，可能是中间状态；`committed_version` 是数据集记录的最终提交快照。第三步 before/after 采用精确 Git 父提交/修改提交的源码，并对照语句和 diff，不用操作中间状态替代提交状态。
- 旧 `log_version_id` 表示历史日志版本，观察引用保存 before/after 等出现来源。它与当前第一步的日志候选 ID、第二步的追踪起点 `case_id`、后续关联 `id` 都不是同一粒度。
- 原第三步 `log_modifications` 每行对应**追踪起点—后续修改关联**，共17,969行。同一次修改可能关联多个起点。本次另提供按既有事件键汇总的1,688行视图；不删除原关联、不据此重新筛选。
- repo/SHA/path 继承原表及 Git 对象；checkpoint/session 由 commits、checkpoints 的双向提交成员关系和 session 列表关联，prompt 再匹配 conversations 中同仓库、checkpoint、session 的 user conversational turn。工具 turn 不冒充 prompt，checkpoint 同属也不证明目的或执行先后。
- `is_agent_author`、文件归因与后续沿袭置信度各自保留。旧 `source_and_purpose` 是字段输出值的来源/用途，`followup_rule_version` 是研究补证规则版本，二者都不是 Git 后续修改动机。

完整继承字典见 [field_dictionary.csv](legacy_audit/field_dictionary.csv)，原始字段出处见 [raw_field_provenance.csv](legacy_audit/raw_field_provenance.csv)，新增字段见 [field_dictionary_supplement.csv](delivery/field_dictionary_supplement.csv)。[unresolved_field_definitions.csv](legacy_audit/unresolved_field_definitions.csv) 是未逐项复核的继承定义清单，不等于数据错误，也不是39.29%的分母。

## 4. 阶段数量与去重

| 口径 | 输入 | 输出 | 比例 |
|---|---:|---:|---:|
| 原范围选择（文件单元） | 85,401 | 10,767 | 12.61% |
| 第一步观察到日志的文件单元 | 10,767 | 805 | 7.48% |
| 第一步日志候选送入第二步 | 4,128 | 4,128 | 100%保留 |
| 第二步已观察到修改的候选 | 4,128 | 991 | 24.01%，当前观察值；全量最终比例为null |
| 第二步修改关联 → 既有键汇总视图 | 17,969 | 1,688 | 粒度转换，不是筛选率 |
| 第三步保留第二步修改关联 | 17,969 | 17,969 | 100% |

4,108个候选已有处理回执，20个仍pending。回执中还包括200个 history_unavailable、2,269个 history_incomplete、100个 anchor_not_observed、544个 no_observed_followup 和4个 coverage_interval_only；后几类不等同于证明永远没有后续修改。第一步还有1,896个 guard 排除/不可结构核查文件单元及103个未对齐单元，不能计作确定无日志。

17,969条关联中：direct_call_change=12,582，dependency_change=5,387；后者可以没有日志文本变化。沿袭 supported=339、possible=17,630。它们是原结果，未因第三步缺少证据而过滤或升级。

汇总事件键为 repository_id、修改SHA、父SHA、路径、before/after起始行、entity_fingerprint、change_kind，沿用既有打包统计定义；不宣称这是跨任意重写的完美语义去重。同源同内容证据按原类型、仓库、子类型、来源ID与内容摘要去重；不同评论版本、命名空间和不同关联保留。现有原关联ID、证据ID和关联ID均通过唯一性校验。

## 5. 证据覆盖与动机状态

共 **3,319条独立证据、186,132条原始事件—证据关联**。来源覆盖表示存在可核查材料，不代表该材料已经证明修改目的。

| 来源 | 原关联行覆盖 | 既有事件键覆盖 | 独立证据数 |
|---|---:|---:|---:|
{coverage}

`review_comment` 子类型分开保留：行内评论覆盖 {review['inline']['events']:,} 条关联，评审总结覆盖 {review['review_summary']['events']:,} 条，普通PR讨论覆盖 {review['pr_conversation']['events']:,} 条；三者重叠，普通PR讨论不冒充正式评审。同PR/同文件只是上下文；只有修订、路径、行区间直接对应时才标直接位置。

动机状态按17,969条保留关联计：**explicit={dist['explicit']}、inferred={dist['inferred']}、unknown={dist['unknown']:,}、conflicting={dist['conflicting']}**。其中只有3条完成本轮带引文的助手审阅；多数unknown含义是材料已取得，但具体日志目的尚未审阅确认，不是证明这些修改没有目的。没有独立人工真值；0个conflicting也不意味着全部材料没有冲突。

observed_change、stated_purposes、inferences 和 claims 独立保存。explicit要求明确目的及精确对应，inferred单列推断；兼容多标签不自动冲突，不同来源对同一命题相反时才判conflicting。同证据的相反解读另记待裁决。初始引入prompt仅能作背景。

## 6. 缺失、失败与适用边界

主采集队列1,530个不同GitHub请求；重试后1,513个有JSON回执，17个仍为404。成功JSON回执中有58个仓库重定向，不能当作正常PR/issue正文；其数字仓库路由的一次实际验证被连接器以 HTTP400 INVALID_ARGUMENT 拒绝，具体回执见 [redirect_source_gaps.jsonl](redirect_source_gaps.jsonl)。未静默重命名原仓库。

一次传输解码错误重试成功，原失败保留。重试讨论新出现的两个引用已额外查实为PR，不当作issue证据；最新缺口解释位于 [current_source_gap_ledger.csv](delivery/current_source_gap_ledger.csv)。原运行缺口表保留当时状态。GitHub远程提交消息副本未重复请求，因为精确本地提交消息已覆盖全部事件；相应offline缓存记录不是“提交消息缺失”。空评审正文、引用其实是PR、未找到明确issue引用也分别记录，不混成网络失败。

原提交明示的 Gitea PR 原链接已经尝试读取，但工具不可访问，见 [non_github_source_gaps.jsonl](non_github_source_gaps.jsonl)。没有编造说明、链接或目的。Issue只沿已验证材料的明确引用扩展；未遍历GraphQL关系或依靠主题/时间猜关联。外部正文是采集时的可见版本，原始回执保存采集时间及正文版本，不能声称它们从未编辑。

## 7. 文件入口

- [日志修改汇总表](delivery/unique_log_modifications.csv)、[完整原关联记录表](stage3_final/log_modifications.csv)、[原关联到汇总事件映射](delivery/association_to_modification.csv)。
- [动机证据表](stage3_final/motive_evidence.csv)、[原证据关联表](stage3_final/evidence_links.csv)、[汇总事件与证据关联](delivery/unique_modification_evidence.csv)、[完整左连接结果](stage3_final/modifications_with_evidence.csv)、[动机结论](stage3_final/motives.csv)。
- [阶段数量](delivery/stage_counts.csv)、[双口径覆盖率](delivery/source_coverage.csv)、[四态分布](delivery/motive_distribution.csv)、[来源类型说明](legacy_audit/source_types.csv)。
- [可追溯样例](delivery/可追溯样例.md)、[机器可读完整样例](delivery/traceable_examples.jsonl)、[实际审阅注释](reviewed_motive_annotations.jsonl)。
- [运行方式](运行方式.md)、[新增代码快照](delivery/code/)、[旧字段/来源台账](legacy_audit/)、[原始外部回执](connector_batches/)。核心表同时提供CSV和JSONL。

## 8. 已执行验证与尚未执行

已执行：公开开发guard通过；657个精确日志源码对象全部校验；第二步原输入、候选、祖先与父提交逐仓库对账；全部事件保留；表间外键、唯一性、原文摘要、引文、覆盖率及无证据左连接核验；59项合成/开发回归测试通过；八项旧审计输入及四个原始会话表摘要核验。交付检查见 [verification.json](delivery/verification.json)，测试原输出见 [regression_tests.txt](verification/regression_tests.txt)。

尚未执行：剩余20个候选的最终上游验收与全量第二步汇总；全量修改动机逐条审阅；独立人工标注、独立准确率或运行时实验。本次不报告这些项目已完成。

建议单独处理而未改变前两步：原possible沿袭影响17,630条关联，应另行复核；依赖变化的5,387条需与语句文本变化分层分析；24,685历史版本和4,128Agent候选不可混为同一漏斗；粗定位重复不能直接删除；重定向及非GitHub材料可在可核查的仓库别名/托管映射具备后继续补证。所有接续使用新目录，保留本次父链。
'''
    (root/'README.md').write_text(text,encoding='utf-8')
    write_json(root/'manifest.json',dict(created_at=datetime.now(timezone.utc).isoformat(),
        scope='validated completed-repository snapshot; pending upstream candidates remain explicit',
        immutable_parents={'stage2':file_hash(root/'stage2_snapshot/manifest.json'),'stage3':file_hash(root/'stage3_final/manifest.json')},
        delivery_files={str(p.relative_to(root)):file_hash(p) for p in out.rglob('*') if p.is_file()},
        raw_inputs_unchanged=True,remote_writes=0,holdout_evaluated=False,
        documentation={'README.md':file_hash(root/'README.md'),'运行方式.md':file_hash(root/'运行方式.md')}))
    print(json.dumps({'status':'PASS','handoff':str((root/'README.md').resolve()),'raw_inputs_unchanged':True}),flush=True)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--root',type=Path,required=True);a=ap.parse_args();finish(a.root)
