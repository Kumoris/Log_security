"""Write a report from executed artifacts only; refuse missing stage results."""
from run_swechat_followups import *
import shutil

def pct(v):return '不可计算' if v is None else f'{v:.2%}'

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--stage3-name',default='stage3');args=ap.parse_args()
    stage2=OUT/'stage2';stage3=OUT/args.stage3_name
    a=json.loads((stage2/'summary.json').read_text(encoding='utf-8'))
    b=json.loads((stage3/'summary.json').read_text(encoding='utf-8'))
    dest=OUT/('delivery' if args.stage3_name=='stage3' else 'delivery-'+args.stage3_name)
    cv=json.loads((stage2/'validation.json').read_text(encoding='utf-8'))
    mv=json.loads((stage3/'validation.json').read_text(encoding='utf-8'))
    if cv['status']!='PASS' or mv['status']!='PASS':raise RuntimeError('Stage validation failed; delivery not finalized')
    dest.mkdir(exist_ok=False)
    stages=[dict(stage='1',input_unit='既有候选文件提交单元',input_count=a['stage1_input_file_units'],output_unit='含日志候选的文件提交单元',output_count=a['stage1_output_log_file_units'],fraction=a['stage1_log_file_fraction']),
            dict(stage='1_detail',input_unit='日志候选',input_count=a['stage1_output_log_candidates'],output_unit='本次第二步原样输入',output_count=a['stage2_input_candidates'],fraction=1),
            dict(stage='2',input_unit='初始日志候选',input_count=a['stage2_input_candidates'],output_unit='观察到后续事件的初始日志候选',output_count=a['initial_logs_with_followups'],fraction=a['stage2_changed_candidate_fraction']),
            dict(stage='2_events',input_unit='初始日志候选与修改的关联',input_count=a['stage2_event_links'],output_unit='去重后的实际修改事件',output_count=a['stage2_unique_modification_events'],fraction=None),
            dict(stage='3',input_unit='第二步修改关联记录',input_count=a['stage2_event_links'],output_unit='保留的动机分析记录',output_count=b['events'],fraction=b['events']/a['stage2_event_links'] if a['stage2_event_links'] else None)]
    from agent_log_motivation_v11 import table,file_hash
    table(dest,'stage_counts',stages,['stage','input_unit','input_count','output_unit','output_count','fraction'])
    fields=[
        ('candidate_ledger','log_id','原第一步日志候选 ID；不重新编号','changed_logs.csv'),
        ('candidate_ledger','status','观察到修改、未观察到修改、历史不全、锚点未映射等；不是动机结论','本次原追踪器执行与精确输入映射'),
        ('candidate_ledger','log_detection_status','第一步 confirmed / possible 日志识别状态原样保留，独立于 Agent 来源、后续沿袭与修改动机','第一步 changed_logs.csv'),
        ('candidate_ledger','source_rows','第一步记录的原始来源行号；保留原字段值，不冒充 Git 行号','第一步 changed_logs.csv 与其来源说明'),
        ('candidate_ledger','attribution_grade','第一步归因等级原样保留；弱归因不升级为 Agent 已证明','第一步已有结果'),
        ('candidate_ledger','file_attribution_labels','保留 agent_only / mixed 等原文件归因','第一步已有结果'),
        ('log_changes','intro_sha / log_added_sha','intro_sha 是本次追踪起点，可对应新增或修改已有日志，不保证日志第一次出现；仅新日志起点才有 log_added_sha','第一步既有候选与原 trace_logs'),
        ('log_changes','pr_id','兼容原追踪器的提交上下文 ID；本次该字段不表示实际 PR','仓库与初始 SHA 的稳定组合'),
        ('log_changes','pr_number / pr_url','没有实际 PR 元数据时为 null；不得据此编造 PR','第二步提交适配层'),
        ('log_changes','censoring_reason','原逻辑的 history_incomplete 会由仓库任一 collect/mine 缺口触发，包含 binary；不能直接等同于 Git 提交图不完整','原 lineage.trace_logs 的仓库级缺口判断'),
        ('log_changes','integration_time_source / observation_start / observation_end','本次没有实际 PR 合并时间时保持 unknown/null；按原回退逻辑观察至采集截止，不构造统一 90 天窗口','原 lineage.trace_logs'),
        ('followups','phase','post_merge 是原字段命名；无 PR 元数据时表示目标分支后续提交，不证明发生了 PR 合并','原 trace_logs'),
        ('followups','relation','direct_call_change 与 dependency_change 分开；依赖变化可以不改变日志语句文本','原 detect_history'),
        ('followups','behavior_confidence','supported / possible 是日志沿袭匹配置信度，独立于 Agent 归因与动机状态','原 trace_logs'),
        ('followups','parent_sha / sha','真实 Git 父提交和本次修改提交；before/after 是两个提交的最终源码状态','冻结 Git 对象'),
        ('log_source_anchors','source_sha256 / git_blob_id','源码字节的 SHA256 和经 Git 对象核对的 blob ID','精确 SHA:path 的 git blob'),
        ('initial_source_anchor_audit','matches_stage1_committed_postimage','真实初始 Git 源码经 LF 规范化后，是否匹配至少一个第一步 committed_version 摘要','Git blob 与既有 log_alignment_evidence'),
        ('initial_source_anchor_audit','all_stage1_postimages_match_git','检查多个原始观测是否全部一致，不能用任一匹配掩盖版本冲突','Git blob 与既有 log_alignment_evidence'),
        ('log_modifications','event_id','本次运行内唯一的第二步事件行 ID；源行及上游 ID 均保留','第二步 followups 的路径、行号、上游 ID'),
        ('log_modifications','stage1_log_ids / stage1_attribution','回连第一步的 ID 和原归因证据等级；mixed 不自动升级','原 log_changes 与第一步候选'),
        ('log_modifications','observed_change','实际观察到的代码变化；不是对修改目的的陈述','已核验的 before/after 与 diff'),
        ('motive_evidence','source_type','仅 prompt / commit_message / pr_description / review_comment / issue','已读取的原始材料'),
        ('motive_evidence','source_subtype','区分行内评论、评审总结、PR 讨论、issue 讨论等命名空间','原材料类型'),
        ('motive_evidence','source_id / source_url / source_local_path / source_time','来源定位与时间；缺失时间明确标记，不补造','原 API 响应或本地原始表'),
        ('motive_evidence','text / excerpt','完整原文和必要摘录；截断标志单独记录','原材料'),
        ('evidence_links','association_method / association_basis','每个事件—证据关系独立保存，包含 SHA、PR、评论、checkpoint/session 等链路','精确对象关联，不以关键词或时间接近建立关联'),
        ('motives','motive_status','explicit / inferred / unknown / conflicting；缺失证据不删除事件','带原文引用和对应关系的结论审核'),
        ('motives','unknown_reason','区分材料不可用、已有材料但该日志目的尚未确认、同源解释分歧','证据与结论校验'),
        ('motives','human_validated','本次助手审核不是独立人工标注，保持 false','流程声明'),
    ]
    fields.extend([
        ('candidate_ledger','repo_id','owner/repository 形式的原始仓库标识，直接继承第一步；与追踪器内部 repository_id 不同','第一步 changed_logs.csv.repo_id'),
        ('candidate_ledger','commit_sha','第一步选定的初始提交 SHA；用于寻找追踪起点，不表示后续修改 SHA','第一步 changed_logs.csv.commit_sha'),
        ('candidate_ledger','path / start_line / end_line / callee','第一步候选路径、调用起止行和 callee 原值；原结果将其定位于提交后版本，是否匹配真实 Git 最终文件另见 initial_source_anchor_audit','第一步 changed_logs.csv；不把工具操作的中间状态替换进此列'),
        ('candidate_ledger','case_id / followup_ids','case_id 回连映射的追踪起点；followup_ids 是其实际修改关联 ID 列表，覆盖间隔不在该列表中','本次原追踪器输出及实际事件视图'),
        ('log_changes','repository / repository_id','repository 是 owner/repository；repository_id 是 stable_id(swechat_followup, repository) 生成的本次内部键','冻结仓库清单与 SWE-chat 输入适配层'),
        ('log_changes','case_id / stage1_log_ids','case_id 是追踪起点 ID；stage1_log_ids 保留该起点对应的全部第一步候选 ID，可能一对多','原 trace_logs 的 case_id 与本次精确初始锚点映射'),
        ('log_changes','before / after','初始追踪事件两侧的检测实体；statement/行号来自对应最终 Git 源码快照，某侧不存在时为 null；不是 prompt 或工具动作','原 detect_history 在 parent_sha / sha 上的检测结果'),
        ('followups','id / case_id / log_change_id','id 标识一条起点—后续事件关联；case_id 回连追踪起点；log_change_id 为原初始检测事件 ID','原 trace_logs 及 stable_id'),
        ('followups','repository_id','本次内部仓库键，可通过 repositories.jsonl 映射到 owner/repository','原检测/追踪输出的 repository_id'),
        ('followups','before / after / file_change_ids','before/after 为此次后续事件两侧实体；file_change_ids 回连文件变更及 diff。依赖变化的日志实体可位于未改文本的文件中，另用 Git 源码锚点核验','原 detect_history、trace_logs 与已隔离核验的 Git 文件变更'),
        ('log_source_anchors','repository_id / sha / path / source_locator','内部仓库键、精确提交和文件路径；source_locator 保存本地仓库位置及 SHA:path 定位字符串','冻结 Git 对象与 package_swechat_followups.py'),
        ('log_source_anchors','source','经过隔离检查的完整 Git 文件源码，属于指定 sha 的最终文件状态','git show SHA:path；不是 Agent 工具编辑中间状态'),
        ('initial_source_anchor_audit','log_id / repository / introduction_sha / file_path','逐条回连第一步候选以及其仓库、初始提交和路径','第一步 changed_logs.csv'),
        ('initial_source_anchor_audit','source_status','allowed 表示源码可读且通过隔离检查；其他值记录源码缺失或隔离限制','Git 对象读取与 Guard.check'),
        ('initial_source_anchor_audit','exact_line_statement_verified','第一步 statement 是否包含于真实 Git 文件指定行段；不代表 Agent 独占归因已经证明','真实初始 Git 文件与第一步 statement/start_line/end_line'),
        ('log_modifications','repository / modification_sha / parent_sha / introduction_sha','repository 是仓库名；modification_sha 是后续修改；parent_sha 是该事件比较父版本；introduction_sha 是第一步追踪锚点','第二步 repositories、followups 和 log_changes 精确外键关联'),
        ('log_modifications','file_path / old_path / new_path','事件路径及两侧实体路径；删除或新增的一侧可为空，重命名两侧分别保留','第二步 followups 的 file_path 和 before.path/after.path'),
        ('log_modifications','input_path / input_row / input_record_sha256','第二步 followups.jsonl 的绝对路径、从 1 开始的源文件行号及原记录内容摘要','normalize_trace 逐行读取；不是 conversations 的 turn_number'),
        ('log_modifications','upstream_event_id / upstream_case_id / upstream_confidence','保留第二步关联 ID、起点 ID 和 supported/possible 沿袭置信度；event_id 另按运行目录与源行生成','第二步 followups.id/case_id/behavior_confidence'),
        ('log_modifications','guard_status / source_anchors / diffs','guard_status 为可用性核验结果；source_anchors 保存 Git 定位摘要；diffs 保留原文件变化与比较 SHA，均不是目的判断','normalize_trace 的路径、SHA、行段、源码摘要及隔离检查'),
        ('motive_evidence','evidence_id / content_sha256','evidence_id 由来源类型、仓库、子类型、来源 ID 和正文摘要生成；content_sha256 是完整 text 摘要，不按关键词合并材料','EvidenceStore.add 的稳定摘要'),
        ('motive_evidence','repository','证据所关联日志修改的仓库；跨仓库 issue 的实际仓库另见 issue_repository','日志修改记录；issue_repository 来自材料中明确引用'),
        ('motive_evidence','source_locators / source_time_status / excerpt_truncated','同一正文的多个已读取定位和时间均保留；缺失时间显式标记；excerpt_truncated 表示摘录是否截断，完整 text 仍保存','原始本地表、Git 记录及实际 API 响应'),
        ('motive_evidence','session_id / checkpoint_pk / turn_id','prompt 的会话、checkpoint 和会话轮次标识；通过修改 SHA、同仓库 checkpoint 成员及用户会话轮次校验，不以时间相邻关联','commits.parquet、checkpoints.parquet、conversations.parquet'),
        ('motive_evidence','pr_number / issue_number / issue_repository / comment_id / reply_to_comment_id','可用时记录实际 PR、issue、评论及回复父评论标识；不同评论命名空间由 source_subtype 区分','精确提交关联 PR 接口、评论响应及材料中的明确 issue 引用'),
        ('evidence_links','link_id / event_id / evidence_id','每条可核查的事件—来源关联独立编号；多个方法可连接同一对事件和证据，不压为单一来源','EvidenceStore.add；摘要包含事件、证据、方法、依据及关系'),
        ('evidence_links','repository / modification_sha / file_path','每条关联均保留修改事件的仓库、后续 SHA 和日志文件路径；证据可供多个事件分别引用','对应 log_modifications 记录'),
        ('evidence_links','relation','区分一般修改上下文、修改会话上下文、PR 上下文、直接行位置等关联范围；关系本身不确定动机','Collector 和 collect_prompts 的已核验关联方式'),
        ('motives','stated_purposes / inferences / claims / motive_labels','明示目的、推断、带证据引用的审核条目和多标签分别保存；没有有效引用时维持 unknown','judge 对注释元数据、原文、事件关联和目标锚点的校验'),
        ('motives','purpose_review_status / annotation_disagreement','表示目的是否已建立及是否存在同一材料的对立解释；同源分歧需要裁决，不能冒称来源之间冲突','有效注释及 claim_key/position/证据集合比较'),
        ('unresolved_records','event_id / source_type / reason','未决项对应的事件、材料类型和具体原因；同一事件可能有多项缺口，行数不等于未知事件数','来源读取、关联、隔离或注释校验的逐项缺失回执'),
    ])
    table(dest,'field_dictionary',[dict(table=t,field=f,meaning=m,source=s) for t,f,m,s in fields],['table','field','meaning','source'])
    # Enumerate actual exported fields, without inventing definitions for inherited fields.
    from package_swechat_followups import readrows
    dictionary={(t,name.strip()):(m,origin) for t,group,m,origin in fields for name in group.split(' / ')}
    for inherited in ('log_modifications','motive_evidence','evidence_links','motives'):
        for (table_name,field_name),definition in list(dictionary.items()):
            if table_name==inherited:
                dictionary.setdefault(('modifications_with_evidence',field_name),definition)
    inventory=[]
    for directory,names in [(stage2,('candidate_ledger','log_changes','followups','coverage_intervals','log_source_anchors','initial_source_anchor_audit')),
                            (stage3,('log_modifications','motive_evidence','evidence_links','motives','modifications_with_evidence','unresolved_records'))]:
        for name in names:
            records=list(readrows(directory/(name+'.jsonl')))
            for key in sorted({k for r in records for k in r}):
                meaning,origin=dictionary.get((name,key),(None,None))
                inventory.append(dict(table=name,field=key,rows=len(records),
                    missing_key_rows=sum(key not in r for r in records),null_rows=sum(key in r and r[key] is None for r in records),
                    observed_json_types=sorted({type(r[key]).__name__ for r in records if key in r}),
                    definition_status='documented' if meaning else 'inherited_definition_not_individually_reviewed',
                    meaning=meaning,source=origin,input_table=str(directory/(name+'.jsonl'))))
    table(dest,'field_inventory',inventory,['table','field','rows','missing_key_rows','null_rows','observed_json_types','definition_status','meaning','source','input_table'])
    unresolved_definitions=[r for r in inventory if r['definition_status']!='documented']
    table(dest,'unresolved_field_definitions',unresolved_definitions,['table','field','definition_status','input_table'])
    legacy_path=ROOT/'outputs/swechat_motivation_20260921/delivery/audit/summary.json'
    legacy=json.loads(legacy_path.read_text(encoding='utf-8'))['legacy_population']
    dump(dest/'legacy_audit_reference.json',dict(source=str(legacy_path),source_sha256=file_hash(legacy_path),
        scope='Previously accepted audit; different grain from current candidates and modification events',
        rows=legacy['rows'],repositories=legacy['repositories'],observation_reference_rows=legacy['observation_reference_rows'],
        extraction_status=legacy['extraction_status'],duplicate_log_id_rows=legacy['duplicate_log_id_rows'],
        duplicate_locator_rows=legacy['duplicate_locator_rows'],same_source_repeated_rows_not_deleted=legacy['same_source_repeated_rows_not_deleted']))
    source_types=[
        dict(source_type='prompt',chain='修改 SHA → 同仓库 commits/checkpoint 双向成员校验 → session → 对应 checkpoint 的用户会话轮次',scope='修改会话上下文；目的和操作先后顺序需另外验证'),
        dict(source_type='commit_message',chain='修改 SHA → 本地 Git 提交或精确 SHA 的 API/Parquet 记录',scope='提交级材料；需要说明与该日志修改的具体对应关系'),
        dict(source_type='pr_description',chain='修改 SHA → commit/pulls 接口 → 同仓库 PR → 标题和正文',scope='PR 上下文；不能自动视作每条日志的目的'),
        dict(source_type='review_comment',chain='修改 SHA → PR → 行内评论、评审总结或 PR 讨论；行内评论另查路径、版本和行号',scope='直接位置对应与一般 PR 上下文分别保留'),
        dict(source_type='issue',chain='已关联提交/PR/评论中的明确 issue 引用 → issue 正文和讨论',scope='明确引用链，不以关键词或时间接近建立关联'),
    ]
    table(dest,'source_types',source_types,['source_type','chain','scope'])
    from package_swechat_followups import readrows
    audit=list(readrows(stage2/'initial_source_anchor_audit.jsonl'))
    issues=[
        dict(issue='repository_level_mining_gap_censoring',affected_records=a['censored_by_repository_mining_gaps_candidates'],unit='初始候选',category='existing_logic_interpretation',impact='原逻辑把仓库任一采集/挖掘缺口（含二进制文件）传播为 history_incomplete，不等于每条日志的提交历史均缺失',recommendation='保留当前标记；后续单独评估区分提交图、相关源码与无关文件缺口的影响，不在本次修改前两步'),
        dict(issue='real_integration_time_unknown',affected_records=a['unknown_integration_time_origins'],unit='映射的日志起点',category='observation_window_unknown',impact='缺少真实 PR 合并时间，原逻辑回退到冻结目标历史；不是统一 90 天可观察样本',recommendation='比较修改比例时说明不同观察窗；第三步取得的 PR 元数据不回写本次第二步筛选'),
        dict(issue='initial_git_source_unavailable_or_guarded',affected_records=sum(r['source_status']!='allowed' for r in audit),unit='初始候选',category='source_missing',impact='不能核验该候选的真实初始源码',recommendation='按逐条原因补历史或保留隔离；不计作无更改'),
        dict(issue='stage1_postimage_does_not_match_git',affected_records=sum(r.get('matches_stage1_committed_postimage') is False for r in audit),unit='初始候选',category='source_version_mismatch',impact='已有 committed_version 不能直接当作真实初始 Git 文件',recommendation='复核原始行、SHA 和版本；本次不改变前两步口径'),
        dict(issue='stage1_postimage_variants_disagree',affected_records=sum(r.get('matches_stage1_committed_postimage') is True and r.get('all_stage1_postimages_match_git') is False for r in audit),unit='初始候选',category='source_version_conflict',impact='至少一个观测匹配，但存在其他不一致版本',recommendation='保留各观测来源，不能用任一匹配掩盖其他冲突'),
        dict(issue='only_possible_followup_links',affected_records=a['changed_candidates_with_possible_links_only'],unit='初始候选',category='association_uncertain',impact='存在后续变化，但与初始日志的沿袭关系仍有歧义',recommendation='单列 possible 并优先人工核对；不反向升级 Agent 归因'),
        dict(issue='unknown_modification_motive',affected_records=b['motive_distribution']['unknown'],unit='修改关联记录',category='purpose_unknown',impact='尚未取得足够支持该条日志目的的证据或尚未完成目的审核',recommendation='按 unknown_reason 区分材料缺失与已有上下文待确认；保留全部记录'),
    ]
    table(dest,'issues_and_impact',issues,['issue','affected_records','unit','category','impact','recommendation'])
    coverage='\n'.join(f"| {k} | {v['events']} | {v['denominator']} | {pct(v['fraction'])} |" for k,v in b['source_coverage'].items())
    distribution='、'.join(f"{k}：{v}" for k,v in b['motive_distribution'].items())
    readme=f'''# SWE-chat 第二步真实运行与第三步主数据交付

本报告只引用本次已经生成的结果。第一步原始数据、筛选结果及归因等级未覆盖。第二步沿用项目的矿取、检测、匹配和追踪规则；增量层只处理 SWE-chat 输入映射、平台路径、隔离、存储与重复计算。歧义候选索引沿用原 before-key OR after-key 判断，并保持候选顺序和重复项；不新增人工匹配，不改变筛选准入。

## 已执行范围与数量

- 第一阶段沿用 {a['stage1_input_file_units']:,} 个文件提交单元，既有日志候选为 {a['stage1_output_log_candidates']:,} 条，涉及 {a['stage1_output_log_file_units']:,} 个文件提交单元。文件单元筛选比例为 {pct(a['stage1_log_file_fraction'])}。不同粒度不相除。
- 第二阶段输入 {a['stage2_input_candidates']:,} 条候选；其中 {a['initial_logs_with_followups']:,} 条观察到后续事件，比例 {pct(a['stage2_changed_candidate_fraction'])}。
- 在观察到事件的候选中，{a['changed_candidates_with_supported_link']:,} 条至少有一项 supported 沿袭关联，{a['changed_candidates_with_possible_links_only']:,} 条只有 possible 关联。后者保留原筛选口径，但不宣称沿袭关系已经确定。
- 第二步映射到真实历史锚点的候选为 {a['mapped_candidates']:,} 条。未能映射的候选仍在总分母和处理账本中保留。
- 第二步输出 {a['stage2_event_links']:,} 条“初始日志—后续修改”关联，对应 {a['stage2_unique_modification_events']:,} 个去重后的修改事件。另有 {a['coverage_intervals']:,} 条覆盖中断/恢复记录，单独保存，不当作已经确定发生的日志修改送入第三步。
- 第三步处理 {b['events']:,} 条第二步输入，得到 {b['evidence_rows']:,} 项证据、{b['links']:,} 条证据关联。证据缺失的输入仍保留。
- 动机状态：{distribution}。

仓库处理状态：`{json.dumps(a['repository_status'],ensure_ascii=False)}`。候选处理状态：`{json.dumps(a['candidate_status'],ensure_ascii=False)}`。变化类型：`{json.dumps(a['event_relation'],ensure_ascii=False)}`。沿袭置信度：`{json.dumps(a['event_confidence'],ensure_ascii=False)}`。

第一步 committed_version 与真实初始 Git 源码完成比较 {a['stage1_postimage_compared']:,} 条，其中至少一个观测版本匹配的有 {a['stage1_postimage_matches']:,} 条。这是来源核验，不改变前两步的筛选规则；多版本不一致记录另见逐条账本。

既有只读核验确认历史集合为 {legacy['rows']:,} 个日志版本、{legacy['repositories']} 个仓库、{legacy['observation_reference_rows']:,} 条观察引用。提取状态 completed 为 {legacy['extraction_status']['completed']:,}（60.71%），partial 为 {legacy['extraction_status']['partial']:,}（39.29%）；这两个比例不是来源、含义或修改动机查明率。日志版本 ID 无重复；粗定位键有 {legacy['duplicate_locator_rows']:,} 条超出首条，同源辅助键有 {legacy['same_source_repeated_rows_not_deleted']:,} 条超出首条，均未擅自去重。该集合与这里的 4,128 条候选粒度和范围不同，不串为同一个漏斗。原核验来源及摘要见 `legacy_audit_reference.json`；此前按开发范围列出的语义、对象成员、包装器映射、扫描预算等未决原因仍保留在原交付中。

## 数据表

- `../stage2/candidate_ledger.csv`：全部第一步候选的处理状态、原归因、后续事件 ID。
- `../stage2/raw_followups.jsonl`：原追踪器全部后续记录，包含覆盖间隔，完整保留。
- `../stage2/followups.csv`：真实后续修改视图；覆盖间隔另存，不删除原记录。
- `../stage2/coverage_intervals.jsonl`：覆盖中断和恢复，不能解释为确定删除或修改。
- `../stage2/initial_source_anchor_audit.jsonl`：第一步源码是否与真实初始 Git 提交一致。
- `../{stage3.name}/log_modifications.csv`：第三步日志修改记录，保留第一步 ID 和归因。
- `../{stage3.name}/motive_evidence.csv`：每项原始证据独立保存。
- `../{stage3.name}/evidence_links.csv`：可核查的事件—证据关联链。
- `../{stage3.name}/modifications_with_evidence.csv`：保留无证据事件的关联结果。
- `../{stage3.name}/motives.csv`：观察、明示目的、推断与 unknown/conflicting 分开。
- `../{stage3.name}/unresolved_records.csv`：缺失来源、来源校验失败及注释错误。
- `field_dictionary.csv`、`stage_counts.csv`：已核实的字段来源与阶段数量口径。
- `field_inventory.csv`：实际导出字段、JSON 类型、空值和缺键数量；`unresolved_field_definitions.csv` 明确列出尚未逐项核验定义的继承字段，不把这些字段数解释成 39.29% 的日志数。
- `issues_and_impact.csv`：本次核验发现的问题、实际影响范围和后续建议；未擅自调整筛选口径。

## 各来源证据覆盖

分母是第二步输入的修改关联记录，同一修改可有多个来源。能关联到材料不等于已经明确该条日志的修改目的。

| 来源 | 覆盖输入记录 | 分母 | 比例 |
|---|---:|---:|---:|
{coverage}

PR 行内评论的 `side` 和 `line` 属于 PR diff 的位置定义，详见 [GitHub 官方接口说明](https://docs.github.com/en/rest/pulls/comments)。本实现据此保守处理：仅在 RIGHT 侧、源码版本、对应版本的文件路径与行号均匹配时标记直接位置对应；LEFT 侧的比较基线未独立核验时保留为文件上下文，跨侧多行范围不混合成同一版本区间。此限制不删除评论或修改记录。

## 原追踪边界与缺失处理

目标分支与 tip 在各仓库采集回执中冻结。保留原追踪器的目标分支第一父链规则、歧义匹配规则及无确切整合时间时不计算精确时延的规则。不用提交时间冒充 PR 合并时间；`post_merge` 的兼容字段也不表示已经证明有 PR 合并。

本次有 {a['unknown_integration_time_origins']:,} 个映射起点的整合时间来源为 unknown。按原回退逻辑，观察到冻结目标历史的采集截止；并未把这些记录构造成统一的 90 天观察窗。因此本次比例不能直接解释为“90 天内修改率”。

原追踪器还会把仓库中任意 collect/mine 缺口（包括二进制文件无法作为源码读取）传播为 `history_incomplete`。共有 {a['censored_by_repository_mining_gaps_candidates']:,} 条候选带有这一 censoring_reason。该标记不一定表示 Git 提交图缺失，也不一定意味着该日志文件本身不可读。本次原样保留，并在 `issues_and_impact.csv` 单列这一既有逻辑的影响。

没有实际 PR 元数据时，每个初始提交建立提交上下文，PR 号与 URL 保持空值。第三步新取得的 PR/issue 材料只用于证据关联，不回写前两步准入条件。

仓库不可访问、初始祖先缺失、源码/解析/预算缺口、独立评估隔离均有记录。`no_observed_followup` 只描述本次可观察范围，不代表所有分支和全部未来历史都没有修改。`history_incomplete` 也不能当作无更改。

第一步日志识别状态为 `{json.dumps(a['stage1_log_detection_status'],ensure_ascii=False)}`。这些是既有候选，不能将全部记录宣称为已确认日志。日志识别状态、Agent 来源归因、后续沿袭置信度、修改动机状态是四个独立维度。

`intro_sha` / `introduction_sha` 表示本次追踪起点。第一步包含新增日志和修改已有日志的候选，因此不能把所有起点都表述为日志历史上的首次出现。

初始日志的 `attribution_grade` 与 `mixed` 文件标签原样保留。找到后续修改或动机证据不会反向证明初始日志一定由 Agent 独占引入。后续修改者没有品牌或作者过滤。

`dependency_change` 包含日志参数或其他受跟踪依赖的改变，日志语句文本可能相同。它与直接调用文本修改分别统计，不能合并宣称为日志文本修改数。

## 去重与验证

第一步不删重、不改 ID。第二步保留每条初始日志的后续链；相同物理修改与多个初始日志关联时，关联数与唯一事件数分别给出。第三步按来源类型、评论命名空间、仓库、来源 ID 和内容摘要去重证据，不丢失多对多关联。不同版本的原文保留为不同证据。

第二步包含 {a['stage2_trace_origins']:,} 个追踪起点；其中 {a['origins_with_multiple_stage1_ids']:,} 个对应多个第一步候选 ID。按第一步候选展开的“候选—后续事件”对共有 {a['stage2_candidate_event_pairs']:,} 条；主要修改表的 {a['stage2_event_links']:,} 行则按追踪起点关联计数。两种粒度分开保存，不靠去重丢弃第一步 ID。

第二步唯一事件键为 `(repository_id, sha, parent_sha, file_path, before.start_line, after.start_line, entity_fingerprint, change_kind)`。这是追踪器事件的去重口径，不能当作独立日志语句数。第三步各来源覆盖率的分母则是全部修改关联记录，已在覆盖表中明确列出。

第二步对账与祖先链验证：{cv['status']}。第三步保留行数、关联外键与无证据事件校验：{mv['status']}。单元/边界测试记录见 `../verification/`，真实平台源码对比见 `../platform-verification/mining_equivalence.json`，独立导出对账见 `../{stage3.name}_independent_validation.json`，原始文件最终摘要核验见 `../verification/parent_integrity_after_main.json`（运行前核验另存 `../verification/parent_integrity_before_resume_delivery.json`）；独立封存评估没有运行。

真实开发快照的缓存等价性检查另见 `../verification/actual_python_cache_oracle.json`：逐文件及调用族通过隔离检查的 3 个小型快照、52 个检测实体，在原检测器与缓存版本中的完整输出一致。该结果不表示全量识别正确率，也不是封存评估。

本次剩余两仓库使用按实际 import 访问建立键的缓存，验证记录见 `../verification/actual_accessed_import_cache_oracle.json` 及 `../verification/cache_equivalence_scope.md`。追踪阶段另以共享只读列表保存同一仓库的缺口记录，避免对每个起点重复复制；原过滤谓词、顺序、重复项和最终输出内容均保持不变。共享缺口适配层的 4 项合成历史完整输出等价测试见 `../verification/lineage_gap_storage_equivalence.json`，实现摘要见 `../verification/shared_gap_runtime_implementation.json`。这些验证只证明列明样例上的等价性；主数据验收另以各阶段 validation 与独立对账为准。每仓库实际运行统计保存在其 history_scope.json 中。进程中断及独立启动核验见 `../verification/independent_process_launch.md`；中断尝试的全部既有文件保留，最终计数只使用通过验收并选用的完整结果。

加速验证使用构造的 Git 分支样例，核对完整文件记录及 ID、提交元数据、源码/diff、非目标分支初始提交和源引用不变。记录见 `../verification/native_git_mirror_alternates_oracle.txt`。该检查使用 Linux Python 直接断言执行；Linux pytest 因缺少 exceptiongroup 未启动，不计作 pytest 通过。实际使用临时对象副本的新任务也核对了冻结提交图；源码分析和隔离检查仍使用项目规定的研究 Python。

## 运行方式

使用项目规定的研究 Python，执行 `scripts/swechat_stage2_then_stage3.py --output-root <新的输出目录>`。默认读取远程材料；`--offline-evidence` 仅改变第三步外部证据的获取方式。新输出目录是防止覆盖旧结果的必要约束。

复现本次第三步时，使用本次 `stage2` 输出与已保存的外部成功缓存、失败回执，并指定新的输出目录：

```text
<研究 Python> scripts/agent_log_motivation_v11.py --workspace . --trace-run outputs/swechat_followup_20260922/stage2 --output <新的第三步输出目录> --swechat-frozen data/cache/swechat-frozen --external-cache <本次已采集的 external_cache 目录> --external-failures <本次连接器 failures 目录>
```

存在审核注释时，同时传入 `--annotations <注释 JSONL 路径>`。该重放使用已经取得的材料；重新联网采集可能读到已编辑的 PR/issue 正文。原始响应及注释输入的摘要保存在第三步 provenance 中。完整三阶段重新采集也可能冻结到新的目标 tip，不能宣称与本次观察窗口相同。

本次通过同一组组件分步执行，并未为验证统一入口而额外重跑第二套全量数据。源码与已有采集回执可复用；所有完成数量以结果表和 manifest 为准。

后续建议：优先复核 `anchor_not_observed`、不可访问历史和 `possible` 沿袭，再审核已有材料但尚未确认目的的 unknown 记录。这些是后续工作建议，不是本次已完成的人工标注或独立准确率评估。
'''
    (dest/'README.md').write_text(readme,encoding='utf-8')
    dump(dest/'manifest.json',dict(artifacts={p.name:file_hash(p) for p in dest.iterdir() if p.is_file()},
        stage2_manifest_sha256=file_hash(stage2/'manifest.json'),stage3_manifest_sha256=file_hash(stage3/'manifest.json')))
    print(dest,flush=True)

if __name__=='__main__':main()
