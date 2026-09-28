"""Package audited results and documentation; write only a new delivery directory."""
from pathlib import Path
import argparse
import json
import shutil
from agent_log_motivation import rows, table, write_json, file_hash, EvidenceStore, export, digest


def package(root):
    root=Path(root).resolve();w=Path(__file__).resolve().parents[1]
    out=root/'delivery';out.mkdir(exist_ok=False)
    audit=json.loads((root/'audit_verified/summary.json').read_text(encoding='utf-8'))
    calibration=json.loads((root/'calibration_delivery/summary.json').read_text(encoding='utf-8'))
    scope=json.loads((w/'outputs/swechat_agent_scope_20260919/final/summary.json').read_text(encoding='utf-8'))
    alignment=json.loads((w/'outputs/swechat_log_alignment_20260921/final/report_summary.json').read_text(encoding='utf-8'))
    pop=audit['legacy_population']
    stages=[
        dict(scope='legacy_dataset_commit_changes',stage='input_commits',input_count=8697,output_count=8387,unit='repository+SHA',fraction=8387/8697,meaning='实际读取数据集提交；不是Agent逐行归因或完整后续历史'),
        dict(scope='legacy_dataset_commit_changes',stage='historical_log_versions',input_count=25627,output_count=24685,unit='observation_reference_to_log_version',fraction=None,meaning='两个不同粒度，不计算筛选率；观察引用全部保留'),
        dict(scope='current_combined_scope',stage='stage1_file_scope',input_count=scope['file_units_repo_commit_path'],output_count=scope['main_code_files'],unit='repository+commit+path',fraction=scope['main_code_files']/scope['file_units_repo_commit_path'],meaning='既有会话、文件归因、工具路径筛选；包含非代码文件的上游文件分母'),
        dict(scope='current_combined_scope',stage='stage1_files_with_changed_logs',input_count=10767,output_count=805,unit='repository+commit+path',fraction=805/10767,meaning='整个输入范围内已检测到候选的文件比例；含1896隔离/不可核查、103未对齐，不能当检测召回率'),
        dict(scope='current_combined_scope',stage='stage1_log_candidates',input_count=10767,output_count=4128,unit='file_to_changed_log_candidate',fraction=None,meaning='首次选定提交patch的日志候选，非后续修改事件；保留856强对齐及其余证据等级'),
        dict(scope='current_swechat',stage='stage2_subsequent_changes',input_count=4128,output_count=None,unit='log_candidate_to_later_modification_event',fraction=None,meaning='未找到与该父范围对应的既有第二步输出；不能生成零修改结论'),
        dict(scope='current_swechat',stage='stage3_motive_evidence',input_count=None,output_count=None,unit='later_modification_event',fraction=None,meaning='代码和空表接口已交付，主总体实际处理待第二步产物'),
        dict(scope='separate_calibration_only',stage='existing_stage2',input_count=44,output_count=1,unit='initial_log_change',fraction=1/44,meaning='原真实校准运行，非SWE-chat主范围；1个possible后续事件'),
        dict(scope='separate_calibration_only',stage='stage3_retention',input_count=1,output_count=1,unit='later_modification_event',fraction=1.0,meaning='实际采集9条证据、10条关联；保留原possible匹配')]
    table(out,'stage_counts',stages,['scope','stage','input_count','output_count','unit','fraction','meaning'])
    definitions={
        'log_version_id':('历史日志版本','原batch观察→type_audit聚合→字段视图','既有去重ID；多个before/after观察引用可指向同一版本；不等于工具操作或修改事件'),
        'observation_ids':('观察引用集合','原log_observations.id','原观察引用，保留25627个，不重复算独立日志'),
        'observation_references':('观察引用集合','freeze.py由原log_observations映射','含dataset_sha、side、变化依据；一个版本可为一次提交after及另一次提交before'),
        'repository':('仓库定位','原SWE-chat repo_id，经原导入上下文保留','历史原仓库名；不按当前GitHub名称静默覆盖'),
        'resolved_repository':('源码获取定位','既有源码恢复记录','实际获取仓库名；原repository另存'),
        'snapshot_sha':('历史源码版本','原观察snapshot_sha','before为父源码版本，after为事件提交；不自动等于修改提交SHA'),
        'path':('仓库内文件路径','Git文件变化或既有历史实体','绑定snapshot_sha的历史路径'),
        'start_line':('源码位置','原detector/历史定位','一基起始行；单独行号不是稳定日志ID'),
        'end_line':('源码位置','原detector/历史定位','一基结束行，闭区间'),
        'source_sha256':('历史源文件','既有冻结源码字节哈希','文件内容SHA256，不能与提交SHA或语句哈希混用'),
        'git_blob_id':('Git源码对象','既有Git blob读取','Git blob身份，不是提交SHA'),
        'target_statement_safe':('日志语句展示','既有脱敏导出','展示文本可能含<literal>；不能作为完整原文'),
        'target_statement_sha256':('目标语句','既有历史源码解析','目标语句哈希'),
        'original_statement_record_sha256':('旧语句记录','旧表语句记录','与目标语句哈希分别保存，旧导出可能已有脱敏'),
        'status':('提取状态','current_log_coverage.jsonl','completed/partial；不表示语义查明、Agent作者查明或修改动机查明'),
        'gaps':('提取/解释缺口集合','既有提取器和叠加补证','保留旧原因码；部分后续补证未回写状态'),
        'agent_attribution':('归因判断','既有字段视图','旧视图unverified；不能因SWE-chat会话关联而升级逐行作者'),
        'field_occurrence_id':('字段出现','字段提取器，含分析身份','每历史日志、参数/成员、源码位置的字段出现；非不同字段名'),
        'count_in_field_summary':('计数控制','既有字段提取器','true计入字段出现，已展开父容器false避免重复计数'),
        'parent_field_occurrence_id':('字段层级','既有容器展开','指向父容器；不代表Git父提交'),
        'language_type':('编程类型','既有字段语法/类型证据','null/空值按unknown统计；不是敏感类别'),
        'semantic_labels':('信息语义标签','既有字段证据规则','多标签及证据等级；不是修改动机'),
        'source_and_purpose':('输出值来源/用途','字段分析','描述被输出值的来源用途，不是修改日志的目的'),
        'meaning':('字段含义','字段分析','可能明确写含义尚未确定；completed不保证meaning已知'),
        'unresolved':('字段缺口集合','字段分析','语义、对象成员、绑定、输出条件等缺口；非同一原因'),
        'actual_runtime':('运行验证','既有字段视图','unverified不等于未运行或已运行'),
        'actual_exposure':('暴露验证','既有字段视图','unverified；不能从源码推出实际泄露'),
        'analysis_signature':('分析身份','原提取代码/配置/输入摘要','混合视图逐记录保留6个有效分析身份'),
        'followup_rule_version':('研究补证规则版本','旧字段补证实现','followup在此指研究补证，不等于Git后续日志修改'),
        'same_source_log_key':('源码同源辅助分组','既有字段视图','不等于跨提交日志谱系；不能直接据此删除记录'),
        'same_source_field_key':('字段同源辅助分组','既有字段视图','同源关系保留，未改变旧计数'),
        'cross_version_relation_key':('跨版本辅助定位','既有字段视图','辅助键，不证明版本等价或Git祖先关系'),
        'github_source':('来源定位','旧历史源码定位','历史记录中的链接；本轮未逐一网络验证'),
        'local_evidence_file':('本地历史源码定位','旧源码恢复/冻结','可能是迁移前路径；本轮未逐文件校验所有压缩源码')}
    dictionary=[]
    schema=json.loads((root/'audit_verified/observed_schema_keys.json').read_text(encoding='utf-8'))
    for kind,keys in schema.items():
        for key in keys:
            known=key in definitions
            grain,source,meaning=definitions.get(key,('继承字段','现有'+kind+'视图','已识别列名；本轮未逐项复核其完整生成逻辑，保持原值，不猜测业务含义'))
            dictionary.append(dict(table=kind,field=key,grain=grain,source=source,definition=meaning,
                                   definition_status='verified_against_code_or_existing_dictionary' if known else 'carried_forward_not_reaudited'))
    new_defs={
        'event_id':'本轮一条上游行的稳定ID：输入路径、行号、上游ID摘要；上游重复行保留',
        'upstream_event_id':'原followups.id，保持原值', 'upstream_case_id':'原case_id，关联引入事件',
        'modification_sha':'原followup_sha或sha：本次后续修改提交', 'introduction_sha':'原case关联intro_sha或sha',
        'parent_sha':'后续修改比较父提交；非最初引入SHA', 'file_path':'原后续修改文件路径',
        'observed_change':'旧追踪观察的before/after语句、位置及级别，不是动机',
        'upstream_confidence':'原behavior_confidence；possible不升级为supported',
        'upstream_attribution':'原cohort、作者类型及置信度，保留unknown/mixed',
        'guard_status':'历史完整源码经原guard核查；blocked记录匿名保留',
        'diffs':'原file_changes差异及diff_basis_sha/diff_target_sha，校验后引用',
        'evidence_id':'source_type、仓库、source_id和原文哈希；同源更新保留不同版本',
        'source_type':'prompt/commit_message/pr_description/review_comment/issue',
        'source_id':'原turn、SHA、PR、评审或issue/评论ID',
        'source_url':'实际API返回的来源链接；缺失为null，不编造链接',
        'source_local_path':'本地表或成功响应缓存路径；结合来源ID或basis中的行号复查',
        'source_locators':'同内容各次可核查来源位置，保留本地与远程来源',
        'source_time':'原时间字段；没有时间则null并记录状态',
        'text':'必要研究材料的本地原文副本；不当作指令执行',
        'excerpt':'原文前2000字符便于浏览；结论citation另存实际支持目的的精确引文',
        'content_sha256':'原文摘要；评论更新按内容版本区分',
        'link_id':'事件、证据、关联方法/依据及关系的摘要',
        'association_method':'确定性的SHA/PR/行位置/checkpoint-session关联方法',
        'association_basis':'关联链、响应SHA、行位置、原表行号或明确引用，不能用关键词/时间相似替代',
        'relation':'direct_log_location/direct_parent_log_location、同文件/PR/会话上下文等',
        'session_id':'原会话ID，仅同仓库同checkpoint证据关联',
        'checkpoint_pk':'原commits/checkpoints/conversations一致的checkpoint主键',
        'pr_number':'commit→PR关联API返回PR号；不是从时间推测',
        'issue_number':'可核查说明材料明确引用并取回确认的issue号',
        'comment_id':'原评论或评审ID，与source_subtype共同解释',
        'motive_status':'explicit/inferred/unknown/conflicting，逐事件保留',
        'motive_labels':'依据有效证据的多标签；不足为unknown',
        'stated_purposes':'材料明确目的；与推断分开，引用不可伪造',
        'inferences':'证据支持但未直接确认的推断',
        'claims':'逐条判断、annotator、理由、目标定位和精确原文引用；不冒充人类标签',
        'reason':'具体缺失或未解析原因；包括HTTP状态、无会话、空正文、隔离、输入冲突'}
    dictionary += [dict(table='stage3',field=k,grain='按对应表定义',source='agent_log_motivation.py增量适配',definition=v,definition_status='implemented_and_tested') for k,v in new_defs.items()]
    table(out,'field_dictionary',dictionary,['table','field','grain','source','definition','definition_status'])
    table(out,'unresolved_field_definitions',[r for r in dictionary if r['definition_status']=='carried_forward_not_reaudited'],['table','field','definition'])
    source_types=[
        ('prompt','conversations中user且is_conversational=True且无tool_name','repo+修改SHA→commit/checkpoint相互包含→session_pks→同checkpoint会话turn','仅修改会话上下文，未证明指令执行顺序；最初prompt不得直接解释本次动机'),
        ('commit_message','原commits导出、commits.parquet或GitHub exact commit响应','同仓库完整SHA','同一提交可能修改多处；通用提交消息不能自动explicit'),
        ('pr_description','PR标题与正文','修改SHA→GitHub commits/{sha}/pulls→PR','PR全局目的与单条日志目的分开'),
        ('review_comment','行内评论、评审总结和PR普通讨论','修改SHA→PR→评论；精确revision/path/行范围可加强对应','总结默认PR上下文；回复保留in_reply_to_id；旧版本行号不强贴新版本'),
        ('issue','issue正文与讨论','已关联commit/PR/评论中的明确#引用或issueURL→GET确认','显式引用不自动表示因果/关闭关系；若返回pull_request则不冒称issue')]
    table(out,'source_types',[dict(source_type=t,content=c,association=a,limit=l) for t,c,a,l in source_types],['source_type','content','association','limit'])
    for directory in ['swechat_stage3_final','calibration_delivery']:
        shutil.copytree(root/directory,out/directory)
    shutil.copytree(root/'audit_verified',out/'audit')
    shutil.copy2(root/'development_guard.json',out/'development_guard.json')
    shutil.copy2(root/'regression_tests.txt',out/'regression_tests.txt')
    code=out/'code';code.mkdir()
    for name in ['agent_log_motivation.py','audit_swechat_motivation_inputs.py','package_swechat_motivation_delivery.py','test_agent_log_motivation.py','test_agent_log_motivation_io.py']:
        shutil.copy2(w/'scripts'/name,code/name)
    # Human-readable real example, with no promotion of its parent attribution.
    event=next(r for _,r in rows(root/'calibration_delivery/log_modifications.jsonl'))
    (out/'可追溯样例.md').write_text('''# 已执行的真实校准样例

此例来自 `outputs/runs/real-types-v030`，cohort=calibration_only，Agent作者unknown，日志实体匹配possible。**不是SWE-chat主总体的样本，也不用于估计主总体比例。**

1. 原始引入case：`4b2e04f89e47e3a8fba725ed`；引入SHA：`22bd1714fc628db2b0a369f65d138167bb59e0a9`。
2. 原始后续事件：`c54878eb18e991169b160239`；后续SHA：`c04d235e0dd68601b7db88dfbdcb484c92690b69`；路径：`kova-ai/app/api/webhooks.py`。
3. 旧追踪把 `logger.error(f"Webhook error: {e}")` 标为deleted，before第288行，after实体为空；原diff同时出现 `logger.exception("Unexpected GitHub webhook error")`。本轮保持原deleted/possible，不改配对。
4. 本地 `commits.jsonl` 消息为 `fix: address webhook security review`。GitHub精确SHA关联API返回 [PR #88](https://github.com/Kathrynhiggs21/Kova-ai-SYSTEM/pull/88)。PR描述提到服务端记录异常并返回通用500响应。
5. [原行内评审](https://github.com/Kathrynhiggs21/Kova-ai-SYSTEM/pull/88#discussion_r3901353725) 原文：`Prefer logging the exception with a stack trace and returning a generic 500 detail.`
6. [修改者回复](https://github.com/Kathrynhiggs21/Kova-ai-SYSTEM/pull/88#discussion_r3901458486) 点名c04d235，并写明 `unexpected exceptions are logged with a stack trace`。回复ID、父评论ID及行/版本元数据在关联表保存。
7. 结论：`inferred`，标签`diagnostics`。推断这次日志变化落实了保留异常堆栈的诊断要求；原日志实体关系尚不确定，因此不提升为explicit。返回通用HTTP错误的安全目的，不等于日志里敏感值已被移除。

证据表9行、关联表10行：同一提交消息分别由本地与远程验证，保留两条关联；证据内容去重为一项。PR全局讨论中的其他文件建议只作上下文。未取回的PR普通讨论及#90引用在首次网络运行返回HTTP403；后续离线复核显示cache miss，原在线失败另存，不据此断言不存在讨论或issue。空评审正文也记录缺失。该修改提交未在本地SWE-chat会话关联中找到有效prompt。

数据文件：[修改事件](calibration_delivery/log_modifications.jsonl)、[证据](calibration_delivery/motive_evidence.jsonl)、[关联链](calibration_delivery/evidence_links.jsonl)、[动机与精确引文](calibration_delivery/motives.jsonl)。

`explicit`、`unknown`、`conflicting` 的处理用自有合成夹具验证，未将它们伪装为真实研究样本；测试覆盖完整commit→PR→review→issue正文/讨论链及prompt关联，见回归记录和测试代码。
''',encoding='utf-8')
    report=f'''# Agent日志三阶段流程：核验与增量交付

**已完成现有数据核验、第三步增量实现、61项回归测试和独立真实校准。SWE-chat主总体的第二步产物尚未找到，因此不能声称这批数据已跑通三阶段，也不能报告其后续修改率或动机分布。**

当前入口仅为本目录。旧原始数据、筛选结果、原追踪逻辑均保留；新增代码位于项目`scripts/`，本目录`code/`为交付快照。前面的audit/audit_final为本轮中间检查，包含已修正的状态枚举/空值统计读取；不引用其统计。没有修改远程资源、发布评论、运行目标业务或启封独立样本。

## 1. 研究现状核验

| 项目 | 实际核验结果 | 正确含义 |
|---|---:|---|
| 历史日志版本 | 24,685，93个仓库 | 固定已观察集合，不等于已确认Agent引入的24,685条日志 |
| 观察引用 | 25,627 | before/after及重复观察引用全部保留 |
| 提取completed | 14,986（60.71%） | 提取状态，不是来源/意义/动机查明率 |
| 提取partial | 9,699（39.29%） | 一个日志可含多个未解决问题 |
| 字段记录 | 48,683 | 含1,291条不重复计数的父容器 |
| 可计数字段出现 | 47,392 | 编程类型未知25,114（53.0%）；并非日志条数 |
| 主键重复 | 日志ID 0；字段ID 0 | 未重写原去重口径 |
| 粗定位重复 | 402条超出首条 | 粗键缺少原实体identity/symbol/列位置，不能擅自删去 |
| 同源辅助键重复 | 4,944条超出首条 | 不是同一提交事件；跨版本同源不能直接去重 |

对所有ID集合及来源引用进行只读对账，原版本ID与当前视图完全相等，观察ID完全相等，当前文件/覆盖视图摘要与最后验收的叠加视图匹配。`audit/input_integrity.json`记录输入哈希及执行前后不变检查。

公开guard验证23,533条开发记录通过。1,152条受保护记录未展开内容/身份。开发范围内有18,775条日志含`semantic_type_undetermined`字段，其中12,969条日志的提取状态仍为completed；这直接说明60.7%不能解释为“来源和含义全部查明”。开发记录的仓库、SHA、路径、source hash、Git blob、观察引用等已检查定位字段空缺数为0；这不代表每一个迁移前本地路径仍可打开或每一个外部链接仍可访问。

39.3%并非统一的“字段来源缺失”。开发范围中的既有日志缺口包括对象成员/语义未解析4,323条、包装器实参到输出映射未解析2,413条、上下文属性存在/初始化未验证1,239条、定义扫描预算1,078条、AST节点预算660条等，类别重叠。字段含义不清、类型未定、归因未证实与修改动机缺失是四个不同维度，未相加成一个完成率。明细见[核验汇总](audit/summary.json)及[逐条开发记录台账](audit/unresolved_legacy_logs.csv)。

## 2. 现有实现对应三阶段

| 环节 | 既有实现/结果 | 本轮处理 |
|---|---|---|
| 历史候选底座 | `swechat-full-risk-20260912/run_full.py→batch_mine`；`type_audit.py`按历史日志版本聚合 | 核验24,685和25,627；其scope是dataset_commit_changes，full_history_tracing_completed=false |
| 第一步范围 | `outputs/swechat_agent_scope_20260919/final`；会话关联、file_attribution、agent_changes路径支持 | 不新增品牌限制、不修改准入或归因；is_agent_author仍是辅助证据 |
| 第一步日志对齐 | `scripts/align_swechat_agent_logs.py`及9月21日final | 10,767文件单位→4,128首次提交变化候选；保留856强工具对齐、其余原等级及mixed不确定性 |
| 第二步后续追踪 | `src/agentlog_unified/lineage.py::trace_logs` | 保留祖先关系、first-parent、生效窗口、同实体/possible、无后续/缺口逻辑；不重跑或改变选集 |
| 第三步动机证据 | 新`scripts/agent_log_motivation.py` | 直接接收原followups.jsonl，保存多证据、多关联和独立动机结论 |

24,685条旧历史版本与4,128条当前Agent范围日志候选有不同来源、粒度和归因强度，不能串成同一个漏斗。`agent_version`是Agent操作留下的快照，`committed_version`是最终提交快照；二者不能混用。`agent_changes`一条是工具编辑操作，一次操作可改多条日志，同一日志也可被多次编辑。旧字段里的`source_and_purpose`描述输出值来源/用途，`followup_rule_version`描述研究补证规则，均不代表日志修改目的或Git后续修改。

## 3. 数量和筛选比例

当前范围从85,401个repo+SHA+path单位保留10,767个代码文件单位（{10767/85401:.2%}）；其中805个文件单位观察到变化日志候选，占输入{805/10767:.2%}。4,128是日志候选数，不能除以文件数当日志筛选率。对齐覆盖为8,768文件已处理、1,896因隔离或无法结构核查跳过、103未对齐；跳过/未对齐不等于无日志。

第二步：**输入候选范围可定位，但与该范围对应的后续修改输出尚缺失**，输出数、筛选比例均为null。已枚举既有followups产物，SWE-chat命名真实运行表为空，原全量报告明确未跟踪后续链；其他AIDev/校准/合成非空表不合并。见[逐阶段表](stage_counts.csv)、[产物盘点](audit/stage2_inventory.csv)。盘点限定既有运行目录并跳过缓存、依赖、输入副本和封存区，不声称搜索了机器上所有文件。

第三步SWE-chat主输出为明确标记`awaiting_upstream_stage2`的接口交付；CSV含表头，JSONL为空。它不是“后续修改为0”的实验结果，explicit/inferred/unknown/conflicting与证据覆盖率全部不可计算。

独立真实校准：原44个引入变化中1个有后续变化（2.27%，原possible）；第三步保留1/1事件，9条证据、10条关联。prompt 0/1、提交消息1/1、PR描述1/1、评审1/1、issue 0/1。动机explicit=0、inferred=1、unknown=0、conflicting=0。只有一个非主范围案例，不能外推。未进行证据审阅的首次采集结果为unknown=1，审阅有原文引用后才改为inferred。

## 4. 第三步的证据与判断规则

- 先核对后续事件的repo、SHA、文件diff和历史语句行锚点，再经原guard核查完整before/after源码。无效或受保护事件仍保留，保护身份按原要求隐藏；不会把证据缺失当删除条件。
- GET精确提交及其PR关联；分别取PR描述、行内评审、评审总结和PR讨论。PR同属关系只是上下文，精确修订、路径及行范围才提升位置对应。评审旧版本与本次parent相同时使用父源码定位，不把旧行号贴到新代码。
- 从已关联材料中的明确issue引用出发取正文及讨论；跨仓库引用保留原仓库。不做主题相似搜索或时间窗口猜测。返回PR的编号不能称为issue。
- prompt要求同仓库、修改SHA、checkpoint双向成员、session以及user对话turn匹配；工具操作不冒充prompt。该关联本身不证明prompt专门要求改该日志，也不证明执行先后。初始引入prompt只可作为背景，不能自动解释后续修改。
- 每项证据独立成行；同源同内容去重，但不同事件的边保留；同评论不同原文版本保留。链接/本地来源、时间、ID、完整关联依据和原文均可回查。
- 自动采集不会靠代码变化或关键词生成动机。证据审阅通过注释输入提供精确引文、关联说明、目标锚点和审阅者。explicit需直接对应且原谱系supported；inferred必须另填推断；unknown保留；同命题相反claims产生conflicting。多个兼容标签不算冲突。该校验能验证结构及引用，不代替人对因果解释的审查。

## 5. 交付文件

- [主范围修改表](swechat_stage3_final/log_modifications.csv)、[证据表](swechat_stage3_final/motive_evidence.csv)、[关联表](swechat_stage3_final/evidence_links.csv)、[左连接结果](swechat_stage3_final/modifications_with_evidence.csv)：空表接口，第二步未就绪。
- [实际校准修改表](calibration_delivery/log_modifications.csv)、[原文证据](calibration_delivery/motive_evidence.csv)、[关联结果](calibration_delivery/modifications_with_evidence.csv)、[动机表](calibration_delivery/motives.jsonl)。各表同时提供JSONL。
- [字段字典](field_dictionary.csv)、[来源类型](source_types.csv)、[继承字段未逐项复核定义清单](unresolved_field_definitions.csv)。后者是本轮审计范围标记，不等于原数据有错误，不能用它拼出39.3%。
- [逐条历史核验/未决台账](audit/unresolved_legacy_logs.csv)、[第三步缺失](calibration_delivery/unresolved_records.csv)、[真实可追溯样例](可追溯样例.md)、[运行说明](运行方式.md)、[回归结果](regression_tests.txt)。

## 6. 已执行验证与未执行事项

已执行：guard通过；全量ID/观察引用/主键/父视图摘要核对；61项测试（新增31、原对齐26、原范围4）通过；原输入摘要前后相同；真实只读采集PR与评审；9条证据/10条关联的外键及一对多去重检查；无证据事件左连接保留；错误SHA/文件/行号、跨会话prompt、工具turn、缺失来源、假引文、同源不同版本、冲突claims及隔离匿名保留测试。

未执行：SWE-chat当前范围的第二步全量历史追踪及第三步主数据运行；真实issue材料取回受HTTP403影响；全量动机逐条审阅；独立人工准确率评估、运行时验证。未重新执行前两步，未对24,685逐条宣称Agent作者已知。主要风险是上游谱系/归因未确认、较粗定位键重复和外部材料不完整，而不是可以用缺失prompt筛掉的“坏行”。

## 7. 保持原口径的接续方案

先恢复或定位已存在的第二步输出及其父输入、观察终点、冻结target、缺口台账；若确实从未运行，则使用原追踪引擎和原配置另起隔离运行，输出每条后续事件及无后续/缺口结果。当前Agent文件/日志范围与原PR追踪入口的映射须明确、可核验，不能为了得到非空表自动创造PR或更改准入。该缺口影响当前全部4,128候选的“后续变更”结论，范围已列出，本轮未擅自选择新观察窗口或新追踪逻辑。

第二步就绪后运行第三步入口；先证据采集，后证据审阅，再在新目录应用带精确引文的注释。unknown永久保留，随着材料补齐追加新证据和结论版本。所有产物指向未改变的父输入；后续补证不得覆盖本轮或已有原始结果。
'''
    (out/'README.md').write_text(report,encoding='utf-8')
    (out/'运行方式.md').write_text('''# 增量运行方式

在项目根目录使用已有研究Python。主实现是项目`scripts/agent_log_motivation.py`；交付内code为冻结快照。不要直接在旧结果目录运行，输出目录必须不存在。Windows PowerShell示例：

```powershell
$researchPython = "research/swechat-windows-continuation-20260914/.venv/Scripts/python.exe"
& $researchPython scripts/agent_log_motivation.py --trace-run "已有追踪运行目录" --swechat-frozen data/cache/swechat-frozen --output outputs/motive-new-run --online
```

输入目录含`data/followups.jsonl`或顶层`followups.jsonl`，并配套同目录`log_changes.jsonl`、`repositories.jsonl`、`commits.jsonl`、`file_changes.jsonl`。这是既有trace_logs导出契约。缺少源表/完整before-after源码时保留事件和明确缺口，不自建日志谱系。语义分析导出若为脱敏片段，需指回同一原始trace运行；不能把脱敏文本冒充原源码。`--online`只执行GitHub GET；默认离线；API失败记具体状态后继续。可用`--external-cache`复制复用已有成功缓存，新结果仍在新目录。

证据审阅与采集分开。注释JSONL必须引用同一输入event_id和evidence_id；必需`status`、`annotator`、`labels`、`rationale`、`claim_key`、`position`、`citations`。explicit另需`stated_purpose`、`direct_correspondence`和`target_anchor`（修改SHA、路径、before/after侧、一基行号）；inferred另需`inference`。精确引文须为原文子串，证据须已关联该事件。实际校准注释是助手审阅，不是人工真值。

```powershell
& $researchPython scripts/agent_log_motivation.py --trace-run "原追踪运行目录" --external-cache outputs/motive-new-run/external_cache --annotations "审阅注释.jsonl" --swechat-frozen data/cache/swechat-frozen --output outputs/motive-reviewed-run
```

缺少第二步产物时只能建立带状态的空表接口：

```powershell
& $researchPython scripts/agent_log_motivation.py --missing-stage2 --output outputs/motive-awaiting-stage2
```

复跑核验前按AGENTS运行guard，并将PASS结果置于新审计目录父级`development_guard.json`；审计入口为`scripts/audit_swechat_motivation_inputs.py --output 新审计目录`。优先Windows研究Python，WSL逐行读取Windows大文件明显较慢。原Parquet读取复用9月21日已隔离安装的pyarrow依赖，未改动研究环境。

验证：

```powershell
& $researchPython -m pytest scripts/test_agent_log_motivation.py scripts/test_agent_log_motivation_io.py scripts/test_align_swechat_agent_logs.py outputs/swechat_agent_scope_20260919/final/test_build_scope.py -q -p no:cacheprovider
```

新增代码不替换原CLI/筛选器，没有付费模型调用、目标代码执行或远程写操作。分类标签允许多项及other/unknown；完整类别枚举见脚本LABELS。单条事件可以关联多项证据；统计覆盖按distinct event_id计算，不能把证据条数相加当日志数。
''',encoding='utf-8')
    shutil.copy2(root/'calibration_online/unresolved_records.jsonl',out/'online_collection_gaps.jsonl')
    write_json(out/'manifest.json',{'status':'implementation_and_audit_delivered_main_stage2_missing',
        'authoritative_sources':{'audit':'audit_verified','main':'swechat_stage3_final','calibration':'calibration_delivery'},
        'artifacts':{str(p.relative_to(out)).replace('\\','/'):file_hash(p) for p in out.rglob('*') if p.is_file()}})
    print(out)


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,required=True);package(ap.parse_args().root)
