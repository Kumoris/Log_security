# 0.4.3：确认清理、C# 检测与新增 Git 样本

两个旧中断导入目录已按用户确认删除。统一工具的多表接入、分类及细类、未知待审和覆盖审计继续可运行，并补充 C# 日志检测。**完整 AIDev/SWE-chat 敏感类型普查仍未完成。** 当前观察对象是应用日志代码；PR、会话和工具消息正文仍仅保留来源引用，尚未做内容分类。

## 已执行清理

严格删除提案中的 `inputs/aidev-full`、`inputs/swechat-full`，共 6 文件、3,191,313,088 字节（约 2.97 GiB）。删除前核对精确路径、文件哈希及占用；原始 24 表、现用导入和证据副本通过保留核验。`papers/` 删除前后的目录及内容哈希一致。详见 [删除回执](cleanup_review_v042/deletion_receipt.json)。没有删除其他历史批次。

回执时点删除后可用空间约 5.36 GiB，原 3 GiB 采集预检阻塞已解除。后续系统显示的可用空间变化不能全部归因于本次删除。

## 实现与真实数据发现的修正

C# 使用已有 Pygments 依赖，支持常见 ILogger、Serilog、NLog 调用、完整跨行参数、消息模板字段、简单插值及局部一跳赋值。修改前后、删除侧、历史快照和可选 SZZ 使用相同检测入口。所有 C# 实体均为低置信词法线索，保持 possible/unknown/pending；未实现编译器级语义或完整污点分析。

解析边界不可靠时设置 `source_analysis_unavailable`：在追踪中保留历史缺口区间，在覆盖审计中排除该源码的已分析计数，不把缺失输出当成日志删除。合成回归首先发现普通字符串错误跨越物理换行，修正后初次完整测试 378 项通过。

随后对真实 C# 缓存做独立复查，发现 29 条失败记录均有解析器原因：7 条由合法 BOM/#nullable 指令触发，22 条由属性字符串内的方括号截断 Pygments 属性 token 触发。已修正词法入口并加入回归检查；没有执行目标仓库或用编译成功冒充验证。首轮失败诊断保存在 [初始对比](csharp_replay_v043_comparison.json)，修正后的同样本结果见 [最终对比](csharp_replay_v043_comparison_final.json)。

## 实际采集与批次

冻结来源及全表导入沿用 [0.4.2 报告](datasets_v042_report.md)：AIDev 18 表、2,456,073 元数据行、939,353 个归一化 PR；SWE-chat 6 表、2,732,252 元数据行。没有把不同上游快照或重复导入当作新增样本。

本轮 [在线对象采集](aidev_collect_objects_v043_execution.json)实际运行约 300 秒，2 仓库、147 个新增提交对象就绪，累计 475 个唯一就绪提交。采集只准备 Git 对象，未生成分类，也没有取得完整历史。扣除 3 个此前已实读提交，形成 144 个仓库＋SHA、147 条原始上下文的 [独立增量输入](aidev_expansion_v043_selection.json)，未按日志或敏感词筛选。

C# 队列从已有实际文件证据中选取 20 个包含 `.cs` 修改的完整提交，保留各提交所有变更文件。它是语言修复的同样本回放，不代表全语料均已识别是否包含 C#；未知语言/缺失对象仍在原队列及 [未选择台账](csharp_replay_v043_unselected_commits.jsonl)。

| 最终新批次 | PyDriller 实读提交 | diff 解析 | 历史源码读取 | 去重日志版本 | 未知待审 | 观察细类 |
|---|---:|---:|---:|---:|---:|---:|
| AIDev 新增提交 | 144 | 475 | 796 | 882 | 386 | 8 |
| SWE-chat C# 同样本回放 | 20 | 548 | 915 | 755 | 755 | 14 |

C# 同样本对比保留 731 个非 C# 日志版本及其全部证据，新增 24 个 C# 日志版本，其中 21 个有弱类型线索；它们全部保持低置信与未知待审。

两批全部作业均已尝试，exit 2 表示记录了源码/语义等覆盖缺口，并非执行崩溃。AIDev 有 40 个作业完整完成、104 个保留部分缺口；C# 的 20 个作业均保留部分缺口。批次的范围仍是 `dataset_commit_changes`，没有完成这些真实日志的所有后续历史追踪。

AIDev 主批次、旧缓存恢复与本次新增提交去重后，累计实际读取 **488 个仓库＋SHA**。增量 144 个与之前 344 个实读提交无重叠，见 [独立核验](aidev_expansion_v043_independent_check.json)。重复回放不再计为新增提交；日志版本及上下文的跨批次重叠仍不可直接相加。

## 类型与全量覆盖

[类型目录 CSV](observed_type_inventory_v043.csv)按来源批次分别列出 6 大类、42 个细类，版本化证据的标签集合共有 **27 个细类有静态观察**。相对上一版新增观察 `BIZ.message_content`、`PII.postal_address`，来自 AIDev 新增样本；这是既有分类目录的新增观察，不是发现新隐私类型或确认泄漏。零观察项不表示不存在。

[来源与分类器指纹](type_inventory_v043_provenance.json)明确区分旧 0.4.2 基线与修正后 0.4.3 增量。首轮 v043 批次保留作为诊断证据，当前目录汇总使用 `*-v043-final`，不同时累加初始和最终回放。旧批次未伪装成由新分类器重新分析。

[最终 AIDev 语料覆盖](../reports/aidev-corpus-v043-final/corpus_coverage.json)保留 939,353 个 PR 分母：110 个有 Git 提交读取、109 个有历史源码、79 个有支持范围源码分析、35 个有日志观察、28 个有类型线索。主分母不纳入不属于冻结 PR 提交成员证据的 25,152 条补充锚点上下文。不同作业状态的 PR 计数存在重叠。

## 测试、命令与输出

修正后完整测试：**400 passed in 28.67s**，见 [最终测试记录](pytest_v043_final.txt)及 [命令、时间、源码哈希](pytest_v043_final_execution.json)。[最终七阶段合成运行](synthetic_v043_final_execution.json)实际运行预演、执行与恢复；合成候选仅用于工具验证。

[导出核验](type_exports_v043_final_verification.json)重算版本 ID、未知队列成员、类型计数、JSONL/CSV 一致性和当前源码指纹。自动检查不属于人工审核。[AIDev 最终回放对比](aidev_expansion_v043_final_comparison.json)核对 C# 修正没有改变该无 C# 队列的已有证据。

实际命令参数与退出码保存于：

- [对象采集](aidev_collect_objects_v043_execution.json)
- [AIDev 最终 PyDriller 扫描](aidev_expansion_v043_final_execution.json)
- [C# 最终 PyDriller 扫描](csharp_batch_v043_execution_final.json)
- [完整测试](pytest_v043_final_execution.json)、[合成流程](synthetic_v043_final_execution.json)
- [最终全量分母覆盖关联](aidev_corpus_v043_final_execution.json)

结果入口：

- AIDev：[类型汇总](../batches/aidev-expansion-v043-final/exports/type_summary.csv)、[未知待审](../batches/aidev-expansion-v043-final/exports/unknown_type_review_queue.csv)、[逐提交审计](../batches/aidev-expansion-v043-final/exports/commit_audit.jsonl)。
- C# 回放：[类型汇总](../batches/csharp-swechat-v043-final/exports/type_summary.csv)、[未知待审](../batches/csharp-swechat-v043-final/exports/unknown_type_review_queue.csv)。
- 完整七阶段的三层输出、逐案例包、后续修改及漏斗：[合成运行目录](../runs/synthetic-v043-final/)。真实批量扫描不能替代后续历史追踪。

大多数 Git 对象、部分 PR 关系、其他语言检测、跨文件语义、未知类型人工审核和完整后续追踪仍未完成。未调用付费模型、未运行目标应用代码、未验证真实凭据、未修改远程仓库；`papers/` 保持完整。完整研究目标继续保持未完成。
