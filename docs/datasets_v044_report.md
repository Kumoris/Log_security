# 0.4.4：数据正文分类入口与新增 Git 样本

四项能力已接入统一工具：多表导入、统一分类及细类、未知类型待审、按类型汇总与覆盖审计。本轮增加独立的正文扫描入口，并实际运行 AIDev、SWE-chat 小批次；**全数据集的敏感类型普查仍未完成**。应用日志代码与数据库文本使用相同类型目录，分别记录证据和分母。

两个旧中断导入目录已按确认删除，共 6 文件、3,191,313,088 字节（约 2.97 GiB）。`papers/` 及现用输入保留，见 [删除回执](cleanup_review_v042/deletion_receipt.json)。本轮没有扩大清理范围。

## 本轮实现

新增 `content-scan`，从已完成的冻结导入读取原始 Parquet 的所有字符串列，区分正文与元数据字段；不把 PR、patch、会话文本当作应用日志调用或 Git 历史证据。范围尚待用户进一步确认，暂按“完整数据库”同时提供两种观察范围。

正文分类沿用 6 大类、42 细类目录。有限规则产生字面形式候选、命名字段候选、标识符引用、载体候选及未知类型线索；示例/占位符线索单列。规则不验证凭证有效性，所有判断均为低置信、待审核。42 个目录项不是已穷尽的实际敏感类型，也不是每项都有独立值检测能力；逐类型能力见 [分类能力审计](content_taxonomy_review_v044.json)。

每个非空文本单元格都保留待审入口。连续无命中的同列单元格用精确的源行范围压缩，匹配或截断单元格单独记录；未命中不表示安全。结果保留来源、Unicode 字符偏移和私有 HMAC，不保存原始正文或真实值。SQLite 检查点、输入及源码指纹支持 `--resume`；锁阻止并发写入，JSONL/CSV 可从检查点重建。`--dry-run` 只校验目录、哈希及表结构。

当前每单元格最多交给规则 1,048,576 字符、保留 1,000 次匹配，触及上限保留截断状态。截断尾部、非文本列、嵌套字符串的完整语义，以及规则未识别的类型仍是覆盖缺口。匹配上限也可能使规则提前结束，因此“交给规则的字符数”不能解释为这些字符都经过了全部规则。

## 冻结来源和实际正文扫描

[字段清单](content_field_inventory_v044.json)核对了 24 张表、5,188,325 行、308 个字段，其中 184 个为文本字段。AIDev 沿用冻结版本 `68ed5f4b80d27a9e057fc57567f38bd322ac73ec` 的 18 表；SWE-chat 沿用 `f66cca95b14caaa4177f7ed5eaa424608dadcffa` 的 6 表。完整元数据导入已完成，但正文扫描为以下有限批次。

| 本轮正文扫描 | AIDev | SWE-chat |
|---|---:|---:|
| 原表行数 | 2,456,073 | 2,732,252 |
| 已处理并解码的不同源行 | 1,218,611 | 18,829 |
| 非空文本单元格，全部保留待审 | 10,180,988 | 212,141 |
| 导出的待审记录，含压缩范围 | 308,597 | 32,956 |
| 候选匹配次数 | 162,760 | 863,343 |
| 单列的示例/占位符匹配 | 2,323 | 6,708 |
| 有候选标签的目录细类 | 37 | 33 |
| 触及字符或匹配上限的单元格 | 1 | 304 |
| 实际耗时，秒 | 311.79 | 324.29 |

两次均在 300 秒扫描预算后保存检查点并导出，退出码为 2、状态为 `partial`。导出耗时另计。AIDev 已完成前 7 表，提交详情表处理了 40,448/711,923 行，其后 10 表尚未处理；SWE-chat 已完成 checkpoint 表，提交表处理了 5,423/14,459 行，**会话、会话日志等后续表尚未扫描**。两次标准错误均仅含 Arrow 硬件探测受权限限制的 4 条警告，未造成扫描失败，见 [警告核验](content_stderr_v044_review.json)。

候选次数按“源单元格＋跨度＋规则＋类型”计数，同一值、重复正文或同一单元格的多种标签可重复出现，不是独立秘密、用户或泄漏数量。分类汇总仅统计有目录标签的匹配；没有类型标签的线索保留在明细和待审队列。

| 候选证据状态，含无类型标签项 | AIDev | SWE-chat |
|---|---:|---:|
| 字面形式候选 | 57,652 | 42,439 |
| 命名字段候选 | 15,395 | 294,774 |
| 标识符引用 | 53,355 | 198,269 |
| 载体候选 | 36,272 | 327,823 |
| 未知命名值 | 86 | 38 |

SWE-chat 交给规则的前缀合计 1,180,721,908 字符，已遇到的完整单元格共 1,587,667,865 字符，至少 406,945,957 个尾部字符未进入规则；匹配上限另有影响。AIDev 两项均为 901,484,262 字符，但 1 个单元格触发匹配上限，仍不算完整分析。

[独立导出核验](content_exports_v044_verification.json)全部通过：只读数据库检查、范围互不重叠、行界与字符计数、逐行 JSONL/CSV/SQLite 对照、类型与状态汇总、源文件与分类器指纹一致。它验证数据处理一致性，不属于人工语义审核。

结果入口：

- AIDev：[类型汇总 CSV](../content-runs/aidev-v044/content_type_summary.csv)、[候选 JSONL](../content-runs/aidev-v044/content_type_occurrences.jsonl)、[未知待审 CSV](../content-runs/aidev-v044/content_unknown_type_review_queue.csv)、[覆盖审计](../content-runs/aidev-v044/content_coverage.json)。
- SWE-chat：[类型汇总 CSV](../content-runs/swechat-v044/content_type_summary.csv)、[候选 JSONL](../content-runs/swechat-v044/content_type_occurrences.jsonl)、[未知待审 CSV](../content-runs/swechat-v044/content_unknown_type_review_queue.csv)、[覆盖审计](../content-runs/swechat-v044/content_coverage.json)。

## 应用日志代码：新增真实 Git 证据

按原队列次序采集，新增 106 个提交对象就绪，与既有实读提交无重叠，未按日志或敏感词预筛。[离线 PyDriller 批次](aidev_expansion_v044_execution.json)实际读取 106 个提交、解析 711 份文件差异、读取 1,223 次历史源码，产生 1,909 条观察、1,842 个去重日志版本，其中 651 个保留未知待审；103 个版本有类型线索，涉及 5 大类、12 细类。

106 个作业中 21 个完成、85 个保留部分缺口。主要缺口包括未解析或外部直接依赖 766 条、依赖预算 86 条、词法降级 56 条。当前批量观察范围仍为 `dataset_commit_changes`，尚未完成这些日志的所有后续历史追踪。[独立批次核验](aidev_expansion_v044_verification.json)全部通过。

AIDev 主队列各版本去重后累计实读 **594 个仓库＋SHA**，较上版新增 106 个。七个版本化应用日志批次的标签并集仍为 **27/42 个细类有静态观察**，正文结果未计入；见 [分类目录](observed_type_inventory_v044.csv)与 [来源及指纹](type_inventory_v044_provenance.json)。日志版本和上下文的跨批次计数不能直接相加。

[AIDev 全量 PR 覆盖关联](../reports/aidev-corpus-v044/corpus_coverage.json)保持 939,353 个归一化 PR 分母：142 个有 Git 读取证据、141 个有历史源码、103 个有支持范围源码分析、51 个有日志观察、41 个有类型线索、50 个有未知待审。939,250 个 PR 仍无已核实的提交分析。补充锚点未改变冻结主分母，正文扫描行数也不计入 Git 覆盖。

## 测试、命令和下一步

完整测试 **441 passed in 26.47s**，见 [测试记录](tests_v044.txt)和 [执行及源码哈希](tests_v044_execution.json)。[七阶段合成执行](synthetic_v044_execution.json)实际通过预演、完整运行与恢复；合成样本只用于验证工具。两份真实正文扫描的源码在执行前后保持一致。

本轮实际命令及参数记录：

- [AIDev 正文预演](aidev_content_v044_dry_run_execution.json)、[真实扫描](aidev_content_v044_execution.json)。
- [SWE-chat 正文预演](swechat_content_v044_dry_run_execution.json)、[真实扫描](swechat_content_v044_execution.json)。
- [在线 Git 对象采集](aidev_collect_objects_v044_execution.json)、[离线 PyDriller 挖掘](aidev_expansion_v044_execution.json)、[全量 PR 覆盖关联](coverage_v044_execution.json)。
- [合成预演](synthetic_v044_dry_run_execution.json)、[合成恢复](synthetic_v044_resume_execution.json)。

恢复正文扫描可沿用当前源码和相同输入、输出与分类预算执行：

```bash
agent_log_privacy/.venv/bin/agentlog-unified content-scan --input agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/content-runs/aidev-v044 --offline --batch-size 64 --max-seconds 300 --resume
agent_log_privacy/.venv/bin/agentlog-unified content-scan --input agentlog_unified/inputs/swechat-full-v3 --output agentlog_unified/content-runs/swechat-v044 --offline --batch-size 64 --max-seconds 300 --resume
```

以上两条是下一次恢复用法，本报告未把它们记为已执行。源码或规则上限改变会拒绝恢复，避免混用不同分类器结果。恢复后当前导出会重建；本报告保留首轮指标，执行时间和指纹用于定位该时点。

尚待推进：未扫描正文、截断尾部、非文本字段的敏感语义、未知类型审查、大量缺失 Git 对象、更多语言和跨文件语义、完整后续修改追踪。本轮未调用付费模型、未运行目标应用、未验证真实凭据、未修改远程仓库。
