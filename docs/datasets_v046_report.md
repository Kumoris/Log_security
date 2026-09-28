# AIDev / SWE-chat：0.4.6 实际执行报告

记录日期：2026-09-09（北京时间）。本轮补齐了压缩续扫、父扫描与补扫去重合并，并将明确字段映射从 18 个扩至 27 个。**全部敏感类型仍未识别完成**；正文规则观察、字段含义候选与应用日志证据继续分开统计。

## 实现与验证

沿用现有 Python 包、CLI、统一分类和七阶段日志流程，没有增加依赖，没有改动两个原工具的源码。本轮主要改动如下。

| 功能 | 实际行为 | 可复核证据 |
|---|---|---|
| `content-advance` | 在原 SQLite 游标上续扫；新目录输出 gzip JSONL/CSV；逐批事务、源与实现指纹校验、排他锁、行数/时间/磁盘预算；支持离线、预演、恢复 | [独立故障与恢复测试](content_advance_v046_independent_review.json)、[真实零行快照核验](swechat_advance_v046_snapshot_verification.json) |
| `content-reconcile` | 按源单元格、Unicode 位置、规则、类型去重；完整且无缺口的补扫替换对应父结果；部分补扫或有缺口时保留并集；详情冲突保留待审 | [AIDev 实际执行](aidev_reconcile_v046_execution.json)、[合并覆盖](../reconciled-runs/aidev-v046/merged_coverage.json) |
| 字段扫描扩展 | 增加 AIDev 八表 `user` 及 `pr_timeline.actor`，只作低置信度账户引用；空值、示例和无效值分开 | [27 个字段核验](schema_exports_v046_verification.json) |
| 回归与日志流程 | 最终源码 **544 项 pytest 通过**；本地合成 Git 历史真实经过 PyDriller 和完整七阶段 | [最终测试](tests_final_v046_stdout.txt)、[执行指纹](tests_final_v046_execution.json)、[合成运行](../runs/synthetic-v046/run_manifest.json) |

合成历史记录了 1 次 PyDriller 遍历、5 个提交、5 次 `diff_parsed`、10 次历史源码读取和 2 次辅助 blob 读取；作者过滤为空。预演、实际运行、恢复均返回 0。这证明工具流程可运行，不是新的真实 Agent 隐私缺陷证据。本轮没有扩大 Git 样本，历史主 AIDev 样本仍为 594 个实际读取的唯一仓库与 SHA 组合。

## 字段扫描：27 个明确字段已读完

冻结来源未改变：AIDev 18 表、2,456,073 源行；SWE-chat 6 表、2,732,252 源行。24 份原始 Parquet 共 3,372,920,679 字节。另一份 AIDev 快照未混入分母。

| 字段扫描指标 | AIDev | SWE-chat | 合计 |
|---|---:|---:|---:|
| 已映射 / 全部字段 | 17 / 160 | 10 / 148 | 27 / 308 |
| 已读取源单元格 | 2,577,531 | 5,473,755 | 8,051,286 |
| 字段含义候选单元格 | 2,561,614 | 4,252,940 | 6,814,554 |
| 空值 | 15,892 | 1,220,715 | 1,236,607 |
| 示例线索 | 12 | 0 | 12 |
| 无效值 | 13 | 100 | 113 |
| 未映射字段 | 143 | 138 | 281 |

新增九字段读取 1,417,434 单元格，其中 1,401,541 为字段含义候选、15,870 为空值、10 为示例、13 为无效值。原 18 个字段的源区间和观察证据与 0.4.5 一致。这里的单元格数不是不同源行、账户或人数，也不能和正文命中数相加。

输出：[AIDev 字段类型](../schema-runs/aidev-v046/schema_type_summary.csv)、[覆盖](../schema-runs/aidev-v046/schema_coverage.json)；[SWE-chat 字段类型](../schema-runs/swechat-v046/schema_type_summary.csv)、[覆盖](../schema-runs/swechat-v046/schema_coverage.json)。各目录另有候选、待审、未映射字段的 JSONL/CSV。

## 固定截断补扫与去重合并

| 补扫指标 | AIDev | SWE-chat |
|---|---:|---:|
| 固定选中 / 全部规则已遍历的单元格 | 1 / 1 | 567 / 567 |
| 选中字符总数 | 74,169 | 2,232,404,563 |
| 已提交分页数 | 29 | 446,785 |
| 候选规则观察 | 4,112 | 904,361 |
| 另列示例观察 | 0 | 3,756 |
| 显式数据缺口 | 0 | 1 |

SWE-chat 本轮实际恢复两次，固定选集从 349 个完成推进到 567 个完成。旧 443,609 条候选记录逐条保留、内容未变，新增 460,752 条。[保留核验](swechat_repair_v046_retention_verification.json)及[最终补扫核验](swechat_repair_v046_final_verification.json)均通过。其 1 个未闭合私钥包络仍是数据缺口；全部单元格仍待语义审查。

AIDev 合并：父候选 1,476,485，完整补扫 4,112，重叠 1,000，得到 **1,479,597 个候选身份，亦为 1,479,597 个证据版本**；另列 11,871 个示例。新增 3,112 个规则观察，无父身份丢失。原未知队列的 17,362,345 个非空单元格保持待审，压缩为 1,114,843 条单元格或连续区间记录。这里不能将父扫描和补扫计数直接相加。独立核验 **37/37 通过**，包括 14 份 gzip 的摘要与字节数、7 组 JSONL/CSV 逐字段比较及全部父记录保留核验。[完整核验](aidev_reconcile_v046_verification.json)

SWE-chat 的新父续扫在 600 秒扫描预算后停止，连同验证与导出共用时 761.303 秒：累计 **760,028 / 2,732,252 源行**，新增 555,971 行；父候选从 2,352,157 增至 **3,610,965**，另列示例 42,941。`conversations` 已扫 732,163 / 2,692,480 行；另三张表的正文仍未开始，合计剩余 **1,972,224 源行**。

本轮新增 29 个截断单元格，累计 596 个；新 29 个未纳入旧 567 个补扫选集。父待审队列包含 1,213,296 条记录，展开为 8,303,039 个非空单元格。增量独立核验 **43/43 通过**：旧候选与示例字段全部保留，无旧 ID 丢失；355,056 条旧队列中 355,044 条保持原样、12 个尾范围合法延长。六份新 gzip 合计 461,429,088 字节。[增量核验](swechat_advance_v046_resume_verification.json)、[当前正文覆盖](../content-runs/swechat-v046/content_coverage.json)

SWE-chat 合并后的候选身份与证据版本均为 **4,181,859**，另列示例 **44,653**。父与补扫共有 335,508 个精确重叠身份；补扫提供 572,609 个新身份（包括候选和示例），完整补扫另外替换掉 3 个旧身份。因此合并后的净增加为 570,894 个候选、1,712 个示例，而不是把两个运行相加。1 个类型集合变化已单列待审。独立核验 **600/600 通过**，确认 566 个无缺口单元格完整替换、1 个缺口单元格保留并集，其中原 110 条父记录全部保留。合并耗时 317.445 秒，源实现未变。[合并覆盖](../reconciled-runs/swechat-v046/merged_coverage.json)、[逐条独立核验](swechat_reconcile_v046_verification.json)

针对变化单独读取两个冻结单元格，在内存中比较完整有限规则与分页规则，结果分别为 75 条、1,263 条，身份与详情完全相同。3 条旧观察的原因是：补齐文本后，一个未分类的外层带引号值成为完整匹配，非重叠正则不再访问其内部字段。这是嵌套文本的规则覆盖边界，不证明旧观察是误报；旧证据仍在父输出与合并审计中。另一个变化是同一字段的第二个标签恰位于规则顺序第 1,001 条，被旧上限截断后由补扫恢复。没有输出正文或真实值。[变更元数据](swechat_reconcile_v046_replacements_review.json)、[原因实测](swechat_reconcile_v046_replacement_causes.json)

新合并目录输出候选、示例、未知队列、类型汇总、去重审计、补扫覆盖和数据缺口的 gzip JSONL/CSV，并附 manifest 与覆盖 JSON。相同身份存在不同分类详情时保留多个证据版本，所以将来应分别报告身份数与版本数。

## 分类清单与待审队列

当前清单按 **11 个独立来源 × 42 个受控细类**生成 462 行，保留 311 个零观察项。不同来源的计数单位不同，不作总和；只合并已观察标签的集合。

| 证据范围 | 观察到的受控细类标签 | 计数单位 |
|---|---:|---|
| 7 个历史应用日志批次 | 27 | 各批次日志类型观察，批次间可能重复 |
| 2 份去重合并正文 | 37 | 源单元格、位置、规则和类型构成的候选身份；另列详情变体 |
| 2 份字段语义扫描 | 4 | 源单元格 |
| 标签集合并集 | 39 / 42 | 标签，不是已确认的真实敏感数据类型 |

另有目录外正文候选：AIDev 3,243（2,854 个标识符引用、389 个未知命名值），SWE-chat 1,402（849 个引用、553 个未知命名值）。它们与全部非空单元格的语义待审队列不是同一个分母。尚未观察到的 3 个受控标签，以及各来源的零观察项，不能解释成全数据集中不存在。

[类型清单 CSV](observed_types_v046.csv) / [JSONL](observed_types_v046.jsonl)、[目录外候选汇总](observed_types_v046_outside_catalog.csv)、[来源与计数口径](observed_types_v046_provenance.json)、[66 项清单核验](type_inventory_v046_verification.json)。历史 0.4.5 清单未修改；其中旧命名的 SWE-chat 补扫汇总文件已随恢复更新，其前后摘要和时间差异单独记录。

## 压缩续扫与历史快照

零行压缩快照没有重复扫描源行。六份 gzip 解压后与旧明文逐块一致，51 项独立检查通过。实测从 2,315,516,844 字节明文变为 264,067,621 字节 gzip（11.404%）；旧明文仍保留，因此不能称为释放了原占用。

`content-runs/swechat-v046` 使用旧 `swechat-v044/content.sqlite` 的同一检查点，没有复制数据库。续扫后，旧目录的明文、manifest 和覆盖属于历史快照，最新游标与统计以新目录为准。读取方须检查 `advance_state.json` 的完成状态、覆盖摘要及 SQLite 游标一致性；不能仅凭文件存在认定导出完成。中断后可恢复导出，不丢失已提交游标。

磁盘预算采用当前数据库及已观察压缩比估计下一次完整导出的空间，并保留最低余量。这是带停止阈值的工程保护，预留量是启发式估算，不保证全量或峰值空间上界。没有通过删除其他历史结果来扩充空间。

最终只读空间检查记录可用约 **1.373 GiB**，按当前检查点计算的默认续扫门槛约 **2.081 GiB**，因此该时刻不满足下一轮扫描的空间条件。没有降低保护阈值或另行删除文件；本轮已完成续扫的停止原因仍是时间预算。空间会随其他进程变化，数值及检查时刻见[实测记录](storage_v046_final.json)。

## 仍未覆盖的类型与数据

- **281 个字段仍未完成含义映射**。未知、嵌套和编码内容均不能记为“无敏感数据”。普通仓库 `id/name` 不泛化为个人信息。
- AIDev 四个 `author/committer` 字段的全量本地关联核验读取 1,600,998 单元格：1,120,281 与冻结账户表的 login 精确匹配、480,709 未匹配、8 个空值。仅记录状态区间和汇总，没有导出登录名；这支持账户关联线索，尚未接入正式分类，也不证明个人身份。[核验记录](aidev_author_account_join_v046.json)
- SWE-chat 的会话引用数组、工具输入和 JSON 元数据需要额外解析；样本格式探测不是全列语义覆盖。[字段缺口清单](schema_gap_v046_review.json)、[格式探测](structured_format_probe_v046.json)
- 当前文本检测有有限的值形态和命名字段规则，42 个受控细类不是现实敏感类型的全集；语义、引用关系、任意编码和完整污点传播没有解决。
- 本次 567 个补扫单元格是旧父运行的固定选集。新续扫发现的截断不自动加入它；新 gzip 父输出的补扫选择适配仍待实现。合并会保留这些未修复区间。
- 真实 Git 提交来源、大多数 PR 的源码、部分语言和完整后续历史仍有缺口。正文中的 patch、聊天内容和字段线索不算应用日志 sink 证据。
- 所有候选均为 `human_review_status=pending`；没有确认真实值归属、凭证有效性、运行泄露或 Agent 独有类型。

## 实际执行与复现

以下为已实际调用的主要入口；[入口与测试的命令、时间、退出码及源码指纹](datasets_v046_commands.json)记录每次执行，包含预演、恢复与修复前诊断，不能把早期测试当作最终源码验证。

```bash
PIP_DISABLE_PIP_VERSION_CHECK=1 agent_log_privacy/.venv/bin/python -m pip install --no-index --no-deps --no-build-isolation -e agentlog_unified
agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q
agent_log_privacy/.venv/bin/agentlog-unified schema-scan --input agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/schema-runs/aidev-v046 --offline --batch-size 4096 --max-seconds 300
agent_log_privacy/.venv/bin/agentlog-unified schema-scan --input agentlog_unified/inputs/swechat-full-v3 --output agentlog_unified/schema-runs/swechat-v046 --offline --batch-size 4096 --max-seconds 300
agent_log_privacy/.venv/bin/agentlog-unified content-advance --input agentlog_unified/content-runs/swechat-v044 --output agentlog_unified/content-runs/swechat-v046 --offline --batch-size 64 --max-rows 0
agent_log_privacy/.venv/bin/agentlog-unified content-advance --input agentlog_unified/content-runs/swechat-v044 --output agentlog_unified/content-runs/swechat-v046 --offline --batch-size 64 --max-seconds 600 --resume
agent_log_privacy/.venv/bin/agentlog-unified content-reconcile --input agentlog_unified/content-runs/aidev-v044 --repair-run agentlog_unified/repair-runs/aidev-v045-final --output agentlog_unified/reconciled-runs/aidev-v046 --offline
agent_log_privacy/.venv/bin/agentlog-unified content-reconcile --input agentlog_unified/content-runs/swechat-v046 --repair-run agentlog_unified/repair-runs/swechat-v045-final --output agentlog_unified/reconciled-runs/swechat-v046 --offline
```

数据运行退出码 2 表示仍有覆盖或语义缺口，不是已发现漏洞；测试和合成流程退出码为 0。未调用付费模型、未执行目标应用代码、未验证或打印真实凭证、未修改远程仓库。

两个旧中断导入目录已按确认删除，释放约 2.97 GiB；`papers` 与现用输入保留，见[删除回执](cleanup_review_v042/deletion_receipt.json)。本轮没有另行清理。后续状态见[机器可读进度](datasets_progress.json)，历史快照见 [0.4.5 报告](datasets_v045_report.md)。
