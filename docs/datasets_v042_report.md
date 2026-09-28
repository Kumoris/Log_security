# 0.4.2：Go 日志识别与真实数据扩展

四项功能已在统一工具中实现并运行：AIDev 多表接入、统一大类及细类、未知类型待审队列、按类型汇总与覆盖审计。**完整数据集的敏感类型普查仍未完成。** 当前类型来自应用日志代码的静态观察，不是确认泄漏；PR 正文、会话和工具消息正文仅保留来源引用，尚未做内容分类。

## 已实现的四项功能

| 功能 | 当前行为与输出 |
|---|---|
| AIDev 多表全量接入 | 按冻结来源版本读取所有 18 表，批量关联并保留字段映射、来源行、哈希、重复和关系缺口；`normalized_prs.jsonl` 保留全量分母，`mining_prs.jsonl` 仅要求有提交证据，没有敏感词预筛。 |
| 统一分类及细分类 | 复用 taxonomy 1.0.0：AUTH、PII、QID、BIZ、CFG、DIAG 六类及 42 个受控细类，允许一个日志版本命中多类；正文载体或弱标识线索与确认泄漏分开。 |
| 未知类型待审队列 | 未分类值、载体内容不明、词法解析与有界语义缺口保留原因和证据引用；输出 `unknown_type_review_queue.jsonl/csv`，人工状态始终 pending，除非导入真实人工审核。 |
| 类型汇总与覆盖审计 | `type_occurrences` 按日志版本去重，`type_summary` 同时导出大类、细类及零观察项；`commit_audit`、语言/读取缺口和 `aidev-coverage` 分开记录元数据、Git、源码、支持范围和类型覆盖。 |

来源沿用 [0.4.1 报告](datasets_v041_report.md)：AIDev 冻结版 `68ed5f4b80d27a9e057fc57567f38bd322ac73ec` 共 2,456,073 行、939,353 个归一化 PR；SWE-chat 冻结版 `f66cca95b14caaa4177f7ed5eaa424608dadcffa` 共 6 表、2,732,252 行元数据。AIDev 主队列是 86,315 个仓库＋SHA、88,564 条上下文；SWE-chat 是 8,697 个仓库＋SHA。补充锚点另外保留 24,468 个仓库＋SHA、25,152 条关联，不能直接计作主 PR 初始提交。

## 本版新增能力

复用已锁定的 Pygments 2.21.0，增加 Go std log/slog、zap、logrus、zerolog 的完整跨行语句、结构字段、局部一跳赋值、删除前代码和未知待审。同步补齐历史快照读取、默认配置、可选 SZZ 反向追踪和覆盖审计，避免 Go 文件同时被计为支持与不支持。

独立合成复查发现并修正三处问题：catalog/analogy 等普通对象被当成 logger、已脱敏 map 字段仍带敏感标签、同一行局部赋值没有被追踪。注释、raw string、rune 中的伪日志、zap 属性构造器、测试输出及无终止调用的构建器也有回归检查。

**Go 仍是低置信词法证据**：每个 Go 文件均保留语义缺口，日志实体均为 possible/unknown；快照有解析缺口时其依赖覆盖也记为 partial。fmt.Print*、裸 print/println、点导入、常量字段键和跨文件值流仍未覆盖。跨语言动态调用与完整污点分析没有完成。

## 测试和实际采集

[完整测试](pytest_v042.txt)为 **325 passed in 22.94s**；[执行记录](pytest_v042_execution.json)保存真实命令、起止时间及退出码。新增测试实际建立 Git 历史，通过 PyDriller 读取新增、跨行修改和删除。另运行 [完整七阶段合成流程](synthetic_v042_execution.json)：5 提交、5 文件差异、6 日志事件、2 初始日志变化、3 后续修改、2 合成候选；预演、运行及恢复均退出 0。这些合成候选不属于真实数据集发现。

本轮 [AIDev 增量采集](aidev_collect_objects_v4_expansion_execution.json)实际用时 301.12 秒：5 仓库、178 个新增提交对象就绪，累计 328 个唯一提交对象就绪；300 次显式 Git fetch，新增采集错误 0。直接依赖候选预算触发 42 次截断，故对象就绪不等于完整依赖或历史已取得。采集本身不生成分类，CLI exit 2 表示剩余队列未完成。

分类器源码已变化，新的实际运行使用 AIDev/SWE-chat v5 与补充锚点 v3，保留旧批次，不把新分类器接写到旧分析指纹中。所有命令均已终止；完整队列尝试完毕仍会因数据或语义缺口返回 exit 2。

## 真实批次结果

| 当前批次 | PyDriller 实读提交 | diff 解析 | 历史源码读取 | 去重日志版本 | 未知待审 | 未读作业 / 待处理 |
|---|---:|---:|---:|---:|---:|---:|
| AIDev 主队列 v5 | 336 | 1,165 | 2,069 | 696 | 654 | 85,979 / 0 |
| SWE-chat v5 | 1,296 | 9,227 | 14,701 | 3,397 | 3,326 | 7,401 / 0 |
| AIDev 补充锚点 v3 | 21 | 76 | 142 | 84 | 84 | 5 / 24,442 |
| AIDev 旧缓存恢复 | 8 | 14 | 24 | 0 | 0 | 0 / 0 |

AIDev 主队列两次运行耗时 326.70 秒与 37.94 秒；SWE-chat 两次为 330.63 秒与 79.48 秒。时间预算按提交边界检查，导出也需要时间，因此总时长可以超过 300 秒。两者全部输入作业已尝试，但大部分 Git 对象仍不可用；“队列已尝试完”不代表全量分析完成。补充锚点受 5 仓库上限限制，保留 24,442 个 pending。

[主样本对比](aidev_v042_expansion_comparison.json)确认 v4 的 134 个已有日志版本在 v5 中全部保持一致；新增 352 个 Go 版本及 210 个其他语言版本。增量同时包含对象补采和语言支持，不能把全部新增类型归因于 Go。另用原缓存独立重读此前遗漏的 8 个提交，未新增日志；主样本与恢复批次去重后实际读取 **344 个提交**，覆盖旧 v3/v4 的全部 265 个已读提交，并新增 79 个。主队列中这 8 个作业的旧 blocked 记录保留，跨批次覆盖以最终审计为准。

[SWE-chat 同样本对比](swechat_v042_classifier_comparison.json)保持 1,296 提交、9,227 次差异解析和 14,701 次源码读取不变。原 2,953 个非 Go 日志版本及其全部导出字段保持一致；新增 **444 个 Go 日志版本**，均为低置信、未知待审。观察细类由 20 增至 24，新增 AUTH.password、CFG.database_connection、QID.network_identifier、QID.user_identifier；它们是既有分类目录的新增观察，不是新隐私类型或运行时泄漏。

[完整类型目录 CSV](observed_type_inventory_v042.csv)分别列出四个当前批次的计数：42 个受控细类中共 25 个有静态观察。零观察项不等于不存在；同一版本可带多个标签，批次之间也可能重叠，不应相加推算总体规模或发生率。

## 覆盖审计与导出核验

[最终 AIDev 覆盖审计](../reports/aidev-corpus-v042-final/corpus_coverage.json)保留 **939,353 个 PR 分母**：83 个有实际 Git 提交读取、82 个有历史源码、62 个有支持范围分析、26 个有日志观察、21 个有类型线索。类型或日志观察 PR 很少，不能据此称已提取完整数据集的所有敏感类型。

补充锚点的 25,152 条上下文全部因不属于冻结 PR 初始提交成员证据而排除出主覆盖统计；旧缓存恢复的原始 AIDev 来源字段保持一致。各作业状态的 PR 计数可重叠，不能将 complete/partial/blocked 的 PR 数直接相加。

[导出核验](type_exports_v042_verification.json)独立重算四个批次的版本唯一性、未知队列成员、类别计数、JSONL/CSV 行数及分类器源码指纹，未发现不一致；Go 标签低置信及人工 pending/运行时未确认边界检查通过。自动测试与核验都不是人工审核。

## 实际命令及结果入口

工作区根目录执行。本轮已经运行的完整参数、时间和退出码保存于下面记录；旧版本的全表导入结果继续复用，没有再次伪报为本轮下载。

```bash
agent_log_privacy/.venv/bin/python -m pip install --no-deps --no-build-isolation -e agentlog_unified
agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/local_fixture_config.yaml --run-id synthetic-v042 --offline
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/local_fixture_config.yaml --run-id synthetic-v042 --offline --resume
agent_log_privacy/.venv/bin/agentlog-unified collect-objects --output agentlog_unified/batches/aidev-full-v4 --cache-dir agentlog_unified/cache/object-repos --online --max-commits 250 --max-seconds 300 --resume
agent_log_privacy/.venv/bin/agentlog-unified batch-mine --output agentlog_unified/batches/aidev-full-v5 --cache-dir agentlog_unified/cache/object-repos --offline --max-seconds 300 --resume
agent_log_privacy/.venv/bin/agentlog-unified batch-mine --output agentlog_unified/batches/swechat-full-v5 --cache-dir agentlog_unified/cache/batch-repos --offline --max-seconds 300 --resume
agent_log_privacy/.venv/bin/agentlog-unified batch-mine --output agentlog_unified/batches/aidev-anchors-v3 --cache-dir agentlog_unified/cache/anchor-object-repos --offline --max-repositories 5 --max-seconds 180 --resume
```

- 队列导入：[AIDev](aidev-full-v5_ingest_command.json)、[SWE-chat](swechat-full-v5_ingest_command.json)、[补充锚点](aidev-anchors-v3_ingest_command.json)。
- 真实执行：[AIDev 首轮](aidev_batch_v5_offline_execution.json)、[恢复](aidev_batch_v5_resume_execution.json)、[SWE-chat 两轮](swechat_batch_v5_offline_execution.json)、[补充锚点](aidev_anchor_batch_v042_execution.json)、[旧缓存恢复](aidev_prior_cache_v042_commands.json)、[最终语料覆盖](aidev_corpus_v042_final_execution.json)。
- AIDev：[类型汇总](../batches/aidev-full-v5/exports/type_summary.csv)、[未知待审](../batches/aidev-full-v5/exports/unknown_type_review_queue.csv)、[提交缺失审计](../batches/aidev-full-v5/exports/commit_audit.jsonl)。
- SWE-chat：[类型汇总](../batches/swechat-full-v5/exports/type_summary.csv)、[未知待审](../batches/swechat-full-v5/exports/unknown_type_review_queue.csv)。
- 七阶段的逐案例包、后续修改、排除和漏斗：[合成运行目录](../runs/synthetic-v042/)。批量提交扫描的观察范围仍为 dataset_commit_changes，尚未完成所有真实样本的后续历史追踪。

## 当前限制与下一步

多数源码提交、未建立的 PR 关系、完整后续历史和人工审核仍未完成。其他语言的真实缓存缺口已做 [聚合盘点](language_gap_inventory_v042.json)，包括 C#、Rust、Java、PHP、Vue；盘点中的调用数来自完整历史文件，未与差异求交，未混入正式日志数量。

当前磁盘可用约 **2.37 GiB**，低于采集器 3 GiB 的预检阈值，因此暂未继续扩大在线采集。已准备 [两个旧中断导入目录的清理提案](cleanup_review_v042/提案.md)，逻辑大小 2.97 GiB；仅生成逐文件哈希和小型证据副本，**尚未删除或移动任何文件，待用户手动确认**。永久删除会失去旧 SQLite 中间状态，实际释放量受文件系统影响。

未调用外部付费模型、未运行目标应用代码、未验证真实凭证、未写远程仓库。`papers/` 与两套原工具源码未修改。完整目标保持未完成。

后续清理更新：用户已明确确认，两个旧中断导入目录已删除；原始表、现用导入及 `papers/` 保留。执行后可用空间约 5.36 GiB，原磁盘阻塞已解除。[删除回执及核验](cleanup_review_v042/deletion_receipt.json)记录实际执行结果。
