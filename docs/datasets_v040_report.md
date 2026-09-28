# AIDev 与 SWE-chat 数据接入和类型筛选报告

> 本文保留 0.4.0 快照；最新进展见 [0.4.1 扩展报告](datasets_v041_report.md)。

**四项工具能力已实现并运行；全量元数据已接入，敏感类型全量普查尚未完成。** 工具版本 0.4.0，分类目录 1.0.0。所有结果仍为静态观察或待审候选，不是人工确认或运行时泄漏证明。

## 全量接入与分母

| 数据集 | 冻结表数 | 实际元数据行 | 可挖掘提交 | 来源缺口 |
|---|---:|---:|---:|---|
| AIDev | 18 | 2,456,073 | 86,315 个仓库＋SHA | 939,353 个归一化 PR 中，905,773 个缺少有效提交关系 |
| SWE-chat | 6 | 2,732,252 | 8,697 个仓库＋SHA | 5,205 条提交记录缺少主键；存在孤立与跨仓库会话引用 |

正式输入是 [aidev-full-v2](../inputs/aidev-full-v2/coverage.json) 与 [swechat-full-v3](../inputs/swechat-full-v3/coverage.json)。AIDev 冻结 revision 为 `68ed5f4b80d27a9e057fc57567f38bd322ac73ec`，SWE-chat 为 `f66cca95b14caaa4177f7ed5eaa424608dadcffa`。两个快照均逐文件匹配原始 LFS 指针 SHA256，见 [AIDev 校验](aidev_frozen_verification.json)、[SWE-chat 校验](swechat_frozen_verification.json)。另一份 AIDev main 快照未混入分母。

AIDev 完整可挖掘清单有 33,580 个 PR、88,564 条提交上下文关联。SWE-chat 的 205 个仓库、5,851 个会话、13,406 个 checkpoint 均已纳入关联审计；197 个仓库具备有效提交上下文。同仓库重复记录为 557 条；合法跨 fork 共享 SHA 按仓库＋SHA 区分。正文与 patch 目前保留来源行引用，未混入应用日志分类。

## 四项新增能力

1. **多表全量接入**：保留 CSV、JSONL 与字段映射入口；流式读取 Parquet，SQLite 关联表与来源证据。所有有效提交均入队，不按日志词或敏感词预筛。
2. **统一分类和细分类**：AUTH、PII、QID、BIZ、CFG、DIAG 六类及 42 个受控细类，记录规则版本、证据、置信度和修改前后观察。42 是目录大小，不是实测缺陷种类数。
3. **未知类型待审队列**：保留未分类参数、宽泛载体、名称线索和语义缺失。已有部分标签的日志仍可能入队；未知不等于新类型，也不等于安全。
4. **按类型汇总与覆盖审计**：按日志版本去重，保留父提交、前后侧和来源引用；JSONL/CSV 输出类型、待审、文件、提交和全量 PR 覆盖。多标签频数不能相加当作独立日志数量。

PyDriller 实际承担指定提交遍历、修改文件提取、diff 解析及历史源码读取；Git 只辅助对象获取、提交图、合并差异和直接依赖读取。每条差异保留提取方法、回退与缺口。持久队列支持离线、预检、恢复与逐提交事务提交。原七阶段历史追踪流程继续保留。

## 最终真实批次

下表来自在线扩展后的一次离线恢复，两个进程均已结束，退出码均为 2（存在缺口）。队列中的所有任务都已有处理状态；**队列没有 pending 不表示代码全部分析完成**。

| 数据集 | 提交队列 | PyDriller 实读提交 | complete / partial | blocked | 去重日志版本 | 未知待审版本 |
|---|---:|---:|---:|---:|---:|---:|
| AIDev | 86,315 | 227 | 84 / 143 | 86,088 | 210 | 171 |
| SWE-chat | 8,697 | 1,296 | 574 / 722 | 7,401 | 2,736 | 2,665 |

`complete` 表示该提交在声明的静态范围内没有已记录缺口；不意味着全程序、所有语言或全部后续历史覆盖。

AIDev 完成 698 次文件差异解析、1,233 次历史源码读取，225 条观察去重为 210 个日志版本；SWE-chat 完成 9,227 次差异解析、14,701 次历史源码读取，2,885 条观察去重为 2,736 个版本。直接依赖辅助读取与 PyDriller 源码读取分开统计。

AIDev 的 blocked 中，86,048 个是在离线阶段缺少仓库，40 个来自先前在线获取失败；SWE-chat 对应为 7,239 和 162 个。在线错误当前记录到获取失败层级，不能据此断言仓库已删除、404 或权限拒绝。缺失项保留为覆盖缺口，可补齐对象后重试。

实际命中的细类频数如下，未命中项仍保留在完整目录和 CSV 中：

| 细分类 | AIDev 日志版本数 | SWE-chat 日志版本数 |
|---|---:|---:|
| AUTH.api_key | 0 | 5 |
| AUTH.password | 10 | 0 |
| BIZ.business_object | 0 | 5 |
| BIZ.request_body | 0 | 4 |
| BIZ.response_body | 0 | 14 |
| BIZ.unclassified_object | 2 | 0 |
| CFG.deployment_configuration | 0 | 10 |
| CFG.environment | 0 | 7 |
| CFG.filesystem_path | 17 | 9 |
| DIAG.exception_message | 16 | 327 |
| DIAG.stack_trace | 0 | 14 |
| QID.request_identifier | 0 | 1 |
| QID.session_identifier | 0 | 68 |

这些标签描述敏感值或可能承载敏感内容的静态线索。载体、名称线索和待定细类尤其需要复核；未出现的类型不能解释为数据集不存在该类型。

## 全量 PR 覆盖审计

最终 [AIDev 覆盖报告](../reports/aidev-corpus-v040-v3-offline/corpus_coverage.json) 将结果回接至 939,353 个 PR：33,580 个进入队列，64 个有真实 Git 提交证据，63 个有历史源码，32 个有支持范围内分析，17 个在单次运行中覆盖了其全部数据集提交。10 个有日志观察，7 个有类型标签，10 个有未知待审；939,321 个仍无可核验分析。

88,564 条上下文全部匹配冻结快照，来源、PR、仓库、SHA、父提交、前后侧及源码指纹均参与证据关联。各 PR 的运行状态可能重叠，不能求和；有记录、入队或匹配 PR URL 均不等于完成分析。

## 验证与修复

完整测试为 [276 passed in 20.21s](pytest_v040_verified.txt)，包含真实 PyDriller 合成 Git 历史、分类与结构化字段、未知队列、恢复、来源匹配和覆盖审计。真实数据还推动修复了纳秒时间戳、checkpoint 冲突、跨 fork 提交身份、结构化 keyword 和嵌套脱敏分类。

两个真实资源问题已修复：源码片段反复分割整份文件改为有界缓存；条件分支重复合并相同证据造成指数膨胀，改为共享函数稳定去重、保留不同证据。原问题提交分别在 1.42 秒及 2.407 秒的保护探针中完成；后者峰值内存约 57 MB，见 [资源验证记录](resource_growth_verification.json)。

初次稳定公共导出的 JSON/CSV 字段、去重引用、各类型与待审计数独立复算均一致，见 [初次输出核验](type_export_verification_v3_initial.json)。[最终恢复后的核验](type_export_verification_v3_final.json)也已完成：16 个导出文件哈希稳定、两套输出均为 0 项完整性问题。SWE-chat 有 2,254 个待审版本包含语义解析不可用原因，不能把这些词法观察算作完整语义覆盖。这些都是程序与自动检查结果，不是人工审核。SWE-chat 全量导入的 `--resume` 已验证来源和输出哈希。

原两套工具源码的 38 个文件哈希保持一致，见 [原源码核验](original_source_verification_v040.json)；papers 未修改。所有中断或旧版目录保留，正式结果以本文和 [机器进度记录](datasets_progress.json) 的 v3 路径为准。

## 实际执行的关键命令

以下路径相对于工作区根目录。完整结果保存在同目录对应 `*_command.json`；退出码 2 是缺口状态，不是全量分类成功。

```bash
agent_log_privacy/.venv/bin/agentlog-unified aidev-import --aidev-dir agentlog_unified/cache/aidev-frozen --output agentlog_unified/inputs/aidev-full-v2 --offline
agent_log_privacy/.venv/bin/agentlog-unified swechat-import --swechat-dir agentlog_unified/cache/swechat-frozen --output agentlog_unified/inputs/swechat-full-v3 --offline
agent_log_privacy/.venv/bin/agentlog-unified swechat-import --swechat-dir agentlog_unified/cache/swechat-frozen --output agentlog_unified/inputs/swechat-full-v3 --offline --resume
agent_log_privacy/.venv/bin/agentlog-unified commit-import --input agentlog_unified/inputs/aidev-full-v2/mining_prs.jsonl --output agentlog_unified/batches/aidev-full-v3 --offline
agent_log_privacy/.venv/bin/agentlog-unified commit-import --input agentlog_unified/inputs/swechat-full-v3/commit_contexts.jsonl --output agentlog_unified/batches/swechat-full-v3 --offline
agent_log_privacy/.venv/bin/agentlog-unified batch-mine --output agentlog_unified/batches/aidev-full-v3 --cache-dir agentlog_unified/cache/batch-repos --online --max-seconds 300 --resume
agent_log_privacy/.venv/bin/agentlog-unified batch-mine --output agentlog_unified/batches/swechat-full-v3 --cache-dir agentlog_unified/cache/batch-repos --online --max-seconds 300 --resume
agent_log_privacy/.venv/bin/agentlog-unified batch-mine --output agentlog_unified/batches/aidev-full-v3 --cache-dir agentlog_unified/cache/batch-repos --offline --max-seconds 300 --resume
agent_log_privacy/.venv/bin/agentlog-unified batch-mine --output agentlog_unified/batches/swechat-full-v3 --cache-dir agentlog_unified/cache/batch-repos --offline --max-seconds 300 --resume
agent_log_privacy/.venv/bin/agentlog-unified aidev-coverage --aidev-import agentlog_unified/inputs/aidev-full-v2 --analysis-run agentlog_unified/batches/aidev-full-v3 --output agentlog_unified/reports/aidev-corpus-v040-v3-offline --offline
agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q
```

当前运行流程和依赖安装见 [README](../README.md)。后续补齐 Git 缓存后，可以显式在线并用 `--retry-failed` 重试 blocked/partial；该参数会重算两种状态，不只是下载缺失对象。程序保留磁盘及获取时间预算，超限仍记录缺口，不删除历史输出。

## 当前结果入口和未完成部分

- AIDev：[类型汇总](../batches/aidev-full-v3/exports/type_summary.csv)、[未知待审](../batches/aidev-full-v3/exports/unknown_type_review_queue.csv)、[提交和文件覆盖](../batches/aidev-full-v3/exports/summary.json)。
- SWE-chat：[类型汇总](../batches/swechat-full-v3/exports/type_summary.csv)、[未知待审](../batches/swechat-full-v3/exports/unknown_type_review_queue.csv)、[提交和文件覆盖](../batches/swechat-full-v3/exports/summary.json)。

仍需补齐缺失仓库/对象及 PR—提交关系、扩展不支持或不完整的语义解析、复核未知类型、运行完整后续历史追踪。批量扫描范围明确为 `dataset_commit_changes`，不能替代七阶段流程的全部后续历史；后续追踪必须包括未命中敏感词的日志。会话、工具调用和 PR 正文目前仅作来源元数据，未做内容分类。

没有调用付费模型、执行目标程序、打印或验证真实凭证、修改远程仓库。当前不声称已经提取整个数据集的所有敏感类型，完整收集目标仍未完成。
