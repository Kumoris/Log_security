# 0.4.1：扩大真实对象获取与敏感类型观察

> 历史版本记录：当前 Go 检测与扩展批次见 [0.4.2 报告](datasets_v042_report.md)。本页统计保留原运行口径。

**本轮继续推进了实际收集和分类，完整目标仍未完成。** 本版增加按需 Git 对象获取、补充提交锚点导出，并修复 JS/TS 模板表达式漏提取。所有类型仍为静态线索或载体标签，未标为人工确认或运行时泄漏。

## 当前数据与新增证据

AIDev 冻结版全部 18 表、2,456,073 行元数据，以及 SWE-chat 全部 6 表、2,732,252 行元数据已接入；版本与哈希沿用 [0.4.0 报告](datasets_v040_report.md)。元数据接入不等于源码已完整分析。

新增补充导出读取已有源表的 371,818 行，恢复此前未使用的结构化 SHA：26,494 个新增 PR＋SHA 关联，其中可挖掘输入为 24,468 个仓库＋SHA、25,152 条上下文。另有 2,017 条 referenced/closed 等仅关联上下文，192 条无法确定 PR 关系的字段缺口。该补充只为此前没有任何结构化 SHA 的 16 个 PR 增加关联锚点，仍有 905,757 个 PR 没有这些结构化锚点。

merge、review、force-push 等锚点不等同 Agent 初始提交；原始 PR 成员表没有扩展。[补充导出与 CLI 核验](aidev_anchor_cli_v041_verification.json)记录了来源行、字段、哈希及角色保留情况。

## 对象获取改进与实际运行

`collect-objects` 显式获取精确 SHA 的两层提交图、变更文件 blob 和有界直接 Python 依赖，再由 PyDriller 离线读取。原生 Git 的 raw tree 差异仅用于决定获取哪些对象，不替代 PyDriller 的代码差异解析。所有 Git 子进程禁用隐式获取，无 checkout、目标代码执行或远程写入。

AIDev 首轮成功准备 150 个提交，耗时 192.89 秒；依赖预算修正后再次核对同一组，耗时 17.83 秒，150 个均就绪。缓存实际磁盘占用约 20.5 MiB。补充锚点另准备 20 个提交，耗时 35.33 秒，缓存约 1.1 MiB。准备完成本身不算已分类；如下表的读取均来自随后实际运行的 PyDriller。

| 当前批次 | 实读提交 | diff 解析 | 历史源码读取 | 去重日志版本 | 未知待审 | pending / blocked |
|---|---:|---:|---:|---:|---:|---:|
| AIDev 主队列 v4 | 155 | 554 | 957 | 134 | 111 | 86,158 / 2 |
| SWE-chat v4 | 1,296 | 9,227 | 14,701 | 2,953 | 2,882 | 0 / 7,401 |
| AIDev 补充锚点 | 21 | 76 | 142 | 3 | 3 | 24,442 / 5 |

AIDev 主队列 v4 是新分类器下的部分重跑，不是 v3 的完整替换：v3 读过 227 个提交，v4 读过 155 个，其中 38 个此前未读到；两代提交去重并集为 265。不同分类器运行的类型计数不能直接相加。补充锚点单独统计，不能与主队列或独立 PR 数直接相加。

所有这些真实命令均已结束，退出码为 2，表示仍有缺口或待处理任务。语义和语言缺口保留为 partial；缺对象不当作没有敏感类型。

## 同一 SWE-chat 样本的实际改进

SWE-chat 两版扫描的是同一批 1,296 个提交，均完成 9,227 次差异解析和 14,701 次历史源码读取。修复后的日志版本从 2,736 增至 2,953，观察类别从 5 增至 6，细类从 11 增至 20；未知待审从 2,665 增至 2,882。

[逐版本对比证据](swechat_v041_classifier_comparison.json)确认：2,731 对可靠匹配中，110 对增加弱类型线索，78 对此前没有标签，没有配对丢失原标签；4 对重复语句保留歧义。另有 218 个新增检测，1 个位于字符串内部的旧误检测被移除。Python 的 482 个日志版本未变。

全部 2,471 个 JS/TS 词法版本仍保留低置信、未知待审和人工 pending，不把 Pygments tokenizer 叫作语义 AST。边界检查没有把记录提升为运行时泄漏、完整历史或全量覆盖。

当前 SWE-chat 实际观察到的细类如下，频数是可重叠的日志版本数：

| 细类 | 含义 | 版本数 |
|---|---|---:|
| AUTH.access_token | 访问令牌 | 1 |
| AUTH.api_key | 服务密钥 | 5 |
| AUTH.credential_bundle | 其他认证秘密或凭证对象 | 1 |
| BIZ.business_object | 业务对象载体 | 32 |
| BIZ.document_content | 文档及内容载体 | 1 |
| BIZ.http_headers | 请求响应头载体 | 1 |
| BIZ.request_body | 请求体载体 | 24 |
| BIZ.response_body | 响应体载体 | 56 |
| BIZ.unclassified_content | 细类待确定 | 3 |
| BIZ.unclassified_object | 细类待确定 | 3 |
| CFG.deployment_configuration | 配置及部署载体 | 38 |
| CFG.environment | 环境变量载体 | 14 |
| CFG.filesystem_path | 内部文件路径 | 16 |
| DIAG.exception_message | 异常内容载体 | 367 |
| DIAG.stack_trace | 堆栈载体 | 27 |
| PII.email | 邮箱 | 5 |
| PII.person_name | 个人姓名 | 15 |
| QID.request_identifier | 请求关联标识 | 21 |
| QID.session_identifier | 会话标识 | 69 |
| QID.transaction_identifier | 业务关联标识 | 2 |

完整 [类型目录 CSV](observed_type_inventory_v041.csv)保留 42 个受控细类，包括本轮零观察项，并分别列出三个当前批次的计数；没有把未观察到的类型判为不存在。20 是当前样本的静态观察目录，不是完整数据集的敏感类型总数。

## 覆盖与正确性验证

当前 [全量 PR 覆盖审计](../reports/aidev-corpus-v041/corpus_coverage.json)保留 939,353 个 PR 分母。v4 中有 42 个 PR 具备真实 Git 提交读取、41 个具备历史源码、16 个具备支持范围分析、6 个具备类型观察。25,152 条补充锚点上下文全部因不属于冻结主 PR 提交成员证据而排除出主覆盖统计；逐 ID 核验一致，没有虚增覆盖。[命令和集合差集核验](aidev_corpus_v041_command.json)同时保留了 v3/v4 的提交并集证据。

[完整测试](pytest_v041_verified.txt)为 **295 passed in 22.58s**。新增检查真实构建 Git 历史，覆盖 blobless 获取后离线 PyDriller、根提交、合并、重命名、子模块、直接依赖、恢复、失败获取留证及 JS/TS 模板新增/删除。

验证期间修复了一处实际依赖预算不一致：旧采集实现先展开所有候选路径再截断，12 个本可解析的 helper 只获取了 7 个。现在与矿工相同，按尝试路径计数、首个可读模块命中后停止，12 个均被读取。显式重试支持 partial 的对象补采；失败 fetch 的尝试数、阶段和失败原因均入证据。已完成获取记录保留在独立 SQLite 表，不随重新挖掘清除；中断未提交的获取会重试，不算已完成。

[最终输出核验](type_exports_v041_verification.json)重算了三个批次的类型计数、未知队列成员、JSONL/CSV 行数和当前源码指纹，均一致。测试与自动核验不是人工审核。

## 实际命令与结果入口

工作区根目录执行；同名 `*_command.json` 保存真实结果。

```bash
agent_log_privacy/.venv/bin/agentlog-unified aidev-anchor-export --aidev-import agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/inputs/aidev-anchors-v2 --offline --resume
agent_log_privacy/.venv/bin/agentlog-unified collect-objects --output agentlog_unified/batches/aidev-full-v4 --cache-dir agentlog_unified/cache/object-repos --online --max-commits 150 --max-seconds 240 --resume
agent_log_privacy/.venv/bin/agentlog-unified collect-objects --output agentlog_unified/batches/aidev-full-v4 --cache-dir agentlog_unified/cache/object-repos --online --max-commits 150 --max-seconds 240 --resume --retry-failed
agent_log_privacy/.venv/bin/agentlog-unified batch-mine --output agentlog_unified/batches/aidev-full-v4 --cache-dir agentlog_unified/cache/object-repos --offline --max-repositories 9 --max-seconds 240 --resume
agent_log_privacy/.venv/bin/agentlog-unified batch-mine --output agentlog_unified/batches/swechat-full-v4 --cache-dir agentlog_unified/cache/batch-repos --offline --max-seconds 300 --resume
agent_log_privacy/.venv/bin/agentlog-unified collect-objects --output agentlog_unified/batches/aidev-anchors-v2 --cache-dir agentlog_unified/cache/anchor-object-repos --online --max-commits 20 --max-seconds 90 --resume
agent_log_privacy/.venv/bin/agentlog-unified batch-mine --output agentlog_unified/batches/aidev-anchors-v2 --cache-dir agentlog_unified/cache/anchor-object-repos --offline --max-repositories 5 --max-seconds 180 --resume
agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q
```

- AIDev 主队列：[类型](../batches/aidev-full-v4/exports/type_summary.csv)、[未知待审](../batches/aidev-full-v4/exports/unknown_type_review_queue.csv)、[对象获取记录](../batches/aidev-full-v4/collection/object_acquisitions.jsonl)。
- SWE-chat：[类型](../batches/swechat-full-v4/exports/type_summary.csv)、[未知待审](../batches/swechat-full-v4/exports/unknown_type_review_queue.csv)。
- 补充锚点：[来源覆盖](../inputs/aidev-anchors-v2/coverage.json)、[类型](../batches/aidev-anchors-v2/exports/type_summary.csv)、[未知待审](../batches/aidev-anchors-v2/exports/unknown_type_review_queue.csv)。

## 尚未完成的部分

绝大多数输入提交仍需获取或分析，很多 PR 缺少提交关联；Go、PHP、C#、Java 等尚未解析。其中当前 AIDev 主队列含 260 个 Go、60 个 Java 未支持文件差异；SWE-chat 含 630 个 Go、229 个 PHP、162 个 C# 未支持文件差异。这些是后续扩展的实际优先项。

未知类型仍需复核；浅层对象扫描没有完成全部后续历史。PR 和会话正文仍只保留来源元数据，没有进行正文敏感内容分类。磁盘剩余约 3.6 GiB，获取工具继续执行磁盘保底，不擅自删除旧输出。两套原工具源码和 papers 未修改，没有调用付费模型、验证真实凭证或改动远程仓库。完整收集并分类目标仍保持未完成。
