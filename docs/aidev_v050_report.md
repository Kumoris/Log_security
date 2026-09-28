# AIDev 0.5.0 实际运行报告

本版已完成工具修改、安装、722 项 pytest、冻结 AIDev 18 表重扫、截断补扫、去重合并和分类清单核验。分类规则为 1.2.0，目录仍有 49 个细类；没有宣称已识别全部真实敏感类型。

## 实现

日志、正文和 JSON 键共用字段规范化及最终字段匹配，修复缩写边界、聚合字段回流和父对象误分类。例如 `APIKey.id` 不再因为父对象名称就被归为密钥。JSON 结构检测器 1.1.0 新增有限直接父字段上下文，以 `json_parent_key_hint` 单列依据；数组元素、再解码及中间对象边界不自动继承祖先含义。具名凭证脱敏复用 AUTH 与邮箱字段规则。[规则说明](taxonomy_v120_notes.md)、[实际应用记录](aidev_v050_apply_execution.json)

沿用已有 Python 包、CLI、配置、锁定依赖与离线流水线，没有新增依赖。正式源码的整体测试为 **722 passed in 33.27s**，包含真正创建本地合成 Git 历史并由 PyDriller 读取的测试，以及 Parquet 接入、补扫和合并测试；测试前后源码与测试文件摘要一致。本轮没有另跑独立七阶段 CLI，也没有新增真实 Git 仓库挖掘。[测试输出](aidev_v050_tests_stdout.txt)、[实际命令及源码摘要](aidev_v050_tests_execution.json)

## 完整数据结果

本次输入是冻结版本 `68ed5f4b80d27a9e057fc57567f38bd322ac73ec`，导入 manifest SHA 为 `a533395acbf4511b384abd33d8ca4b7f88d5bc8f5eddcbcdd420177c88979bd1`。两路都完成 **18 表、2,456,073 行、17,362,345 个非空文本单元格**的处理。源行计数表示已提交处理的行，不等于恢复过程中的物理读取次数。

| 结果范围 | 候选 | 示例或排除 | 覆盖及单位 |
|---|---:|---:|---|
| 正文扫描 | 1,481,325 | 11,872 | 单元格、跨度、规则与类型的观察 |
| 唯一截断单元格补扫 | 4,112 | 0 | 74,169 字符、29 个规则页，补扫缺口 0 |
| 正文去重合并 | **1,484,437** | **11,872** | 候选身份与证据变体数量相同 |
| JSON 结构扫描 | **1,180** | 57 | 文档、成员序号、解码跨度及有限分类详情 |

补扫中原有 1,000 条观察完整保留，增加 3,112 个身份；合并识别并替换这 1,000 条重复，无父身份移除或详情冲突。正文与补扫不能直接相加，JSON 结构观察也不能加到正文或应用日志数量中。[合并覆盖](../reconciled-runs/aidev-v050/merged_coverage.json)

正文规则观察总数相对 v049 净增 **2,470**，排除记录净增 1。质量类别的净变化为引用 +1,070、载体 +1,039、命名值候选 +361、字面值候选 0。32 个细类的计数改变，包括出生日期 −4、路径 −3、失败响应 −1；这些是规则观察差异，不是已确认隐私缺陷增益。[逐类型计数比较](aidev_plaintext_v049_v050_type_delta.json)

结构化结果中，原 1,216 条候选及示例记录完整元数据逐字段保留，新增 **21 条**、减少 0。其中 16 条来自有有限依据支持的直接父字段组合（用户标识 8、姓名 6、年龄 1、交易标识 1）；其余 5 条仍为未决组合（请求标识 1、请求体 2、响应体 2）。原先另 25 条不受控组合仍被拒绝。新增项全部低置信，17 条命名提示、4 条载体提示；未转成人工确认。

当前结构候选观察到 36 个目录标签，仍保留 **44,289 条语法或解码缺口**，以及 22,952 个未知节点。570,513 条结构待审区间和 1,115,569 条正文待审记录分别覆盖全部非空文本单元格，两个队列可能重叠。[结构化独立核验](aidev_structured_v050_verification_attempt02.json)

## 类型清单与探查边界

最终清单有 **588 行 = 12 个来源 × 49 类**。历史 490 行、4 条目录外记录和 10 个来源对象均原样保留；56 行仍是 `not_evaluated/null`，没有倒填为零。其余 532 行在各自来源规则下评估，其中 268 行没有候选。跨来源观察标签并集为 **45 类**，本版正文为 44 类、结构化为 36 类，不能相加。正文目录外候选仍为 3,243 条；未知标签计数不能代表全部未知语义。

[清单 CSV](aidev_observed_types_v050.csv) / [JSONL](aidev_observed_types_v050.jsonl)、[目录外清单](aidev_observed_types_v050_outside_catalog.csv)、[来源与单位](aidev_observed_types_v050_provenance.json)、[清单独立核验](aidev_inventory_v050_verification.json)

本轮还完成两类独立探查：

- 5,422 份可回放顶层 JSON 文档（含 35 份有内层缺口的 `partial`）中，98 个预设别名没有产生新增观察。父上下文探查仅选其中 5,387 份无解析缺口文档；其 16 个新增节点×类型位置的去重关系为 13 个单元格×类型、10 个单元格，不能把 13 当成相对旧全单元格基线的净增。
- 全部 105 个字符串列、18,932,477 个文本单元格（含空值）和 2,706,989,370 个字符中，发现 28 处固定别名赋值、19 个单元格。有限回放选 14 处、11 个单元格：1 处同跨度已有类型，13 处没有；但 12 处所在整个单元格已含对应类型，余下 2 处是未决的环境变量标记。本版未据此新增别名或目录类型。

上述探查只输出有限标签与来源坐标，未导出原值、动态键或值哈希；不能将语法线索称为真实敏感值或真实漏报。[探查简报及全部证据](alias_discovery_v050_summary.md)、[父上下文固定回放](aidev_structured_parent_context_v050_replay.json)

## 实际运行与核验

| 执行 | 实际结果 |
|---|---|
| 正文首轮 | 935.42 秒，时间预算停止于 1,561,291 行；中间快照另存 |
| 正文恢复 | 502.06 秒，完成全部源行 |
| 结构化完整运行 | 574.79 秒，完成全部源行 |
| 结构化恢复 | 10.39 秒，新增 0 行，5 个逻辑表和 12 个压缩导出一致 |
| 补扫 / 再恢复 | 14.79 秒 / 0.51 秒；再恢复新增 0 页，10 个导出和 manifest 一致 |
| 去重合并 | 112.76 秒，来源验证完成 |

上述数据阶段均退出 2，表示结果仍有覆盖或语义缺口；安装、预演和测试退出 0。所有实际命令、参数、时间、退出码和前后源码摘要见 [16 条执行记录索引](aidev_v050_commands.json)。本轮独立核验全部通过：正文 **69/69**、结构化 **83/83**、补扫 **65/65**、合并 **181/181**、清单 **29/29**。[正文](aidev_content_v050_verification.json)、[补扫](aidev_repair_v050_verification.json)、[合并](aidev_reconcile_v050_verification.json)

结构化首次独立核验为 80/81：核验器把结构化运行 manifest 的摘要误当成原始导入 manifest 的摘要。改为验证“探查 → 旧结构化运行 → 原始导入及文件签名”的来源链后，83/83 通过；原始数据和探查结果没有改写，首次失败报告及首版 helper 保留。[首次失败](aidev_structured_v050_verification.json)、[修正记录](aidev_structured_v050_verifier_correction.json)

主要实际入口如下；从工作区根目录运行。已有目录恢复使用 `--resume`，预演使用 `--dry-run`，精确参数以执行索引为准。

```bash
agent_log_privacy/.venv/bin/python -m pip install --no-index --no-deps --no-build-isolation -e agentlog_unified
agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q
agent_log_privacy/.venv/bin/agentlog-unified content-advance --input agentlog_unified/content-runs/aidev-v050-seed --output agentlog_unified/content-runs/aidev-v050 --offline --batch-size 64 --max-seconds 900 --min-free-gib 2 --resume
agent_log_privacy/.venv/bin/agentlog-unified structured-scan --input agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/structured-runs/aidev-v050 --offline --batch-size 32 --max-seconds 900
agent_log_privacy/.venv/bin/agentlog-unified content-repair --input agentlog_unified/content-runs/aidev-v050 --output agentlog_unified/repair-runs/aidev-v050 --offline --max-seconds 300
agent_log_privacy/.venv/bin/agentlog-unified content-reconcile --input agentlog_unified/content-runs/aidev-v050 --repair-run agentlog_unified/repair-runs/aidev-v050 --output agentlog_unified/reconciled-runs/aidev-v050 --offline
```

## 仍未完成的目标

本轮没有环境阻断，所有数据处理和独立核验已结束。仍未解决的是语义与数据覆盖：49 类有限目录不等于现实敏感类型全集；138 个 schema 字段和 485,812 个账户关联单元格沿用此前待审状态，本轮没有重算 schema。任意编码、复杂上下文、未映射类型及大部分真实 Git 历史仍需继续研究。

本轮没有新增真实 Git 提交观察（历史累计 594 个），没有调用外部付费模型、执行目标应用、验证真实凭证、修改远程仓库或继续扩扫 SWE-chat，也没有新增删除操作。所有规则候选保持 `human_review_status=pending`、`runtime_confirmed=false`、`new_type_status=not_established`。最终版本、文档链接和记录一致性见 [交付核验](aidev_delivery_v050_verification.json)。
