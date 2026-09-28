# AIDev 敏感类型收集：0.4.8 实际运行报告

记录日期：2026-09-09（北京时间）。本轮完成 **18 表、2,456,073 行的 JSON 结构补充扫描**，并核验恢复和导出。相对既有正文结果，新增 **14 组“源单元格 × 类型”观察关系**，涉及 7 个已有标签；全局标签并集仍为 38。**尚未识别全部真实敏感数据类型。**

## 本轮实现

新增 `structured-scan`，复用现有 Python、PyArrow、SQLite、有限分类规则和压缩导出，未新增依赖。扫描整格 JSON、明确标记为 JSON 的 Markdown 围栏，以及最多两层 JSON 字符串解码。先识别语法并遍历所有节点，不按敏感关键词预筛文档。保留重复键的成员顺序；容器类型不传播给子项；空值、布尔值、空容器和示例分别计数。

支持 `--offline`、`--dry-run`、`--resume`、行数/时间预算和原子检查点，输入与实现均有哈希约束。限制为每单元格 1,048,576 个 Unicode 字符、128 个文档、深度 32、10,000 个节点、1,000 条匹配；超限记录原因，不假装完整。输出只含受控标签、来源位置与整数节点路径，不输出源值、动态 JSON 键或值哈希。原始文档偏移与解码后叶节点偏移分开，不能互相替用。

本轮观察范围是 `dataset_structured_text`。PyDriller 仍承担应用日志流程的 Git 读取；此次 JSON 扫描不是新增的应用日志缺陷证据，也未新增真实 Git 提交挖掘，历史 AIDev 实际去重提交数仍为 594。

## 实际扫描结果

冻结数据版本为 `68ed5f4b80d27a9e057fc57567f38bd322ac73ec`，继续使用已有全量导入。访问行数表示已提交处理的源行，恢复跳过前缀时 Arrow 可能额外解码，不能当成物理读取次数。

| 指标 | 实际数量 |
|---|---:|
| 已完成表 / 源行 | 18 / 2,456,073 |
| 访问文本单元格 | 18,932,477 |
| 非空 / 空值 / 空字符串 | 17,362,345 / 1,570,131 / 1 |
| 选中的 JSON 文档候选，包含解析失败项 | 49,669 |
| 成功解析顶层 JSON / 无效 JSON / 未闭合围栏 | 5,422 / 44,166 / 81 |
| 非排除候选 / 示例或排除观察 | 1,140 / 57 |
| 结构化观察到的受控标签 | 32 |
| 解析缺口记录 | 44,289 |
| 待审行区间 / 覆盖非空单元格 | 570,513 / 17,362,345 |

1,140 条候选包含 627 条载体线索、429 条命名值线索、74 条字面值形态线索和 10 条标识符引用，不是 1,140 份已确认敏感数据。44,289 个缺口由 44,166 个无效 JSON、81 个未闭合围栏、42 次无效内层 JSON 解码组成；本次没有触发节点、匹配、深度或源长度上限。成功顶层解析可能仍有内层缺口，文档状态因此另分为 5,387 个 `parsed_with_semantic_gaps`、116 个 `partial` 和 44,166 个 `invalid_json`。

[完整覆盖与限制](../structured-runs/aidev-v048/structured_coverage.json)保存逐表计数；[导出状态](../structured-runs/aidev-v048/export_state.json)保存文件摘要。6 组结果同时提供压缩 JSONL/CSV：文档、候选、排除、缺口、未知待审、按类型汇总。例如 [候选 JSONL](../structured-runs/aidev-v048/structured_type_occurrences.jsonl.gz) / [CSV](../structured-runs/aidev-v048/structured_type_occurrences.csv.gz)、[待审 JSONL](../structured-runs/aidev-v048/structured_unknown_type_review_queue.jsonl.gz)。每个非空单元格都保留待审范围，`not_applicable` 只表示未识别支持的结构，不能解释为安全。汇总的未知标签为零，是因为未映射键仅进入计数和待审，不能说明没有未知类型。

## 与既有结果比较

按同一冻结来源的“表、列、行、类别、细类”去重比较，旧正文基线有 639,210 组受控关系，结构化结果有 866 组，其中 852 组已在基线中，14 组为增量。审计验证了旧正文、补扫和合并的来源与实现，才采用其非排除集合并集；没有把不同解析器的字符坐标强行对齐。[增益核验](aidev_structured_gain_v048.json)

| 既有标签 | 新增单元格 × 类型关系 |
|---|---:|
| `AUTH.password` | 2 |
| `AUTH.access_token` | 3 |
| `AUTH.credential_bundle` | 2 |
| `BIZ.document_content` | 1 |
| `BIZ.business_object` | 4 |
| `CFG.database_connection` | 1 |
| `DIAG.stack_trace` | 1 |

14 组关系对应 18 条结构化观察证据，见 [证据 JSONL](aidev_structured_gain_v048_evidence.jsonl.gz) / [CSV](aidev_structured_gain_v048_evidence.csv.gz)。这表示新增识别位置，**不代表新发现的真实秘密、泄露或敏感类型**；尚未人工确认。

新类型清单为 **8 个来源 × 42 个受控细类，共 336 行**，原 294 行保持不变，保留 231 个零观察组合。AIDev 标签并集仍是 38，全部来源零观察的四项仍为 `BIZ.unclassified_content`、`CFG.unclassified_internal_resource`、`PII.unspecified_personal_information`、`QID.unspecified_linkable_identifier`。目录外正文 3,243 条候选另列；新结构化来源的零观察也显式列出。旧正文 1,479,597 个候选身份、字段候选和本轮结构化观察的计数单位不同，不能直接相加。

[清单 CSV](aidev_observed_types_v048.csv) / [JSONL](aidev_observed_types_v048.jsonl)、[目录外清单](aidev_observed_types_v048_outside_catalog.csv)、[来源和口径](aidev_observed_types_v048_provenance.json)、[清单核验](aidev_inventory_v048_verification.json)。

## 实际执行与验证

以下命令均已执行；路径相对于工作区根目录。完整参数、退出码、时间与摘要见 [执行记录索引](aidev_v048_commands.json)。

```bash
PIP_DISABLE_PIP_VERSION_CHECK=1 agent_log_privacy/.venv/bin/python -m pip install --no-index --no-deps --no-build-isolation -e agentlog_unified
agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q
agent_log_privacy/.venv/bin/agentlog-unified structured-scan --input agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/structured-runs/aidev-v048 --offline --batch-size 32 --max-seconds 900 --dry-run
agent_log_privacy/.venv/bin/agentlog-unified structured-scan --input agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/structured-runs/aidev-v048 --offline --batch-size 32 --max-seconds 900 --max-rows 1000
agent_log_privacy/.venv/bin/agentlog-unified structured-scan --input agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/structured-runs/aidev-v048 --offline --batch-size 32 --max-seconds 900 --resume
agent_log_privacy/.venv/bin/python agentlog_unified/docs/build_aidev_inventory_v048.py
agent_log_privacy/.venv/bin/python agentlog_unified/docs/verify_aidev_structured_v048.py
agent_log_privacy/.venv/bin/python agentlog_unified/docs/audit_aidev_structured_gain_v048.py
```

- **627 项 pytest 通过**，pytest 耗时 30.06 秒；[执行前后源码与测试哈希一致](aidev_v048_tests_execution.json)。测试包含真正读取本地合成 Git 历史的 PyDriller 测试；本轮没有另跑 `synthetic-v048` 七阶段命令。
- 预演退出 0；1,000 行试跑退出 2。全量从试跑检查点继续，新增处理 2,455,073 行，耗时 463.72 秒，退出 2。退出 2 表示语义缺口仍在，不是发现漏洞的确认。
- 上述恢复命令实际执行两次：第二次耗时 8.15 秒，新增处理 0 行。恢复前后 5 个逻辑表与 12 个压缩导出全部相同。[恢复对照](aidev_structured_v048_resume_verification.json)
- [71 项真实导出核验](aidev_structured_v048_verification.json)通过：6 组 CSV/JSONL 与 SQLite 逐字段一致，有限输出字段、坐标、分类零项、来源与待审区间均验证；试跑文档、匹配、缺口完整保留，部分相邻待审区间在续扫中正常延伸。
- 增益核验首次因辅助脚本误解旧合并指纹格式而退出 1；已只修正核验脚本，重跑退出 0。失败记录保留，扫描源码与结果未改动。[修正及重跑记录](aidev_structured_gain_v048_execution.json)

这些运行已结束，没有后台扫描写入。当前源码/导出与文档的最终核对见 [交付核验](aidev_delivery_v048_verification.json)。

## 尚未完成的范围

JSON 结构解析补上了有限嵌套场景，仍不支持任意编码、任意格式或完整程序语义。138 个字段的语义映射、五个账户关联字段中的 485,812 个未匹配单元格仍待解决。作者字段的本地文档描述 login 优先、commit name 回退，但冻结版本的实际生产分支和逐行归属未核实，不能把未匹配值直接改标为姓名。[作者语义核对](aidev_author_semantics_v048_review.json)

全部 17,362,345 个非空文本单元格继续保留语义待审；各扫描队列重叠，不能相加。有限目录的 42 个细类不是现实类型全集，38 个观察标签也不是 38 种人工确认数据。候选继续保持 `human_review_status=pending`、`runtime_confirmed=false`、`new_type_status=not_established`，大部分真实 Git 历史覆盖仍未完成。

本轮全量扫描没有因环境或缺失文件中断；解析失败已逐条记录。未调用付费模型、未执行目标应用、未验证或输出真实凭证、未修改远程仓库；SWE-chat 未扩扫。两个旧中断导入目录已按此前确认删除，逻辑文件量约 2.97 GiB，现用导入保留，删除回执中的 `papers` 校验未变；本轮未追加清理。[删除回执](cleanup_review_v042/deletion_receipt.json)、[当前进度](datasets_progress.json)
