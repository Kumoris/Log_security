# AIDev 敏感类型收集：0.4.7 实际运行报告

记录日期：2026-09-09（北京时间）。当前目标仅为 AIDev；SWE-chat 的工具能力和历史证据保留，本轮未继续扫描。**本轮补齐了五个账户关联字段的全量分类，但尚未识别全部真实敏感数据类型。**

## 实现和实际数据结果

`schema-scan` 新增 `pr_commits.author/committer`、`pr_commit_details.author/committer` 和 `pr_timeline.assignee`，复用冻结 `user.login ∪ all_user.login` 做原字符串精确关联。不修剪、不忽略大小写、不做 Unicode 归一化；先检查空值、示例和异常，再匹配。匹配仅支持低置信 `QID.user_identifier`，未匹配保持 `unresolved`，不猜测姓名或判为安全。引用缺失、不完整及空表分别记录。

复用现有 Python、PyArrow、SQLite、统一分类及 CLI，没有新增依赖。原 27 个字段角色保持不变，总注册角色为 32 个，其中 AIDev 22 个。原工具源码未改动。

| AIDev 字段扫描 | 0.4.6 | 0.4.7 |
|---|---:|---:|
| 全部字段 | 160 | 160 |
| 明确映射字段 | 17 | 22 |
| 未完成语义映射字段 | 143 | 138 |
| 已分类源单元格 | 2,577,531 | 4,504,029 |
| 账户标识候选单元格 | 2,561,614 | 3,688,655 |
| 新增关联未匹配、类型待定单元格 | — | 485,812 |
| 空值 | 15,892 | 329,537 |
| 示例／占位线索 | 12 | 12 |
| 异常值 | 13 | 13 |

新增五字段共处理 **1,926,498** 个源单元格：1,127,041 个精确匹配候选、485,812 个未匹配待审、313,645 个空值。另读取 73,985 个引用表单元格，得到 72,189 个不同非空字符串；引用读取量独立统计，这些数值不是人数或有效账号数。

完整输出见 [字段覆盖](../schema-runs/aidev-v047/schema_coverage.json)、[候选 CSV](../schema-runs/aidev-v047/schema_context_candidates.csv)、[待审 CSV](../schema-runs/aidev-v047/schema_context_review_queue.csv)、[未映射字段 CSV](../schema-runs/aidev-v047/schema_unresolved_fields.csv)。每组同时提供 JSONL，按源表、列和精确行区间定位，不导出账号原值或其哈希。待审队列包含候选及其他质量状态，应按 `status` 筛选；未匹配的新增字段没有强行填入类型。

## 数据集范围与类型清单

冻结版本 `68ed5f4b80d27a9e057fc57567f38bd322ac73ec` 的 **18 表、2,456,073 行**已经全量导入。既有正文扫描已访问这些源行；唯一被规则匹配上限截断的单元格已完成有限规则补扫。去重合并结果仍为 **1,479,597 个正文候选身份**、11,871 个示例／排除观察；本轮没有重算或改写它们。[全量导入覆盖](../inputs/aidev-full-v2/coverage.json)、[正文去重合并覆盖](../reconciled-runs/aidev-v046/merged_coverage.json)

新清单仅汇总 AIDev：5 个历史 Git 批次、1 个正文合并来源、1 个新字段扫描来源，各自列出全部 42 个受控细类，共 294 行，保留零观察项。历史 Git 观察到 17 个标签，正文观察到 37 个，字段扫描观察到 1 个；**标签并集为 38 个**，不能把不同来源的候选计数相加。目录外正文候选为 3,243 个，其中 2,854 个标识符引用、389 个未知命名值。

[类型清单 CSV](aidev_observed_types_v047.csv) / [JSONL](aidev_observed_types_v047.jsonl)、[目录外汇总](aidev_observed_types_v047_outside_catalog.csv)、[来源、摘要与计数口径](aidev_observed_types_v047_provenance.json)。38 个观察标签不代表 38 种已经确认的真实敏感数据，42 个受控细类也不是现实类型全集。221 条来源／标签组合为零观察；AIDev 全部来源均为零的四个标签是 `BIZ.unclassified_content`、`CFG.unclassified_internal_resource`、`PII.unspecified_personal_information`、`QID.unspecified_linkable_identifier`，零观察不能解释为不存在。

## 实际执行与验证

以下入口均已实际运行；路径相对于工作区根目录。扫描和测试的完整参数、起止时间、退出码、源码和输出摘要见 [命令与执行记录](aidev_v047_commands.json)。

```bash
PIP_DISABLE_PIP_VERSION_CHECK=1 agent_log_privacy/.venv/bin/python -m pip install --no-index --no-deps --no-build-isolation -e agentlog_unified
agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q
agent_log_privacy/.venv/bin/agentlog-unified schema-scan --input agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/schema-runs/aidev-v047 --offline --batch-size 4096 --max-seconds 300 --dry-run
agent_log_privacy/.venv/bin/agentlog-unified schema-scan --input agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/schema-runs/aidev-v047 --offline --batch-size 4096 --max-seconds 300
agent_log_privacy/.venv/bin/agentlog-unified schema-scan --input agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/schema-runs/aidev-v047 --offline --batch-size 4096 --max-seconds 300 --resume
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/local_fixture_config.yaml --run-id synthetic-v047 --offline
```

- 清单构建脚本 [build_aidev_inventory_v047.py](build_aidev_inventory_v047.py) 已运行；10 项合成自检和 [20 项独立核验](aidev_inventory_v047_verification.json)通过。已有清单可用 `--check-only` 只读复核，直接重建会拒绝覆盖当前快照。
- **560 项 pytest 通过**，pytest 报告耗时 28.74 秒；[执行记录](aidev_v047_tests_execution.json)保存前后源码哈希。
- 预演退出 0，没有解码字段值或写入扫描目录；全量字段运行约 17.10 秒、恢复约 3.05 秒，两次计数一致。退出 2 表示仍有语义覆盖缺口，不表示漏洞已确认。
- 原 27 字段的合成输出对照一致；最终 28 项引用专项检查通过。[合成对照](schema_account_join_v047_legacy_comparison_final.json)、[引用边界验证](schema_account_join_v047_reference_audit_final.json)。实际数据的原 17 字段、区间、分类计数与导出一致性见 [独立核验](aidev_schema_v047_verification.json)。
- 合成七阶段流程退出 0，PyDriller 实际遍历 5 个提交、解析 5 次文件差异、读取 10 次历史源码；产生 2 个初始日志改动、3 个可能后续事件、1 个待审候选，属于校准样本。[合成运行记录](../runs/synthetic-v047/run_manifest.json)。本轮没有新增真实 Git 提交挖掘，历史 AIDev 去重实际提交数仍为 594。

## 尚未解决的部分

138 个字段尚未完成字段语义映射；这包含正文载体、资源引用、计数和普通元数据，不能把它们全部判敏感，也不能把它们当作安全。对未映射字段的有界格式探查覆盖 71,168 个单元格，在明确 JSON 围栏中成功解析 22 块；这只证明存在结构解码机会，不证明新增敏感类型。通用嵌套／编码解析本轮尚未接入。[格式与 assignee 全列证据](aidev_schema_gap_v047_review.json)

当前检测依赖有限值形态和字段名规则，仍可能漏掉隐含语义、嵌套字段、任意编码及间接值流。正文未知待审范围继续覆盖 17,362,345 个非空单元格；这些范围与字段未匹配队列重叠，不能相加。全部候选保持 `human_review_status=pending`、`runtime_confirmed=false`、`new_type_status=not_established`；没有完成真实值归属、凭证有效性或运行泄露确认。

本轮字段扫描没有因环境或数据缺失中断。未调用付费模型、未执行目标应用、未验证或打印真实凭证、未修改远程仓库。两份旧中断导入目录此前已经按确认删除，释放约 2.97 GiB；本轮复核均不存在，未追加清理，`papers` 保留。[删除回执](cleanup_review_v042/deletion_receipt.json)、[当前进度](datasets_progress.json)
