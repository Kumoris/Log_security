# AIDev / SWE-chat：0.4.5 实际执行报告

> 历史快照：本文数字截至 2026-09-08 21:52 UTC。后续执行见 [0.4.6 报告](datasets_v046_report.md)；尤其 SWE-chat 补扫已继续推进，v044 的共享 SQLite 也已由 v046 续扫，本文所链接的部分运行文件可能已更新。本文旧数字保留，不作为最新统计。

记录日期：2026-09-09（北京时间）。当前工具已增加字段语义扫描和截断单元格补扫，AIDev 冻结版全部 2,456,073 表行的字符串列已实际遍历。**完整数据库的全部敏感类型仍未识别完成**：SWE-chat 正文未扫完，字段和文本语义仍有未知，真实 Git 历史覆盖也不完整。

## 当前能力与入口

沿用 `ingest → collect → mine → detect → trace → assess → export`，保留 PyDriller、统一分类、未知队列、JSONL/CSV、证据包与覆盖审计。新功能直接加入现有包，没有新依赖；原 `agent_log_privacy/src` 和下载的 `agentlog-core/agentlog` 未改动。

| 入口 | 当前实现 | 证据范围 |
|---|---|---|
| `content-scan` | 冻结 Parquet 所有字符串列、完整源行游标、空值/截断/待审记录、恢复 | `dataset_text_cells` |
| `schema-scan` | 全部字段清单；18 个明确字段逐值扫描；空值、无效值、示例和未映射字段分别导出 | `dataset_schema_context` |
| `content-repair` | 固定父运行中的截断单元格选择；按规则分页补扫整个单元格；跨页、长 PEM、事务游标和恢复 | `dataset_text_cell_rescan` |
| 原日志分析 | PyDriller 提交遍历、文件差异、前后源码与历史日志行为；分类和待审独立保留 | 应用日志代码证据 |

三个数据扫描入口均支持 `--offline`、`--dry-run`、`--resume`。恢复校验输入和实现指纹；修复补扫还校验选集、源文件和私有单元格指纹。正文/字段扫描不执行目标仓库，也不把数据库中的 patch 或会话文本当作实际 Git 日志证据。关于数据库正文是否属于最终研究范围，继续采用“与应用日志分开分析”的工作假设。

## 已实际扫描的数据

保持冻结来源：AIDev 18 表，修订 `68ed5f4b80d27a9e057fc57567f38bd322ac73ec`；SWE-chat 6 表，修订 `f66cca95b14caaa4177f7ed5eaa424608dadcffa`。24 表原始文件总计 3,372,920,679 字节。另一份 AIDev 11 表快照未混入分母。

| 正文指标 | AIDev | SWE-chat |
|---|---:|---:|
| 已解码源行 / 全表源行 | 2,456,073 / 2,456,073 | 204,057 / 2,732,252 |
| 已访问非空文本单元格 | 17,362,345 | 2,242,473 |
| 父运行候选命中 | 1,476,485 | 2,352,157 |
| 另列示例线索命中 | 11,871 | 26,018 |
| 父运行截断单元格 | 1 | 567 |
| 父正文观察到的受控细类 | 37 | 36 |
| 状态 | `complete_with_semantic_gaps` | `partial` |

这里的“行”是各源表实际解码的行，不是独立 PR 或用户。“命中”是单元格、字符位置、规则和类型的观察，包含引用和内容载体，不能当作秘密、人数、日志条数或泄露事件数。AIDev 的候选状态包括：387,789 个值形态线索、136,826 个命名值线索、521,033 个标识符引用、430,448 个载体线索、389 个未知命名值。语义未知部分持续保留待审。

SWE-chat 的 `checkpoints` 13,406 行、`commits` 14,459 行已完成；`conversations` 已扫 176,192 / 2,692,480 行；`repositories`、`session_logs`、`sessions` 的正文扫描尚未开始。仍有 **2,528,195 源行**未解码。字段扫描可能已读取其中特定字段，不能因此将这些行的正文记为已完成。

当前输出：[AIDev 正文覆盖](../content-runs/aidev-v044/content_coverage.json)、[类型汇总](../content-runs/aidev-v044/content_type_summary.csv)；[SWE-chat 正文覆盖](../content-runs/swechat-v044/content_coverage.json)、[类型汇总](../content-runs/swechat-v044/content_type_summary.csv)。旧 v044 首轮报告和指标快照保留；这些运行目录的正文结果已通过真实 `--resume` 更新。

## 字段语义：清单完整，映射有界

完整盘点 **308 个字段定义**：AIDev 160，SWE-chat 148。其中 184 个是文本字段，124 个是非文本字段。完成 18 个明确字段的补充扫描（6 个数字账户 ID 字段、12 个文本字段）；其余 **290 个字段仍为 `schema_semantics_unresolved`**，不能写成完成了全部字段的语义分类。

| 字段扫描指标 | AIDev | SWE-chat |
|---|---:|---:|
| 完成映射字段 / 全部字段 | 8 / 160 | 10 / 148 |
| 解码源单元格 | 1,160,097 | 5,473,755 |
| 字段含义候选单元格 | 1,160,073 | 4,252,940 |
| 空值 | 22 | 1,220,715 |
| 无效值 | 0 | 100 |
| 示例线索 | 2 | 0 |
| 未映射字段 | 152 | 138 |

AIDev 映射明确账户 ID 和 login；SWE-chat 映射作者姓名/邮箱/GitHub 用户名、账户及会话 ID。普通仓库 `id/name` 不据名称泛化为个人信息。精度不可靠的浮点 ID、空值和不符合字段形态的值单列；未解码列的空白/无效值计数保持未知。

上述 **6,633,852 是源单元格数**，不是不同源行、账户或人数。候选区间记录有 3,922 条，全部待审区间有 7,831 条，它们只是连续源行的压缩表示。字段含义不证明个人归属、真实敏感性或泄露。

输出：[AIDev 字段覆盖](../schema-runs/aidev-v045/schema_coverage.json)、[字段类型汇总](../schema-runs/aidev-v045/schema_type_summary.csv)；[SWE-chat 字段覆盖](../schema-runs/swechat-v045/schema_coverage.json)、[字段类型汇总](../schema-runs/swechat-v045/schema_type_summary.csv)。同目录包含 `schema_context_candidates`、`schema_context_review_queue`、`schema_unresolved_fields` 的 JSONL/CSV。

## 截断补扫与发现的计数问题

旧匹配上限按规则顺序选取前 1,000 条，不能从“最后匹配位置”简单续扫。新入口固定选集后，重新分页执行整个单元格的规则；结果和游标在同一事务提交。分页按多个规则分别推进，不应把页数乘以页宽当成已扫描字符总量。

| 最终补扫运行 | AIDev | SWE-chat |
|---|---:|---:|
| 固定选中单元格 | 1 | 567 |
| 选中字符总数 | 74,169 | 2,232,404,563 |
| 已完成规则遍历的单元格 | 1 | 349 |
| 部分完成 / 待扫描单元格 | 0 / 0 | 1 / 217 |
| 已提交分页数 | 29 | 163,911 |
| 候选命中 | 4,112 | 443,609 |
| 另列示例命中 | 0 | 727 |
| 状态 | `complete_with_semantic_gaps` | `partial`，时间预算到达 |

AIDev 的旧 1,000 条命中逐条保留，额外找回 3,112 条规则观察；这补足匹配上限造成的遗漏，不代表发现了 3,112 个新秘密。父运行仍保留原截断审计，没有篡改其历史状态。SWE-chat 已真实执行一次 CLI 恢复，累计进度从 187 个完整单元格推进到 349 个。

**父正文与补扫计数不能相加。** 补扫从整个单元格重新执行，会包含旧匹配；目前未生成按单元格替换的联合明细。部分补扫也不能替换并丢弃父运行已获得的线索。后续正文继续扫描还可能发现新的截断单元格，不在本次固定选集中。

实际运行发现初版 `repair_coverage.candidate_occurrences` 被最后一个分组计数覆盖：AIDev 错报 4,106（实际 4,112），SWE-chat 错报 192（实际 110,675）。候选记录没有丢失。已修正公共导出函数、增加多类型/多状态回归测试，并在独立 `*-v045-final` 目录重新运行。旧目录保留为诊断证据，不进入当前汇总；详见[问题与修复记录](repair_v045_known_issue.json)。

当前证据：[AIDev 补扫](../repair-runs/aidev-v045-final/scan/repair_coverage.json)、[SWE-chat 补扫](../repair-runs/swechat-v045-final/scan/repair_coverage.json)。同目录提供命中、示例、未知队列、数据缺口及类型汇总的 JSONL/CSV。未知队列保留全部选中单元格，包括已完成词法规则遍历的单元格。

## 统一分类及覆盖审计

分类目录沿用 `taxonomy_version=1.0.0`，包含 AUTH、PII、QID、BIZ、CFG、DIAG 六大类、42 个受控细类。[跨来源类型表 CSV](observed_types_v045.csv) 与 [JSONL](observed_types_v045.jsonl) 为每个来源、每个细类保留单独行，明确计数单位、证据范围、候选状态分层和覆盖状态。[来源及哈希](observed_types_v045_provenance.json)固定其依据。

历史应用日志批次观察 27 个目录细类，正文观察 37 个，字段扫描观察 4 个，补扫观察 32 个。跨范围仅对标签取并集，共 39 个目录细类；这个数字**不是完整敏感类型覆盖率，也不是新增 12 类 Agent 日志隐私缺陷**。目录本身包含载体和“细类待确定”项，正文只有有限值形态和名称线索。未命中或未分类不代表安全。

42 项目录表不包含没有受控细类标签的候选；这些记录仍在源命中表与未知队列中，其数量另记在来源清单的 `candidate_occurrences_outside_catalog_rows`：AIDev 父正文 3,243、SWE-chat 父正文 499、SWE-chat 补扫 15（补扫与父正文仍不相加）。不同来源的计数不加总，历史批次间重复观察也不作为独立样本合并。

应用日志 Git 覆盖沿用已核验的 v044：本轮没有扩大 Git 提交样本。AIDev 当前实际读取过 594 个主队列仓库/提交组合；按 PR 关联核算，939,353 个归一化 PR 中，142 个有实际提交证据、141 个有源码证据、103 个有支持语言的源码、51 个有日志观察、41 个有类型标签，仍有 939,250 个没有已验证的受支持代码分析。详见[代码覆盖分母](../reports/aidev-corpus-v044/corpus_coverage.json)和[历史类型来源](type_inventory_v044_provenance.json)。

## 实际验证与命令

最终完整测试 **488 项通过，29.30 秒**：[测试输出](tests_v045_final.txt)、[执行与源码指纹](tests_v045_final_execution.json)。新增测试覆盖字段精度/空值、分页边界、长 PEM、输入变更、事务恢复及导出计数。未增加依赖。

[合成七阶段运行](../runs/synthetic-v045-final/run_manifest.json)实际使用 PyDriller 遍历 5 个提交、读取 5 个文件差异并调用 10 次历史源码读取，产生 2 个初始日志变更、3 个可能后续修改、1 个待审隐私候选；属于合成校准，不是真实缺陷。预检、完整运行和恢复均退出 0。真实数据扫描退出 2 表示部分覆盖或语义缺口，不能解释为程序成功证明了泄露，也不是未抓到数据。

已独立核对：[字段导出](schema_exports_v045_verification.json)、[AIDev 全文本导出](aidev_text_v045_final_verification.json)、[正文第二次恢复](content_exports_v044_resume02_verification.json)、[AIDev 最终补扫](aidev_repair_v045_final_verification.json)、[SWE-chat 最终补扫](swechat_repair_v045_final_verification.json)。核对内容包括 SQLite/JSONL/CSV/汇总一致、源行或字符范围、候选状态和源码指纹；不打印、验证真实凭证。

以下命令已实际执行；所有正文恢复、两数据集预检/实跑的完整参数、起止时间、退出码在[执行清单](datasets_v045_commands.json)。均从工作区根目录运行。

```bash
agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/local_fixture_config.yaml --run-id synthetic-v045-final --offline
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/local_fixture_config.yaml --run-id synthetic-v045-final --offline --resume
agent_log_privacy/.venv/bin/agentlog-unified schema-scan --input agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/schema-runs/aidev-v045 --offline --batch-size 4096 --max-seconds 300
agent_log_privacy/.venv/bin/agentlog-unified schema-scan --input agentlog_unified/inputs/swechat-full-v3 --output agentlog_unified/schema-runs/swechat-v045 --offline --batch-size 4096 --max-seconds 300
agent_log_privacy/.venv/bin/agentlog-unified content-repair --input agentlog_unified/content-runs/aidev-v044 --output agentlog_unified/repair-runs/aidev-v045-final --offline --max-seconds 120
agent_log_privacy/.venv/bin/agentlog-unified content-repair --input agentlog_unified/content-runs/swechat-v044 --output agentlog_unified/repair-runs/swechat-v045-final --offline --max-seconds 120 --resume
```

时间预算约束扫描部分，导出还需额外时间。例如 SWE-chat 最终补扫首次 126.91 秒，恢复 129.49 秒。正文恢复的导出耗时更长；执行清单使用真实总耗时。没有后台运行留在此报告快照中。

## 剩余工作与限制

- 继续 SWE-chat 剩余正文和 218 个未完成的固定补扫单元格；目前本机约剩 4.6 GiB 空间，扩大明细前需重新核算空间。
- 290 个未映射字段、编码/嵌套结构、未知业务含义、超过规则宽度的值和真实敏感性仍待处理。完整 Arrow 单元格仍需暂存于内存，分页不等于流式解码超大标量。
- 还未把父正文和已完成补扫按单元格替换，形成联合明细；当前各自导出已经可审计。
- 大部分 Git 对象与 PR 关联、其他语言日志解析、跨文件值流以及真实全量后续历史仍有缺口。字段或正文完成不能消除这些缺口。
- 所有机器结论保持 pending、低置信候选；无人工确认、运行时泄露确认或 Agent 独有类型结论。

已按用户确认删除两个旧中断导入目录，保留 `papers`，见[删除回执](cleanup_review_v042/deletion_receipt.json)。未删除其他历史结果。当前状态与续跑缺口见[机器可读进度](datasets_progress.json)。
