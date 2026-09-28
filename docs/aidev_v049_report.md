# AIDev 敏感类型收集：0.4.9 运行报告

记录日期：2026-09-09（北京时间）。本轮将统一分类目录由 **42 个细类扩展为 49 个**，完成冻结 AIDev 的 18 表正文与 JSON 结构重扫、截断补扫及去重汇总；最终 **669 项测试通过**。按来源汇总观察到 **45 个受控类型标签**，结果仍是待审候选，不能据此声称已找齐现实中的敏感类型或确认泄露。

## 已实现与验证

统一 taxonomy 升至 `1.1.0`，增加出生日期、个人年龄、性别及性别认同、族群及种族属性、宗教信仰、教育背景、就业及职业背景七个细类。它们是明确命名字段的低置信线索，不是对值的真实性或个人归属的确认。正文和结构化扫描复用同一目录；修正带 `$` 的点式变量引用识别，引用继续标为 `identifier_reference`，不提升为真实字面值。[目录缺口审计](taxonomy_gap_v049_review.json)、[引用修复测试](aidev_reference_v049_focused_execution.json)

补扫工具已兼容 `content-advance` 产生的压缩父结果：分别验证实际父目录和原始 seed，持有两处共享锁，核对导出状态、共享数据库进度、完整 gzip 队列及选中单元格元数据。恢复沿用固定选集；合并仅允许精确父目录或其已验证祖先，拒绝兄弟 advance。四文件补丁已应用，应用后指纹与评审版本一致；旧补扫指纹不兼容，须保留历史输出并新建运行。[应用记录](advance_repair_v049_apply_execution.json)

合成链路实际经过 Parquet → 真正 AIDev 导入 → 0 行 seed → 压缩正文扫描 → 截断选集 → 暂停/恢复补扫 → 合并。3 行扫描得到 1 条初始候选，补扫 1 个截断单元格后得到 3 条候选；合并识别 1 条重复和 2 条增量。再次补扫新增 0 页，合并压缩导出逐字节一致，seed 历史导出未重写。[逐阶段证据](advance_repair_v049_synthetic_e2e_execution.json)、[75 项专项回归](advance_repair_v049_staged_pytest_execution.json)

## 真实探查与定点复核

旧 `unknown_named_value` 队列只有 222 个源单元格，且规则只覆盖泛称敏感字段，无法代表从未识别的具体个人属性。先回读其中 32 个单元格，未发现本轮预定属性赋值；随后仅做 **一次全量正文列探查**，完成 13 个含正文表、22 个字段、4,034,221 个源单元格的遍历。其中非空 3,718,349 个，检查 2,395,474,725 个 Unicode 字符，未触发源长度截断；得到 858 处固定字段名的赋值语法线索。两次观察范围可能重叠，不相加。[探查报告](personal_attribute_probe_v049.json)、[执行记录](personal_attribute_probe_v049_execution.json)

| 新细类 | 字段赋值语法线索 | 其中字面或数值赋值 | 本轮 JSON 结构观察 | 本轮正文去重候选 |
|---|---:|---:|---:|---:|
| `PII.birth_date` | 304 | 55 | 9 | 358 |
| `PII.age` | 8 | 4 | 0 | 51 |
| `PII.sex_gender` | 441 | 288 | 7 | 1,844 |
| `PII.ethnicity` | 4 | 3 | 0 | 4 |
| `PII.religious_belief` | 50 | 41 | 0 | 50 |
| `PII.education` | 8 | 7 | 0 | 8 |
| `PII.employment` | 43 | 9 | 3 | 55 |

探查只覆盖预先固定字段名与有限赋值形式。没有命中政治观点、性取向字段赋值，因此本轮没有据此增加这两个细类；零命中不能解释为数据中不存在。表内四个计数列来自不同观察方式，不能相加，也不是人数、秘密数量或漏洞数量。

从已有证据刻意选择 27 条记录、23 个不同源单元格，用新分类器回读：**26 条在原值跨度上命中预期新类型**，唯一未命中是空值比较项，未强行补成正例。有限角色检查得到日期形态 3 条、数值年龄 3 条、固定枚举形态 7 条、其他未决字面 8 条、引用/声明 5 条、空值 1 条。21 个字面样本中 8 个仍无法仅凭形态区分属性值与标签、映射等用途；该 **8/21 比例仅属于刻意选取的小样本**。所有样本仍待审，未输出原值、动态键或值哈希。[回读结果](personal_attribute_replay_v049.json)、[来源索引与逐条证据](personal_attribute_replay_v049_evidence.jsonl)

## JSON 结构扫描已完成

本轮继续使用冻结 AIDev 的 **18 表、2,456,073 行**。行数表示已提交处理的源行，不等于物理读取次数；恢复跳过前缀时 Arrow 可能额外解码。单元格以表、列、行为单位，不按真实人物去重。

| 指标 | 已核验结果 |
|---|---:|
| 已处理源行 / 总源行 | 2,456,073 / 2,456,073 |
| 非空文本单元格 | 17,362,345 |
| 选中的结构文档候选，含解析失败 | 49,669 |
| 非排除候选 / 示例或排除观察 | 1,159 / 57 |
| 观察到的受控细类 | 35 |
| 解析缺口记录 | 44,289 |
| 待审范围记录 / 覆盖非空单元格 | 570,513 / 17,362,345 |

**72/72 项独立导出核验通过**，覆盖 SQLite、6 组压缩 CSV/JSONL、来源指纹、有限字段、坐标和待审范围。类型汇总保留 49 个受控细类及 1 个未知汇总行；未知计数为零，不等于不存在未知类型。候选细分为载体 627、命名值 448、字面形态 74、引用 10。[独立核验](aidev_structured_v049_verification.json)

与 v048 按同一来源坐标、类型和规则对齐，1,197 条旧观察的分类细节保持一致，新增 **19 条观察**，无删除；新增项为出生日期 9、性别 7、就业 3。比较不包含版本化记录 ID，19 条不是新增真实个人信息或泄露，也不能与旧正文的“单元格 × 类型”增益直接相加。新细类在旧 taxonomy 中属于未评估，不应把旧值补成零。

结构全量运行耗时 619.58 秒、退出 2；恢复耗时 17.61 秒、退出 2，新增 0 行，5 个逻辑表和 12 个压缩导出全部相同。退出 2 表示仍有语义或覆盖缺口。[全量执行](aidev_v049_structured_full_execution.json)、[恢复执行](aidev_v049_structured_resume_execution.json)、[恢复核验](aidev_structured_v049_resume_verification.json)

## 正文、补扫与最终汇总

正文采用 `content-runs/aidev-v049-seed` 的共享检查点及 `content-runs/aidev-v049` 的压缩导出。**已结束的首轮快照**按时间预算停止：已处理 1,548,105 / 2,456,073 行、12,430,320 个非空文本单元格；候选 827,402、示例或排除 8,815、截断单元格 1。包含导出的总耗时 948.49 秒，退出 2，源码指纹未变。这些是首轮中间结果，不能用作最终数量。[首轮执行](aidev_v049_content_full_execution.json)、[独立保存的首轮覆盖快照](aidev_v049_content_full_content_coverage.json)

正文恢复已终止，耗时 **509.29 秒**、退出 2，源码指纹未变。最终已提交处理全部 **2,456,073 / 2,456,073 行**，访问 18,932,477 个文本单元格，其中非空 17,362,345 个、null 1,570,131 个、空字符串 1 个。正文产生 **1,478,855 条候选、11,871 条示例或排除观察**；1,115,211 条待审记录覆盖全部 17,362,345 个非空单元格。[恢复执行](aidev_v049_content_resume_execution.json)、[最终正文覆盖](../content-runs/aidev-v049/content_coverage.json)

计数中的 2,706,989,370 个字符表示传入有限规则的前缀长度；**父正文仍记录 1 个单元格触发匹配截断**，因此 `all_available_text_characters_scanned=false`。全行遍历完成不等于规则和语义完整，截断项由下述独立补扫处理。正文独立导出核验 **69/69 项通过**，已验证当前数据库、压缩导出和覆盖分母一致。[正文独立核验](aidev_content_v049_verification.json)、[核验执行](aidev_content_v049_verification_execution.json)

真实补扫固定选择 **1 个截断单元格、74,169 个字符**，累计提交 29 个规则页；选中单元格的全部有限规则已遍历，源文件验证完成，输出 **4,112 条候选、0 条示例或排除观察、0 条补扫数据缺口**。实际全流程耗时 15.75 秒、退出 2，源码指纹未变；再次恢复新增 0 页，JSONL/CSV、manifest 和候选计数一致。[补扫执行](aidev_v049_repair_full_execution.json)、[恢复核验](aidev_repair_v049_resume_verification.json)

**65/65 项独立核验通过**，包括固定选集、来源和私有指纹、规则游标、5 组 CSV/JSONL、分类汇总及与同版本父正文的逐条比较：父正文中该单元格的 1,000 条观察完整保留，分类细节无变化、无缺失，补扫增加 3,112 个观察身份。不能直接把 4,112 加到父正文总数；最终总量须由后续合并核定。规则遍历完成仍非语义完整，这个单元格继续待审。[补扫独立核验](aidev_repair_v049_verification.json)、[核验执行](aidev_repair_v049_verification_execution.json)

合并已结束：去重后有 **1,481,967 条候选身份**、1,481,967 个证据变体，另有 11,871 条示例或排除身份。补扫与父结果重合 1,000 条，新增 3,112 条；无父身份移除。合并用完整补扫替换该单元格原有 1,000 条，并保留覆盖全部 17,362,345 个非空单元格的待审入口。父正文与补扫数量不能直接相加。实际合并耗时 106.14 秒、退出 2，来源验证完成，源码指纹未变。[合并覆盖](../reconciled-runs/aidev-v049/merged_coverage.json)、[实际执行](aidev_v049_merge_full_execution.json)

合并独立核验 **178/178 项通过**：7 组压缩 CSV/JSONL、来源数据库、类型和身份汇总逐字段一致，详情冲突为 0。[合并核验](aidev_reconcile_v049_verification.json)

最终分类清单有 **490 行 = 10 个来源 × 49 个细类**，独立核验 **27/27 项通过**。保留旧版 336 行原有字段；旧 8 个来源对新增 7 类共 56 行标为 `not_evaluated`，计数为 `null`。剩余 434 行已在各自来源规则下评估，其中 250 行为零观察；零仅表示对应处理范围内没有候选。全 AIDev 的已观察标签并集为 **45 类**，本版正文观察到 44 类、结构化观察到 35 类，不能相加。正文另有 3,243 条目录外候选，仍保留未知待审。

[清单 CSV](aidev_observed_types_v049.csv) / [JSONL](aidev_observed_types_v049.jsonl)、[目录外清单](aidev_observed_types_v049_outside_catalog.csv)、[来源与口径](aidev_observed_types_v049_provenance.json)、[清单独立核验](aidev_inventory_v049_verification.json)。清单同时保留旧来源以供核对；各来源的计数单位不同，不应汇成一个候选总数。

## 测试与失败记录

正式应用兼容补丁后，**最终完整 pytest：669 passed in 31.25s**；外层执行耗时 32.17 秒、退出 0，执行前后源码与测试指纹一致。[最终执行](aidev_v049_tests_final_execution.json)、[测试输出](aidev_v049_tests_final_stdout.txt)

保留了真实失败过程，未以成功记录覆盖：

- 引用专项测试首次为 69 通过、1 失败，原因是新测试预期 49 类而目录编辑尚未完成；随后 70 项通过。另一合成机制探针的错误预期暴露了点式 `$` 引用状态缺口。[专项记录](aidev_reference_v049_focused_execution.json)、[机制探针](aidev_structured_v049_gap_review.json)
- 定点回读包装器首次把虚拟环境解释器链接解析到外部环境，导入即失败，未解码源值；改用正确解释器后退出 0。[首次失败](personal_attribute_replay_v049_attempt01_execution.json)、[成功回读](personal_attribute_replay_v049_execution.json)
- 兼容补丁专项测试首次 74 通过、1 失败：旧测试手写的 advance manifest 缺少检查点身份。测试改为调用真实 producer，未削弱校验，随后 75 项通过。[首次失败](advance_repair_v049_staged_pytest_attempt01.json)、[专项输出](advance_repair_v049_staged_pytest_stdout.txt)

## 仍未覆盖的边界

49 类目录是有限分类规范，不是现实敏感数据类型全集。正文目前只有 7 类有限字面形态检测、44 类命名字段提示；任意编码、复杂程序语义、未支持的语言键和完整上下文识别仍有缺口。JSON 解析失败、内层解码失败和未闭合围栏仍保留待审；当前键匹配也不能代替完整身份关系或污点分析。

字段语义沿用此前已核验结果：AIDev 160 个 scalar 字段仅映射 22 个，138 个未映射；账户关联字段仍有 485,812 个未匹配单元格，不能把它们当作安全负例或直接判为姓名。[既有字段核验](aidev_schema_v047_verification.json)

本轮是数据内容分类和覆盖改进，未新增真实 Git 历史挖掘或应用日志缺陷证明。不同范围的候选队列可能重叠，不相加为人数、秘密数或漏洞数；模型及规则判断保持 `human_review_status=pending`、`runtime_confirmed=false`、`new_type_status=not_established`。未调用外部付费模型、未执行目标应用、未验证真实凭证或修改远程仓库；本轮未扩扫 SWE-chat。

本轮扫描、补扫、合并和独立数据核验均已结束，没有继续写入这些运行目录。实际参数、时间、退出码和执行前后源码摘要见 [执行记录索引](aidev_v049_commands.json)，包括预演、完整扫描、恢复、补扫和合并。正文首轮因时间预算分段，后续已完成；本轮没有环境阻断，尚未解决的是上述数据关联与语义覆盖缺口。源码与目录已交付，最终版本、链接和执行记录核对见 [交付核验](aidev_delivery_v049_verification.json)。

以下为本轮实际执行过的主要入口，完整参数以执行记录为准，已有目录恢复使用 `--resume`：

```bash
agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q
agent_log_privacy/.venv/bin/agentlog-unified structured-scan --input agentlog_unified/inputs/aidev-full-v2 --output agentlog_unified/structured-runs/aidev-v049 --offline --batch-size 32 --max-seconds 900
agent_log_privacy/.venv/bin/agentlog-unified content-advance --input agentlog_unified/content-runs/aidev-v049-seed --output agentlog_unified/content-runs/aidev-v049 --offline --batch-size 64 --max-seconds 900 --min-free-gib 2 --resume
agent_log_privacy/.venv/bin/agentlog-unified content-repair --input agentlog_unified/content-runs/aidev-v049 --output agentlog_unified/repair-runs/aidev-v049 --offline --max-seconds 300
agent_log_privacy/.venv/bin/agentlog-unified content-reconcile --input agentlog_unified/content-runs/aidev-v049 --repair-run agentlog_unified/repair-runs/aidev-v049 --output agentlog_unified/reconciled-runs/aidev-v049 --offline
```
