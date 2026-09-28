# SWE-chat 筛选判定与独立复核接口

本页描述本轮新接口；既有实验和既有 `semantic_review` 账本保持原状。规则计算、AI 复核、人工标注分别存储，图文件、模板、导入测试和规则预测均不是人工真值。当前敏感性政策为 `screening-policy-v1`，规则为 `screening-queues-v1`；政策文件为 `configs/screening_policy_v1.json`。本模块无网络、模型或目标程序执行入口。

## 判定输入与共同逻辑

`screening_policy.assess(case, base_evidence, dfg_evidence=None)` 不修改输入。baseline 和 dfg_augmented 共享该函数、政策及同一基础证据；唯一额外输入是 DFG 证据。新增证据可以补全维度，但路径和证据引用累积保留；原始两个输入快照由运行器保存。

| 字段 | 值与含义 |
| --- | --- |
| `source_sensitivity` / `output_sensitivity` | `supported`、`suspected`、`not_found`、`unknown`，分别记录来源与输出残留 |
| `connection.status` | `supported`、`partial`、`not_established`、`not_applicable` |
| `connection.reason_code` | 未建立时区分 `insufficient_evidence` 与 `target_connection_excluded`；其余可以记录具体有界路径依据 |
| `processing.kind` | `raw`、`partial_mask`、`transformed`、`fixed`、`unknown`；`steps` 保存有序处理证据 |
| `boundary` | `level` 为 `call_argument`、`log_record`、`formatted_output`；`status` 为 `supported`、`partial`、`unknown` |
| `paths` | 每条路径独立记录来源/残留敏感性、`connection_supported`、`semantics_supported`、`evidence_ids`、`critical_unknowns` 及已有位置/边引用 |
| `critical_unknowns` | 顶层条目影响全部结论；路径内条目只影响该路径。与充分风险路径无关的缺口放 `noncritical_unknowns` |
| `checks_complete` / `non_sensitive_basis` | C 必须完成必要检查，并提供有证据引用的非敏感输出或连接排除依据 |
| `processing_status` | 与队列独立；失败、受阻、排除、部分完成不自动意味着无风险 |
| `severity` / `certainty` | 严重程度当前为 `null` 并保留缺失上下文原因；证据确定性另记，不使用未经校准的概率 |
| `review_status` | 规则 `executed`；未实际复核的 AI 与人工均 `pending`，对应独立 `rule_result`、`ai_review`、`human_review` |

队列由 `choose_queue` 实际执行，并有表驱动测试。A 要求至少一条独立路径支持敏感来源、敏感残留、连接、必要处理语义和声明边界，引用证据且没有推翻该路径的关键未知。B 要求有可定位、可复核的具体风险线索，仍缺必要证据。C 要求声明范围内检查完成、处理成功、边界有依据、有非敏感或连接排除证据，且没有关键未解析路径。其余为 D。规则未命中、空图、类型边、未解析参数、失败或预算截断不能支持 C。

A 优先保留独立充分路径；一个无关分支失败不抹除该路径。若未知可能改变该路径的字段、传播或脱敏，必须标在其关键未知中。直接敏感常量可以是零跳路径；固定值也要检查其内容。`mask`、`redact`、`hash` 名称不证明处理有效，形式参数只作为追踪边界，不被改写成最终业务来源。

当前最小自动非敏感值规则覆盖 Python 布尔值、null、现有 `detector.MASKED` 正则完整匹配的固定占位符，以及固定字面词 `ok` / `done` / `started` / `finished`。MASKED 是正则变量名，规则还包括空字符串、星号串、至少三个 x、redacted/hidden/masked 等固定表示，不是仅识别文字 MASKED；它也不证明任意名为 mask 的函数有效。普通其他字符串即使没有风险正则命中仍保留未知。直接凭据赋值字面量命中明确类别语法时可提供静态类别证据；嵌在变换、布尔短路等表达式里的字面量仍需路径语义。测试、示例和合成值的用途范围独立保留，不作为生产暴露事实。

## 复核包、导入与哈希

`export_review_packages(cases, out, policy_version)` 接收由运行器预先隔离的独立评估案例。输出：

- `review_manifest.json`：政策版本、政策文件哈希、每个案例证据指纹；同目录不允许改版本或改证据后静默复用。
- `reviewer_1` 与 `reviewer_2`：相同的历史证据元数据和各自独立的 pending 表；初始包不包含 A/B 预测、最终队列、归因或机器敏感性线索。
- `adjudication_template.jsonl`：通过两个已有标注 ID 关联分歧，第三位独立人工裁决后追加保存。
- `ai_prompt.txt`、`ai_inputs.jsonl`、`ai_review_template.jsonl`、`review_result.schema.json` 和政策副本：离线模板和校验契约，生成这些文件不代表调用 AI。

证据指纹绑定案例 ID、政策实际文件哈希、仓库、提交/比较父版本、before/after、源码哈希、日志与输出精确锚点、依赖源码版本以及证据索引。源码、依赖、政策或定位变化后旧复核被拒绝。精确列号不可得时沿用其明确未知状态，不生成假列号。

原 review 包虽然不复制整段源码，字段名/输出键仍可能保留合法标识符形态的秘密，因此整个原包作为受限本地材料，不能宣称已彻底脱敏可公开。审查者须另获受限本地历史证据索引访问，读取对应 SHA 与哈希的源码；只有坐标包而无法查看必要证据时保持 pending/unknown，不能伪称已经完成盲标。不要把两个标注者的目录和后续分歧结果同时发给正在独立标注的人。

公开副本由独立 `scripts/export_screening_share.py` 生成：所有源码派生名称/文字均省略或转换为 SHA256 引用，原始图及其 code_view 不复制，保留锚点、哈希与局部私有映射关联。脚本和测试位于 `src/config` 之外，不改变已冻结的分析签名。准确 dry-run、导出、验证命令及原始材料权限说明见 [SOP 的独立分享导出](swechat_screening_sop.md#独立分享导出不改变冻结分析)。分享副本仅是元数据报告，人工导入仍通过受限原包完成。

`import_review(path, cases, output, kind)` 接受 JSONL，`kind` 为 `human`、`ai` 或 `adjudication`。完整批次先校验再写入；未知案例、错政策/证据版本、未解析证据 ID、错误标签、无时区时间、AI 伪装人工、pending 携带结果和不一致 A/C 维度均拒绝。报错只返回行号与原因码。相同完整记录重复导入幂等；新版本追加历史，不覆盖原标注、规则或 AI 结果。

提交结果保留 `case_id`、`policy_version`、`evidence_sha256` 和 `evidence_ids`。`result` 包含 queue、独立 dimensions、facts、inferences、critical_unknowns、rationale；facts/inferences 每条必须包含 `text` 和有效 `evidence_ids`。dimensions 的完整字段与值域以导出的 schema 为准，包括连接排除原因、有序处理步骤、严重程度及证据确定性。人工记录还需不同的 `reviewer`、`annotator_slot` 与实际带时区 `timestamp`；身份仅为自声明，未认证。

AI 记录保存实际来源、可获得的模型标识（不可得为 null）、时间、提示版本及输入/输出哈希。`input_sha256` 是 `screening_review._digest(ai_input(case))`，`output_sha256` 是结构化 `result` 的规范 JSON 哈希。它们验证本框架收到的结构化输入/结果，不能证明外部模型服务身份。没有实际调用的行保持 pending；框架不自动上传源码或调用额外模型。

成功导入后的 `review_history.json` 与分开的 `human_results.jsonl`、`ai_results.jsonl`、`adjudication_results.jsonl` 只存受控标签、引用、文本哈希和审查者哈希；`disagreements.jsonl` 记录未决或已裁决分歧。原始解释、模型元数据和原始标注者标识存在输出目录的 `.raw_reviews` 内（目录 0700，文件 0600），通过记录 ID/哈希可本地回查。原始输入文件本身保持不动，请将其保存在受限目录。

## 指标接口与真实分母

`review_metrics(evaluation_cases, predictions, imported_history)` 区分风险判定与日志检测。只有同一冻结评估案例上两个不同人工标注者、两个独立槽位的完整一致 A/C 标签，或者第三人引用当前两份标注后的有效裁决，才产生二元人工真值。任一评估案例仍 pending、分歧未解、B/D 不确定或缺预测时，整个声明分母上的 precision/recall/accuracy/F1 为 null 并说明原因。AI 与待填模板从不作为真值。

有完整可靠二元真值时，风险指标将 A 视为正预测，其余队列视为非正预测；每个输出单元计一次。precision 分母无正预测或 recall 分母无真阳性时相应指标仍为 null。这是声明样本上的筛选指标，不宣称自然总体发生率或总体准确率，也不混入工程调规则案例。

`detection_metrics(file_manifest, predictions, annotations)` 单独从原始修改文件计算日志检测 precision/recall。manifest 使用 `file_version_id`、`source_sha256`；预测包含相同字段、`status=success` 与 `log_anchors`。每条日志锚点是 `{line,column,end_line,end_column}`。两名人工标注者分别提供 `origin=human`、`status=submitted`、reviewer、annotator_slot、实际 timestamp、`review_scope=original_modified_file`、`inspection_complete=true`、空 critical_unknowns 及完整 log_anchors。全文件双人枚举一致、源码哈希一致且整个分母完成后才计算；不会把拆分输出参数数当作日志数。分歧文件需复核后提交完整一致记录，当前接口不自动裁决文件级分歧。

`review_metrics(..., detection_annotations={"files": [...], "predictions": [...], "annotations": [...]})` 可同时调用文件级指标接口。缺标签、缺分母、分析失败或有未决文件时返回 null。

## 测试与后续使用

本轮实际运行的针对命令如下；测试使用本框架和虚构测试标注，不执行目标应用，不把测试导入算作真实人工复核：

```sh
cd '/Users/lzh/Downloads/Log 研究/agentlog_unified'
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 '../agent_log_privacy/.venv/bin/python' -m pytest -q tests/test_screening_policy.py tests/test_screening_review.py tests/test_screening_evidence.py
```

上述测试覆盖队列条件、独立路径与关键未知、类型关系、常量、名字不等于脱敏、规则输入不变、pending/AI 不充当真值、严格导入与原子拒绝、盲包泄露防护、依赖版本、导入幂等、分歧裁决、双人身份与文件级漏检分母。实际测试数量以本轮运行报告为准。

以下是后续填写真实标签后才使用的命令，未执行人工复核前不应把它们记为评估完成；运行目录应使用本轮新目录：

```sh
cd '/Users/lzh/Downloads/Log 研究/agentlog_unified'
'../agent_log_privacy/.venv/bin/python' -m agentlog_unified screening review-import --output '/绝对路径/本轮运行目录' --file '/受限本地目录/reviewer_1.jsonl' --kind human
'../agent_log_privacy/.venv/bin/python' -m agentlog_unified screening review-import --output '/绝对路径/本轮运行目录' --file '/受限本地目录/reviewer_2.jsonl' --kind human
'../agent_log_privacy/.venv/bin/python' -m agentlog_unified screening metrics --output '/绝对路径/本轮运行目录'
```

规则源码或政策更新后应生成新的分析身份与新的复核包，不能覆盖已冻结的人类评估版本。框架只交付静态证据队列和可继续执行的离线接口，不确认运行时泄露、Agent 独有风险或人工已完成评估。
