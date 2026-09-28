# 0.8.0 按需语义证据闭环

在既有 `semantic-scan`、PyDriller 历史缓存、Python AST、Tree-sitter 和 Codex CLI 上新增 `semantic-demand`，不重挖全量 AIDev schema。机器输出仍然是待人工审阅的解释和静态候选。

## 运行

在 `agentlog_unified` 目录使用现有 Python 环境：

```sh
../agent_log_privacy/.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
../agent_log_privacy/.venv/bin/python -m pytest -q

# 查看计划，不写分析产物、不调用模型
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-demand \
  --input semantic-runs/real-v070-final --output semantic-runs/my-demand \
  --config semantic-inputs/demand-development-v080.yaml --dry-run

# 实际离线上下文提取、程序检查、待审导出，零模型/网络调用
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-demand \
  --input semantic-runs/real-v070-final --output semantic-runs/my-offline-demand \
  --config semantic-inputs/demand-development-v080.yaml --offline

# 显式使用现有 ChatGPT 登录的 Codex CLI
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-demand \
  --input semantic-runs/real-v070-final --output semantic-runs/my-online-demand \
  --config semantic-inputs/demand-development-v080.yaml --online

# 完全相同的输入、源代码、模型、配置才能恢复
# 在上一条命令末尾加 --resume
```

示例 YAML 中的 `budget_ledger` 是本机绝对路径。分享工具后必须改为接收者自己的路径。一次研究的合成冒烟、开发和评估配置必须共用同一个 `experiment_id` 与预算账本。已用预算不会因输出目录变化而清零；改变预算身份或限额会拒绝恢复。不要将真实运行的账本替换为空文件来续跑。

```yaml
semantic_demand:
  case_ids: [已冻结证据包中的案例ID]
  experiment_id: a-new-explicit-experiment
  budget_ledger: /absolute/path/to/experiment-budget.sqlite
  phase: development
  model: gpt-5.5
  timeout: 120
  max_rounds: 2
  max_files: 8
  initial_chars: 12000
  expanded_chars: 24000
  per_case_calls: 6
  total_calls: 80
```

上述数字是硬上限，允许调低。初始和扩展字符限额针对传给模型的**全部代码视图之和**，不包括系统提示、JSON、分类目录等，因此不能把代码字符数当作总输入 token。到达上限后保留具体缺口。`max_seconds` 可用于在案例之间暂停，返回码 2；相同配置 `--resume` 从检查点继续。失败请求不自动重试，崩溃前预留的模型调用也占预算。

## 实现与证据边界

- `semantic_context.py`：从完整且哈希校验通过的历史运行读取私有 SQLite 快照，按 repo/SHA/路径/使用锚点构造上下文；请求中的 origin 是已发布证据 ID，不是文件路径。宿主解析实际符号、作用域、类型、函数、schema 和源码内显式引用。补充文件只能来自相同 SHA 的快照。没有 HEAD 或工作区源码回退。
- `semantic_demand.py`：A 为冻结的既有规则结果；B 为固定初始上下文提取与新会话复核；C 复用完全相同的初始提取，最多扩展两轮，再以原始代码视图、候选和程序检查交给复核模型。只有完整输入相同的请求可以复用。程序限制与原始模型判断分别保留。
- `semantic_model.invoke`：复用既有 ChatGPT 认证的 Codex CLI，仅增加可传入响应 schema 的参数。目标工具、网络搜索、MCP、应用、插件和执行工具禁用；观测到工具调用会失败。没有读取、复制凭证或切换到收费 API。
- `semantic_bindings.literal`：补上明确导入的静态 schema 常量，并核对定义唯一性、条件赋值和调用方/定义模块中的已知修改。原始证据复核重新计算绑定，记录源文件哈希。
- CLI 增加 `semantic-demand`。包版本为 0.8.0，依赖锁保持原版本，无新增依赖。

Python 支持局部赋值、参数、字段投影、有限函数实际参数到形式参数及返回值证据；JS/TS/Go 延用 Tree-sitter 检查，补充 JS/TS 命名相对导入的定义检索。取回定义本身不等于证明跨过程传播。包别名、重导出、虚调用、复杂闭包、条件和循环路径、反射、未知别名副作用仍有边界，单列待审。脱敏名称不构成脱敏有效性证据；只复用原有有限静态固定输出检查，没有执行目标代码或运行时验证。

规则检查分别记录：锚点/文件哈希/版本有效性、局部 AST 结构、有限传播证据、路径可行性未证明、运行时未执行。含 `len(data)` 的输出与原始 `data` 分开；模型声称的原值关联与 AST 投影冲突时会被限制。完整日志锚点同时匹配位置和语句哈希，避免把同一行的内层调用误认为外层日志。

交付版还检查该语句是否为可识别的日志/stdout 调用：包装函数的参数先保留 possible，不能直接视为该函数内部的日志内容。`len(data)` 或布尔派生输出也不能反向证明原始 data 非敏感。这两项修复来自本轮评估检查，因此旧模型比较仅作探索性记录；规则重核和修正后 1 例真实模型验证分开导出。

语义、敏感类别、日志关联、隐私风险四维独立；本轮程序使用实例的数据集元数据含义为不适用。分类目录仍有限，可输出 unknown、未映射和多种解释。`model`、`rules`、`human` 不混用。复核使用新模型会话，不宣称统计独立、人工确认或形式化证明。

视图不是源码逐字副本。保留 AST 结构标识符、类型注解、白名单 schema 关键字/format/type 枚举，以及有代码声明对应的结构键；所有运行时字面值、自由描述、注释和不安全标识符隐藏。未知键不因“正则没命中凭证”而放行。自由文档只输出历史引用、哈希和隐藏说明，不能据此声称已经实现一般业务文档自动理解。这样的信息损失会限制模型解释范围，记录在每个 block 的 `redaction`。

沿用已由 PyDriller 遍历、diff 解析和历史源码提取得到的检查点，保留 `revision_backend`、`source_backend`、`fallback_reason`。未修改的全树文件沿用 `pydriller.Git.get_commit` 固定版本、GitPython 读取对象的辅助路径，明确标记缓存复用；本轮真实语义阶段没有再次抓取 GitHub 或扩充远程历史。

补充文件上限约束新增的模型证据路径。宿主会载入已有私有快照并建立符号索引，这不是全体缓存文件的 I/O 上限；模型实际收到的路径与缓存中未发送的路径在额外覆盖审计中分开记录。跨版本代码或配置不能恢复到同一结果目录，需创建新目录；旧冻结模型结果仍可只读校验。

## 输出

每组运行分别生成 JSONL 和 CSV：

| 文件前缀 | 内容 |
|---|---|
| `field_semantics` | B/C 复核后四维解释及源码身份 |
| `context_retrievals` | 模型请求、规范化符号、检索状态、预算、后端与失败原因 |
| `flow_step_checks` | 定向证据步骤、赋值/定义/返回锚点、实际参数绑定、投影和未解析项 |
| `model_records` | 各阶段原始模型解释、程序限制、上下文、调用回执 |
| `independent_reviews` | 独立会话的原始复核与程序限制结果 |
| `review_queues` | 多个待审原因、主阻塞项及停止原因 |
| `abc_comparison` | 同案例 A/B/C、C 复核前后变化 |
| `model_budget_ledger` | 该时刻全局真实 CLI 调用账本快照，包含失败/预留调用 |
| `human_annotation_template` | 空白开放编码、四维判定和拆分/合并建议模板 |
| `exclusions` | 冻结 100 案例中未入本轮队列的实例 |

`evidence/<case_id>.json` 提供逐例证据包，`coverage.json` 提供分组覆盖与漏斗，`manifest.json` 固定源码、输入和产物哈希。SQLite/JSON 检查点为私有权限，不应在分享最小代码包时无意包含原始历史源码。

支持语义未知、上下文缺失、解析器不支持、绑定未解决、动态流未解决、预算耗尽、已知语义未映射、解释冲突、证据支持非敏感、模型未运行/失败等队列。没有证据不等于非敏感；所有模型解释仍待人工真值。没有实际人工标注时不计算准确率、召回率或一致率。

本轮最终运行数字、案例变化与限制见同目录的 [实验汇总](demand-v080/results.md)；可核查的结构化记录见 `docs/demand-v080/` 与对应 `semantic-runs/demand-*-v080*`。旧 0.7.0 结果、数据缓存和 papers 原样保留。
