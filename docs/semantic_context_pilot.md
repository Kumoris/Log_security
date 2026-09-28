# 泛称字段语义小样本：运行与证据边界

本扩展保留既有流水线，增加 `semantic-scan`；默认纯本地、规则分析，不调用模型，不运行目标程序。新增依赖为零，继续使用现有锁定依赖。数据集字段的 schema 扫描不在本轮重算，原有待审状态不变。

## 方法依据

已阅读本地 `papers/2605.29442v2.pdf` 的第 3 节、附录 A.2 与附录 D。采用其“结构化提取 → 独立复核 → 统一分类”的结构，参考其固定样本、复核消融和截断预算检查。论文自己的开发者反对条件不适用于代码字段语义；源码和类型定义可以直接提供证据，无人评论的日志保留。附录中的提示词只作为研究资料，没有当作任务指令执行。

论文的模型质量数值、人工标注和类别饱和结论不能移植到此工具。本轮没有模型输出或人工真值，所有人工标注模板均为待审。输出数量增加不等于准确率提高。

## 可运行路径

从工作区根目录执行：

```sh
PYTHONDONTWRITEBYTECODE=1 agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests/test_semantic_evidence.py -q
PYTHONDONTWRITEBYTECODE=1 agent_log_privacy/.venv/bin/python agentlog_unified/examples/build_semantic_fixture.py /tmp/my-semantic-fixture
PYTHONDONTWRITEBYTECODE=1 agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-scan --input /tmp/my-semantic-fixture/input.jsonl --output /tmp/my-semantic-run --offline --dry-run
PYTHONDONTWRITEBYTECODE=1 agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-scan --input /tmp/my-semantic-fixture/input.jsonl --output /tmp/my-semantic-run --offline
PYTHONDONTWRITEBYTECODE=1 agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-scan --input /tmp/my-semantic-fixture/input.jsonl --output /tmp/my-semantic-run --offline --resume
```

安装好的环境可直接用 `agentlog-unified semantic-scan`。`python -m agentlog_unified` 是模块入口；不要使用没有 main 调用的 `python -m agentlog_unified.cli`。

输入复用 `ingest_records`，支持 CSV/JSONL/JSON/AIDev 导出和既有 `input.column_mapping`。需要 `local_repo_path`、`initial_commit_shas`（或 `commit_shas`/`head_sha`），`target_ref` 必须是完整固定 SHA；省略时使用最后一个初始 SHA。不能用活动 HEAD 解释旧版本。

输入可携带 repository、PR 和作者来源；仅有提交锚点时不伪造 PR 编号。来源未知作者保留。先用本地 Git 对象遍历日志变化，再抽字段，不按敏感词决定是否追踪。

```yaml
semantics:
  max_fields: 100
  max_context_chars: 16000
  max_snapshot_files: 500
  max_history_commits: 20
  max_source_bytes: 262144
  ablations: true
  vocabulary: []
```

`--max-seconds` 在提交单元之间检查，暂停后 `--resume` 继续；每个提交单元原始历史证据保存在私有 SQLite 事务中。配置、输入或源码改变后拒绝续跑，应使用新的输出目录；已完成输出续跑会验证输出文件摘要。`--dry-run` 不访问目标仓库、不创建目录。语义命令拒绝 `--online`。

## 分离的判断

每条 `field_semantics` 含四个独立字段：

- `dataset_metadata_semantics`：本轮程序字段不能替代 AIDev schema 字段解释；此处明确标为未分析。
- `program_semantics`：字段的含义、支持状态、类型/待映射状态。
- `log_association`：静态日志调用实参证据，区分已识别 logger 和可能的 sink/词法关联。
- `privacy_risk`：静态风险候选或未定；运行时泄露永远没有由本分析确认。

A 阶段输出位置、版本和赋值/调用连接的候选证据。B 阶段重新解析原始历史 AST，逐项检查源码摘要、作用域、位置、参数绑定、字段投影与类型契约，不用 A 阶段的文字理由证明自己。B 是独立规则复核，不是另一个模型或人工专家；不支持的语法和动态行为进入待审。

名称只能作为线索。首版可支持已导入的 Pydantic EmailStr/SecretStr 等明确类型契约、局部别名、元组解包、字典构造/字段写入、声明模型的字段投影和一跳简单返回。`NewType` 提供项目声明的名义类型，未映射到现有目录时保留新类型待审。普通 str/int 类型或固定字符串的形状不等于业务语义，单纯名称不证明敏感性。

五种队列分别保存：语义未知、语义已知类别未映射、解释冲突、上下文/历史缺失、证据支持的非敏感字段。最后一类只在当前实现的明确固定 null/boolean 等条件下成立，不是对整个程序的安全认证。

业务词汇映射必须包含 repository、module、scope、精确 revision、field、meaning、definition_path、definition_sha256、definition_quote。仓库/模块/作用域/版本任一不匹配均不使用。定义缺失或摘要失效会被否决；仅有文档映射也仍需人工核实它与变量的连接，不能把词汇表当作人工确认。

## 历史与隐私边界

Git 遍历、提交、ModifiedFile、diff_parsed 和修改前后源码继续来自既有 PyDriller。整树历史快照通过 `PyDriller.Git.get_commit` 固定修订，再用 GitPython tree/blob 辅助读取，明确记录 `pydriller_2_11_has_no_whole_tree_source_API` 回退。缺失对象按文件记录，不再因首个不可用 blob 提前终止整树扫描。

保留完整前后日志语句的归一化视图、原始跨度与摘要、所在函数、直接依赖和导入上下文。证据文件的所有 Python 字面量及注释隐藏；它不是原文引用。人工可用仓库、SHA、路径、行列与摘要在本地定位原文。SQLite 检查点包含私有原始历史源码，不适合直接分享。

合并差异仍逐父提交提取，首父净变化用于日志整合；原始多父差异保留审计。删除、重命名、跨文件修复和未知作者继续走原有追踪。shallow/promisor 缓存、缺失对象和未提供后续 tip 都限制历史覆盖，未观察到后续变化不等于没有修复。

局部证据和简单一跳是本轮上限。动态调用、复杂控制流、一般序列化/脱敏效果、任意编码、跨多跳污点、自动理解任意业务 schema/文档尚未解决。Go/TypeScript 等保留词法字段候选与原有日志证据，不能视为完成其绑定语义分析。测试/示例路径单独标记，类型识别不证明数据是真实个人资料。

## 输出与评估

同时输出 JSONL/CSV：字段结果、独立复核、五种待审队列、新类型候选、模型请求接口、人工模板、固定样本消融、筛选框、排除、缺失、日志变化、后续、无后续和来源未知样本。逐案例文件在 `evidence/`，统计在 `coverage.json`，源码/输入/配置冻结及产物摘要在 `manifest.json`。

真实抽样源于五个已有 AIDev Git 批次中具有日志观察的本地缓存。先按仓库选择可读取提交，给类型定义控制留位置；然后按仓库、语言、歧义来源、类型上下文分层轮转抽取最多 100 个使用实例。该条件化抽样框不是 AIDev 全量总体。开发与评估按仓库分开，但无实际人工反馈，不能声称完成类别开发或最终评估。

消融在同一批 Python 实例上比较 name-only、local-only、one-hop + review、without-review、256 字符截断。比较的是支持状态和审查差异，未计算准确率、召回率或一致率；全标签参考真值不存在。无复核的标签只称未审提议，不能和复核支持混算。

模型请求和复核 JSON 接口只导出，不执行；`model=null`、`model_stage=not_run`、`prompt_version=semantic-extract-review-1`。上下文预算记录的是规则证据跨度预算；补充人工上下文单独计数，尚未向任何模型发送合并后的包。

## 2026-09-09 实际执行结果

交付源码版本 0.6.0；最终目录为 `semantic-runs/synthetic-delivery/` 和 `semantic-runs/aidev-pilot-final/`。规则阶段已执行，模型提取、模型复核、人工编码与人工评估未运行。PATH 未找到 ollama、llama-cli 或 lmstudio；未调用其他模型服务。

| 指标与分母 | 合成校准 | 真实固定小样本 |
|---|---:|---:|
| 输入仓库锚点 | 1 | 10 |
| PyDriller 实际提交读取 | 4 | 13 |
| PyDriller diff_parsed 调用 | 5 | 210 |
| PyDriller 历史源码读取调用 | 8 | 347 |
| 检出的日志变化事件 | 13 | 863 |
| 可枚举使用实例抽样框 | 12 | 781 |
| 语义处理实例 | 12/12 | 100/781 |
| 独立规则复核支持 | 9/12 | 0/100 |
| ambiguous | 3/12 | 100/100 |
| unsupported（正常样本） | 0/12 | 0/100 |
| 已支持目录类型 | PII/email：1 个实例 | 0 个实例 |
| 已知语义但类型未映射 | 3/12 | 0/100 |
| 已支持非敏感 | 5/12 | 0/100 |
| 风险候选（非真实泄露） | 1/12 | 0/100 |
| 静态日志实参关联支持 | 12/12 | 17/100 |
| 可能 sink 或词法关联 | 0/12 | 83/100 |
| 部分上下文 | 3/12 | 100/100 |
| 历史/文件等缺口记录 | 0 | 6,262 |

真实样本全部进入语义未知待审，不能解释为非敏感。6,262 是缺口记录数，不是 6,262 个字段，不能和 100 个样本相加；上下文“部分可用”也不意味着每一处缺失都影响当前字段。正常真实样本没有独立复核支持的敏感标签，因此本轮没有真实敏感类型识别提升的证据。

真实字段样本来自 7 个仓库：Python 68、Go 30、TypeScript 2；46 个按名称形状划入业务缩写层、54 个为其他或具名字段。15/100 携带已声明模型的上下文，尚不是有人工真值的 15 个控制样本。此次冻结的真实样本没有单独命中泛称名层（0/100）；泛称 data/value/payload 的正负验证来自合成历史，不能外推为真实泛称字段覆盖。100 个固定使用身份来自首轮可用分层抽样，后续修复沿用同一组 ID，没有累计扩大到 100 个以外的真实语义案例。最终可枚举框扩大到 781，新增但未抽中的记录留在 sampling_frame，不冒充已经做过语义分析。

开发集 24/100、评估待审集 76/100，仓库互斥；这些是待人工工作的划分，不是已经开发完成的类别和已经评估过的真值集。真实历史导出保留 669 个初始日志事件、128 条后续记录，其中 621 个初始事件没有观察到后续，669 个初始事件作者归属仍为 unknown。初始事件数、后续数、字段实例数是不同单位。

固定消融：合成 12 个实例中，仅名称支持 0，局部上下文支持 6，加入一跳并复核支持 9，256 字符预算支持 9；3 个新增支持是同一合成流程的历史使用版本，不能算 3 个独立现实发现。真实 68 个 Python 实例中，各有复核条件支持数都为 0。无复核时，2/68 有非空提议，但复核后仍为 ambiguous，不能称为正确敏感标签。截断没有在此真实小样本产生支持状态改善；专门的预算测试仍验证截断时保留 unknown。完整结果逐案例在 ablations.jsonl，未估计任何准确率/召回率。

最终全套 pytest：**736 passed in 31.97s**，其中新增语义与缺失 blob 回归测试 14 项。合成和真实最终 CLI 均退出 0（表示规定运行完成，非完整语义覆盖）；实际执行 `--max-seconds 0` 得到 paused/退出 2，再用 `--resume` 完成；最终再次续跑验证摘要后跳过重复处理。已核验合成 61 个产物摘要、真实 149 个产物摘要，以及两次运行各 39 个源码摘要；字段、复核、案例包 ID 对齐，真实样本 ID 与冻结样本完全相同。SQLite 权限为 0600。

补充实际命令：

```sh
PYTHONDONTWRITEBYTECODE=1 agent_log_privacy/.venv/bin/python agentlog_unified/semantic-inputs/build_pilot.py
PYTHONDONTWRITEBYTECODE=1 agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-scan --config agentlog_unified/semantic-inputs/fixed-pilot.yaml --input agentlog_unified/semantic-inputs/aidev-pilot.jsonl --output agentlog_unified/semantic-runs/aidev-pilot-final --offline --max-seconds 0
PYTHONDONTWRITEBYTECODE=1 agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-scan --config agentlog_unified/semantic-inputs/fixed-pilot.yaml --input agentlog_unified/semantic-inputs/aidev-pilot.jsonl --output agentlog_unified/semantic-runs/aidev-pilot-final --offline --resume
PYTHONDONTWRITEBYTECODE=1 agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q
PYTHONDONTWRITEBYTECODE=1 agent_log_privacy/.venv/bin/python -m pip install --no-deps --no-build-isolation -e ./agentlog_unified
```

过程记录也保留：v1 真实读取 13 个提交但得到 0 个字段，暴露首个缺失 blob 中止快照问题；v2 修复后完成 100 个字段；v3 扩展到已由 PyDriller 读取的同版本源码回退，但导出时重复附加仓库缺口造成膨胀，主动中断，未标为完成。最终版改用共享缺口引用并完成同一固定 100 个样本。没有删除这些中间记录，没有删除或修改 papers。原有 49 类分类表、138 个未映射 schema 字段及 485,812 个账户关联待审单元格没有重算，也没有改变它们的既有待审结论。

尚未完成：一般 schema/文档与代码绑定的自动解释、多语言 AST 绑定分析、复杂动态流与脱敏效果验证、模型执行、人工开放编码/类别合并拆分决策、真实泛称名对照样本和完整真实历史。当前可交付的是可复现的局部上下文、证据复核与待审工具，不是已经验证语义准确率的模型系统。
