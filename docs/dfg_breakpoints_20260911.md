# DFG 真实断点补充：2026-09-11

本轮复用 `agentlog_unified` 的 PyDriller、历史 AST、语义提取/独立规则复核和 `semantic-dfg` CLI，补充 Python 方法接收者、Go 字段定义、条件赋值与对象写入。图格式为 `dfg-slice-3`，未增加依赖。

## 实现范围

Python 方法调用者现在可根据显式构造、名称别名、同类接收者或接收者类型声明寻找绑定，支持位置参数、关键字参数、默认参数、普通方法以及有限的 staticmethod/classmethod。接收者、类声明和调用点均保存历史锚点。类型声明不能排除子类和运行时替换，方法调用边标为 `possible`。一般继承/MRO、自定义动态属性访问、装饰器改写和无法核实的接收者继续保持未解析。默认仍为两层调用者追踪、8 个调用绑定、每次检索 64 个文件。

Go 新增独立的字段定义证据：接收者/形参类型 → 显式 import → 同版本 go.mod → 同仓库 type/struct → 直接字段声明。类型证据通过 metadata 边连接，`carries_value=false`，不自动传播敏感类型。历史快照读取增加 `.mod`；外部模块缺失、局部类型遮蔽、提升字段、别名/接口、预算与歧义会单独记录。生产 import 不使用 `_test.go` 的字段定义来补缺失类型；公开证据遮蔽字面量和标签内容。

条件与写入分析新增：

- 赋值与使用位于同一控制分支时，可以保留到达定义；不再仅因赋值位于 if/try/loop 内就整体丢弃。
- 有限的 if/else 显式赋值合流保留两个来源和条件，条件可行性未求解，边标为 possible。
- 显式名称别名的一跳字段写入可追踪；别名重新绑定后不污染原对象。
- 排除同一次路径中互斥的 if/elif 分支写入。循环跨迭代写入、容器别名、动态键、多层写入和未知逃逸仍保留不确定性。
- 图中新增 `control_context`，记录日志所在分支/控制结构，最多 8 层；条件不求值，不执行目标程序。

实现位置：`semantic_callers.py`、`semantic_flow.py`、`semantic_go.py`、`semantic_ast.py`、`semantic_evidence.py`、`semantic_dfg.py` 和历史快照扩展。语义复核重新读取原始 AST 并验证赋值、分支、写入链和源码锚点，不接受提取阶段标签作为真值。

## 固定真实样本结果

最终产物使用 `research/dfg-breakpoints-20260911/` 下的 `*-verified` 目录。早期探索输出保留，不能相加当作新增数据。

| 范围 | 分母 | 结果 |
|---|---:|---|
| 原 AIDev 历史代码案例 | 16 个案例、35 个字段使用位置 | 16/16 重现；35/35 生成图 |
| 条件赋值断点 | 同一组 35 个使用位置 | 6/35 补出赋值连接：Python 5 个、TypeScript 1 个 |
| 真实对象写入 | 同一组 35 个使用位置 | 1/35 补出对象字段写入；它也属于上述 6 个案例，不另算第 7 个 |
| Python 方法边界 | 原 35 例中的 2 例 | 已运行接收者/调用者检索，仍无可核实的调用点；两例均触及 64 文件检索预算 |
| 原 issue 历史样本 | 固定 20 个 Java 使用位置 | 20/20 生成图；保持已有的 1 条调用者连接 |
| 新增 Go 上下文对照 | 17 个候选位置中选取 14 个 | 4 个绑定到同仓库字段定义、10 个未解析；有 1 个位置与原 AIDev 35 例重合 |

Go 对照按“已绑定/未解析定义”目的性分层抽取，不能用于报告语义准确率或召回率，也不意味着这些附加日志都被 Agent 修改。4 个成功绑定来自 **两个字段在两个历史版本中的使用**：`config.PortConfig.Port → uint16`、`config.PortConfig.TLSProfile → string`。定义分别指向 `internal/config/config.go` 第 25、27 行；日志使用位于 `internal/server/server.go` 第 103、148 行。它们不是 4 种新敏感类型。

真实对象写入案例 `c0507d3672fa7dd10cfce63c` 来自 instructor 的 `handle_genai_structured_outputs`。现在能排除互斥 if 分支的写入，追到第 654 行对 `templated_msg` 的字段写入以及第 655 行日志使用。上游仍存在 `msg.copy` 与复杂修改/逃逸问题，因此整体业务含义仍未知。

固定 AIDev 35 例仍有 26 例带 unknown 来源边界，2 例带参数边界，7 例到达常量。展开对象后，一例可以同时出现多个 unknown 来源，因此节点数量不能当作案例数量。常量来源也不等于非敏感。规则复核为 34 ambiguous、1 supported，supported 是有限规则证据检查结果，不是人工确认。

这轮没有得到新的目标字段人工真值或新增已验证敏感类型，accuracy/recall 保持 null。67 组人工敏感性参考及原有待审分类没有被更改。模型阶段未运行。

## 历史证据与验证

最终冻结流程实际通过 PyDriller 重新遍历 12 个事件提交，提取 76 条文件差异、调用 diff_parsed 76 次、读取修改前后源码 128 次。`frozen-verified/extraction_audit.*` 记录每条差异和源码的提取方式、回退原因；4 次辅助 blob 读取单独保留。未修改依赖沿用 PyDriller 锚定 revision、GitPython 辅助读取整棵历史树的既有路径。

这是同一批事件提交和历史快照的重新读取，不是新增完整真实 Git 历史。仍有 2,772 条历史/源码/解析缺失记录，不是缺陷数量；35 个 AIDev 使用位置中 25 个带有快照缺失标记。`net/http.Request.RemoteAddr` 缺少对应历史外部源码定义，保持待补，未用当前 SDK 源码或字段名称猜测替代。

合成测试包括真实本地 Git 提交，经 PyDriller 读取方法调用、条件/别名写入的前后版本；另有继承/覆盖/遮蔽、方法参数绑定、互斥分支、循环跨迭代、别名重绑、Go 同仓库 import、错误包/测试文件、历史哈希与删除/重命名等回归检查。最终完整测试 **828 passed in 30.91s**，见 `pytest-verified.txt`；新增断点测试单独运行 **19 passed in 0.36s**。这与真实样本人工评估分开。

`audit.py` 验证固定使用位置的 ID/历史 SHA、原图使用过的源码哈希、新图全部源码锚点、边端点、metadata 边属性、输出哈希与 SVG XML。`comparison_cases.*` 保留逐例前后差异；`semantic_replay.*` 分别保存程序语义、日志关联和未判定的隐私风险；`manual_review_template.csv` 保持待人工审阅。模板分组含重合位置，不应把行数当成独立样本数。

## 实际执行命令

从 `agentlog_unified` 包目录执行；已完成目录用同一代码/输入追加 `--resume`，代码改变则使用新目录。

```bash
../agent_log_privacy/.venv/bin/python examples/trace_aidev_reference_dfg.py \
  --input research/aidev-human-reference-20260910/type-audit \
  --output research/dfg-breakpoints-20260911/frozen-verified \
  --cache-dir cache/object-repos \
  --repo-map research/dfg-callers-20260910/repo-map.json --offline

../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-dfg \
  --input research/dfg-breakpoints-20260911/frozen-verified \
  --output research/dfg-breakpoints-20260911/aidev-verified --max-rows 100 --offline

../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-dfg \
  --input research/seven-stage-v090/development-release \
  --output research/dfg-breakpoints-20260911/issue-verified --max-rows 20 --offline

../agent_log_privacy/.venv/bin/python examples/dfg_breakpoint_controls.py \
  --input research/dfg-breakpoints-20260911/frozen-verified \
  --output research/dfg-breakpoints-20260911/go-controls-verified --offline

../agent_log_privacy/.venv/bin/python -m pytest -q
../agent_log_privacy/.venv/bin/python research/dfg-breakpoints-20260911/audit.py
```

既有 `semantic-dfg` 和历史接入工具的 `--offline`、`--dry-run`、`--resume` 继续验证；额外的 Go 对照抽样脚本要求新的输出目录。没有网络抓取、外部付费模型调用、目标程序执行、真实凭证验证、远程仓库修改或数据/papers 删除。
