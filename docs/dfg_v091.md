# 历史数据来源 DFG：0.9.1

参考用户提供的 `papers/3603719.3603734.pdf`，Zhou 等，*Privacy-Preserving Redaction of Diagnosis Data through Source Code Analysis*，SSDBM 2023，DOI 10.1145/3603719.3603734。已阅读全部 4 页，并核对第 3–4 页方法图。论文内容作为研究材料处理。

## 论文方法与本地实现

论文 §1.2、§2.2、§2.3 及图 1–4 的思路是：提取函数的输入、输出、导入等元数据，以 AST 和赋值关系建立函数级 DFG，按函数标识保存；查询时从日志语句反向追踪，利用实参与形参、返回值连接函数子图。论文还配置 logger 输出源码位置，从真实日志定位源码，然后将源属性与专家敏感性标注对照。

| 论文组件 | 本轮对应 | 边界 |
|---|---|---|
| Scanner/Parser | 复用 Python AST、JS/TS/Go/Java tree-sitter 与既有绑定证据 | Java 调用解析、闭包、动态写入等仍有限；未实现 Scala DFG |
| 函数 DFG Repository | `functions.jsonl` 以仓库、SHA、路径、函数锚点形成稳定 ID，并保存参数/返回/import 锚点和节点索引 | 只为选定日志反向切片建立索引，没有构建全部函数的完整 DFG |
| 跨函数连接 | Python 有限显式调用的 actual-to-formal、返回值和赋值边；调用上下文参与节点身份 | JS/TS/Go 跨帧绑定标为 possible，Java 动态成员调用保留 unknown |
| 日志定位 | 使用既有历史日志语句、SHA、行列与源哈希 | 不配置目标 logger，不收集真实运行时日志；Java 日志入口仍是词法候选 |
| 源敏感性标注 | 保留现有类型判断及人工账本，图只提供额外证据 | 本轮没有专家源属性标签或新人工真值，不自动执行 redaction |

这是方法的有限改造，不是对论文系统或实验指标的复现。论文只报告了三个 Spark 应用场景，不能把其指标外推为本工具的识别率。

## 图怎样阅读

图的箭头沿“产生值 → 使用值”的方向；来源查询沿箭头反向进行。例如合成测试实际构建：

```text
emit(data) 的参数
  → 调用处的 data
  → helper.identity(payload) 的形参
  → return payload
  → identity(data) 调用结果
  → value 的赋值
  → logger.info(value)
```

实线标为 `structural_ast`，表示有局部 AST 绑定证据，不证明路径一定执行。虚线的种类必须看边的 kind/status：`metadata` 是类型/schema 解释关系，`possible` 是未确定的传播关系。外部调用的参数只是消费依赖，`call_argument_dependency` 不参与值来源可达性统计。

函数参数节点是来源追踪的边界，仍标记 `caller_origin_not_traced`；它不等于已识别数据库列、网络字段或用户输入。动态调用、作用域外符号、突变和预算不足保留 unknown。敏感类型识别与 DFG 来源绑定不是同一指标。

投影切片会剪掉已确定未读取的对象字段：`payload['safe']` 不会自动继承 `payload['private']` 的来源。固定返回 helper 的反向路径不会加入未被返回值使用的输入参数；仅保留既有“这个日志参数的固定输出”静态检查结果，不宣称脱敏全面有效。

每个节点保存原始 SHA、文件、行列、函数/调用上下文、源码与片段哈希、提取后端和回退信息。可读片段隐藏字面量和注释；显示预算不足会单独标记。没有用最新工作区源码解释旧版本。

## 实际执行与结果

结果目录：`research/dfg-v091/real-release/` 和 `research/dfg-v091/synthetic-release/`。探索输出保留，不能相加当作新数据。

| 指标 | 真实开发样本 | 合成历史 |
|---|---:|---:|
| 输入/生成 DFG | 20/20 | 43/43 |
| 节点记录 | 54 | 250 |
| 边记录 | 34 | 207 |
| 带版本的函数索引条目 | 12 | 41 |
| 追到当前函数参数的案例 | 5/20 | 24/43 |
| 常量边界 | 0 | 10/43 |
| 未知来源边界 | 15/20 | 9/43 |
| 模型调用、人工新增标注、目标程序执行 | 0、0、0 | 0、0、0 |

真实样本复用上一轮的 20 个 Java 使用实例，来自 4 个仓库，没有新增真实 Git 历史。这 20 个中精确叫 `value` 的有 6 个，DFG 在其中 2 个追到本函数形参，另外 4 个仍未知；不存在新的 `data/payload` 对照。这里的 2/6 不是语义准确率。

例如 KAFKA-7510 的一个 before 实例 `2e42d55c0f0b6dcdfe044e79`，图把 `RecordCollectorImpl.java:131` 的日志参数 `value` 连到同一历史版本 `recordSendError` 的 `V value` 形参（第 120 行）。`V` 的类型关系单列为 metadata，具体业务敏感类型仍未确定。

合成端到端先新建真实 Git fixture，经 `semantic-scan` 真正运行 PyDriller，再运行 DFG。读取 4 个提交，覆盖跨文件 helper 修改、重命名和删除，包含 Python/JS/TS/Go/Java。不是手工写出的模型结果。

新增 7 项 DFG 测试覆盖跨文件参数/返回、同名作用域、版本隔离、混合对象投影、固定输出、未知调用、Java 泛称名、预算、真实 PyDriller 历史、离线续跑及证据篡改拒绝。最终完整测试为 782 passed in 33.90s，输出见 `research/dfg-v091/pytest-release.txt`。没有人工参考标注，因此 accuracy 和 recall 保持 null。

## 命令

在 `agentlog_unified` 包目录运行；`--input` 接受已经完成的 semantic-scan 目录。新命令只读本地历史对象的冻结快照，拒绝 `--online`，不新增网络或模型调用。

```bash
# 本轮实际运行的真实样本 DFG
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-dfg \
  --input research/seven-stage-v090/development-release \
  --output research/dfg-v091/real-release --max-rows 20 --offline

# 续跑需使用相同的代码、输入和预算
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-dfg \
  --input research/seven-stage-v090/development-release \
  --output research/dfg-v091/real-release --max-rows 20 --offline --resume

# dry-run 不创建输出，不读取目标源码
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-dfg \
  --input research/seven-stage-v090/development-release \
  --output research/dfg-v091/dry-run --offline --dry-run

# 本轮实际新建的合成历史（已有目录不可覆盖）
../agent_log_privacy/.venv/bin/python examples/build_semantic_expansion.py research/dfg-v091/synthetic
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-scan \
  --input research/dfg-v091/synthetic/input.jsonl --config research/seven-stage-v090/synthetic.yaml \
  --output research/dfg-v091/synthetic-scan --offline
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-dfg \
  --input research/dfg-v091/synthetic-scan --output research/dfg-v091/synthetic-release --max-rows 100 --offline
../agent_log_privacy/.venv/bin/python -m pytest -q
```

预算配置在 `config.example.yaml` 的 `dfg` 节：默认 200 个节点、24,000 字符、2 跳。截断时允许额外一个明确的 budget boundary 节点。CLI 单次最多 100 个案例，按冻结 case ID 排序取预算内样本，未选择案例单独导出。

## 交付与局限

- `index.html`：离线折叠案例查看器，不使用外部脚本、字体或网络资源。
- `graphs/<case_id>.svg/.json`：逐案例图与可核查节点证据；SVG 悬停可查看边类型和原始锚点。
- `nodes/edges/functions/source_summaries`：JSONL/CSV，用于后续检索、模型上下文或 DFG 辅助人工复核。
- `unresolved_cases/not_selected`：处理失败与未抽中案例；“生成图成功”与“来源已解析”分别统计。
- `coverage.json/manifest.json`：分母、预算、哈希和执行边界。

本轮未将 DFG 自动注入模型提示词或原来的盲标包。使用 DFG 的人工检查应标记为辅助条件，避免混入先前无机器辅助的标注条件。没有改写既有敏感分类、人工参考答案或模型预算账本。

内置浏览器的本地 HTML URL 访问被浏览器安全策略拒绝，未绕过；因此未声称完成页面视觉预览。SVG 会进行 XML、节点/边引用与坐标边界检查，离线文件可由用户自行查看。
