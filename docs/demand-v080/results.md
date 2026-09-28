# 实际运行结果：0.8.0 按需语义试验

已实现并运行真实闭环，但本轮不能声称真实语义识别准确率提高。评估阶段发现了两处程序检查边界错误，已修复并保留回归测试；因此本轮比较整体标为**探索性结果**。原始模型输入、输出和旧运行均保留，修正后的规则重核与新模型实验分开记录。

## 修改和验证

新增 `semantic_context.py`、`semantic_demand.py` 和 CLI 命令 `semantic-demand`；复用并扩展 `semantic_model.invoke`、`semantic_bindings.literal`，更新包版本至 0.8.0。新增 `tests/test_semantic_demand.py`、固定样本配置、汇总校验脚本和说明，无新增依赖。具体接口见 [运行说明](../semantic_demand_v080.md)。

交付版本全量测试：**765 passed in 32.18s，退出码 0**。新增 16 项测试实例，覆盖真实合成 Git/PyDriller 历史、跨文件 schema/函数、作用域、别名、覆盖/修改、混合对象投影、派生输出、删除/改名、历史文档缺失、伪造引用/越界/预算、模型不可用/超时/无效响应、离线与恢复。协议模拟只在 pytest 中使用，不计入真实模型实验。

新建的合成历史实际遍历 **4 个提交**，读取 **11 个 diff、15 次 PyDriller 历史源码**，另有明确标记的辅助读取；得到 32 个日志事件、40 个字段使用实例。目标程序从未执行。合成真实模型 smoke 使用其中一个 `data.value` 实例，4 次真实调用完成请求、补取和复核。

主要实际命令如下；完整命令、退出码和输出文件见 [execution.json](execution.json)。

| 命令（在 agentlog_unified 目录，使用 `../agent_log_privacy/.venv/bin/python`） | 退出码/结果 |
|---|---|
| `examples/build_semantic_expansion.py semantic-inputs/synthetic-demand-v080` | 0，新建合成历史 |
| `-m agentlog_unified semantic-scan … --offline` | 0，PyDriller 实际读取 |
| `-m agentlog_unified semantic-demand … --dry-run` | 0，不写分析产物/不调用模型 |
| `-m agentlog_unified semantic-demand … --offline` | 0，模型调用 0 |
| `semantic-demand … --online`，依次 smoke、开发、评估 | 各 0，失败响应保留在账本 |
| 修正后的 `semantic-demand … --online`，原开发队列 1 例 | 0，2 次真实调用 |
| 修正后运行 `… --online --resume` | 0，不重新调用模型 |
| 不兼容配置 `… --resume` | 1，按预期拒绝，未覆盖旧产物 |
| `-m pytest -q` | 0，765 项通过 |
| `-m pip install --no-deps --no-build-isolation -e .`、`-m pip check` | 各 0，无依赖冲突 |
| `examples/report_semantic_demand.py` | 0，逐产物哈希及预算校验 |

开发中曾有 2 项测试失败及一次合成样本选择脚本的 `StopIteration`，均在真实评估前修复。开发首轮一个模型响应被 `supported_without_evidence` 校验拒绝，没有把该响应算作成功解释。随后修复了同一行嵌套调用的完整日志锚点选择，并在新目录重新验证开发队列。

## 真实样本和分母

源数据为既有 `real-v070-final`，其来源是冻结 AIDev 快照 `68ed5f4b80d27a9e057fc57567f38bd322ac73ec` 的本地历史小样本。上游漏斗是 **3 个仓库 → 50 个已挖掘提交 → 447 个日志事件 → 821 个字段使用实例 → 先前冻结的 100 例 → 本轮固定 12 例**；其余 88/100 与更早的 721/821 未入样本记录均保留。

| 原划分 | 仓库 | 数量 | 语言 |
|---|---|---:|---|
| 开发 | 0x80/isolate-package | 4 | TypeScript |
| 评估队列 | 567-labs/kura | 5 | Python |
| 评估队列 | 0x4d31/galah | 3 | Go |

歧义来源为泛称名 3、缩写 4、其他/结构对照 5；包含 1 个上游标记的明确类型上下文对照。没有用模型成功与否补样或替换案例。真实泛称名只出现在 kura，开发集没有泛称名层；冻结 100 例中没有 JavaScript 层。语言与开发/评估角色存在混杂。

最初沿用 4 开发、8 评估。`05fcc…` 在实现时被用于源码检查，已提前单列探索样本；另 7 例在模型运行前冻结。随后评估结果暴露程序检查问题，触发修复，故**最终全轮仅作探索性报告**，不能再宣称独立的保留集性能。选择、冻结时间、源码哈希和暴露原因见 [cohort-freeze-evaluation.json](cohort-freeze-evaluation.json)、[post-evaluation-changes.json](post-evaluation-changes.json)。

## 模型执行和预算

真实 Codex CLI 调用共 **44/80**：合成 4、开发及开发修复 11、原评估队列 27、修正后原开发案例验证 2。最高单案例 5 次，低于 6 次上限。全部使用请求模型 `gpt-5.5`、既有 ChatGPT 登录；44 次回执均未报告可独立核实的运行时模型 ID，故该字段为 unknown。没有外部收费 API 调用。

按运行时回执原字段求和：`input_tokens=647171`、`cached_input_tokens=197120`、`output_tokens=42348`、`reasoning_output_tokens=8853`。缓存和 reasoning 子计数不再加到输入/输出总数上。各次回执耗时合计 1031.333 秒，不包括编写工具、测试和其他运行时间。宿主自动重试为 0；CLI 内部传输重试细节未暴露，不猜测。没有估算金额。

44 次均返回响应，其中早期开发 1 次未通过语义协议校验；最终固定队列 12/12 获得 B、C 的复核响应。旧失败、完全相同请求的缓存复用和新调用分别可查，见 [全局调用账本](global-model-attempts.jsonl)。

真实队列共发出 **28 个补充请求：7 次取得新证据、17 次未找到可确认绑定、4 次重复或无新证据**。17 次未命中中，10 次属于多语言跨模块/动态分派解析不足，4 次符号不在指定使用作用域，3 次绑定未解决；这些不能统称为 Git 文件丢失。

每例新增的模型证据文件最多 1 个，单次全部代码视图最多 11,108 字符，均在设定上限内。**8 文件限制针对补充的模型证据文件，不是既有私有快照载入/建符号索引的 I/O 上限**；缓存载入与未送给模型的文件清单另见 [context-file-availability.jsonl](context-file-availability.jsonl)。没有再次抓取远程仓库。

## A/B/C 比较及事后修正

A 是原冻结规则结果，B 是固定上下文模型解释及复核，C 是按需上下文解释及复核。下表是**原始实际模型运行和当时程序检查的状态计数**，不是正确率：

| 原样本角色 | 分母 | A 语义 supported | B supported | C supported |
|---|---:|---:|---:|---:|
| 开发 | 4 | 0 | 2 | 2 |
| 原来未用于模型开发的评估 | 7 | 0 | 0 | 1 |
| 提前标记的源码探索样本 | 1 | 0 | 0 | 0 |
| 合计 | 12 | 0 | 2 | 3 |

唯一新增 supported 是包装函数参数 `summaries` 的**名义类型**，不是其业务内容，更不是日志泄露；相关参数注解初始视图已经存在，不能将这次状态变化归因为补取带来了新的语义事实。9/12 的 C 语义解释仍然 ambiguous/unknown。C 有 2/12 个 supported 的目录映射，均来自开发样本；没有人工真值，不能声称映射正确率或敏感类型召回率。

原始 C 在 3/12 例中，复核前后至少一个维度的状态或类别发生变化。程序限制记录还包含跨条件重复和未解析步骤，不能把记录条数当作独立模型错误数。

评估后修复并对原始代码视图/模型响应做了**零模型调用的程序重核**：涉及 2 个案例、3 个条件记录。旧原始包不变，修正记录见 [post-evaluation-gate-replay.jsonl](post-evaluation-gate-replay.jsonl)。这是旧模型响应的新规则校验，不是重新进行的模型实验。修正后又对原开发队列中的 1 例进行了 2 次真实调用，验证新代码完整流程可运行；**没有在修正后的版本上重做全 12 例模型比较**。部分原案例已消耗 5/6 次额度，无法在原单案例预算内重做完整 B/C。

## 三个可核查案例

1. **合成 `data.value`：**初始函数声明 `data: Account`，未提供 Account 定义。模型请求 `Account`，宿主取回同 SHA 类定义中的 `Field(json_schema_extra={format: email})`。B 的敏感类型未知，C 支持声明的 `PII/email`；仍仅为静态候选。见 [合成证据](../../semantic-runs/demand-smoke-v080/evidence/6e80d29e4239de650a5c4bc9.json)。
2. **真实 `summaries`，kura/cluster.py:492：**使用位置是 `embed_summaries(summaries, embedding_model)`。取回函数定义不等于原始对象被写入日志。独立模型复核指出它不是具体日志输出；旧程序错误地强制改成 direct_original。新检查保留 unknown/possible，区分包装函数参数与实际输出。见 [原始证据](../../semantic-runs/demand-evaluation-v080/evidence/7f6e6dbb18581f8792d172e9.json)及事后重核表。
3. **真实 `result`，scripts/tutorial_class_api.py:129：**实际打印的是 `len(result)`。补取赋值和 `process_conversations` 后，原值仍经过 `asyncio.run` 及未解决的方法返回链。模型将其按派生计数判为 non_sensitive，这不能说明原始 result 非敏感；新规则将该输入的敏感性改为 ambiguous/unknown，保留 derived_count 日志关系。它是教程路径，单列标记。见 [原始证据](../../semantic-runs/demand-evaluation-v080/evidence/ef227df12c83b80ffb316754.json)。

修正后的 C 日志关系为：possible 3/12、selected_field 3/12、direct_original 3/12、derived_count 3/12；这是关系分类，不表示 12 例均已验证到日志的传播路径。敏感类型状态为 unknown 6/12、unmapped 1/12、mapped 4/12、non_sensitive 1/12；其中包含 ambiguous 状态，**不能把后两类数量当作已确认分类**。

## 尚未完成的范围

- 没有人工真值、人工开放编码或类别拆分/合并决策；仅生成空白模板。准确率、召回率、一致率、类别饱和均为空。
- 一般自由文档、schema 描述和业务缩写的开放解释仍受隐私视图和绑定能力限制。保留白名单结构语义，不直接向模型开放任意注释或文字，更没有把 data/value/payload 加入敏感关键词表。
- 复杂条件、循环、别名副作用、动态分派、导入重导出和跨语言传播尚未完全解析。原运行队列中动态流未解决 8/12、解析不足 6/12、绑定未解决 5/12，可重叠。1 例消耗了两轮上限；不能据此推断多给预算就能解决。
- 没有执行目标代码、安装其依赖、验证真实凭证、测试真实脱敏效果或确认运行时泄露。真实 12 例没有产生已确认隐私缺陷；原模型风险状态为 undetermined 8/12、no_current_risk_evidence 4/12。
- 真实历史复用已有 SHA 固定的 PyDriller 检查点，不等于全部 AIDev 或全部远程历史。先前的历史缺失、合并/分支关联和作者未知状态不被新语义结果覆盖；本轮没有重算此前 138 个待审 schema 字段及 485,812 个账户关联单元格。

最终结构化结果见 [results.json](results.json)，逐例 A/B/C 表见 [comparison-cohort.csv](comparison-cohort.csv)。旧数据、旧运行、缓存和 papers 均保留。后续需要另行冻结未暴露样本并建立人工参考标注，才能讨论真实识别率提升。
