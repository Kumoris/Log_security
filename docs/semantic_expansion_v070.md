# 0.7.0 语义扩展：实际运行与边界

本轮在原工具上实现并运行了一个增量版本。**提高了可解析和可审阅的范围；尚不能声称提高了真实业务语义的准确率。** 真实固定样本为 100 个字段使用实例，其中 7 个使用 `data` 或 `result`，这 7 个目前均未获得规则支持。没有人工真值、人工开放编码结果或类别饱和证据。

论文的方法结构沿用此前对 `papers/2605.29442v2.pdf` 第 3 节、附录 A.2、附录 D 的阅读：候选提取、独立复核、分类/开放编码分开。论文提示词是研究材料；无人评论的代码实例照常保留。

## 实际实现

| 部分 | 已实现 | 明确上限 |
|---|---|---|
| schema 与代码绑定 | `jsonschema.validate` 的显式导入、作用域、实例参数和 schema 绑定；静态字典/常量；本地 JSON Pointer、循环/预算检测；Pydantic `Field` 和 dataclass 字段 metadata | 相对外部 `$ref` 的运行时基准未确定时只进入待审；不自动联网解析 schema；任意加载器、组合 schema、自定义校验器未通解 |
| 文档绑定 | 同一历史函数的 `:param` 文档；声明字段的 description/title 指纹；显式同仓库文档引用和缺失/截断记录 | 参数文档可能过时，不能单独成为已支持敏感类型；未实现任意自然语言文档的通用自动解释 |
| 多语言绑定 | Python `ast`；JavaScript、TypeScript、Go 的 Tree-sitter 参数、局部赋值、成员投影、对象和局部类型声明；原始源码独立重解析复核 | JS/TS/Go 主要是同模块绑定，跨过程展开仍需复核；跨文件语言符号解析、闭包和复杂解包未通解；C# 仍降级 |
| 动态流与处理效果 | Python 可配置 1–4 跳，默认 3 跳；`await`、别名、静态键投影、已有分支/对象路径；固定返回值的静态输入独立性检查 | 动态分派、反射、循环、回调、复杂副作用仍 unknown；没有执行目标代码，也没有验证真实哈希、截断、正则脱敏或运行时泄露 |
| 模型 | `semantic-model`：工具关闭、只读、两个独立 Codex CLI 会话；schema/引用检查、实际用量和错误记录、恢复运行 | 模型建议与规则、人类分开；模型给出的分析维度名称不会自动成为敏感分类；模型 `supported` 不是人工正确率 |
| 人工编码 | `semantic-codebook`：100 份四维标注模板、幂等追加账本、证据 hash 检查、分歧队列、类别提议和接受/拒绝/推迟记录 | 本轮实际人工标注和类别决策均为 0；身份为自述，未认证；类别决策不悄悄改写正式 taxonomy |
| 真实历史 | 新专用 bare clone；对象缺失审计；PyDriller 全目标提交提取；另行运行较小的语义/日志追踪样本 | 可达对象齐全不代表删除分支或所有远程历史齐全；两个初始提交的主分支整合仍未确认 |

仍保留四个独立维度：数据集元数据含义、程序值含义、日志输出关联、隐私候选。`len(data)` 中的 `data` 会进入字段使用样本，但标为 `nested_expression_input`；不将其整份内容判作已进入日志。

新增代码集中在 `semantic_bindings.py`、`semantic_ast.py`、`semantic_history.py`、`semantic_model.py`、`semantic_review.py`，复用既有 `semantic_evidence.py`、`semantic_scan.py`、PyDriller、匹配、追踪及导出路径。没有重写原流水线，没有改变 49 类目录，也没有重算 AIDev 元数据 schema。

## 实际测试和合成运行

- 完整 pytest：**749 passed in 28.55s**，见 [原始输出](v070-pytest.txt)。此前 736 项基础上，本轮增加 13 项测试。
- 合成 Git：4 个提交、32 个日志变化事件、40 个字段使用实例，包含 Python 36、JS 2、TS 1、Go 1。PyDriller 实际读取历史，目标程序没有被执行。
- 40 个实例中，规则复核 supported 18、ambiguous 22；12 个类型映射为 PII/email，只有其中 6 个满足此工具的静态日志候选条件。它们全部是合成代码，不能计入真实缺陷数量。
- 25 个合成泛称名实例中规则支持 15；2 个实例满足限定的静态固定输出检查。发现 21 条合成后续修改，包括跨文件变化、重命名、删除和未知作者。
- 固定 40 例消融：仅名称支持 0，局部支持 12，一跳支持 12，最多三跳支持 18，256 字符截断支持 18。这里的数字是规则证据支持量，不是准确率或召回率；本次截断没有改变支持量。

结果：[synthetic-v070-final/coverage.json](../semantic-runs/synthetic-v070-final/coverage.json)。

## 真实历史与字段小样本

新增缓存位于 `cache/semantic-full-v070`，原缓存和原输出没有删除。

| 仓库 | 本地 advertised refs 可达提交数 | 本轮全目标 Git 审计提交数 | 语义/追踪选取提交数 |
|---|---:|---:|---:|
| 0x4d31/galah | 146 | 146 | 10 |
| 0x80/isolate-package | 524 | 252 | 20 |
| 567-labs/kura | 659 | 262 | 20 |
| 合计 | 1,329 | 660 | 50 |

前一列覆盖缓存中多个 refs；中间列覆盖冻结默认目标的全部可达提交及给定初始提交，范围不同。3 个缓存均非 shallow、无 partial-clone 配置，所审计对象缺失数为 0。**660/660 个所请求提交均获得 PyDriller 提交记录**，实际调用 `diff_parsed` 3,063 次、读取历史源码 5,116 次；仍有 197 条提取缺口记录，包含源码/diff 大小限制等，不能说每个文件的全部源码都已分析。

`galah` 初始提交是目标 tip 的祖先，初始至 tip 的 10 个提交均进入语义历史流程。另两个初始提交不在当前目标祖先链上，保留“整合未确认”；不能仅凭这一点判定 squash。其语义运行存在提交预算缺口。

证据：[对象补采审计](../semantic-runs/history-v070/history_collection.json)、[全 Git 提取审计](../semantic-runs/history-v070/full_git_mining_audit.json)、[逐提交与逐文件差异记录](../semantic-runs/history-v070/full_git_audit)。每条差异保留提取方式、回退原因、版本、路径、变更行号和源码指纹。

语义运行在上述 50 个提交中产生 447 个日志事件、821 个唯一字段使用位置，固定选取其中 **100 个**。先覆盖日志，再抽字段；未选的 721 个位置、排除项和缺口均保留。

| 100 个固定真实实例的维度 | 实际结果 |
|---|---|
| 语言 | Python 46、TypeScript 26、Go 28 |
| 歧义来源 | 泛称名 7、短名/缩写 40、其他 53 |
| 泛称名的范围 | 可用框中的 7/7 均入样；全部来自 kura。5 个位于教程/示例程序，另外 2 个 `data` 位于程序模块。不能当成 7 个生产隐私事件 |
| 类型上下文对照 | 13/100 有现有检测器记录的数据模型上下文，不是人工标注的正确答案 |
| 规则复核 | supported 2/100、ambiguous 98/100 |
| 支持的内容 | 2 个明确的模型类构造调用身份；**没有进一步证明这些对象的字段内容或敏感类型** |
| 泛称名规则支持 | 0/7，业务语义仍待审 |
| 待审分流 | 已知声明类型但未映射 2；上下文/历史缺失 2；语义未知 96 |
| 日志关联 | 9/100 满足原工具静态参数关联条件；91/100 仍为可能关联或内部表达式输入 |
| 隐私候选 | 规则候选 0/100；运行时泄露确认 0 |
| 开发/评估分离 | 26/74，按仓库隔离；尚无人工真值 |

在相同 100 个使用 ID 上，`real-v070-third` 到 `real-v070-final` 新增了 2 个**名义构造类型**支持，不能表述为业务敏感语义识别率提升。最终固定样本的名称基线支持 0/100，局部、一跳、三跳和截断各支持 2/100；本小样本没有证明多跳提高了真实敏感类型覆盖。

本次语义追踪导出 146 个初始日志记录，观察到的对应 followup 为 **0/146**。不能由此推断没有后续修复：两个仓库存在整合/预算缺口。本轮 2,882 条数据缺口中，2,786 条是原日志发现层保留的词法降级提示；AST 字段绑定并没有把这些日志自动升级为已确认 sink。

结果：[字段与类型](../semantic-runs/real-v070-final/field_semantics.jsonl)、[独立复核](../semantic-runs/real-v070-final/independent_reviews.jsonl)、[证据包](../semantic-runs/real-v070-final/evidence)、[漏斗与覆盖](../semantic-runs/real-v070-final/coverage.json)。

## 真实模型执行与人工待审

模型参数固定为 `gpt-5.5`，提示词版本 `semantic-model-evidence-2`。合成 smoke 完成 1 例的两个阶段。随后从固定真实样本选择 1 个泛称名实例和 1 个类型上下文对照，分别使用新会话执行提取和复核，共 **4 次调用、4 份有效响应、2 份独立复核**。运行记录未观察到工具调用。当前执行器强制 ChatGPT 登录，移除 API key 环境变量；默认 CLI 行为仍不运行模型。

- `result`：模型支持“异步调用结果，随后用于计算长度并返回”的有限解释；缺少被调用函数契约，具体元素含义未证实。
- `cached`：提取阶段提出隐私候选；复核发现当前日志只输出 `len(cached)`，风险改为 `undetermined`。它没有证明缓存内容泄露。
- 两份复核的 `supported` 是**模型输出的状态**。原始响应还将“派生量的日志关联”统称为 `supported_static_argument`，分析维度名称也出现在 category 字段；这些不作为整值日志证明或正式敏感 taxonomy。额外[维度审计](model_dimension_audit_v070.json)将它们保留待审，规则结论未被覆盖。

实际用量记录：60,375 input tokens、6,656 cached input tokens、2,436 output tokens；缓存输入是输入的子集。12,000 字符预算限制的是证据代码视图，不等于 CLI 系统提示和完整请求的 token 总量。没有准确率、召回率或人工一致率估计。

证据：[模型执行账本](../semantic-runs/model-real-v070/model_manifest.json)、[模型审计](../semantic-runs/model-real-v070/model_audit.json)。CLI 参数参考[官方非交互执行说明](https://learn.chatgpt.com/docs/non-interactive-mode)及[官方配置文档](https://learn.chatgpt.com/docs/config-file/config-reference)。

人工输出：[标注 CSV](../semantic-runs/human-coding-v070/annotation_template.csv)、[编码审计](../semantic-runs/human-coding-v070/coding_audit.json)。目前 100 个案例均待人工检查，实际人工标注 0、类别决定 0。导入未填写模板实测为 no-op，没有伪造确认。

## 运行方式

以下命令均在工作区根目录执行。完整的已执行命令、退出码及 stdout 见 [执行记录](semantic_v070_execution.json)。已有语义输出目录必须使用 `--resume`；源码、解析器版本、输入或配置改变后应使用新目录。

```bash
# 合成历史已创建；重复扫描使用新的输出目录
agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-scan \
  --input agentlog_unified/semantic-inputs/synthetic-v070/input.jsonl \
  --output agentlog_unified/semantic-runs/synthetic-v070-final --offline --resume

# 恢复固定 100 个真实使用位置
agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-scan \
  --config agentlog_unified/semantic-inputs/fixed-expansion-v070.yaml \
  --input agentlog_unified/semantic-runs/history-v070/input.jsonl \
  --output agentlog_unified/semantic-runs/real-v070-final --offline --resume

# 模型默认关闭；显式 online 才执行。此已完成目录恢复时不再发起调用
agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-model \
  --input agentlog_unified/semantic-runs/real-v070-final \
  --output agentlog_unified/semantic-runs/model-real-v070 \
  --online --model gpt-5.5 --max-rows 2 --resume

# 核对冻结产物、100 例 ID、PyDriller 计数、模型与人工边界
agent_log_privacy/.venv/bin/python agentlog_unified/examples/verify_semantic_expansion.py
```

人工填写模板时，复制到新文件，将 `status` 改为 `submitted`，保留 `origin=human`、证据 hash，四项判断分别填写 `correct/incorrect/unknown/not_applicable`，补充解释和证据引用。然后运行：

```bash
agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-codebook \
  --input agentlog_unified/semantic-runs/real-v070-final \
  --output agentlog_unified/semantic-runs/human-coding-v070 \
  --file /absolute/path/filled-annotations.csv --reviewer REVIEWER_ID --offline --resume
```

类别变更使用 JSONL：`kind=category_proposal`，附 `origin=human`、`status=submitted`、开发样本 `case_ids`、`action=new/split/merge/rename/map`、`categories`、`rationale`。先导入提议，再以返回的提议 ID 提交 `kind=category_decision`、`proposal_id` 和 `status=accepted/rejected/deferred`；保留同一 action/categories/case_ids。评估仓库案例不能用于类别开发，历史记录不覆盖，正式目录需要另行明确更新。

依赖锁定在 `requirements.lock`。Tree-sitter 0.26.0 在真实 TS 文件上发生可复现的原生崩溃；同一批 54 个日志版本在 **0.25.2** 完成，因此最终锁定 0.25.2。失败输出保留在 `real-v070-first`。两个模型初始失败尝试也保留，不能计为有效模型结果。

`--dry-run` 实测不创建输出；真实语义流程实测暂停退出 2、恢复完成退出 0、再次恢复跳过重算；模型离线实测零调用零写入。验证结果见 [机器审计](semantic_v070_verification.json)。原数据、旧输出和 papers 均保留，未执行目标仓库代码、验证真实凭证或写远程仓库。

下一步仍需要实际人工反馈，以及扩大具有明确业务契约的真实泛称名对照。任意文档解释、多语言跨文件符号解析、复杂动态流、实际脱敏效果和未确认的分支整合仍未完成；本轮没有把这些阶段标为已解决，也没有把 49 类当作现实敏感类型全集。
