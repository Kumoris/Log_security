# DFG 调用者反向追踪：实现与实测

这轮在原有历史 DFG 上补了“形参 ← 调用点实参”，没有替换原来的日志检测、PyDriller、语义提取或独立规则复核。方法仍对应 `papers/3603719.3603734.pdf` 的函数内 DFG 与实参/形参连接；这是有预算限制的实现，不是论文完整系统的复现。

## 实际修改

- `semantic_callers.py`：Python 模块函数和显式导入；JS/TS 同模块函数；Go 同目录同 package 函数；Java 同类内可核实的 private/static 方法。支持 Python 显式位置参数、关键字参数、默认参数。默认反向展开两层，每例最多 8 个调用绑定，每次检索最多 64 个源码文件。
- `semantic_dfg.py`：增加带调用上下文的实参节点、反向参数边、调用点证据、每个实参的独立规则复核，以及预算、递归、未解析分派记录。`dfg.max_caller_hops=0` 可关闭新能力，生成相同样本的基线。图格式版本为 `dfg-slice-2`。
- `semantic_context.py`：优先记录逐文件的源码回退原因，防止 PyDriller 已读取的文件被误标为整棵树辅助读取。
- `examples/trace_aidev_reference_dfg.py`：复用已有 73 条 AIDev 参考关联样本，校验源文件哈希、记录 ID、位置及原日志语句；重新读取确切历史版本，并提取选中日志的所有可用 AST 参数使用位置。保留源参考关联、排除项和数据缺失项。不是重新运行全量 AIDev 分类。
- 添加调用者和接入测试；扩展原有真实合成 Git 测试。未增加依赖。

同名、遮蔽、解包、重载、动态接收者等无法核实的关系不生成确定绑定。跨文件 Python 导入边标为 `possible`；所有边均未证明运行时实际执行。保留参数边界及 `additional_callers_not_excluded`，因为找到了部分调用者并不证明覆盖了全部调用者。

调用者实参的语义结果限定为 `caller_actual_argument_only`，不自动传播成整个日志对象或其所有字段的类型。混合对象的字段投影仍独立处理。67 组人工敏感性参考继续保留；本轮没有添加目标代码字段的人工标准答案。

## 最终数据与分母

最终结果目录为 `research/dfg-callers-20260910/`。带 `release` 的目录用于以下统计；早期探索输出保留，不能累加为新样本。

| 范围 | 输入分母 | 实际结果 |
|---|---:|---|
| AIDev 参考关联材料 | 73 条 | 16 条有历史日志坐标；57 条缺少代码绑定，保留在 exclusions |
| AIDev 历史日志案例 | 16 条 | 16/16 重现原日志语句并取得 AST 使用位置，共 35 例 |
| AIDev DFG | 35 个使用位置 | 35/35 生成图；Python 25、Go 9、TypeScript 1 |
| AIDev 新调用者连接 | 同一组 35 例，深度 0 对照深度 2 | 0/35 新增调用者；没有新增已支持的实参语义解释 |
| 既有 issue 历史 DFG | 固定 20 个 Java 使用位置 | 20/20 生成图；1/20 新增 1 条调用者连接，实参语义仍为 ambiguous |

AIDev 35 例来自 4 个仓库：`567-labs/instructor` 19、`0x4d31/galah` 9、`3rditeration/btcrecover` 6、`0x80/isolate-package` 1。这是既有候选的目的性样本，不是全量数据、泛称字段全集或独立评估集。

最终冻结流程实际运行 12 次 PyDriller 提交遍历，读取 12 个唯一事件提交，提取 76 条文件差异记录、调用 `diff_parsed` 76 次、读取修改前后源码 128 次。修改文件来自 `Commit.modified_files` 或合并差异的 `Git.diff`；4 次辅助 blob 读取和每条差异的提取方式/回退原因记录在 `frozen-release/extraction_audit.*`。其他未修改依赖文件通过 PyDriller 锚定 revision 后使用已有 GitPython whole-tree 辅助路径读取，原因明确记录为 PyDriller 2.11 无整棵历史源码 API。

最初只用 `cache/object-repos` 时两个 galah 案例缺少版本对象；复用工作区已有 `cache/semantic-full-v070` 后全部恢复。没有网络抓取，也没有使用工作区最新源码补旧版本。12 个历史快照中仍有依赖文件缺失等限制，共 2,772 条缺失/解析/历史范围记录，见 `frozen-release/gaps.*`；这不是缺陷或泄露数量。图中 25/35 个 AIDev 使用位置带有快照缺失标记，该标记不代表每一条已有边都无效。

## 新接通的真实例子

Apache Zeppelin，历史 SHA `33eb08be765b08ced3b750290c9d7cd155ef60ff`，文件 `zeppelin-zengine/src/main/java/org/apache/zeppelin/notebook/repo/zeppelinhub/security/Authentication.java`：

```text
第 116 行 getAuthKey(userKey) 的实参
    → 第 136 行 getAuthKey 的形参 userKey
    → 第 137 行日志中的 userKey
```

逐例图：`issue-release/graphs/5d15304269e0d8061738a131.svg`，同名 JSON 保存调用点源码锚点、遮蔽后的证据与复核记录。第 116 行实参此前可能发生修改或逃逸，独立规则复核返回 `ambiguous / mutation_or_escape_unresolved`。因此只是多找到一层来源，不能据此断言 userKey 的业务类型，更不能证明泄露。

## 仍然未知的内容

AIDev 35 例中，26 例有 unknown 边界、2 例停在函数参数、7 例到达常量。常量来源也不自动等于非敏感。两个形参边界位于 Python 方法，当前不能可靠解析其动态调用。其余主要断点包括 mutation/escape、条件赋值、结构字段定义缺失和未解析调用。

issue 20 例仍有 5 例带参数边界；加入调用点后有 unknown 边界的案例由 15 变为 16，新暴露的是上述实参的数据流中断。边界是可重叠统计，不能相加当作案例总数。

本轮没有支持复杂对象别名的完整 points-to 分析、虚方法/回调/框架路由的完整调用图、多层动态写入、运行时脱敏验证或全仓完整历史。没有运行模型或目标程序；没有新增人工评估。DFG 的来源连接不等于语义准确率提升，55 个真实字段使用位置都尚无本轮人工真值，accuracy/recall 维持 null。

## 命令与验证

在 `agentlog_unified` 包目录执行以下命令。源码快照 checkpoint 为本地权限 0600 的证据缓存；分享时优先使用遮蔽后的图和导出表。

```bash
# 重新冻结 16 个历史代码案例；repo-map 指向本机已有缓存
../agent_log_privacy/.venv/bin/python examples/trace_aidev_reference_dfg.py \
  --input research/aidev-human-reference-20260910/type-audit \
  --output research/dfg-callers-20260910/frozen-release \
  --cache-dir cache/object-repos \
  --repo-map research/dfg-callers-20260910/repo-map.json --offline

# 默认两层调用者追踪
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-dfg \
  --input research/dfg-callers-20260910/frozen-release \
  --output research/dfg-callers-20260910/aidev-release --max-rows 100 --offline

# 相同源码、相同使用位置，关闭调用者扩展的基线
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-dfg \
  --config research/dfg-callers-20260910/baseline.yaml \
  --input research/dfg-callers-20260910/frozen-release \
  --output research/dfg-callers-20260910/aidev-baseline-release --max-rows 100 --offline

# 复用已有 issue 历史快照
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-dfg \
  --input research/seven-stage-v090/development-release \
  --output research/dfg-callers-20260910/issue-release --max-rows 20 --offline

# issue 基线另加 --config research/dfg-callers-20260910/baseline.yaml，输出 issue-baseline
# 已完成目录追加 --resume；--dry-run 不创建输出。代码或输入改变时需新目录。
../agent_log_privacy/.venv/bin/python -m pytest -q
../agent_log_privacy/.venv/bin/python research/dfg-callers-20260910/verify_outputs.py
```

最终完整测试：**809 passed in 34.04s**；相关定向测试：**30 passed in 1.05s**。合成测试与真实样本结果分开，测试通过不代表真实语义识别率。测试覆盖五种语言的直接绑定、关键字/默认参数、同名遮蔽、多个调用者、递归和预算、混合对象投影、历史版本隔离、跨文件脱敏、重命名、删除和哈希篡改拒绝。

`comparison.json` 和 `comparison_cases.*` 保存逐例固定样本对照；`verification.json` 保存实际历史锚点与输出哈希检查。`manual_review_template.csv` 提供 55 例待审模板，业务含义、类别、日志关联和评审人保持空白，状态为 pending。图集分别见 `aidev-release/index.html`、`issue-release/index.html`。

下一步应优先解决真实样本已暴露的断点：有类型约束的 Python 方法接收者、Go 结构体字段定义、以及有限条件/写入路径。先在这批固定样本上补来源证据，再检验是否能新增可靠的业务解释。
