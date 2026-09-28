# 七阶段计划：0.9.0 首批实施报告

执行日期：2026-09-10。完成 M0 基线记录与 M1 的代码、证据提取、真实开发小批和人工入口；M1 的人工核对尚未完成，七个研究步骤没有全部完成。

实验根目录：`research/seven-stage-v090/`。后缀 `release` 是本轮最终代码下的运行。其他目录保留了探索过程、失败原因与中间版本，不能把重复运行相加当作新增样本。

## 实际修改

- `issue-reference`：校验冻结 issue 中的 PR/提交链接，按需获取公开集成信息；支持记录连接工具补充的提交搜索和祖先关系。原生 Git 只获取提交及父对象；PyDriller 遍历提交、提取修改文件、解析 diff、读取前后源码。每个差异保留提取方式、回退原因与缺口。
- 对 GitHub 中 closed/unmerged 的 Apache 镜像 PR 不直接采信其 merge_commit_sha。首批 6 例由只读连接工具定位 issue 关联提交并检查目标分支祖先关系。它们不是经过证明的完整最终修复链。
- 新增 Java grammar `tree-sitter-java==0.23.5`，接入参数使用位置、局部赋值、别名和字段投影；源视图隐藏字面量及注释，保持行序。Java 日志入口仍为词法候选，Java 类、导入、重载及跨模块绑定尚不完整。Scala 已读取差异，但没有新增 Scala AST 分析。
- `semantic-codebook` 新增 `reference_annotation`，独立记录含义、敏感类型、日志关联、隐私风险，校验案例哈希和证据编号；导出盲标说明、JSON 证据、CSV/JSONL 模板及追加账本。模型来源不能进入人工账本；人工身份是自声明，非认证。
- `semantics.development_only: true` 防止已用于开发的材料进入评估分区。默认既有分区行为保持。未知、新类型候选与非敏感证据分别记录。
- `semantic-demand` 的显式总预算最高支持 300，默认仍为 80，每例最多 6。新实验使用独立账本，初始化为 0/300；旧账本未改动。保留单批最多 4 个开发或 8 个评估样本的限制。

## 实际数据结果

| 层级 | 本轮数量及分母 | 含义 |
|---|---:|---|
| 冻结 issue 组 | 67 | 沿用原始 issue/评论证据 |
| 新取得代码对的 issue | 12/67，8 个仓库 | 每例一个关联集成提交及父版本；不是完整修复历史 |
| PyDriller 首次成功代码对 | 12 次提交遍历，90 次 diff 解析，149 次源码读取 | 90 条修改文件/父差异记录，不是 90 个缺陷；合并提交使用两次 PyDriller 父差异读取 |
| 助手静态源码观察 | 12/12 | 见 `code-review/`；人工确认数仍为 0 |
| 真实日志事件 | 26 | 在所选 12 个提交及可用源码预算内检出 |
| 字段使用抽样框 | 137 | 日志行为检测后建立，没有先按敏感词筛掉日志 |
| 新开发使用实例 | 20/137，4 个仓库，全部 Java | 与旧 100 例按仓库、SHA、路径、使用锚点对比，重合 0 |
| 精确 data/value/payload | 6/20 | 全部为 value；没有 data 或 payload，不满足目标 60 个的总体配额 |
| 工具宽泛 generic_name | 8/20 | 另含 result，不能替代上一行 |
| 语义未知 | 15/20 | 不能解释为非敏感 |
| 上下文或历史缺失 | 5/20 | 依赖、类型和预算等不足 |
| 规则独立复核 supported | 0/20 | 没有真实样本识别率提升结论 |
| Java 日志关联 | 20/20 为 possible | 尚未通过完整日志库绑定确认 |
| 排除/审计记录 | 257 | 171 个变化未与当前 diff 相交、74 个没有受支持的日志行为变化、12 个固定模板；记录数不是不重复样本数 |
| 数据缺口记录 | 436 | 包含词法降级 362、文件预算 24、Python 解析失败 22、浅历史 12 等；可能一例对应多项 |
| 本轮人工标注/模型调用/目标代码执行 | 0 / 0 / 0 | 不计算准确率、召回率、人工一致率或脱敏有效率 |

最终覆盖分母和机器可读漏斗见 `development-release/coverage.json`。未抽中的 117 个使用实例保留在 sampling_frame；日志、后续、无后续、来源未知、排除和缺失均分别导出。无后续只表示所给提交范围内没有观察到后续。

12 例包括 BROOKLYN-10、CALCITE-2463、CAMEL-10885/12480/14150、GEODE-9354、KAFKA-4056/7510、QPID-8460、SPARK-27244/29247、ZEPPELIN-2733。代码核对说明有逐行 SHA、路径、源哈希及 PyDriller 提取来源。

几个实际边界：KAFKA-4056 的告警移除配置值参数；KAFKA-7510 仍在 TRACE 输出记录内容；CALCITE-2463 增加 DEBUG 条件；QPID-8460 修改私有解码异常，尚需补查异常到日志的路径；CAMEL-10885 已发现其他后续提交但未读取完整修复链。不能把这些变化一律标为“彻底修复隐私泄露”。

## 可执行验证

最终全量 pytest：**775 passed in 35.28s**，原始输出在 `pytest-release.txt`。包含真实合成 Git/PyDriller、离线读取、续跑无新提取、证据篡改拒绝、Java 同名作用域/别名/投影、字面量隐藏与行序、盲包不含机器答案、人工记录校验以及 300 次预算边界。

独立合成端到端运行 `synthetic-history-run/` 真正读取 4 个提交，覆盖 Python/JS/TS/Go/Java、schema、跨文件 helper 修改、删除和重命名；检出 34 个日志事件、43 个使用实例，19 个规则复核 supported，22 个语义未知。43/43 都是 synthetic_calibration；这些处理量不是对真实数据的准确率。更早 `synthetic-run/` 只读 1 个提交，保留为截断尝试，不用作完整合成历史结果。

真实 release 离线续跑已成功并返回 `resumed_without_reprocessing`；6 例带冻结集成凭据的 issue-reference 离线提取成功，再续跑 `new_attempts=0`。两个 dry-run 未建立目标输出目录或调用模型。

## 实际命令与复跑

以下在包目录运行；Python 复用 `../agent_log_privacy/.venv/bin/python`。网络获取仅在首批公开对象不足时使用，默认离线。中间运行会因源码指纹变化拒绝直接续跑，应使用新输出目录，不能修改原清单绕过校验。

```bash
# 本轮安装了锁定 Java grammar；随后更新本地可编辑包元数据
../agent_log_privacy/.venv/bin/python -m pip install --no-deps tree-sitter-java==0.23.5
../agent_log_privacy/.venv/bin/python -m pip install --no-index --no-deps --no-build-isolation -e .

# 首批真实获取（已执行，原输出不可覆盖）
../agent_log_privacy/.venv/bin/python -m agentlog_unified issue-reference --input research/seven-stage-v090/issue-selection.jsonl --file research/issue-reference-20260910 --output research/seven-stage-v090/code-pairs --cache-dir cache/issue-code-v090 --online
# 后续使用 resolved-selection.jsonl / resolved-code-pairs 完成另外 6 例

# 最终真实扫描：已存在的完成目录加 --resume 验证，不会重新挖掘
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-scan --input research/seven-stage-v090/development-input.jsonl --config research/seven-stage-v090/development.yaml --output research/seven-stage-v090/development-release --offline --resume
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-codebook --input research/seven-stage-v090/development-release --output research/seven-stage-v090/human-review-release --offline --resume
../agent_log_privacy/.venv/bin/python -m agentlog_unified issue-reference --input research/seven-stage-v090/resolved-selection.jsonl --file research/issue-reference-20260910 --output research/seven-stage-v090/references-release --cache-dir cache/issue-code-v090 --offline --resume

# 合成构建与运行使用新目录；已有证据保留在 synthetic-history-run
../agent_log_privacy/.venv/bin/python examples/build_semantic_expansion.py research/seven-stage-v090/synthetic-new
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-scan --input research/seven-stage-v090/synthetic-new/input.jsonl --config research/seven-stage-v090/synthetic.yaml --output research/seven-stage-v090/synthetic-new-run --offline

../agent_log_privacy/.venv/bin/python research/seven-stage-v090/build_code_review.py
../agent_log_privacy/.venv/bin/python -m pytest -q
```

## 用户人工入口

先看 `human-review-release/blind-review.md`，再另存并填写 `reference_template.csv` 或 `.jsonl`。不要先读机器预测后再补称为独立参考答案。每行分别填写四个维度；不足时保留 unknown 和原因。新的概念可暂不映射到 49 类。初始模板全部 pending，不能当成已标注数据。

完成后导入示例（本轮**未执行**，不存在虚构的用户标注）：

```bash
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-codebook --input research/seven-stage-v090/development-release --output research/seven-stage-v090/human-review-release --file PATH_TO_YOUR_COMPLETED_REFERENCE.csv --reviewer user --offline --resume
```

接口不会因人工填写而自动改变运行时分类目录；类别合并、拆分和 16 个既有提案仍需具体决定与映射验证。

## 七步状态与下一批

| 研究步骤 | 本轮推进 | 未完成工作 |
|---|---|---|
| 1. issue 参考答案 | 12/67 补齐所选提交与代码对、助手逐行观察 | 剩余 55 组代码处置；多提交最终修复链和人工核对 |
| 2. 字段人工真值 | 20 个盲包和可校验导入接口 | 用户逐例标注、非敏感对照、16 个类别提案决定 |
| 3. 泛称名和缩写 | 有限 Java AST；20 个新开发实例 | 补足 40 开发/60 独立评估目标及 60 个严格泛称名，绑定缺失类型与定义 |
| 4. 复杂数据流 | 新 Java 局部路径和明确 unknown | 多函数、对象突变、外部库、跨模块和动态路径仍不完整 |
| 5. 模型和评估 | 新 300 次账本、4 个开发 case 的 dry-run 配置 | 本轮 0 调用；完成开发标注后运行有原始证据的模型批次，再冻结独立评估集 |
| 6. 运行时和脱敏 | 检查隔离环境 | Docker CLI 可用，daemon 当前不可用；未执行任何目标代码。恢复后才运行已授权的虚构输入小例 |
| 7. 历史与全量覆盖 | 新增 8 仓库所选 12 个代码对 | 深度为 2 的对象获取不是完整历史；138 schema 字段与 485,812 关联单元格仍沿用待审状态，未重算 |

默认不调用付费 API，不修改远程仓库，不验证真实凭证。本轮没有删除既有数据或操作 papers。匿名 GitHub API 曾限流；相关失败尝试保留，连接工具补充来源另记，不能把限流当成“该 issue 无代码”。

`baseline.json` 是旧状态的 100 个文件哈希清单，不是旧源码完整备份；旧模型账本和 issue manifest 的哈希复查一致。当前实现另保存源码快照用于复现。本轮没有人工准确率、召回率、类别饱和或 Agent 特有类型结论。
