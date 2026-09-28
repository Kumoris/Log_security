# AIDev 接入、分类与覆盖审计执行报告

日期：2026-09-09。工具版本：0.3.0。分类版本：1.0.0。

四项功能均已实现并运行：AIDev Parquet 多表接入、统一主类与细类、未知类型待审队列、类型汇总及覆盖审计。完整测试 **217 passed in 34.35s**。机器可读验证记录见 [aidev_verification.json](aidev_verification.json)，操作说明见 [README.md](../README.md)。

## 数据版本与全量接入结果

原 `data/repos/AIDev/` 的 18 个文件实际是 Git LFS 指针。本轮先尝试取得公开主分支，下载得到 11 表、2,743,854 行主 PR 表的另一版本，不能与既有研究分母混用。随后查询公开版本历史，定位到 [固定版本 68ed5f4](https://huggingface.co/datasets/hao-li/AIDev/tree/68ed5f4b80d27a9e057fc57567f38bd322ac73ec)，将其恢复至 `cache/aidev-frozen/`。

**18 张表全部通过原指针的 SHA256 校验**，合计 964,775,076 字节。原指针目录未修改。校验明细见 [冻结数据验证](aidev_frozen_verification.json)；主分支差异见 [初次下载核对](aidev_download_verification.json)，未纳入本轮导入分母。

| 本轮实际读取与关联 | 数量 |
|---|---:|
| 完整读取的本地表 | 18 |
| 所有表记录之和 | 2,456,073 |
| all_pull_request 表记录 | 932,791 |
| 三张 PR 表记录之和 | 973,005 |
| 合并去重后的 PR 身份 | 939,353 |
| 被合并的重复 PR 行 | 33,652 |
| 无法定位 PR 身份的 PR 行 | 0 |
| 有有效提交关系、进入 mining_prs 的 PR | 33,580 |
| 缺少有效提交关系的 PR | 905,773 |
| 存在元数据或标签冲突的 PR | 56 |
| 提交文件记录中的非空 patch 文本 | 641,721 |
| 提交文件记录中的空值 patch | 70,202 |

939,353 包括合并后的 Agent 元数据和 Human PR；它不是单张 all_pull_request 的行数，也不是已经分析源码的数量。`mining_prs` 仅根据可关联提交 SHA 选择，没有用日志或敏感词预筛。存在 orphan 用户/仓库引用和部分无法关联的评审评论，逐表记录在 [导入覆盖报告](../inputs/aidev-full-v2/coverage.json)。非空 patch 仍为 `present_unverified`，不替代 PyDriller 读取的 Git 源码。

导入正常走完，退出码 **2** 表示上述覆盖缺口。输出目录是 `inputs/aidev-full-v2/`，包含 `normalized_prs.jsonl`、`mining_prs.jsonl`、私有 `aidev.sqlite`、`coverage.json` 和 `manifest.json`。原始正文、补丁及未规范化字段仍通过原表及行号定位，不复制到类型汇总中。来源标签保持 provided/unverified。

第一次全量尝试已读完所有表，但用户关联 SQL 使用了低效的相关查询。已改为分别按用户 ID、登录名索引查询，加入查询计划及中断测试，再在新目录完整重跑。原 `inputs/aidev-full/` 保留为中断记录，不是交付结果，不能拿其未完成数据库续作正式分析。

## 分类、未知队列与统计口径

统一目录包含 **AUTH、PII、QID、BIZ、CFG、DIAG 六类、42 个受控细类**，覆盖密码、密钥、邮箱、手机号、医疗、金融、精确位置、生物特征、可关联 ID、业务内容、内部资源和诊断载体。类别中的 unspecified/载体项也计入这 42 个条目；它们不代表已识别出 42 种实际缺陷。

分类读取实际日志输出值的静态证据；固定文案、计数和已验证脱敏不直接生成敏感类型。原 `data_types` 保持兼容，新增字段标明主类、细类、证据依据、置信度和版本。未知值、仅凭名字的线索、宽泛载体和语义分析缺口进入独立待审队列。待审不等于新类型，所有结果保持人工 pending。

输出自动覆盖全部日志事件的 before/after 及已保存源码快照，包括删除、后续变化和一跳依赖变化；不只读取 L3 候选。`type_occurrences` 的单位是“仓库＋提交快照＋路径＋日志位置/身份”，同一版本的事件和快照引用合并，但不同提交中的同一条日志仍是不同版本。多标签、日志版本数、事件数与初始 PR 数分别统计，不能相加混用。

新增文件：

- `data/taxonomy_catalog.json`：版本化分类目录。
- `data/type_occurrences.jsonl`、`reports/type_occurrences.csv`：逐日志版本与来源引用。
- `reports/type_summary.csv/json`：主类和细类汇总，保留零计数。
- `data/unknown_type_review_queue.jsonl`、`reports/unknown_type_review_queue.csv`：待审队列。
- `data/pr_coverage_audit.jsonl`、`reports/pr_coverage_audit.csv`：逐 PR 的 Git、语言、解析和缺失证据。
- `reports/code_coverage_audit.json/csv`：该运行的覆盖分母；未分析或有缺口时，负例字段为 null。

## 真实代码验证

| 运行 | AIDev 数据集内小样本 | 原融合版缓存校准样本 |
|---|---:|---:|
| run ID | aidev-types-smoke | real-types-v030 |
| PR 数 | 3 | 6 |
| PyDriller 遍历提交 | 53 | 54 |
| 文件差异 / diff_parsed 调用 | 142 | 298 |
| PyDriller 历史源码读取 | 242 | 520 |
| 全历史日志事件 | 18 | 92 |
| 去重日志版本 | 172 | 6,551 |
| 未知类型待审版本 | 103 | 4,640 |
| 初始 PR 日志改动 | 0 | 44 |
| 隐私复查候选 | 0 | 11 |
| 覆盖缺口记录 | 20 | 97 |
| 退出码 | 2 | 2 |

AIDev 小样本选取 `osori/korean-romanizer` 中按 PR 编号排序的前三条输入（18、20、21），选择发生在日志检测前。仓库只克隆 Git 历史，没有检出或执行应用代码。三个初始提交均成功读取；其中两个 PR 有支持范围内的代码分析证据。未观察到这三个初始 PR 的日志行为修改；全历史快照中存在 11 个 DIAG 载体版本，不能归为这三个 PR 新引入的隐私缺陷。20 条缺口为 3 条 GitHub 元数据离线缓存缺失及 17 条动态配置影响未解析。

原缓存样本用于检验类型输出，观察到 AUTH/BIZ/CFG/DIAG/PII 标签，但仍全部是静态候选。其 6 个 PR **不在本轮冻结的 AIDev 元数据中**，已从全量 AIDev 覆盖分子排除，不能用于声称 AIDev 全量覆盖。

真实运行结果入口：

- AIDev：[类型汇总](../runs/aidev-types-smoke/reports/type_summary.csv)、[未知队列](../runs/aidev-types-smoke/reports/unknown_type_review_queue.csv)、[代码覆盖](../runs/aidev-types-smoke/reports/code_coverage_audit.json)。
- 缓存校准：[类型汇总](../runs/real-types-v030/reports/type_summary.csv)、[未知队列](../runs/real-types-v030/reports/unknown_type_review_queue.csv)。

## 全量分母与实际代码覆盖关联

新增 `aidev-coverage` 命令，将完成的多表导入与一个或多个运行进行只读关联。只有 PR 身份匹配，且数据集提交 SHA 同时出现在实际 Git 记录与分析快照中，才计入提交分析覆盖。重复运行只计一次。

[跨运行覆盖报告](../reports/aidev-corpus-coverage/corpus_coverage.json)的实际结果：

- 冻结导入共有 939,353 个 PR。
- 当前运行选择了其中 3 个 PR，2 个有可核对的数据集提交分析证据。
- 939,351 个 PR 尚无本轮可核对的提交分析证据，不能视为无日志或不敏感。
- 另有 6 个校准 PR 不属于该冻结数据集，单独报告。

因此，本轮完成的是**全量多表接入与小样本代码验证**，尚未完成 939,353 个 PR 的全量 Git/源码敏感类型普查。`run_mode: full` 已取消输入 PR/仓库抽样上限，但 Git 历史、文件和磁盘预算仍显式生效。核心单运行仍在内存保留分析记录，大规模挖掘应按仓库分批，并使用覆盖命令合并观察范围。

## 实际执行命令

以下列出在工作区根目录执行的关键命令，省略输出重定向及下载的超时、缓存环境变量。相同正式输出不得覆盖，重新实验请使用新名称。

```bash
# 安装读取 Parquet 的可选锁定依赖（本轮实际安装 PyArrow 21.0.0）
PIP_NO_INDEX=false agent_log_privacy/.venv/bin/python -m pip install --index-url https://pypi.org/simple pyarrow==21.0.0
agent_log_privacy/.venv/bin/python -m pip install --no-deps --no-build-isolation -e ./agentlog_unified

# 恢复与原指针一致的公开快照
HF_HUB_DISABLE_IMPLICIT_TOKEN=1 hf download hao-li/AIDev --type dataset --revision 68ed5f4b80d27a9e057fc57567f38bd322ac73ec --include '*.parquet' --local-dir agentlog_unified/cache/aidev-frozen --max-workers 4 --quiet

# 全量接入、恢复与测试
agent_log_privacy/.venv/bin/agentlog-unified aidev-import --aidev-dir agentlog_unified/cache/aidev-frozen --output agentlog_unified/inputs/aidev-full-v2 --offline
agent_log_privacy/.venv/bin/agentlog-unified aidev-import --aidev-dir agentlog_unified/cache/aidev-frozen --output agentlog_unified/inputs/aidev-full-v2 --offline --resume
agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q

# 独立 Git 缓存与真实小样本
GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null -c protocol.file.allow=never clone --no-checkout https://github.com/osori/korean-romanizer.git agentlog_unified/cache/repos/osori__korean-romanizer
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/aidev_smoke_config.yaml --run-id aidev-types-smoke --offline
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/aidev_smoke_config.yaml --run-id aidev-types-smoke --offline --resume
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/real_expanded_config.yaml --run-id real-types-v030 --offline --with-reverse

# 合并全量分母与代码覆盖
agent_log_privacy/.venv/bin/agentlog-unified aidev-coverage --aidev-import agentlog_unified/inputs/aidev-full-v2 --analysis-run agentlog_unified/runs/aidev-types-smoke --analysis-run agentlog_unified/runs/real-types-v030 --output agentlog_unified/reports/aidev-corpus-coverage --offline
```

导入 resume 已验证输入和输出哈希；AIDev 小样本 resume 保持截止时间与类型输出哈希不变。dry-run 无写入、全量模式取消抽样、字段映射、LFS 缺失、重复/矛盾关系、删除日志、未知参数、多标签分母及公共导出脱敏均有测试。

本轮仅进行公开数据下载、依赖安装和只读 Git 克隆；导入及挖掘运行使用 offline。未调用付费模型，未运行目标程序，未验证真实凭证，未修改远程仓库。原两套工具源码哈希复核一致，`papers/` 未修改。
