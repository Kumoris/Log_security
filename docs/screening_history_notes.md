# 历史台账与源码适配核实记录（2026-09-12）

本轮历史适配位于 `src/agentlog_unified/screening_history.py`。旧实验、原始输入和 Git 对象缓存只读；没有执行目标项目安装、构建、测试或应用入口，没有联网、checkout、提交或更改目标 Git 配置。

## 已核实的复用范围

- `batch_mine.ingest_commit_contexts` 使用 SQLite `jobs / contexts / input_gaps / records / metadata`。提交按规范化 `repository + sha` 去重，关联上下文单独保存。
- 旧 `run_full.py` 从 `inputs/swechat-full-v3/commit_contexts.jsonl` 按仓库分片；`merge_results.py` 把初次结果与恢复结果投影到 `research/swechat-full-risk-20260912/final/batch/batch.sqlite`。新模块直接以 SQLite `mode=ro` 和 `query_only` 读最终投影，没有调用会创建锁、更新表或重导出旧文件的 `_database`。
- 旧 `_mine_commit` 实际调用 `Repository(..., single=sha, num_workers=1).traverse_commits()`、`ModifiedFile.source_code_before/source_code`、`diff_parsed`。合并提交旧策略逐个父提交比较，并通过 `Git.diff`、独立路径集合和显式父树差异回退保留审计。
- 旧 `file_audit` 保留源码指纹、提取状态和 diff，没有完整源码。旧 `log_observations` 只保留与修改行或一跳依赖修改相交的日志，不能代替本轮“修改文件前后完整源码”的日志发现总体。
- 本轮历史提取复用 `_record_file`、`diff_paths`、`merge_diff_fallback`，显式冻结 `first_parent`；恢复旧文件台账时也只选择相同父提交的事件。其他合并父分支列入 `uncompared_parents`。

## 实际恢复的总体

产物位于 `research/swechat-screening-20260912/population/`。本表为旧最终投影的完整输入恢复及 first-parent 文件事件恢复，不代表所有源码已重新读取，也不代表全量 DFG 已运行。

| 台账 | 数量 | 分母说明 |
| --- | ---: | --- |
| 输入记录 | 8,697 | 固定原始 `final/input.jsonl` 的记录 |
| 去重提交 | 8,697 | `repository + 完整 SHA` |
| 仓库 | 197 | 规范化仓库标识 |
| 原旧投影文件事件 | 85,010 | 包含多个 merge-parent 比较 |
| 本轮 first-parent 文件事件 | 84,156 | 每个提交只使用选定父提交 |
| 文件版本侧记录 | 168,312 | 每个事件 before/after 各一条；包含正常不存在侧 |
| 旧 first-parent 日志观察 | 24,940 | 仅用于旧证据关联与预 DFG 分层 |
| 原旧提取缺口记录 | 89,325 | 保留旧原因，不转成风险判定 |
| 没有文件事件的提交 | 319 | 留在提交层，不伪造文件或输出单元 |

旧提交处理状态为 complete 2,465、partial 5,922、blocked 310。`complete` 是旧声明范围内完成，不能继承成本轮完整源码发现或 DFG 完成状态。

文件侧旧源码状态为 `ok` 107,139、`absent_by_change_type` 35,287、`path_absent` 12,839、`binary` 12,683、`source_budget_exceeded` 339、`source_extraction_error` 23、`decode_error` 2。本轮恢复时统一保留 `source_state=unverified_cached`，待当前 SHA 对象读取后再区分 `present / absent_verified / object_unavailable / extraction_failed`。

输入 SHA-256 为 `12001bfd652404edb5c432c17a569e1c0d091f15aed1471588360a53f6e1ad18`，与 `preparation.json` 及当前规范化输入一致；旧最终数据库 SHA-256 为 `8eda5a302546b91ba7c8e020c49d399ec399d52218af69171ac21f7f5b65fe23`。恢复前后重新计算上述哈希并核对一致。

## 调用契约

`recover_population(project, old_root, output)` 返回数量、路径和哈希，输出：

- `input_records.jsonl`：原始行、数据集快照、源表/行号、会话关联、提交 ID。
- `commits.jsonl`：全部已知父 SHA、选定比较父 SHA、输入映射、缓存位置、旧处理状态及提取指标。
- `file_versions.jsonl`：旧新路径、事件 SHA、实际源码 SHA、before/after、语言/用途范围、旧日志 ID、旧分层、当前尚未核验状态。
- `old_log_observations.jsonl`：仅位置和旧状态，不复制原始敏感源码，不继承最终标签。
- `legacy_gaps.jsonl`、`population_summary.json`：缺口和各层分母。

`iter_historical_sources(repo_path, file_versions, out, max_bytes=2097152)` 每仓库使用单个 `git cat-file --batch`，按完整 `SHA:path` 读取对象。每行返回 `source_state / source_sha256 / blob_oid / source_path / reason / source_cache_hit / source_read_seconds`。源码只写 `out/private/sources/<SHA256>.txt`，文件权限 0600，目录权限 0700。读取后独立重算 Git blob OID 和 SHA-256；缓存同名文件也核验内容，声明的源码哈希不匹配则拒绝复用。

`extract_commit(repo_path, repository, sha, out)` 真正执行上述 PyDriller 入口，读取实际 commit 对象中的全部 parent 行并与 PyDriller 核对，返回 `files`（嵌套 before/after）和 `file_versions`（平铺），两者都含精确源码路径和哈希。审计保存实际调用参数、版本、调用数量、后端、回退原因和时间。Git 辅助校验源码与 PyDriller 源码必须一致；PyDriller 空值通过树/对象读取消除“空文件/不存在/丢对象”歧义。

新源码缓存是内容寻址缓存；不缓存风险判定。恢复旧总体不代表复用旧分析规则或判定缓存。上层运行器负责把本轮代码、配置、规则和敏感性政策纳入分析 ID 和恢复兼容性检查。

## 安全处理与覆盖边界

- PyDriller/GitPython 的原始调用没有统一传入 `--no-textconv`。本模块使用局部命令适配器，为实际 diff/diff-tree 添加 `--no-textconv --no-ext-diff`，并禁用 hooks、fsmonitor、协议访问；不修改仓库磁盘配置。该适配器是进程内暂时修改 GitPython 命令入口，上层应在独立单工作进程调用历史提取。
- 正常缺侧通过准确历史树确认。根提交核实原始 commit 无 parent；重命名分别使用 old_path 和 new_path；不能将 `None` 一律视作不存在。二进制、解码失败、字节预算超限不视为安全。
- `git cat-file --batch` 是 Git 辅助读取，审计不会把它写成 PyDriller 挖掘。所选案例的重新挖掘才统计实际 PyDriller 调用。
- 旧 `max_changed_files=2000` 和历史对象缺失可能令部分提交缺少文件事件。本轮忠实恢复旧已知文件总体；不能宣称这些缺口已经补齐。
- 首父比较不覆盖其他父分支；未修改日志文件的逆向影响分析不在本模块能力内。路径含换行、回车或不可信相对跳转会显式失败，不猜测路径。
- 模块不执行目标软件，也不确认日志运行时触发、落盘、外传、真实泄露或输出单元的 Agent 作者事实。

## 实际执行的验证

2026-09-12 在框架自己的隔离临时 Git 仓库执行：

```sh
cd '/Users/lzh/Downloads/Log 研究/agentlog_unified'
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  '../agent_log_privacy/.venv/bin/python' -m pytest -q tests/test_screening_history.py
```

结果 `4 passed in 0.98s`。四项实际集成测试覆盖根/新增/空文件/重命名/删除、真实 merge 首父比较及 textconv 禁用、精确 SHA 和哈希/损坏缓存/缺对象/正常缺路径/字节预算、完整输入恢复/重复上下文/无日志文件/受阻提交及旧材料哈希不变。测试使用虚构固定输出，无真实凭证；未以 mock 代替 PyDriller 或 Git 提取。

上述四项不替代整体 DFG、工作队列、跨批恢复、AI/人工导入或真实数据适用性验收；这些由本轮主流程的独立结果报告说明。
