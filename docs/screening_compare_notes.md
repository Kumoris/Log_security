# 同提交前后对照的最小实施

`screening_compare.compare_cases(cases, results, extraction_records)` 仅比较传入主试跑清单，不新增未抽中的输出单元，也不为未分析的一侧编造 A/B 结果。每个主案例一行，`variant_changes` 分别保存 baseline 和 dfg_augmented；顶层 `change_label` 对应 dfg_augmented。

配对要求同时成立：同一仓库、事件完整 SHA 和 first-parent 上下文；实际 PyDriller 提取返回的 old/new 文件事件；两侧源码状态 present、准确源码 SHA 与哈希；相同函数语法范围与输出键、角色和拆分版本；日志及输出表达式语法哈希均未改变；日志行不与 diff 新增/删除行相交，且唯一满足 diff 的未变化行映射。重命名使用提取证据中的 old_path/new_path。只凭同名变量、相同日志文本或相似行号不会配对。

执行的保守标签规则：

- after 的实际结果为 A，且 before 文件侧经历史树核实为 absent_verified，才标 `added_risk`。
- before 的实际结果为 A，且 after 文件侧经历史树核实为 absent_verified，才标 `removed_path`。它只表示本条日志路径移除，不表示其他日志或全仓库风险消失。
- 可靠配对两侧均完成限定范围的 C 检查，声明日志边界一致，可标 `no_relevant_change`。两侧均为 A 时，还要求全部已检查源文件的路径和内容哈希一致才给此标签。
- 其他情况为 `cannot_compare`；新增日志不会自动成为新增风险，队列迁移本身不会被解释为输出扩大或风险降低。

每行记录旧新日志和输出锚点、实际源码 SHA/状态、配对依据、未知原因、各变体分析 ID。Agent 归因保持独立；风险变化不会升级为输出单元级作者事实。当前最小适配不支持对发生结构变化的日志自动判定 expanded_output 或风险降低；复杂变化保留无法比较。

2026-09-12 已实际运行框架测试：

```sh
cd '/Users/lzh/Downloads/Log 研究/agentlog_unified'
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  '../agent_log_privacy/.venv/bin/python' -m pytest -q \
  tests/test_screening_compare.py tests/test_screening_history.py
```

结果 `9 passed in 2.31s`。比较模块的 5 项测试使用真实隔离 Git 历史、实际 PyDriller 源码适配及日志输出发现，涵盖新增/删除的证据条件、无风险新增日志、缺对象、同文本不同函数、未变化日志行位移、重命名、未选对侧、变体失败、源码哈希错误和改变文本后的保守拒绝。测试结果不等于真实样本已有多少可比较对；真实输出以本轮 `before_after.jsonl` 为准。
