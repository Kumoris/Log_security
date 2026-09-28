# 融合版实际执行报告

日期：2026-09-09（Asia/Shanghai）。版本：`agentlog-unified 0.2.0`。

已交付独立 Python 包和 CLI，完成合成 Git 历史与真实缓存小样本的七阶段运行。两套原工具的 Python 源码哈希复核一致，未修改 `papers/`。本报告中的数字来自本轮执行；机器可读记录见 [verification.json](verification.json)。

## 融合内容

| 保留或吸收的能力 | 本轮落地方式 |
|---|---|
| 本地工具的证据与挖掘主线 | 保留 ingest → collect → mine → detect → trace → assess → export；PyDriller 实际遍历、提取 diff 和读取源码；提取方式与回退原因逐条记录 |
| agentlog-core 的 Python 依赖分析思路 | 加入字典更新、下标赋值、删除、简单别名、LoggerAdapter 字段和执行条件；保留一跳依赖及未知副作用 |
| 日志身份与历史连续性 | AST 语义匹配消除纯格式变化；同提交唯一跨文件搬移；重复候选保留歧义，解析缺口恢复保留不确定区间 |
| 人工审核与匹配纠正 | CSV 审核原子导入、追加历史、重复导入幂等、过期提示；JSONL 配对纠正后重放分析；人工字段独立于机器结果 |
| 反向修复线索 | 可选 SZZ，只回溯完整日志语句中实际删除的行；输出独立 repair_enriched 队列，不改变正向样本分母 |
| 输入与复用 | 增加 TXT PR 清单、可选按日期分区的 GitHub 搜索；支持固定运行 resume 和新运行 extend-from |

直接复用已安装依赖，无新增依赖下载。原工具环境中另行安装了新的可编辑包；两套原工具源码均保留。来源说明见 [NOTICE.md](../NOTICE.md)，使用方法及输入格式见 [README.md](../README.md)。

## 实际执行命令

以下命令在 `/Users/lzh/Downloads/Log 研究` 执行：

```bash
PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_CACHE_DIR=/private/tmp/agentlog-unified-pip-cache agent_log_privacy/.venv/bin/python -m pip install --no-deps --no-build-isolation -e ./agentlog_unified
python3 agentlog_unified/examples/build_fixture.py
agent_log_privacy/.venv/bin/agentlog-unified doctor --offline
agent_log_privacy/.venv/bin/python -m pytest agentlog_unified/tests -q
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/local_fixture_config.yaml --run-id synthetic-unified --offline --with-reverse
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/real_expanded_config.yaml --run-id real-unified --offline --with-reverse
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/real_expanded_config.yaml --run-id real-unified --offline --with-reverse --resume
agent_log_privacy/.venv/bin/agentlog-unified run --config agentlog_unified/examples/real_expanded_config.yaml --run-id dry-only --offline --with-reverse --dry-run
```

环境检查：Python 3.11.15、Git 2.51.0、PyDriller 2.11、GitPython 3.1.61、PyYAML 6.0.2、pytest 8.3.5、jsonschema 4.23.0。依赖版本见 [requirements.lock](../requirements.lock)。

## 测试与运行结果

最终测试：**142 passed in 16.69s，退出码 0**。测试包含真实创建 Git 提交并由 PyDriller 读取的合成历史；覆盖依赖变化、日志歧义、跨文件匹配、缺口恢复、审核导入、人工纠正重放、语义字段脱敏、反向 SZZ 和增量复用。

增量集成测试实际复用 2 个提交，只提取 1 个新提交；与完整重挖结果比较，并验证旧运行数据库和清单未变。SZZ 专项测试实际调用 PyDriller，验证仅改跨行日志参数时能够回溯，且不会混入同文件无关变更的作者。搜索分区、截断和重复分页使用模拟 API 测试；未进行实时网络搜索。

| 指标 | 合成历史 | 真实缓存小样本 |
|---|---:|---:|
| 输入 | 1 个本地提交输入 | 6 个 PR，1 个仓库 |
| PyDriller 提交遍历 | 5 | 54 |
| 文件差异 / diff_parsed 调用 | 5 | 298 |
| PyDriller 历史源码读取 | 10 | 520 |
| 原生辅助 blob 读取 | 2 | 6 |
| 全历史日志事件 | 6 | 92 |
| 初始日志改动 log_changes | 2 | 44 |
| 存在可能后续关联的初始日志 | 1 | 1 |
| 可能后续事件数 | 3 | 1 |
| 隐私人工复查候选 | 1 | 11 |
| 未观察到后续修改的日志 | 1 | 43 |
| 来源未知的初始日志 | 0 | 44 |
| 覆盖缺口记录 | 0 | 97 |
| 退出码 | 0 | 2 |

合成历史中的消息变化被保守匹配拆成新增和删除，形成 2 条初始改动。后续关联均为 possible，没有升级为 supported。上述候选数不能视为准确率或缺陷数。

真实样本来自现有 `Kathrynhiggs21/Kova-ai-SYSTEM` 缓存。七阶段及可选 reverse 均完成，退出码 2 表示覆盖缺口。97 条记录分别为 **72 条无 AST 的词法降级、25 条动态日志配置影响未解析**；这是缺口记录数，不是 97 个失败 PR。没有选定提交缺失，执行失败表为 0。

真实样本的 44 条初始改动全部保留 `calibration_only` 和来源 `unknown`；评估分桶为 29 条 NEEDS_CONTEXT、15 条 OUT_OF_SCOPE_OR_FALSE_POSITIVE，无 REVIEW_READY。其中 11 条进入隐私复查队列。这批数据验证流程可运行，不证明存在 11 个隐私缺陷，也不能用于 Agent 与人类的差异结论。

两次完整运行的 reverse 分别扫描 5 和 13 个主线提交，修复关键词匹配均为 0，SZZ 调用及反向候选均为 0。因此反向能力的执行证据来自专项合成测试，真实样本尚未验证到实际修复案例。

恢复检查确认真实运行的截止时间及三层主表哈希保持不变；dry-run 未创建文件、未访问目标仓库。[原工具源码基线](original_source_hashes.json)复核一致。

## 交付结果入口

- [真实样本汇总](../runs/real-unified/reports/summary.json)、[筛选漏斗](../runs/real-unified/reports/screening_funnel.csv)、[覆盖报告](../runs/real-unified/reports/coverage_report.md)。
- [初始日志改动 CSV](../runs/real-unified/reports/log_changes.csv)、[后续关联 CSV](../runs/real-unified/reports/logs_with_followups.csv)、[隐私复查候选 CSV](../runs/real-unified/reports/privacy_review_candidates.csv)。
- 同名 JSONL 位于 `runs/real-unified/data/`；逐案例包位于 `runs/real-unified/evidence/`；人工审核模板位于 `runs/real-unified/reports/human_review_template.csv`。
- [合成运行清单](../runs/synthetic-unified/run_manifest.json)、[真实运行清单](../runs/real-unified/run_manifest.json)记录源码、输入、配置、冻结末端、阶段状态和真实提取计数。

## 当前边界

增量仅复用 Git 提取，检测及追踪仍重算。新运行不会自动继承旧运行的人工审核和匹配，需要核对新证据后重新导入。安装已验证可编辑源码模式，未验证独立 wheel 部署。

Python 支持有限静态依赖；JS/TS 仍使用跨行词法检测。重复日志、复杂动态副作用、跨缺口精确配对与非唯一跨文件移动仍保留不确定性。反向 SZZ 仅覆盖已挖掘区间；merge/root 及仅改日志外部依赖的修复存在覆盖限制。

本轮未调用付费模型、未执行目标应用程序、未打印或验证真实凭证、未修改远程仓库；没有导入真实人工审核结果。实时 GitHub 搜索、真实修复案例和确证作者来源仍待后续数据支持。
