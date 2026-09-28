# Logtrace 分享包（2026-09-28）

- 代码：Logtrace 项目的全部源码与测试（git 提交 9f28f14），见 `REDESIGN_AIDEV.md`（设计）与 `README.md`（用法）。
- 结果：`results/aidev_dataset/`，AIDev 全量运行的最终链结果（由上述提交的代码生成）。
- 不含：AIDev 原始数据表（`data/`）、仓库克隆、各仓库的中间文件和其他历史运行结果。
  如需复现，按 `README.md` 下载 AIDev 表后运行 `python -m src.cli seeds` 和 `python -m src.cli run`。

## 结果概况

- 仓库 494 个，追踪链 15,615 条，其中入选（任一版本命中明确隐私特征）3,059 条。
- 特征词典版本 1.2.0+logtrace.2。

## 结果文件（每张表都有 .parquet 和 .csv 两种格式；列表和字典列是 JSON 文本）

| 文件 | 每行 |
|---|---|
| chains | 一条入选链：仓库、种子 PR、agent、引入方式、命中类别、结局、过滤字段（path_kind / pr_seed_count / bulk_change_size）等 |
| all_chains | 全部链（含未入选，`selected` 列区分），用作统计分母 |
| versions | 入选链上的一个日志版本：提交、作者认定、代码 |
| items | 一个版本的一个输出项：表达式、类别、证据 |
| changes | 入选链上的一次改动：改了哪部分、谁改的、改前改后代码 |
| unclassified_items | 没有命中任何明确特征的输出项，按出现次数排序 |
| coverage | 流水线每一步的数量和流失原因 |
| summary.json | 汇总数字 |

## 已知问题（尚未修正）

特征识别仍有几类系统性误判（只输出长度或真假值、只输出状态码等元信息、大模型 token 用量被当成凭证、
按函数名推断来源等），约影响 5% 的入选链；结果未经人工核验。
