# logtrace

`REDESIGN_AIDEV.md` 的实现：从 AIDev 找出 agent 在已合并 PR 里新增或修改的 Python 日志语句，
沿默认分支的第一父历史追踪每一条之后 90 天的变化（修改已有日志的，再向前追溯到它最初被创建的提交），
按明确特征识别每个版本输出的隐私数据，把涉及隐私数据的链条连同全部版本、改动和证据输出为数据集。
核心流程全部是确定性代码，不调用大模型；判断改动性质和结果分析留给研究者。

环境：conda env `Log`（Python 3.12，依赖 `pyarrow`，测试用 `pytest`）。旧版（SWE-chat、全历史 ledger、
agentlog_unified 判定器）完整代码备份在 `../Logtrace_code_20260928_pre_redesign.tar.gz`。

## 用法

```bash
PY=/home/ubuntu/miniconda3/envs/Log/bin/python

$PY -m src.cli seeds                                  # 阶段 1：AIDev 表 → out/aidev/seeds/（约 1.5 分钟）
$PY -m src.cli run --workers 6                        # 阶段 2-5：克隆、落点、追踪、特征、数据集
$PY -m src.cli run --repos-file list.txt --skip-done  # 指定仓库；跳过已有结果的（续跑）
$PY -m src.cli track --repo owner/name                # 只跑阶段 2-3
$PY -m src.cli features                               # 只重跑阶段 4（改了特征词典后）
$PY -m src.cli dataset                                # 只重跑阶段 5（改了筛选口径后）
$PY -m src.cli samples                                # 人工核验样本 → out/aidev/samples/
$PY -m pytest -q                                      # 单测 + 合成仓库端到端测试
```

常用选项：`--out`（默认 `out/aidev`）、`--seeds`（默认 `<out>/seeds`）、`--max-stars`、`--smallest N`、
`--window-days`（默认 90）、`--no-print`（不把 `print()` 算作日志）、`--no-fetch-pr-refs`（不拉取 PR 分支）。
测试运行一律放到 `out/tests/<名字>`，并用 `--seeds out/aidev/seeds` 共用种子层。

## 数据

`data/aidev/`：AIDev 的 `repository`、`pull_request`、`pr_commits`、`pr_commit_details` 四张表，以及从
`all_pull_request` 抽出的本批仓库的行（`all_pull_request.ourrepos.parquet`，来源见 `data/aidev/README.md`）。
`data/repos/`：克隆（`--no-checkout`，只有 `.git`），各次运行共用。

## 输出

```
out/aidev/seeds/          prs.jsonl（种子 PR）pr_index.jsonl（提交 → PR → agent）repos.jsonl  manifest.json
out/aidev/repos/<owner__name>/
    lock.json             冻结点。重跑复用；删掉它才会重新冻结
    anchors.jsonl         每个种子 PR 的落点、入主干点、方法（pr_number / pr_head_in_history / patch_id / text）
    seedlogs.jsonl        在落点找到的种子日志（新增 / 修改已有）及逐行归属
    lineages.jsonl        每条种子日志一条链：向前版本、种子版本、向后版本，每次改动的客观记录
    items.jsonl           每个版本的输出项及其明确特征和证据
    result.json           状态、计数、缺口、耗时
out/aidev/dataset/        chains  all_chains  versions  items  changes  unclassified_items  coverage
                          （Parquet + CSV；列表和字典列是 JSON 文本）  summary.json
out/aidev/samples/        人工核验样本（anchors / tracking / authorship / features / unclassified）
```

## 代码结构（`src/`）

| 模块 | 内容 |
|---|---|
| `seeds/aidev.py` | 阶段 1：PR 级种子、提交归属、`pr_index`；全项目唯一认识 AIDev 表的地方 |
| `seeds/exclude.py` `seeds/prefilter.py` | 排除规则（vendored、构建产物、生成代码）；patch 解析与日志正则 |
| `repo/clone.py` `repo/gitcmd.py` `repo/materialize.py` | 加固克隆与 git 调用、冻结点、`cat-file --batch` |
| `repo/history.py` | 第一父历史、改动列表、blob diff、拉取 PR 分支、patch-id、`git log -L` |
| `repo/anchor.py` | 落点识别（三级）与两层落点 |
| `detect/python_ast.py` `detect/items.py` | 日志识别、输出项拆分 |
| `track/match.py` | 逐行对应 + 区域内最优配对（匈牙利算法）+ 改动记录 |
| `track/attribution.py` | 作者认定：提交 → PR → AIDev，外加 agent 签名；三种取值 |
| `track/tracker.py` | 预扫描、向后单遍追踪、合并细看分支、向前追溯 |
| `features/taxonomy.py` `features/identify.py` | 明确特征词典（taxonomy 1.2.0 + 大模型内容）与识别 |
| `report/dataset.py` `report/samples.py` | 链条筛选与数据集输出；人工核验样本 |
| `pipeline.py` `cli.py` | 编排与命令行 |
