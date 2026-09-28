# 当前结构与历史路径

2026-09-28 起，最外层 `agentlog/` 即项目根目录。源码与依赖只维护一份，Python 导入名仍为 `agentlog_unified`。

| 原路径（相对原 agentlog/） | 现路径 |
|---|---|
| workspace/agentlog_unified/src、tests、configs、schemas、examples、docs | 根目录同名目录 |
| workspace/agentlog_unified/pyproject.toml、config.example.yaml、requirements*.lock | 根目录同名文件 |
| workspace/agentlog_unified/cache、inputs、semantic-inputs | data/ 下同名目录 |
| workspace/dataset.json | data/dataset.json |
| workspace/agentlog_unified/runs、batches、各类 *-runs | outputs/ 下同名目录 |
| workspace/agentlog_unified/reports | outputs/tool-reports |
| workspace/outputs | outputs（原日期目录保留） |
| workspace/report | outputs/presentations |
| workspace/agentlog_unified/research | research |
| workspace/papers | papers |
| workspace/scripts | scripts |
| workspace/docs | archive/legacy-docs |
| 核心内原 agentlog_unified/research/tracer-recursion-perf-20260928 | archive/legacy-nested-results/research/tracer-recursion-perf-20260928 |

输入文件、历史结果、docs 中版本报告和 research 中封存交付保持原内容，内含的旧绝对路径是来源记录。它们不是当前操作指南，旧报告中的命令不应直接复制执行。最新入口与安装方式以根目录 README 为准。历史报告的相对链接按上表解释。

`src/agentlog_unified/paths.py` 支持已知旧项目路径在读取时映射，优先使用仍存在的原路径，不搜索同名仓库，不改记录和摘要。当前输入导入、配置加载及活动 SWE-chat 路径读取入口使用该解析器。冻结交付中保存的历史脚本仍保留旧版本；不承诺直接恢复任何旧冻结运行，使用原代码快照复核时需按映射指定数据位置并遵守 guard。

新缓存使用 `data/cache/`，新标准运行使用 `outputs/runs/`。`storage.index_database: data/index.sqlite` 是每次运行内部的相对路径，因此位于 `outputs/runs/<run-id>/data/index.sqlite`，与项目级 `data/` 不冲突。

迁移将目录原地重命名，并在 `archive/flatten-20260928/moves.json` 记录前后路径与文件系统身份。`code-before.zip` 保存修改前活动代码。此次不改变研究口径，不重跑原始数据分析，不调整独立评估隔离范围。
