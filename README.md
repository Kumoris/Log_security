# AgentLog

日志变更挖掘、历史追踪与人工审阅工具，核心版本 **0.9.1**。本目录就是项目根目录，可直接安装和运行。

```text
agentlog/
├── src/agentlog_unified/     Python 核心包
├── tests/                   核心测试
├── configs/                 专项规则与配置
├── schemas/                 输出结构定义
├── examples/                示例、校准工具及保留的输入
├── scripts/                 研究流程与验证脚本
├── data/                    数据集、输入、仓库与接口缓存
├── outputs/                 各类运行结果与汇报
├── research/                研究记录、协议和独立评估封存材料
├── papers/                  论文与参考资料
├── docs/                    技术说明及历史版本报告
├── archive/                 旧材料、迁移清单与恢复备份
├── pyproject.toml           包定义、依赖和命令行入口
├── requirements.lock        核心与测试依赖锁定
├── requirements-aidev.lock  AIDev 可选依赖锁定
├── config.example.yaml      默认配置
└── run.py                   便捷启动入口
```

`src/agentlog_unified/` 是正常的 Python 包名，不是另一个完整项目。原 `workspace/` 和嵌套项目层已移除，没有目录链接。

## 安装与使用

完整工具建议在 **WSL/Linux、Python 3.11+** 下运行；部分模块使用 `fcntl`，原生 Windows 不支持完整功能。在当前目录执行：

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock -r requirements-aidev.lock
python -m pip install --no-deps --no-build-isolation -e .
agentlog-unified --help
python -m pytest tests -q
```

也可以使用便捷入口：

```bash
python run.py paths
python run.py check
python run.py tool --help
python run.py research scripts/agent_log_motivation_v12.py --help
```

`check` 只检查目录结构；工具和研究流程仍需各自的运行验证。研究脚本的 `--workspace .` 现在直接指本项目根目录。实际研究执行前必须遵守 [AGENTS.md](AGENTS.md) 的隔离检查。

## 数据和结果位置

- `data/dataset.json`：原工作区数据集文件。
- `data/inputs/`、`data/semantic-inputs/`：导入数据与语义研究输入。
- `data/cache/`：仓库和接口缓存；旧隐私工具缓存在 `legacy-privacy/` 子目录。
- `outputs/runs/`：核心工具运行结果；旧隐私工具结果在 `legacy-privacy/` 子目录。
- `outputs/batches/` 和 `outputs/*-runs/`：批次及各类专项分析结果。
- `outputs/` 下原日期目录：既有研究流程交付。
- `outputs/presentations/`：原 `workspace/report/` 汇报材料；`outputs/tool-reports/`：原核心 `reports/`。

目录整理未重新计算研究结果。历史记录保留原路径和摘要，通过运行时映射寻找新位置；**旧冻结运行不能因移动而绕过代码、配置和输入哈希校验**。新计算使用新的运行 ID。

详细迁移映射和历史材料使用说明见 [项目结构说明](docs/project-layout.md)。恢复清单、修改前代码和验证记录位于 `archive/flatten-20260928/`。
