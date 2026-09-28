# 历史输出适配与 DFG 证据接口

本模块只提供证据，不输出最终 A/B/C/D 队列，也不执行目标软件。`screening_evidence.py` 复用 `detector.detect_snapshot` / `PythonSnapshot.sink` 发现日志，再按输出位置拆分；实际图由 `HistoricalContext` 和 `semantic_dfg.build_graph` 生成。旧 `export_dfg` 默认单批 20 及内部导出截断不参与新入口；新入口每个案例直接调用一次现有 `build_graph`，全局调度另行负责。

## 输入与输出

- `discover_file_status(path, source)`：文件层检测日志数、解析状态、输出支持和原因码。解析失败、语言不支持及检测未命中在文件账保留，不能从空案例列表推定安全。
- `discover_outputs(repository, event_sha, parent_sha, source_sha, side, path, source, files=None)`：全长 SHA 必须与 before/after 比较侧一致；`files` 是调用方已经按同一历史 SHA 读取的源码字典。输出稳定 `case_id`、`log_id`、原 detector 日志 identity、精确 AST 行列锚点、输出角色、日志边界、源码及片段哈希、依赖版本与基础证据。源码、消息文本与完整常量不进入案例。
- `baseline_evidence(case)`：基础证据深拷贝；只检查实际输出表达式中的直接常量/字段/标识符，不复用 DFG 结果。
- `analyze_dfg(case, files, config)`：逐文件核对冻结 `source_versions=[{path,sha,source_sha256}]`；若额外提供 `config.snapshot_sha` 或 `config.source_versions` 也必须一致。重新核对日志和输出片段锚点/哈希。错误 SHA、依赖变更或缺失、错位锚点均抛出 `ValueError`，由主流程记录受阻，不能以近似源码补齐。

`case_id` 由仓库、事件 SHA、比较父 SHA、实际源码 SHA、比较侧、路径、日志与输出 AST 锚点、输出角色索引以及拆分版本构成；不含 A/B 变体、运行目录、重试编号。`source_versions` 在冻结选择前允许加入同一历史 SHA 的依赖，最终分析必须逐字节一致；它不是从工作区推测文件版本的替代品。主流程保存实际采集后端及仓库对象验证证据。

DFG 返回 `{graph,evidence,processing_status,reason_codes,source_versions,elapsed_seconds}`；存在图时可把 `graph` 直接写 JSON，并通过 `semantic_dfg.svg(graph)` 写 SVG。既有 `safe_view` 会替换字面值、注释及自由文本，但允许列表中的 schema 值、部分字段名和满足标识符规则的内容仍可能保留；图的其他字段也不因此自动脱敏。写成标识符或字段名的秘密可能出现在节点 `code_view` 或字段标签中，因此不能宣称原图已隐藏所有秘密。原始 JSON/SVG 必须作为受限本地产物保留；可分享报告须由单独的白名单导出步骤选择位置、边类型、哈希等必要字段，不能直接复制原图或按敏感词未命中认定可分享。输出证据维度使用 `source_sensitivity`、`output_sensitivity`、`connection`、`processing`、`boundary`、`paths`、`critical_unknowns` 等字段，与判定模块契约一致。

## 本轮支持与保守边界

Python 的日志消息模板、格式化参数与常量均有输出单元；`logging.log` 的 level、`stacklevel` 等控制参数不作为输出。`extra` 的字段支持到日志记录边界；未宣称格式化器一定输出字段。`exc_info` / `stack_info` 控制的隐式异常内容用明确未知单元保存，布尔标志本身不当作敏感输出。`print` 的 `file` / `flush` 是控制项，显式 `sep` / `end` 是输出。

Python 字典及 JS/TS 对象直接字面量可拆分已知字段，动态展开保留排除已知字段后的余项；没有父对象重复单元。动态展开可能覆盖前面的静态字段时，该字段保留关键未知。经变量传入的对象、动态字段、复杂模型实例尚不扩展成伪造的字段锚点。包装器发现复用原 detector 的有界函数检查；包装器参数、未核实 API 和附加 logger 上下文的最终输出语义不视为已证明。

JS/TS/Go/Java 复用既有 Tree-sitter 精确语法锚点；Go 显式 Context/LogAttrs 的控制参数有界排除。通用第三方结构化 API、Go 的完整 builder/键值语义、logger alias/方法重写仍有限，保留 API 未解析。C# 虽有检测器，现有历史 DFG 没有 C# AST 后端，因此文件层记不支持，不构造虚假的输出或图。未修改文件的逆向影响发现不在此适配层实现。

敏感常量可形成零跳证据；未知调用中出现敏感常量仅是线索。变量名、字段名只构成疑似，不凭名称构造业务来源。固定 boolean/null 或明示政策占位符可以完整检查；一般字符串即使未命中规则仍保留未知。已有 DFG 的实际参数/形式参数、赋值、返回与字段投影边保留各自历史位置；类型/schema 边不是值传播，形式参数不是最终业务源。未核实序列化、复合格式化、函数调用和条件可达性仍不宣称原始敏感值必然残留。

既有 `input_independent_output` 的 raw AST 固定返回验证可证明此输出未携带调用参数；参数自身仍可疑。无关未解析参数不会抹除已充分支持的独立风险路径；可能改变该路径的未知仍记录在路径上。

## 预算与验证

默认预算：200 节点（另有最多 1 个截断哨兵）、24,000 上下文字符、2 级调用和 2 级调用者扩展、64 文件。现有内部硬上限另为每次 8 个调用者绑定、每次调用者搜索 64 文件；图记录实际预算和触发缺口。底层 `analyze_dfg` 的 `max_seconds` 默认为 30 秒，仅在返回后检查实际耗时并记录软时限超出；它自身不提供抢占式中断。主流程 `screening.py` 另以 `deadline(cfg['max_case_seconds'])` 包装单案例 DFG 调用，通过 POSIX `SIGALRM` / `ITIMER_REAL` 触发 `TimeoutError` 实施截止，并保留受阻尝试及已有独立证据。不能把底层软检查描述为整个 runner 的唯一时间限制。主流程可冻结更小预算，但不得将失败或截断当成安全。

已实际执行框架测试命令（项目根目录）：

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ../agent_log_privacy/.venv/bin/python -m pytest -q tests/test_screening_evidence.py tests/test_semantic_dfg.py tests/test_semantic_breakpoints.py
```

针对测试覆盖零跳敏感常量与报告不复制原值、消息/格式参数/控制参数、extra 边界、部分对象余项、函数同名变量、版本和依赖哈希拒绝、实际跨文件实参/形参/返回 DFG、固定 helper 返回、类型边隔离、节点预算、非 Python 常量，以及解析失败/不支持状态。此处是合成语义与旧 DFG 集成回归；真实数据适用性必须以主流程本轮真实产物另行验收，不能从这些测试推断。
