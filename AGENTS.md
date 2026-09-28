# 项目结构

本目录 `agentlog/` 是唯一核心项目根目录；`src/`、`tests/`、配置与依赖文件直接位于这里。不要再次创建 `workspace/agentlog_unified/` 或并行开发副本。`src/agentlog_unified/` 是 Python 包目录，必须保留。

输入和缓存位于 `data/`，运行与汇报结果位于 `outputs/`，研究协议及封存材料位于 `research/`，论文位于 `papers/`，旧材料位于 `archive/`。研究脚本的 `--workspace` 参数指本目录。

冻结研究、原始输入、历史报告和已接受交付不因路径整理而改写。历史路径通过 `agentlog_unified.paths` 在运行时解析；冻结哈希校验和运行续跑限制必须保持。旧版本报告见 `docs/`，其命令与路径按 `docs/project-layout.md` 解释。

# Independent evaluation holdout

An evaluation holdout was sealed on 2026-09-14 in `research/swechat-independent-holdout-20260914`.

- Before source inspection, rule adjustment, manual case review or regression selection, run its `guard.py` against the proposed record batch or source file. Use the research Python at `research/swechat-windows-continuation-20260914/.venv/Scripts/python.exe`. A nonzero guard exit means the scope includes held-out material or cannot be checked; choose an unrelated development scope.
- Do not read or display files in `research/swechat-independent-holdout-20260914/sealed/` for development. Do not use their source code, identities, previous predictions or aggregate behavior to adjust rules. Old full-corpus exports and source caches also contain held-out records; their location does not exempt them.
- `development_allowed_ids.jsonl` is the allowed existing record-ID list for new development runs. Related files, all source versions, source clones and function families remain protected even under new IDs. Use `guard.py --source-file ... --repository ... --path ...` for new source.
- Read the public `封存说明.md` and `人工标注与评估口径.md` for the protocol. The 49 + 180 + 150 earlier cases are development/regression material, not an independent benchmark.
- Keep the sealed delivery and all accepted parent deliveries unchanged. Run structural integrity checks without displaying case content. Rule freezing, blinded human annotation and prediction locking must precede evaluation; `evaluation_gate.py` must pass. No evaluation has been run at sealing time.
- If held-out material is deliberately used for development under later explicit user instructions, record the entire affected isolation cluster as contaminated and retire it from independent evaluation. Never silently reuse or replace it to improve a score.
