# SWE-chat 关联应用日志筛选 SOP

本 SOP 说明实际框架入口、阶段输入输出和失败处理，不代替本轮执行报告。运行目录为 `research/swechat-screening-20260912`，旧目录 `research/swechat-full-risk-20260912` 及其数据库、候选表和输入只读。任何样本数、批次数、成功数与耗时均以新运行目录中的清单和实际产物为准；下文命令不表示所有阶段已经执行完成。

本轮完整源码发现因磁盘预算不足暂停，**没有完成全量源码发现**。暂停时的 `discovery/streaming-export.json` 记录原始发现框 174412 个输出单元，以及 728 个输出的源码哈希不一致；这些数量是修复前快照，不是最终可用总体或风险数量。未扫描文件侧在文件台账保持 pending。问题来自文本读取对换行的规范化，使文本重新编码后的哈希不等于原始 Git blob；应按原始字节重新读取受影响历史版本、重建其输出单元并保存映射，然后由 `active_frame` 选择核验过的修复框。不得在必要源码修复之前冻结选择，不得将原框全部当作已经核验的案例。

后续 `source-hash-repair.json` 已记录本轮实际修复成功：31 个文件版本、728 个受影响输出重新发现，框大小仍为 174412，源码哈希失配降为 0，173684 条未受影响记录逐字节保留。修复发生在选择冻结前，原框保留且未替换已选样本。该修复不补齐磁盘中止导致的未扫描源码，不能据此升级为全量发现完成。

本轮大台账已保存为 gzip；发现 checkpoint 已无损归档，原始本轮数据库已移除以释放空间。该归档与旧实验数据库无关。完整输入台账恢复、小规模实际 A/B、跨批恢复和已发现框的分批准备须分别判断，磁盘中止不能改写成全量发现完成。当前工作流不主动跨模型调用。

研究对象是固定 SWE-chat 关联提交所修改软件的应用日志输出单元。会话和 Agent 元数据只支持提交关联。静态 A 队列、SWE-chat 关联、完成工程试跑、准备全量批次及生成人工模板，分别不等于运行时泄露、输出单元 Agent 作者事实、全量深度审查或人工评估完成。

## 1. 工作目录、预算和保护

所有命令从项目根目录运行，正确引用带空格的路径：

```sh
cd '/Users/lzh/Downloads/Log 研究/agentlog_unified'
```

使用已有框架环境 `/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python`。入口是 `-m agentlog_unified screening`；配置为 `configs/screening_v1.json`，敏感性政策为 `configs/screening_policy_v1.json`。不安装或执行目标仓库，不 checkout，不隐式获取历史对象，不上传源码，不调用额外模型 API，不自动提交、推送或改写用户原有文件。

默认发现设计范围为修改文件 before/after 的完整对应历史源码；当前只完成其中已落账的一部分，不代表每个声明文件侧均已扫描。当前依赖扩展是同 SHA 的有界 Python import 读取；未修改日志文件的反向影响分析、任意跨文件包装器发现和不支持日志框架不在已证实覆盖范围。`application_or_unknown` 仅是路径分类，不能直接当作 production；测试、示例、生成/第三方及开发工具范围分别报告。

默认预算应从冻结的 `selection/config.json` 核对：单源码 524288 字节、同案例依赖最多 64 文件/4194304 字节、发现单文件 15 秒、DFG 单案例 30 秒、每批 25 案例、节点 200、字符 24000、值追踪与调用者深度各 2。现有旧 DFG 导出入口的 100 案例限制不作为本轮调度入口；本轮按案例调用现有 `build_graph`，仍遵守其内部支持边界及节点/追踪预算。

原始源码及带源码的 snapshot 放在新运行的 `private` 子目录，原始复核文字放 `.raw_reviews`。受限目录为 0700、敏感文件为 0600。**原 review 包、原图及 evidence_index 都按私有证据管理，只有独立生成并校验的 share-report 用作分享副本。**合法标识符形态的凭据可能被原字段名/参数键或代码视图保留；不能将“只含字段名”理解为完整脱敏。不要把整个运行目录当作可公开压缩包发送。私有索引仅用于有权限的本地人工回查。

## 2. 预检查与版本记录

输入是项目实际代码、依赖环境、固定旧输入/数据库/候选表和本轮配置：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening precheck --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912'
```

检查 `precheck/current.json` 的输入存在性与 SHA256、Python/PyDriller/解析器实际版本、配置哈希、旧发现范围和旧 DFG 硬上限。`precheck/execution-code/version.json` 与 `source` 目录保存实际参与运行源码的哈希和副本；Git 可用时另保留工作区状态与补丁。Git 元数据不可用时 `git_head=null`、`workspace_status=git_metadata_unavailable`，使用实际源码快照追溯，不编造 HEAD，不因此初始化现有项目仓库。

若指定旧材料不可得或哈希不一致，保留受阻原因，不用风险候选表反推完整总体，也不用其他快照或最新源码替代。修复真实输入条件后使用新运行目录或相应有界恢复入口。

## 3. 恢复完整声明输入台账

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening recover --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912'
```

该阶段以只读 SQLite 方式读取旧实验 `final/batch/batch.sqlite`，核验 `final/input.jsonl` 与 preparation 中固定哈希及提交作业集合。输出 `population/input_records.jsonl`、`commits.jsonl`、`file_versions.jsonl`、`old_log_observations.jsonl`、`legacy_gaps.jsonl` 和 `population_summary.json`。

判定标准是每个输入记录都有提交映射或明确受阻原因；候选、未知、未命中、无旧日志、失败和未处理提交均保留。`population_scope=full_frozen_commit_input` 只说明固定提交输入被恢复，旧文件提取缺口仍然存在；不能将其写成仓库全部历史或完整文件覆盖。旧日志标签只参与抽样分层，不继承到本轮风险真值。

合并提交保存全部 parents，默认 first-parent 比较，其他父分支变化列为未覆盖。新增、删除、根提交与重命名分别保留 old/new 路径和版本事件。

## 4. 历史文件发现、部分覆盖与磁盘中止

以下是磁盘空间恢复后**新独立运行**的发现命令合同，不是恢复当前归档数据库的指令。先在同一新目录运行 precheck/recover，再发现：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening precheck --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-next-discovery'
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening recover --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-next-discovery'
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening discover --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-next-discovery'
```

调试时可加 `--max-files 100` 限制本次新增处理文件版本数。该限制产生的剩余项在文件台账保持 pending，不是没有日志。仅在未归档且指纹兼容的新运行中，重复 discover 才读取 checkpoint 并继续未登记文件；已经记录的失败不会被静默换成其他案例。发现代码、相关依赖、源台账或配置指纹改变后拒绝复用旧 checkpoint，应新建运行目录。

当前运行存在 `discovery/checkpoint.sqlite.gz` 而没有原数据库时，discover 明确拒绝并报 `discovery_checkpoint_archived_restore_verified_archive_before_resume`，避免误建空数据库。`checkpoint-archive.json` 记录 gzip SHA256、原数据库 SHA256、两者字节数和 verified_lossless。归档原数据库为 873050112 字节；本轮移除的是该已核验的当前运行明文副本，旧冻结实验未被改动。

需要本地审计归档时，先释放足够磁盘，核验 gzip 的 gzip_sha256，解压到新的临时路径，核验解压后的 original_sha256 和 original_bytes，确认后才原子恢复为 checkpoint.sqlite，并保持文件 0600/目录 0700。不要删除唯一已核验归档，不要将 gzip 当作 SQLite 直接打开。即使归档恢复成功，修复后的源码 reader 已改变发现代码指纹，因此仍不能在当前运行上继续旧发现流程；保留旧 execution-code 快照供审计，使用修复代码的新独立运行进行后续发现，不推荐用存在换行缺陷的旧 reader 扩量。

历史读取使用明确标注的 Git `cat-file` 辅助入口，解析完整 SHA:path，保存 blob OID/源码 SHA256；该读取不冒充 PyDriller 挖掘。先识别日志，再拆分实际输出并做敏感性判断。`extra`、消息、格式参数、异常上下文及对象字段按已支持 API 语义区分；不支持/无法定位的输出保留文件级记录，不能伪造参数案例。

主要输出是 `discovery/file_coverage.jsonl.gz`、`output_units.jsonl.gz`、manifest、checkpoint/归档和受限源码缓存；本轮中止后的流式导出摘要为 `streaming-export.json`，不能假设正常结束的 coverage.json 必然存在。修复框另存为 `output_units.repaired.jsonl.gz` 并保留原框。源码状态必须区分 present、absent_verified、object_unavailable、extraction_failed。确认不存在的版本没有日志案例；空提取结果、解析失败、超时和不支持均不能转成无风险结论。

框架 `rows` 在逻辑 `.jsonl` 不存在时自动读取同名 `.jsonl.gz`。`file_hash('name.jsonl')` 的此类回退计算解压后字节哈希；显式 `file_hash('name.jsonl.gz')` 计算 gzip 文件本身哈希。两种哈希不可互换。active_frame 有修复 manifest 时按其中 output_path 和 output_physical_sha256 核验压缩修复框；没有 manifest 才回退到原逻辑框。换行、依赖和输出锚点的修复必须有自己的记录，不覆盖旧证据或篡改旧哈希。

发现完成或需要审计当前进度时，生成分层台账覆盖；这不触发 DFG：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening ledger-coverage --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912'
```

输出 `coverage/ledger_coverage.json`、`log_versions.jsonl` 和 `commit_status.jsonl`，分别核对输入、提交、文件版本、日志版本、输出单元和映射。

继续 freeze 前先完成必要原始字节哈希修复，再核对当前 active_frame 哈希、文件记录集合、pending/blocked/excluded 数及范围限制。冻结只代表这个实际观察到、可恢复的输出框；未扫描文件侧仍是已声明缺口，不能从可用框反推出未发现输出。

修复接口为 `screening_repair.repair_source_hashes(out)`，必须在 selection/manifest.json 不存在时运行。它读取当前运行已核验的精确 Git blob 字节缓存，逐文件再验 SHA256，仅重新发现确因换行转换发生哈希失配的文件，不重新挖掘 PyDriller、不执行目标。输出 source-hash-repair.json、source-hash-repair-mapping.jsonl、source-hash-repair-files.jsonl 与新 gzip 框。未受影响记录逐字节保留；有歧义的新旧案例只记录 unmatched，不强行配对。现有 manifest/修复产物会拒绝被覆盖；代码存在或模板生成不等于修复已实际通过。

CLI 合同如下。本轮已经有成功修复产物，不要重复执行；它只用于尚无修复产物、尚未冻结选择的对应运行：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening repair-sources --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912'
```

## 5. 冻结分组、分层抽样与历史依赖

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening freeze --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912'
```

先按仓库及相同规范化所在语法内容的跨仓关系分组，再按固定种子划 engineering/evaluation，避免同一日志的前后版本、字段拆分和已识别近重复跨区。此近重复规则有界，不保证识别所有语义近重复。分层仅使用新增 DFG 前已知的旧观察状态与语言；各层稳定排序后按轮转配额抽取，某层不足时如实记录，不伪造补足。

输出 `selection/engineering.jsonl`、`evaluation.jsonl`、`groups.jsonl`、`batches.jsonl`、`full_batches.jsonl`、`pair_context.jsonl`、`config.json`、`manifest.json`，以及选中案例同 SHA 的受限源码/依赖 snapshot。默认目标分别约 100 个工程案例和 24 个独立评估案例，实际数量读 manifest。manifest 保存 frame_artifact、frame_sha256、frame_coverage 和 population_prevalence_claim=false；本轮框的范围明确受磁盘中止影响。freeze 发现已有 manifest 会拒绝改选，不能以失败或判定结果换样。

`pair_context.jsonl` 当前可为空，保留附属对照接口；未纳入主清单的对侧不自动分析、不增加主分母。engineering 用于本轮真实 A/B，evaluation 保留给独立人工评估，不参与调规则。`full_batches.jsonl` 只是 active_frame 中已发现输出的稳定分批清单；文件名中的 full 不代表未扫描源码已补齐，生成它不触发全量 DFG。

## 6. 显式批次实际 A/B、续跑和失败重试

批次 ID 从 0 开始，先读 `selection/batches.jsonl`。以下示范仅执行第一批：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening run --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912' --batch 0 --label main
```

继续已冻结的后续批次需显式指定批次并使用同一 label：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening run --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912' --batch 1 --resume --label main
```

重复同一批次可核验缓存/恢复，只有兼容 analysis_id、完整事务结果、源码/依赖/snapshot 与证据产物哈希全部通过才可跳过。开始后中断的 attempt 被保留为 interrupted，重新尝试不增加独立 case 数。文件存在本身不算完成。

若已记录 blocked 结果并且原历史对象等外部条件已恢复，显式重试原案例：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening run --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912' --batch 0 --resume --retry-failed --label main
```

`--retry-failed` 不换样本，只重试相应失败；正常完成结果仍按兼容规则复用。改变实际分析代码或政策/配置/选单后不得在同 label 上 resume；分析入口会报签名不兼容，应使用新 label 并保持旧产物，必要时新建完整运行目录。`--interrupt-after` 仅用于隔离合成恢复测试，不应对真实运行人为制造中断。

本阶段对关联事件实际调用 PyDriller `Repository(..., single=SHA).traverse_commits()`，再核对 before/after、源码和 parent；merge 使用声明的显式父比较，若后端回退则审计中记录真实后端。来源读取/依赖补充仍分别标注 Git 用途。DFG 增强组通过适配层调用现有 `semantic_dfg.build_graph`，不导入或执行被审查程序。

两变体共享同一 case、基础检测证据、历史 snapshot、政策和 `assess` 逻辑；只允许增强组增加 DFG 证据。每个变体有自己的 analysis_id，每次执行有 attempt_id。失败/未知/截断也保留 A/B 配对。逐案例时间的 `timing_scope=analysis_only_excludes_discovery_and_mining`；基础检测来自冻结发现缓存，不能将其耗时缺失解释为完整基础检测成本。invocation 与 extraction 审计耗时另列，缓存命中只代表读取/校验复用。

## 7. 导出、对账与三层验收

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening export --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912' --label main
```

导出先核验分析签名和证据文件哈希，再写 `analyses/main/results.jsonl`、`ab_pairs.jsonl/.csv`、`paths.jsonl`、`evidence_index.jsonl`、`risk_labels.jsonl`、`attempts.jsonl`、`before_after.jsonl` 与 `coverage.json`。实际图在 `graphs/<analysis_id>/<attempt_id>.json/.svg`；失败案例没有图时保留失败记录，不补假图。

核对 expected/actual、missing/unexpected、重复结果、A/B 基础证据相等、各语言/范围/状态覆盖，以及队列迁移、独立证据维度、关键未知与成本。只执行部分批次时 missing 是真实未完成，不能将 export 成功等同整个选单完成。

提交前后配对须有同事件/父版本、已核验 old/new 文件、输出与函数上下文和唯一 diff 行映射依据；相同文本或变量名不足以配对。仅声明已分析主案例；未选或不可靠对侧保持 cannot_compare。风险变化与 Agent 归因分开，移除单条路径不能推出其他日志或全仓风险消失。

验收分三层：流程完整性看输入去向、集合/哈希和恢复；合成语义看实际框架测试；真实适用性看真实历史定位及有效传播边证据。只有空图、参数边界或失败文件时不能宣称真实 DFG 适用性通过。节点/路径/图/重试计数不是独立漏洞数；没有人工真值，A/B 迁移不称准确率提升。

### 独立分享导出，不改变冻结分析

`scripts/export_screening_share.py` 是 `src/config` 之外的标准库脚本，读取已完成 export 的元数据与产物哈希，不重跑分析。它不复制任何原始源码、源码派生文字、原始 DFG JSON/SVG；仓库、路径、字段名、output_key 和未知文字转换为稳定 SHA256 引用。分享图清单仅保留案例/分析关联与原图哈希。源码行列、源码哈希和证据 ID 可与受限本地映射回查，分享副本不能单独支撑完整人工语义确认。

先进行不会写文件或改权限的本地 dry run：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' scripts/export_screening_share.py --run '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912' --dry-run
```

首次导出到默认 share-report，同时把原 review 目录/文件权限收紧为 0700/0600，私有引用映射保存到 `private/share-maps`：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' scripts/export_screening_share.py --run '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912'
```

脚本拒绝覆盖已存在分享目录；本轮已完成这一步，重新生成时通过 `--output` 指定另一个新目录。原分析、原图、原复核文件的内容和原分析签名保持不变。后续复核/评估修改后若要再分享，先用 metrics 生成对应最新统计，再导出新副本；原主 export 的默认统计不代表后续人工账本的动态真值。

验证独立分享副本：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' scripts/export_screening_share.py --verify --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912/share-report'
```

验证逐文件哈希/字节数、限定字段/枚举与引用格式、完整文件集合和初始盲包无预测字段，不只依赖敏感词正则。share_manifest 绑定原产物集合哈希及私有映射哈希；未知字符串不原样进入分享结果。原 review 包供有权限的人工本地审查，分享包中的 metadata-only 盲表不直接替代原包导入契约。

## 8. 独立人工、AI 和日志漏检评估

export 生成 `review/reviewer_1`、`review/reviewer_2`、裁决模板、AI 提示/schema/输入、政策副本和 private_source_index。初始盲包不包含 A/B 预测及队列；只含历史定位和哈希，因此人工需有权限读取私有历史源索引。两名标注者独立工作，第三人裁决引用原标注 ID。详细结果字段与校验规则见 [判定和复核说明](screening_policy_notes.md)。

真实人工填写完后才运行，例如：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening review-import --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912' --file '/受限本地目录/reviewer_1.jsonl' --kind human
```

第二人使用自己的文件；裁决使用 `--kind adjudication`。`--kind ai` 只用于导入已实际执行且元数据/哈希可校验的额外 AI 阶段，本框架不自动调用模型，也不将 AI 记录作为人工真值。未知案例、错政策或证据版本、错误标签、无证据引用及不一致队列被原子拒绝，模板不能覆盖已完成记录。

风险评估使用预先保留的 evaluation 清单、导入的人类账本与另行生成的同案例预测：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening metrics --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912' --file '/受限本地目录/evaluation_predictions.jsonl'
```

没有真实预测或可靠双人/裁决标签时可不传 `--file`，指标保持 null 并报告原因。每个评估预测至少包含 case_id、queue，实际来源/代码/输入哈希应由其生成阶段保留；不能把 engineering 预测冒充 evaluation 预测。

日志漏检从原始修改文件独立抽检清单 `review/log_detection_omission_sample.jsonl` 进入，不从已检测日志/风险候选倒推。经双人完整文件枚举并准备文件级输入后：

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening metrics --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912' --detection-annotations '/受限本地目录/file_detection_evaluation.json'
```

该 JSON 的 files/predictions/annotations 契约见字段字典与 `detection_metrics`。文件/源码版本必须一致，未审完/无可靠定位的文件不得删去分母或当作无日志。风险指标和日志检测指标分开；缺可靠标签或适用分母时 precision/recall 为 null，不能写 0。

## 9. 全量分批的防误触入口

下列是后续**已发现输出框**的单批准备/执行命令合同，不表示本轮已完成全量发现或全量分析。full_batch_count 只覆盖当前 active_frame，不能覆盖尚未扫描文件可能含有的输出。`prepare-full-batch` 必须显式给一个已存在的批次 ID；不指定批次不得默认遍历数千案例。

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening prepare-full-batch --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912' --batch 0
```

该阶段只从冻结的 `selection/full_batches.jsonl` 为所选批次物化子运行 `full_batches/batch-0` 的选择与历史 snapshot，不执行 DFG。子运行最多原配置的 25 案例；以准备结果返回的 child_run 与子清单为准。父批次 ID 在子 manifest 的 parent_full_batch_id 保存，子运行内部只有 batch 0；已有子选择不被重新物化覆盖。

```sh
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening run --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912/full_batches/batch-0' --batch 0 --label main
'/Users/lzh/Downloads/Log 研究/agent_log_privacy/.venv/bin/python' -m agentlog_unified screening export --output '/Users/lzh/Downloads/Log 研究/agentlog_unified/research/swechat-screening-20260912/full_batches/batch-0' --label main
```

后续批次由操作者逐一明确选择，不使用隐含全量循环。准备全量某批可能包含原 holdout 案例，后续若分析这类案例，不得再用其结果调规则并仍声称原独立评估隔离成立。全量清单核对、跨批/恢复入口验证和实际 DFG 案例数须分别报告。

## 10. 失败与恢复速查

| 症状 | 处理 |
| --- | --- |
| 磁盘不足、发现暂停 | 文件层剩余项保持 pending；保留压缩台账与归档，不称全量源码发现完成 |
| checkpoint 已归档 | discover 拒绝误建空 DB；释放空间、逐项验证归档后才能恢复审计；发现代码变更仍需新独立 run |
| 换行规范化导致 blob/source 哈希不等 | 核验精确历史 SHA 的原始字节，重建受影响输出和映射，保留旧框并核验修复 active_frame 后再 freeze |
| 旧输入/数据库缺失或哈希不匹配 | 停止总体恢复，保留原因；不替换指定材料、不从候选凑总体 |
| object_unavailable / extraction_failed | 保留原案例或文件级受阻；恢复真实历史对象后重试同案例，禁用最新源码替代 |
| absent_verified | 保留版本事件，不创建该侧日志/输出案例，不作安全结论 |
| parser/语言/API/包装器不支持 | 保留文件或输出单元未知与原因，不用规则未命中支持 C |
| DFG 深度/节点/时间/依赖预算触发 | 路径或边界标记未知；独立充分风险路径与其无关缺口分开 |
| 半成品/中断 | 同 label、同冻结输入 `--resume`；校验事务结果和产物哈希，保留新 attempt |
| analysis_code_config_or_selection_changed | 不跨签名 resume；保留旧结果，用新 label/运行记录实际代码 |
| 复核导入校验失败 | 修正原标注引用/版本；整批拒绝不留下部分真值，不改规则结果 |
| 无人工标签或无预测 | 保持 pending/null，继续执行不依赖人工的工程部分 |

最终交付以执行记录分别说明已实现、实际执行、验证通过、待复核、受阻及未支持能力；禁止用 SOP 中的未来命令替代运行证据。
