# SWE-chat 筛选台账、标识与缓存字段字典

此字典对应本轮 `screening.py`、`screening_history.py`、`screening_evidence.py`、`screening_policy.py`、`screening_compare.py`、`screening_review.py`。默认新运行根为 `research/swechat-screening-20260912`；下列产物路径均相对该根。实际运行值以冻结 JSON/JSONL 和 SQLite 为准，字段缺失或 null 表示不可获取，不能推算为零或安全。

当前完整源码发现因磁盘空间中止，只形成部分已观察输出框。原 `streaming-export.json` 记录 174412 输出与 728 个源码哈希不一致案例；这些是修复前审计值。换行规范化缺陷由 `screening_repair.py` 根据对应历史 blob 的原始字节重新发现修复，原框保留，修复框由 active_frame 和 source-hash-repair manifest 选择/校验。源码修复、最终选择及分析数量以相应产物为准；尚未扫描文件侧继续 pending。`full_output_frame` / `full_batch_count` 均仅覆盖当前已发现可恢复输出，不能解释为所有固定提交文件已完成发现。

本字典中的 `.jsonl` 有些是逻辑入口：大文件实际为 `.jsonl.gz`。`rows` 会在逻辑路径缺失时回退 gzip 并流式解压；显式 gzip 与逻辑回退的哈希含义不同，详见第 10 节。

## 1. 层级与分母

| 层级/产物 | 主标识 | 映射与计数口径 |
| --- | --- | --- |
| `population/input_records.jsonl` | `input_record_id` | 固定原始记录；一条可以关联多个提交，同提交可被多个记录引用 |
| `population/commits.jsonl` | `commit_id` | 规范化仓库 + 精确提交 + first-parent 上下文去重，不按 Agent 会话数计提交 |
| `population/file_versions.jsonl` | `file_version_id` | 文件事件的 before/after 分开；正常不存在、失败和排除仍保留文件版本记录 |
| `population/old_log_observations.jsonl` | `legacy_log_id` | 历史观察，仅作追溯/分层，非本轮全源码发现结果或判定真值 |
| `active_frame` 指向的 `discovery/output_units*.jsonl.gz` | `log_id`、`case_id` | 原始框或经 manifest 核验的修复框；log_id 是日志版本，case_id 是实际输出单元；同日志多单元不等于多漏洞 |
| `analyses/<label>/results.jsonl` | `analysis_id` | 同一案例和实际执行签名/变体下一份有效结果；每个 case × variant 至多一份 |
| `analyses/<label>/attempts.jsonl` | `attempt_id` | 实际启动/重试/恢复，不能增加 case、日志或风险事件分母 |
| `analyses/<label>/paths.jsonl` | `path_id` | 一个分析中的多条路径，不作为独立案例数 |

文件级未检测到日志、解析失败、未扫描或无法定位输出的记录留在 `file_coverage.jsonl.gz`，不制造 output_units。对象可靠拆分按字段计；动态剩余为明确对象未知单元，`excluded_known_fields` 指明已拆字段，避免重复累计父对象与字段。文件侧已有 pending 记录不表示它已完成源码读取。

`ledger-coverage` 另物化 `coverage/log_versions.jsonl`（每条日志的 output_case_ids）、`coverage/commit_status.jsonl`（聚合文件状态）和 `coverage/ledger_coverage.json`（分层分母与映射检查），不进行 DFG 深度分析。

## 2. 输入与提交

| 字段 | 含义 |
| --- | --- |
| `dataset`、`dataset_snapshot` | 输入声明的数据集与可获取版本；不知道时保留 unknown/null |
| `input_sha256`、`input_line`、`original_record_id` | 固定输入文件哈希、原始行和原始记录 ID，连接到原始材料 |
| `repository` | 规范化 `owner/repo` 标识；本地读取位置另用 repo_path |
| `commit_shas`、`commit_ids` | 原记录关联的完整 SHA 及其提交层映射 |
| `source_rows`、`session_ids`、`checkpoint_pks` | 数据集关联引用，不能直接当应用日志字段或作者证明 |
| `provided_agent_names`、`verified_actor_type` | 输入自带 Agent 名称与经确认演员类型分离，后者不足时 unknown |
| `sha`、`parents`、`parent_sha` | 事件提交 SHA、全部父提交、明确选定比较父提交 |
| `comparison_strategy`、`uncompared_parents` | 当前 first_parent，其他合并父分支不在该对照内 |
| `parents_state` | 旧记录或实时提取依据；旧记录不自动等于本轮已核验父关系 |
| `repo_path` | 指定缓存仓库的本地位置；不可用时报告受阻，不能借同仓最新 checkout 替代 |
| `legacy_status`、`legacy_attempts`、`legacy_metrics`、`legacy_analysis_fingerprint` | 旧实验处理证据，不能作为当前兼容判定缓存 |
| `processing_status`、`reason`、`file_event_count` | 本层处理去向、原因及恢复出的文件事件数；没有事件可能是历史缺口 |

`population_summary.json` 包含 input/database/output 哈希、恢复的层级数量、canonical_input_hash_matches、candidate_only、总体范围及局限。即使 `candidate_only=false`，也只确认声明的固定输入总体，不能抹除旧挖掘缺失文件或受阻提交。

## 3. 历史文件、源码状态和范围

| 字段 | 含义 |
| --- | --- |
| `side`、`source_sha` | before/after 与实际读取源码版本；before 通常为选定 parent，after 为事件 SHA |
| `old_path`、`new_path`、`path`、`change_type` | 文件事件旧新路径、该版本实际路径及新增/删除/重命名等类型 |
| `file_event_id` / `legacy_record_id` | 新提取事件或旧文件审计记录引用 |
| `source_state` | present / absent_verified / object_unavailable / extraction_failed；恢复初态可为 unverified_cached |
| `blob_oid`、`source_sha256` | 对应历史 tree 解析出的 blob OID 和实际内容 SHA256 |
| `source_path`、`source_cache_hit` | 受限本地源码路径及内容校验后的缓存命中，不应公开原始内容 |
| `legacy_source_status`、`pydriller_source_status` | 原始后端提供状态，不与最终经树核验状态混为一谈 |
| `source_backend`、`pydriller_source_backend`、`source_fallback_reason` | 真实源码后端与辅助读取原因；Git blob 辅读不是 PyDriller 挖掘 |
| `pydriller_exact_blob_agrees` | PyDriller 源码与精确 blob 内容比对；null 表示未取得可比 PyDriller 源码 |
| `language`、`scope` | 语言和路径用途范围，不能据此确认生产运行 |
| `parser_and_output_support`、`processing_status`、`reason` | 解析/日志输出能力与文件处理状态，失败与无日志分别记录 |
| `old_log_ids`、`old_stratum`、`output_units` | 旧观察引用、发现前分层线索和本次可靠输出数量 |

`present` 要求得到并核验历史内容；`absent_verified` 要求对应历史 tree 确认该版本路径正常不存在；`object_unavailable` 表示所需对象无法取得；`extraction_failed` 表示尚不能确定有效内容。PyDriller 空值、空图、空修改列表不能自动等于 absent_verified。

source_sha256 应校验原始历史字节；不能经 `read_text()` 的通用换行转换后重新编码，仍把该值称作 blob 原文哈希。旧框存在该缺陷时，保留旧 case/source/version 记录及修复映射，重新核验源码、锚点和相关输出哈希；不能只把不匹配值改成预期字符串，或跨版本继承判定。

实际路径范围分类来自 `classify_file_scope`：test、example、generated_or_vendor、development_tool、application_or_unknown。scope_classes 配置是声明辅助，统计和实际解释应与代码产出的范围值核对。`function_scope` 另存函数上下文，不能与文件用途 scope 混淆。

## 4. 日志版本和输出案例

| 字段 | 含义 |
| --- | --- |
| `case_id` | 仓库、事件和 parent 上下文、source_sha、side、path、日志锚点、输出锚点/输出键及拆分版本共同生成的稳定 ID |
| `log_id`、`original_log_id` | 本轮精确版本日志 ID 与现有 detector 身份；前后源码不同仍是不同日志版本 |
| `event_sha`、`parent_sha`、`source_sha` | 事件与实际版本/比较关系，禁止仅按同名变量合并 |
| `log_anchor`、`output_anchor` | 日志和输出单元的精确语法定位，含 path/行/列/结束位置；解析器附加字段按原始锚点保存 |
| `log_statement_sha256`、`output_sha256` | 日志语句和实际输出表达式内容哈希，用于历史锚点核验，不用明文作为跨版本最终标签键 |
| `output_key`、`output_role`、`field` | 参数/关键字/字段或未知剩余的稳定位置键、API 语义角色、安全字段名 |
| `api`、`detector_status`、`boundary` | 已支持/未验证日志 API、日志确认状态及声明的静态日志边界 |
| `split_version`、`excluded_known_fields` | 当前拆分规则版本及剩余对象应排除的已拆字段 |
| `base_evidence` | 在新增 DFG 前冻结的基础检测证据；两变体完全一致使用 |
| `file_version_id`、`commit_id`、`input_record_ids`、`legacy_log_ids` | 输出到文件、提交、原始输入和旧观察的映射 |
| `source_versions` | 此案例实际允许读取的同 SHA 文件集合，每条包含 path/sha/source_sha256 |
| `snapshot_ref`、`snapshot_sha256` | 受限本地冻结源码 JSON 路径及文件内容哈希 |
| `dependency_gaps`、`limitations` | 读取不到的历史依赖、预算/框架/边界局限，不填推测源码 |
| `scope`、`function_scope`、`language` | 文件用途、函数上下文与语言分别记录 |

case_id 不包含 baseline/dfg_augmented、随机运行目录或重试编号。当前拆分版本实际以案例中的 `split_version` 为准；代码快照另有版本标记，不能只用一个手写版本字符串替代实际源码哈希。拆分规则变化后应记录新旧映射或失配，不强行继承旧判定。

AST/树解析器锚点采用一基行号、零基列偏移；Python AST 列偏移按 UTF-8 字节，不能当作显示字符宽度。结束位置沿用解析器的结束边界。锚点可能另带 node_kind/parser/字节信息；历史适配必须使用原锚点契约，不能用报表中的排版位置替代。

## 5. 分组、选择和批次

| 字段/文件 | 合同 |
| --- | --- |
| `near_duplicate_key`、`group_id` | 规范化所在语法内容键，以及仓库/跨仓键连接分组；近重复识别有界 |
| `split` | engineering 或 evaluation，在新增 DFG 结果之前决定 |
| `legacy_stratum`、`sampling_stratum` | 旧观察/未知/未命中/无旧日志的互斥线索，不能继承为本轮风险标签 |
| `selection/groups.jsonl` | 每个发现 case 到 group/split 的映射，保护前后版本、拆分字段及已识别近重复隔离 |
| `batch_id`、`case_ids` | 零起始批次编号及稳定案例列表，单批上限来自冻结配置 |
| `selection/batches.jsonl` | 工程主样本批次，run 默认消费的选择范围 |
| `selection/full_batches.jsonl` | 所有已发现可靠输出的稳定分批清单，不直接触发全量深度分析 |
| `selection/pair_context.jsonl` | 未纳入主分母的附属对照案例引用，role=unanalysed_pair_context |
| `seed`、`quotas`、`evaluation_quotas` | 固定种子和实际分层配额，不能当作总体自然频率 |
| `population_sha256`、`frame_sha256`、`selection_sha256`、`evaluation_sha256`、`groups_sha256`、`batches_sha256`、`full_batches_sha256` | 各声明总体/抽样框/列表的文件哈希 |
| `frame_artifact`、`frame_coverage`、`population_prevalence_claim` | 实际原始/修复框路径、已发现范围及磁盘缺口说明，总体风险率声明为 false |
| `replacement_policy` | no_replacement_for_failure_or_outcome，失败与未命中都保留原案例 |
| `primary_selected`、`evaluation_selected`、`full_output_frame` | 不同分母分别报告，不能互相替换 |

`prepare-full-batch --batch N` 根据父 full_batches 为某一批物化独立子运行 `full_batches/batch-N`。子 manifest 保存 parent_run、parent_full_batch_id、full_depth_executed=false、explicit_batch_only=true 和重新计算的选择哈希；`parent_manifest.json` 保留父 manifest 路径/哈希。子批次内部编号为 0，split=full_census_batch，evaluation 为空。准备返回 status=materialized_not_analyzed 和 child_run，不运行 DFG，也不把所有批次写为 completed。

## 6. 分析、尝试和成本

| 字段 | 含义 |
| --- | --- |
| `variant` | baseline 或 dfg_augmented，唯一预定差异为新增 DFG 证据 |
| `analysis_id` | case_id + variant + 实际执行签名 + source_versions + snapshot_sha256 的稳定身份 |
| `attempt_id` | UUID，一次真实启动或恢复/重试，不进入 case 身份 |
| `signature` / `code_signature` | 实际代码/依赖、冻结配置和选单共同指纹 |
| `assessment`、`queue`、`processing_status`、`failure_reason` | 独立维度及队列、处理状态和失败原因；blocked 不自动成为 C |
| `base_evidence_sha256` | 主 A/B 基础证据相等核对键 |
| `artifact_hashes` | 此有效 attempt 的图和证据输入索引路径 → SHA256 |
| `elapsed_seconds`、`cpu_seconds` | 本次案例分析壁钟与进程 CPU 时间，不包括发现和事件挖掘 |
| `max_rss_platform_units` | 平台原始进程峰值 RSS；未换算时不得直接标成 MB，且不是单案例增量内存 |
| `cache_hit`、`base_evidence_origin`、`timing_scope` | 是否复用、基础证据来自 frozen_discovery_cache，分析计时边界明确记录 |
| `started_at`、`finished_at` | 实际带时区时间戳 |
| `dfg_reason_codes` | DFG 图/来源/预算停止原因 |
| `ai_review`、`human_review`、`runtime_confirmed` | 未执行复核均 pending，运行时确认始终 false |

SQLite results 表对 analysis_id 及 `(case_id, variant)` 设唯一约束；attempts 另存 started/completed/interrupted。恢复只认兼容且完整的有效结果，残留图或文件不等于完成。批次 complete 表示该批规定分析尝试/结果均有去向，不等于每个案例成功或确定无风险。

`invocations/*.json` 的 processed_this_invocation 是分析记录数（两变体各一次），cache_hits 是有效结果复用数；其耗时与逐案例统计范围不同。`mining/*/runner-extraction.json` 及 extraction 审计记录实际 PyDriller 后端、完整 SHA/parents、调用计数、回退原因与提取耗时，不能将 Git 读源码或缓存读取耗时当作重新挖掘。

## 7. 路径证据、判定和日志边界

独立敏感性、连接、处理、关键未知及 A/B/C/D 可执行规则详见 [判定说明](screening_policy_notes.md)。主要结果位于 `assessment.dimensions`，保存 source_sensitivity、output_sensitivity、connection、processing、boundary、paths、risk_clues、critical_unknowns、noncritical_unknowns、checks_complete、non_sensitive_basis、evidence_ids、severity、certainty。严重程度缺合理上下文时为 null；证据确定性独立记录，不生成概率。

| 证据对象 | 字段与边界 |
| --- | --- |
| path | path_id/case_id/analysis_id/variant，加来源/残留敏感性、连接/语义支持、关键未知、source_anchor、origin_category、edge_ids、evidence_ids |
| graph | graph ID、sha、nodes、edges、gaps、origin_counts；图存在不代表业务来源已追完 |
| edge | source/target、kind、status、carries_value；type/schema 和 possible 关系不能提升为确定值传播 |
| node | 历史 sha/anchor、kind、endpoint 和证据 ID；function_parameter 仅为局部追踪边界 |
| `evidence_index.jsonl` | evidence_id、case_id、kind、anchor、源码 sha/hash 与本地引用；可分享文本不得含完整秘密 |
| `call_argument` | 数据到达日志调用参数，仅静态调用边界 |
| `log_record` | 证据支持进入日志记录/结构化字段；`extra` 不自动代表格式化文本 |
| `formatted_output` | 只有静态 formatter/handler/filter 配置确证才可声明；当前不能默认到达此层 |

critical_unknowns 顶层影响所有拟议结论，路径内仅影响该路径；不相关失败放 noncritical_unknowns。A 的独立充分路径不被其他分支失败抹除，C 则要求必要输出/连接检查完成且没有可改变结论的关键未知。所有结论限于声明历史源码和边界，不执行目标，不确认落盘或外传。

## 8. A/B、覆盖和前后对照

| 产物 | 关键字段 |
| --- | --- |
| `ab_pairs.jsonl/.csv` | 同 case_id 的两 analysis_id、两队列、两处理状态、base_evidence_equal、各组分析秒数；失败/未执行侧保留 blocked/pending/null |
| `coverage.json` | primary_cases、expected_analyses、actual_analyses、missing、unexpected、duplicate_results、queue_migrations、variants、languages、scope_counts |
| variants 汇总 | queue_counts、processing_status_counts、elapsed_seconds、cpu_seconds、critical_unknown_cases/ratio、来源/残留/连接/处理/边界维度 |
| graph_evidence 汇总 | value_edges、effective_propagation_edges、origin_counts、gaps、history_locations_valid；不能用节点数替代证据质量 |
| `before_after.jsonl` | comparison_version、pair_id、counterpart_case_id、candidate_counterpart_ids、pairing_status、pairing_basis、uncertainty |
| 对照锚点 | old/new_anchor、old/new_output_anchor、old/new_source_sha、old/new_source_state、comparison_strategy |
| 对照变化 | variant_changes、change_label、reason，区分变体且关联双方 analysis_id；无法充分说明处理/风险变化时 cannot_compare |
| 归因 | attribution、attribution_inferred_from_risk_change=false、output_unit_authorship/agent_introduction=unknown（证据不足时） |

当前可靠配对要求同仓/事件/first-parent、核验过的旧新文件、相同函数和输出键、相同语法哈希及唯一未修改 diff 行映射。只有同名变量/相似文本不够。支持的变化标签以实际对照结果为准；removed_path 只说明该日志路径移除，不是全仓风险清除。上游变更可能改变数据含义，即使日志文本相同也不得直接继承判定。

## 9. 复核与指标

复核包使用 policy_version、policy_sha256、case_id、evidence_sha256、evidence_ids 绑定具体历史证据；source_versions 变化也改变证据指纹。最初 reviewer_1/2 目录不含机器预测、来源归因或最终队列。原始历史代码访问通过 private_source_index，不能因为只有坐标包就声称人工已完成。

人工/AI/裁决结果严格 schema 在 `review/review_result.schema.json`，统一字段包括 kind、origin、status、timestamp、result 及版本/证据哈希。人工需 reviewer 与独立 annotator_slot；裁决需第三人和 annotation_ids；AI 需实际来源、可获取模型 ID、提示版本、input_sha256、output_sha256。不可获取模型身份保持 null/unknown，不虚构。

`review/imported/review_history.json` 保留追加历史；human_results、ai_results、adjudication_results 分离；disagreements 记录分歧。共享记录中的 reviewer_hash、rationale_sha256、facts/inferences 文本哈希可连接到本地 `.raw_reviews/<id>.json`，原始文字不复制到分享包。

`review/metrics.json` 的 risk_judgment 与 log_detection 分开。risk 只有整个声明 evaluation 分母有可靠双人共识/第三人裁决二元 A/C 真值及对应预测时才计算，A 为正预测，B/D 为未形成真值。AI、pending、工程调规则标签不作为独立 gold。precision/recall 分母为零或标签不可靠时为 null，而非 0。

文件级日志检测评估 JSON 结构是 `{files: [...], predictions: [...], annotations: [...]}`：

| 记录 | 必需内容 |
| --- | --- |
| files | 冻结原始修改文件的 file_version_id、source_sha256，可保留仓库/SHA/path 作为定位 |
| predictions | 同 file_version_id/source_sha256、status=success、log_anchors；一条日志计一个调用锚点，不按输出字段计数 |
| annotations | origin=human、status=submitted、不同 reviewer、reviewer_1/reviewer_2 槽位、实际带时区 timestamp、inspection_complete=true、空 critical_unknowns、review_scope=original_modified_file、log_anchors |
| log_anchor | 精确 `{line,column,end_line,end_column}`，原始源码坐标，不能通过模糊文本强行匹配 |

双人完整文件枚举一致且整个文件分母就绪后才计算 TP/FP/FN。无日志文件的空锚点列表也是合法审查结果；无法确定日志位置/源码或有未审路径时保持 pending/unknown，不能空数组冒充阴性。

## 10. 压缩归档、修复框、哈希和兼容性

`discovery/streaming-export.json` 是本轮发现中止后的流式导出摘要，包含 output_units、recorded_file_versions、checkpoint_status_counts、output_logical_sha256、output_gzip_sha256、case_file_source_hash_mismatches、status=partial_disk_budget_blocked、remaining_files_are_explicit_pending。recorded_file_versions 含排除项等已登记记录，不等于成功读取源码数；未完成发现时不假设正常 coverage.json 存在。

`discovery/checkpoint-archive.json` 保存 original、original_sha256、original_bytes、gzip、gzip_sha256、gzip_bytes、verified_lossless 和 reason。归档对象仅是本轮 discovery/checkpoint.sqlite，旧实验数据库保持只读。原数据库 873050112 字节已在无损验证后移除，压缩副本保留；不应将归档变成新的空 SQLite。恢复时先核验 gzip 物理哈希，再将解压结果写入临时文件并核验原始哈希/字节数，最终原子恢复且保留限制权限。归档还原不等于旧发现代码指纹与修复 reader 兼容，新增发现应使用新独立 run。

哈希调用存在两种明确语义：传逻辑 `name.jsonl` 且明文缺失时，`file_hash` 回退 `name.jsonl.gz` 并计算解压字节；直接传 `name.jsonl.gz` 时计算压缩文件本身。`rows` 无论哪种入口都解析 JSONL 内容。记录 frame_artifact 时要同时读该清单生成时的 frame_sha256 语义，不能仅按路径后缀猜测逻辑/物理哈希。

`active_frame(out)` 优先读取 `discovery/source-hash-repair.json`，用 output_path 定位修复框，并以 output_physical_sha256 核验该压缩产物；manifest 缺失才回退原逻辑 `output_units.jsonl`。原框、修复映射、修复执行证据和代码版本需共同保留；没有实际完成/核验的修复产物不能被描述为修复通过。

| 修复证据字段/产物 | 合同 |
| --- | --- |
| `version`、`status`、`performed_before_sample_freeze` | screening-raw-source-repair-1 的实际结果，仅允许选择冻结前修复 |
| `input_path`、`input_physical_sha256`、`input_logical_sha256` | 保留的原始 gzip 框及物理/逻辑哈希 |
| `file_coverage_path`、`file_coverage_physical_sha256` | 冻结文件台账与精确 blob 哈希依据 |
| `output_path`、`output_physical_sha256`、`output_logical_sha256` | 新 repaired gzip 框；active_frame 使用物理哈希核验 |
| `affected_file_versions`、`mismatched_cases_before/after`、`old_cases_replaced`、`new_cases_generated` | 修复文件/案例数量和前后核验，不是风险变化数 |
| `unaffected_case_count`、`unaffected_records_byte_identical`、两份 unaffected 字节哈希 | 未影响案例直接保留原行字节，不借修复重新判定全框 |
| `sample_replacement=false`、`original_frame_preserved=true` | 修复发生选样前，不替换已选失败案例，不覆盖原框 |
| `source-hash-repair-mapping.jsonl` | 唯一函数/输出坐标可记录 old_case_id/new_case_id；否则 old/new_case_ids + unmatched_or_ambiguous，不强行合并 |
| `source-hash-repair-files.jsonl` | 逐文件 raw source_sha256、normalized_input_sha256、CRLF/CR 数、字节数及真实来源；不复制源文本 |
| `actual_code_sha256`、`config_sha256`、`elapsed_seconds` | 实际修复代码/配置和执行成本 |
| `target_code_executed=false`、`pydriller_remining_performed=false` | 该修复使用当前运行已经核验的 Git blob 字节缓存重新发现，不冒充新的 PyDriller 挖掘 |

| 层 | 允许复用的依据 | 拒绝/保留的情况 |
| --- | --- | --- |
| 旧采集总体 | preparation 固定 input 哈希、数据库哈希和完整提交作业集合一致 | 材料缺失、哈希/作业集合错配；旧判定不复用为当前真值 |
| 历史源码 | 精确 source_sha:path 的树/blob、内容哈希，命中缓存再核内容 | SHA/路径错配、对象缺失、内容变更、二进制/解码/预算失败 |
| 发现 checkpoint | 文件总体哈希、冻结配置、相关发现函数/依赖/运行版本指纹一致；归档先核验恢复 | 相关代码/配置变更须新运行；归档不允许误建空库；失败/未扫描不等于没日志 |
| 修复输出框 | output_path/物理哈希、原始框哈希、原始字节读取及新旧案例映射 | 不覆盖原框、不静默删除无法恢复项、不把换行规范化哈希当作 blob 原文 |
| 冻结上下文 | snapshot 文件哈希 + 每个 source_versions 的路径/SHA/内容哈希 | 任一依赖或 snapshot 变更，不以同名文件补齐 |
| 挖掘审计缓存 | 精确事件和 code_signature 一致，保留实际后端/版本；失败需显式 retry | 不将审计 marker 存在本身作为成功，也不将辅助 Git 读取标为 PyDriller |
| DFG/最终结果 | analysis_id 签名兼容、snapshot/依赖和 artifact_hashes 完整；事务中有有效结果 | 只存在图文件/半成品、证据哈希变更、配置/代码/规则/政策/选单改变 |
| 复核 | case_id、政策实际哈希、历史位置/源码/依赖及 evidence_sha256 一致 | 错版本、未知 evidence_id、AI 冒充人工、pending 带结果；整批原子拒绝 |

SHA256 用于文件/内容完整性；stable_id 使用现有存储规范生成稳定身份，不能混淆为 Git commit SHA。Git HEAD 仅为代码版本的一部分，实际未提交或新增代码通过源码哈希和快照进入执行记录。源码快照既不证明目标程序运行，也不证明任何运行时泄露。
