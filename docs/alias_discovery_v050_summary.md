# v050 固定别名发现：独立证据，未修改规则

已解析 JSON 的原探查结果保持为零增量：5,422 个成功解析文档、4,974 个源单元格、16,108 个键中，98 个预先固定别名均未命中。本轮没有将这些别名加入正式分类器。[JSON 报告](json_key_alias_probe_v050.json)

随后使用独立 v049 源码副本，单次扫描冻结 AIDev 的全部 18 表、105 个字符串列、2,456,073 行，共 18,932,477 个单元格，其中非空 17,362,345、null 1,570,131、空白 1。检查了 2,706,989,370 个字符，没有源前缀截断，169.383 秒内完成，退出码 0，37 个源码模块及辅助程序指纹未变。扫描未按敏感词选择行；只在 Unicode 显式 `key:value` / `key=value` 语法中检查这 98 个固定别名。[执行记录](plaintext_alias_probe_v050_execution.json) · [覆盖报告](plaintext_alias_probe_v050.json) · [26 项核验](plaintext_alias_probe_v050_verification.json)

共发现 28 处赋值、19 个源单元格、7 个固定别名。2 处位于 PR body，26 处位于 patch；全部不在此前成功 JSON 文档的源跨度内。

| 预先固定别名 | 赋值数 | 预期字段语义线索 |
| --- | ---: | --- |
| IPAddr | 12 | network_identifier |
| 请求ID | 8 | request_identifier |
| 环境变量 | 3 | environment |
| 会话ID | 2 | session_identifier |
| 用户ID | 1 | user_identifier |
| IP地址 | 1 | network_identifier |
| 请求头 | 1 | http_headers |

旧探查的粗粒度质量标签是 27 处 `reference_or_expression`、1 处 `type_declaration`。这不是 28 条已确认敏感值。冻结规则对 canonical `request_id` 还会返回粗粒度 `request_body` 重叠提示，原始证据如实保留，不把两项提示解释为两个已确认含义。

对预先选择的 11 个单元格、14 处赋值做有限基线和语境回读，结果为 7 处插值语法、4 处标记或引号语法、2 处其他未解语法、1 处 IPv4 字面形状。IPv4 那一处已被旧字面形状规则在同一值跨度识别。其余 13 处没有同跨度类型，但其中 11 处的预期类型已在同一源单元格其他位置出现，因此不能称为 13 个新增单元格与类型关系。[有限语境报告](plaintext_alias_context_v050.json) · [执行记录](plaintext_alias_context_v050_execution.json) · [9 项核验](plaintext_alias_context_v050_verification.json)

仅有 2 处有限对照在整个旧基线单元格中未出现预期类型，均是 `环境变量` 的标记或引号语法，来源为 `pr_commit_details.parquet` 的 `patch`，源行 365514、365524。它们仍是待审载体线索，不能确认实际环境变量值或秘密。最早的 `用户ID`、`IP地址` 两处 PR body 命中也属于标记或引号语法，且旧基线已在各自源单元格其他位置识别预期类型。

本次仅交付明确坐标和固定枚举证据，没有导出原值、实际动态键、值摘要或 HMAC。正式源码与测试未改，没有新增敏感类型、没有宣称实际泄露。对照是有界选集，不能作为全体漏检率；赋值识别仍受固定语法、4096 字符引号值及 256 字符未引号值边界限制。此前 JSON 零增量与此次正文语法命中是不同范围，必须分别保留。

可复现辅助程序：[全字段探查](probe_plaintext_aliases_v050.py)、[元数据核验](verify_plaintext_alias_probe_v050.py)、[有限语境回读](replay_plaintext_alias_context_v050.py)。完整位置证据：[28 条赋值](plaintext_alias_probe_v050_evidence.jsonl)、[14 条语境回读](plaintext_alias_context_v050_evidence.jsonl)。
