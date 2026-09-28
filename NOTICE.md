# 来源与融合范围

本工具由原 `agent_log_privacy` 基座派生，并参考用户提供的 `agentlog-core` 源码设计。旧基座源码、文档和示例已保存至 `archive/retired-privacy-20260928/old-tool-source-and-docs.zip`；来源哈希快照仍见 `docs/original_source_hashes.json`。

采用本地基座的 PyDriller 正向挖掘、严格来源判定、冻结运行、分层结果和统一脱敏。重新实现并整合 core 所体现的更丰富依赖、身份匹配、人工审核、搜索发现、反向 SZZ 与增量状态思路，没有将 core 原生 Git 正向管线直接搬入。

`agentlog-core/pyproject.toml` 声明 MIT，但所提供目录没有独立 LICENSE 文件；本轮没有对外发布或为整个融合项目新增、推定统一开源许可。若未来公开发布，应先核对双方来源与适用许可。
