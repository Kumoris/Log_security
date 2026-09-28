# 来源

本目录两个文件从 `agentlog_unified/src/agentlog_unified/` **原样复制，未做任何修改**。
logtrace 的敏感类型表和敏感性判定全部调用它们，保证与 agentlog_unified 的判断一致。

| 文件 | 原位置 | sha256 |
|---|---|---|
| `detector.py` | `agentlog_unified/src/agentlog_unified/detector.py` | `cbd3b34b996a73b2e2488d72f07f03ad11adc741bfa8f28c47cead679211d5ee` |
| `taxonomy.py` | `agentlog_unified/src/agentlog_unified/taxonomy.py`（TAXONOMY_VERSION 1.2.0） | `f2d1ba2ca56fb2500f883ff0924e37a1848a7789e7d964340213ee5ff84d8973` |

`detector.match_entities` 依赖原项目的 `matching.py`/`storage.py`，logtrace 不调用它，因此没有复制。
原项目更新后重新复制并更新本表的哈希即可。
