# Issue 人工材料接入与语义提示（0.8.1）

更新：用户已明确将全部 **67/67 组**确认为人工敏感性参考，[最新记录](issue_human67_20260910.md)取代本文旧的 62/67 人工敏感性统计。以下实验数字仍是当时的冻结结果。

本轮读取了用户提供的 Google 文档 **Sensitive logs from issue reports**。原始快照留在本地、权限 0600；公共结果只包含固定概念名称、issue 链接、文档版本、段落/匹配位置及哈希，不复原隐藏值，不向模型传递原文凭证或自由文本。Google 文档未修改。

运行报告：[results.json](issue-knowledge-20260910/results.json)；测试记录：[pytest.txt](issue-knowledge-20260910/pytest.txt)。

## 实际结果与分母

- 文档 1 个 tab、122 个非空段落、68 次 issue 链接，合并重复后 **67 个 issue 组**，来自 38 个项目。62 组有摘录说明并接受用户的人工敏感性标注；5 组只有链接，保留为证据缺失。
- 67 组中 **45 组**提取出明确概念描述，共 **75 个概念提案、31 种概念**。其中 50 个提案可候选映射到现有目录；25 个涉及未映射/拆分类别。22 组仍缺乏足够类型解释，其中 17 组有文字但不能确定类型。
- **16 种新类/拆分类别提案**保留待审，例如账户登录名与真实姓名的区别、hostname/port、partition name、record key/value、row key、table schema、mutation 内容、加密密钥和 IV。没有自动将它们写入原来的 49 类目录。
- 独立重读原始段落，45/45 个有概念提案的组通过短语与 UTF-16 位置重放；这仅验证提取依据，**不是 45/45 语义准确率或人工 subtype 复核**。
- 真实历史重放 **100 个使用实例 / 3 个仓库**：Python 46、TypeScript 26、Go 28。100 个历史上下文均可构造，26 个取得案例提示（24 个异常相关实例、2 个网络地址实例；多标签计数另见 JSON）。其余 74 个继续保留。精确名称为 data/value/payload 的实例仅 2 个，二者都未取得提示；这批真实样本不足以验证泛称字段的改善。
- 开发过程中，整函数检索曾让 76/100 个字段取得提示。现已收紧到目标字段和可见证据节点，降为 26/100。数量下降是排除邻近无关变量触发，不能换算为精确率提升。
- 新建并扫描了 **4 个提交**的合成历史，PyDriller 实际读取修改文件、diff 与历史版本：32 个日志事件、40 个字段使用实例。目标仓库代码未执行。
- **769 项 pytest 通过**。新增测试覆盖同名泛称与上下文区分、无关变量隔离、来源项目限制、重复链接、UTF-16 锚点重放、原始值不导出、缺失与未知、完整性检查及 dry-run/resume。

## 模型执行结果

沿用原来的 `demand-v080-20260909` 预算账本：全局调用从 44 增至 **46/80**，未重置每案例最多 6 次的限制。使用现有 ChatGPT 登录和禁用工具的 Codex CLI，请求模型 `gpt-5.5`；运行时未报告模型身份，故实际模型身份仍为 unknown。没有调用外部付费模型 API。

本轮对 1 个已暴露真实案例 `c725de41aaa6933b1d38cfd5`（`r.RemoteAddr`）执行提取与独立复核，共 2 次真实调用，均通过响应格式验证。B/C 复用相同请求，不能计成 4 次独立试验。提取提出网络关联标识候选；复核认为缺少历史版本绑定的字段定义，敏感类型保持 **unknown**，隐私风险保持 **undetermined**。名义接收者类型与字段投影日志关联可描述，但不等于业务含义或内容泄露已验证。

没有新增代码案例人工真值，不能报告准确率、召回率或“真实识别率提高”。原始模型输出、被程序约束的结果、复核记录与请求失败原因均保留在 `semantic-runs/issue-knowledge-model-20260910/`。本轮模型引用路径也发生变化，不能把与旧报告的 supported 状态差异直接归因于知识接入。

## 用法与实际执行命令

从项目目录运行；下列输出目录本轮已存在，重新执行需 `--resume`，或换新目录。

```bash
cd '/Users/lzh/Downloads/Log 研究/agentlog_unified'

# 源文件是 Google Docs get_document 返回文档及 metadata 的本地 JSON 快照。
../agent_log_privacy/.venv/bin/python -m agentlog_unified issue-knowledge \
  --input semantic-inputs/issue-report-human-20260910/source-google-doc.json \
  --output semantic-runs/issue-knowledge-scoped-20260910 \
  --reviewer workspace-user --analysis-run semantic-runs/real-v070-final --offline

../agent_log_privacy/.venv/bin/python examples/build_semantic_expansion.py \
  semantic-inputs/issue-knowledge-fixture-20260910
../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-scan \
  --input semantic-inputs/issue-knowledge-fixture-20260910/input.jsonl \
  --output semantic-runs/issue-knowledge-synthetic-scan-20260910 \
  --config semantic-inputs/demand-synthetic-scan.yaml --offline

../agent_log_privacy/.venv/bin/python -m pytest tests/test_issue_knowledge.py tests/test_semantic_demand.py -q
../agent_log_privacy/.venv/bin/python -m pytest -q

../agent_log_privacy/.venv/bin/python -m agentlog_unified semantic-demand \
  --input semantic-runs/real-v070-final \
  --output semantic-runs/issue-knowledge-model-20260910 \
  --config semantic-inputs/issue-knowledge-model-20260910.yaml --online

../agent_log_privacy/.venv/bin/python examples/report_issue_knowledge.py
```

还实际运行并验证了：`issue-knowledge --resume`；`semantic-demand --dry-run --offline`；独立 `issue-knowledge-offline-20260910` 目录的 `--offline` 与 `--offline --resume`；模型目录的 `--online --resume`。三次 resume 均未调用模型，dry-run 不创建输出。

现有 `semantic-demand` 配置仅新增一个可选键：

```yaml
semantic_demand:
  issue_knowledge: /absolute/path/to/completed/issue-knowledge-output
```

该目录需已完成且通过内容哈希校验；它的 manifest 哈希计入模型运行指纹与恢复判断。每轮最多取 4 种相关概念、每概念 2 个来源案例、例子 JSON 至多 4000 字符。此预算独立于原有代码上下文预算，具体字符数和截断量逐调用记录。提取与复核收到相同的来源边界约束；issue ID 不允许冒充代码证据 ID。

## 文件与证据边界

`issue_annotations.jsonl/.csv` 是用户认可的 **issue 摘录组敏感性标注**；它不是逐值删除区间或目标代码字段真值。文档包含 issue 链接、说明、条件性报告与示例，没有完整的逐字段原文—脱敏后对照。继承前一个链接是可审计的文档布局关联，尚未访问每个原始 issue 验证。文档末尾散记也保留该限制。

`type_proposals` 是规则提案；`independent_source_reviews` 是原始短语/锚点重放；`program_knowledge_candidates` 是目标字段相关案例提示；`review_queue`、`category_proposals`、`exclusions` 保留未知、未映射、缺失和排除项。`evidence/` 保存逐案例定位证据；`coverage.json` 提供筛选漏斗。人工细类检查可用 [标注模板](issue-knowledge-20260910/human_type_annotation_template.csv)，留空项保持待审。分类拆分/合并未替人工作决定，也未自动改写 taxonomy。

本轮已经阅读整份来源文档，所有来源条目均作为开发材料；没有将其中一部分事后宣称为独立评估集。现有真实样本仍沿用历史缓存与 PyDriller 版本定位，未抓取新的真实 Git 历史，未重扫全量 AIDev schema 或账户单元格。通用库类型定义、复杂动态流、脱敏效果与独立真实泛称名真值仍是限制。原有数据、旧运行与 papers 均保留。
