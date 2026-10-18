# PR B：E2E_06 执行效率收尾

本次只修改 local-candidate 的任务指引与派发前工作区事实交接。
没有模型派发，没有 E2E_07；E2E_01–06 的账本、候选和 UNKNOWN 均保持原样。
离线验证不证明真实 tokens 一定下降，也不改变 PR B 尚未完成真实交付的结论。

## 原始证据与能够确定的结论

输入是 E2E_06 的原始 `.raw`、operation JSON，以及 thread/start 指向的原生 rollout：

```text
~/.local/state/codex-factory-prb-real-e2e-06/evidence/
  HARNESS_MVP_PR_B_REAL_BUSINESS_DELIVERY_E2E_06/
  c02847f63604413c8582b2ca22457d30.raw
~/.codex/sessions/2026/10/18/
  rollout-2026-10-18T10-25-12-01a14cd3-ccf4-7f01-9e34-3e2f2e076bac.jsonl
```

只读分析及可重复比较脚本、源文件 SHA256 和结果位于：

`/home/xupeng/.local/state/harness-delivery-evidence/PRB_EFFICIENCY_20261018T023315Z/`

1. rollout 第 10 行持久化的真实任务 JSON 是 **3,580 UTF-8 字节**，包含 objective、
   acceptance、constraints、scope、authorization 及 mission scope 身份，不是完整 Mission/账本。
2. 第 6 行包含完整的 `AGENTS.md` 原文：**21,475 字节、216 行**。
   同条消息连同 environment 为 23,556 字节；此前还有原生 base instructions 21,779 字节，
   developer 消息分别为 8,278、2,400、271 字节，预算提示为 107 字节。
   这些是持久化文本大小，**不是逐组件 token 数**；工具 schema 和 provider 序列化未完整量化。
3. 第二批工具又执行 `sed -n '1,230p' AGENTS.md`，完整读回相同的 21,475 字节。
   与 workflow 摘录合并的命令输出为 26,799 字节；11 个命令总输出为 46,685 字节。
   原生已加载全文与再次读回的字节一致，重复本身是确定事实。
4. Agent 没有重新读取 Controller Mission/授权文件，也没有重复读取两份业务文件。
   workflow 文档阅读由 AGENTS.md §10 明确要求，不能直接删去。
5. import 搜索输出后，Agent 又读取 conftest、pyproject 和 Makefile 片段；这有判断测试依赖的作用，
   但不需要为不可运行的本地检查继续扩大配置探索。缺依赖后的语法、diff 检查均有正常工程价值。
6. Agent 查询了不存在的 `origin/main`，exit 128。原任务有 cwd/base，却没有交接已准备候选的
   branch/HEAD/clean 状态。现在提供已验证事实，并说明无 remote 的隔离 clone 使用已授权 base。

官方说明也确认 Codex 会将发现的 AGENTS.md 自动注入对话；本次以实际 rollout 全文为准，
没有仅凭配置或文档推断：[OpenAI Codex Prompting Guide](https://developers.openai.com/cookbook/examples/gpt-5/codex_prompting_guide)。

## token 增长的解释边界

原生 rollout 恰好保存了五条带 response ID 的 `token_usage_record`，均与 App Server 的累计
usage 对账一致。下表列出这些记录，不将其外推为完整网络重试/物理请求账单：

| 记录 | 输入 tokens | 其中 cached input | 输出 tokens | 此前返回的工具文本字节 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 19,181 | 0 | 188 | 0 |
| 2 | 22,053 | 18,944 | 408 | 9,848 |
| 3 | 30,193 | 21,888 | 709 | 30,329 |
| 4 | 33,377 | 29,952 | 748 | 9,624 |
| 5 | 34,149 | 33,152 | 738 | 124 |
| 合计 | 138,953 | 103,936 | 2,791 | — |

工具文本大小来自相邻持久化 tool-output item，包含工具包装，不能与原始 command output
字节直接混加。第三条输入增长与治理文件大输出时间相邻，但无法把 8,140-token 增量逐项
精确归因给某个文件：历史消息、reasoning、工具定义与编码也参与输入。
第五条此前仅返回很小的 patch 结果仍输入 34,149 tokens，说明正常会话历史会反复参与输入；
不能把这些正常重复上下文全部列为无效工作。cached input 已包含在 input 内，不能重复相加。

## 最小实现

- `src/harness/factory.py`：local-candidate payload 增加执行指引：复用已经在上下文中的未变指令；
  缺失/变更时仍读取；仍读取必需 workflow 和适用的嵌套指令。合并独立的读取/可用性探测，
  限定相关片段；合并必要的收尾检查，不因本地依赖缺失反复扩大探索，最终如实返回 JSON。
- 同文件：首次与返修派发前均调用现有 `target()`，复用 clean、base ancestry、scope 与
  项目合同校验，核实 branch/无 remote，交接 PROJECT_ROOT、CURRENT_BRANCH、CURRENT_HEAD、
  CURRENT_DIRTY_STATE、BASE_SHA。返修重新计算，不能沿用第一 turn 的旧 HEAD。
- 没有过滤工具输出、隐藏错误、替 Agent 阅读/改写业务代码，或注入一个裁剪过的 AGENTS.md。
  没有修改原生 base instructions、project_doc_max_bytes、模型、effort、权限、预算或 QA。

## 可重复比较与测试

证据目录中的 `analyze_e2e06.py`、`compare_handoff.py` 可直接用 Python 重算，无模型执行：

| 比较项 | 修改前 | 修改后 |
| --- | --- | --- |
| 代表性任务 JSON | 3,580 字节 | 5,104 字节 |
| branch/HEAD/clean 事实 | 未交接 | 派发前验证，逐 turn 刷新 |
| 已加载指令复用及批量检查提示 | 未明确 | 明确；保留缺失/变更时读取与所有必要检查 |
| 已记录治理输出中去掉重复 AGENTS 前缀的示例 | 26,799 字节 | 5,324 字节，workflow 输出逐字节保留 |

任务本身**增加 1,524 字节**，用于减少重复调查，不声称初始 prompt 缩短。
最后一行只是对已记录文本的确定性比较；实现没有过滤输出，也没有证明未来 Agent 会遵循指引。
不能把 21,475 字节换算成确定 token 节省，或推断一定能在 120,000 内结束。

新增确定性测试验证：首次/返修交接事实与真实临时 Git 一致、返修 HEAD 更新；acceptance、
constraints、scope 和 authorization 原样保留；dirty/branch/remote 漂移在任何派发/预留前阻断；
本机 App Server 仍加载 AGENTS.md，未覆盖 baseInstructions 或降低文档上限。
现有完整回归继续覆盖预算超限/UNKNOWN 保留、终态处理、一次同 thread 返修、独立 QA、
scope、凭据/网络隔离和禁止远端动作。具体命令及结果保存在 `targeted.log`、`make-verify.log`。

- `PYTHONPATH=src:tests python3 -m unittest test_factory_candidate test_factory_local_protocol -q`：
  57 项通过，8.227 秒。
- `make verify`：700 项全部通过，57.200 秒。
- `git diff --check`：通过。

## 已解决与尚未证明

已解决的是 Harness 缺少复用已加载指令/合并检查的明确指引，以及没有向 Agent 提供经过
校验、逐 turn 刷新的候选 Git 事实。Agent 是否遵循这些提示、具体减少几轮工具/推理和真实
token 消耗，仍需新授权实测。原生还注入技能目录与 multi-agent 模式说明，字节可见，但本次
没有证据证明能安全移除这些原生内容，所以不修改它们，也不归类为确定无效费用。

保留全部安全合同。值得在独立审查通过后申请一次预算不变的真实验证；本次不申请执行、
不创建 E2E_07，不恢复 E2E_06，也不宣称真实交付完成。
