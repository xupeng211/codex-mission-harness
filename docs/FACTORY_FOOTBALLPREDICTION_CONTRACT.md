# Factory FootballPrediction 合同适配：阶段 1

本模块只接入项目合同，不提供 Docker executor、PR 发布或 PR CI waiter。
Fixture 通过为 `OFFLINE_CONTRACT_PASS`，不是真实 `READY_FOR_USER_ACCEPTANCE`、
`MERGE_READY` 或 `DONE`。真实模式在最终项目门禁返回明确的阶段 2 blocker。

## 显式选择与 Controller 授权

Operator 配置增加 `"project_contract": "footballprediction"` 才选择项目模式。
不设置时，普通 Factory 的 OpenAI App Server + direct DeepSeek 双审不变。
项目模式仍要求 `independent_review_required=true` 和现有三个 profile；只有
developer profile 用于 App Server，canonical reviewers 的模型、认证及执行器
由项目受信任 base 的 policy 决定，不能由 reviewer profile 覆盖。
现有 push-only `hosted_ci` 配置与此阶段项目模式不兼容，显式拒绝。

Factory version 2 mission 可通过现有 mission JSON 输入接收
`approved_mission_scope`，不需要新 CLI 或任务框架。其字段全部必需：

| 字段 | 合同 |
|---|---|
| `approval_id` | Controller 提供的非空审批记录引用；不是密码学授权证明 |
| `mission_id` | 必须等于当前 mission |
| `base` | 批准绑定的完整 base SHA，必须与实际解析的 mission base 一致 |
| `path` | 必须是 `docs/agentic/missions/<mission-id>.json` |
| `content` | 已批准 scope 的原始 UTF-8 文本，最多 64 KiB；不重新序列化 |
| `sha256` | 上述精确字节的 SHA-256 |
| `expires_at` | 带 timezone 的到期时间；提交、执行及状态读取均检查到期 |

Scope schema、类别、路径授权/exclude 和 required backend 由项目当前的
`MissionScope.from_mapping`、`validate_mission_scope`、`required_backends` 与
active registry 决定。Controller 输入必须也授权 scope 文件自身；缺失并不
隐式增加授权。审批 envelope 冻结在现有 immutable mission SQLite 记录中。
输入信任边界仍是 Controller/Owner，Builder 无权提交或改变审批输入。

Controller 在隔离 clone 中先加入 scope commit。Builder 获得 scope 的只读
filesystem permission；checkpoint 在任何 commit 前比较实际字节，target
再比较 HEAD regular blob。冒用 mission/base、重复 JSON key、冲突 reference、
过期、缺失、修改或 symlink 均阻断。不会修改原项目仓库或为旧 mission 补授权。
只有 Controller scope commit、没有业务实现的候选也不能交付。

## 审核、证据与最终门禁

复用 `FootballPredictionAdapter` 的受信任 base checkout、canonical runner
argv/environment、Codex classifier 和 DeepSeek 原 receipt consumer。
新增桥不制造 receipt、不把 App Server/direct HTTP evidence 改写成 CLI evidence。
受信任代码按 base 验证；候选不能修改 canonical authority 路径，修改它们需要
另一个显式 policy mission。每个 Factory clone 有独立的相邻受信任 worktree 根。

| Workflow class | 项目必需 backend | 此阶段 Factory 额外要求 |
|---|---|---|
| NORMAL | 默认 Claude/DeepSeek | 同时收集 Codex receipt |
| STRICT | Codex | 同时收集 advisory Claude/DeepSeek receipt |
| CRITICAL | Codex + Claude/DeepSeek | 两份均有效 |

**保守策略没有放宽：**任一 finding（包括 P3）仍进入 Factory 返工；基础设施失败
或缺少有效 receipt 阻断，没有 silent fallback。减少 NORMAL/STRICT 审核数量、
采用项目的 P3 非阻断策略，均是未批准的 Owner 决策项，本阶段不提供开关。
最终适配器使用项目默认 policy，不传 CRITICAL 禁止的 backend override。

完整 base/head/tree、全部 changed files、每个 hunk 的位置和哈希、base/head
blob/mode/内容哈希、完整 diff 与 scope 哈希随 target 和 reviewer operation
保存。完整 diff 超过授权容量直接阻断；binary、非 UTF-8、symlink/gitlink 不
进入这条文本审核路径。rename 按 delete/add 枚举，mode-only/空文件保留 file
记录，即使没有 textual hunk。记录真实提交的范围为 exact refs 和可读 detached
worktree，`semantic_coverage=NOT_MACHINE_PROVEN`，不把范围清单当成模型理解证明。
Factory diff hash 与项目自身 diff policy/hash 保留各自含义。

真实 runner argv、原 receipt 与其 provenance 原样引用；原 validator 每次消费
和 delivery status 读取均重新运行。Factory operation/raw artifact 哈希也必须
通过。UNKNOWN 不重发，预算、scope 和审批不重置。canonical runner 尚无统一
可证明完整的 token usage 接口，因此其 usage 为 UNKNOWN，保留原 per-run
reservation，不宣称免费或退还额度。现有 watchdog 限制时长，不保证物理费用帽。

`final_gate` 可委托现有项目 `agent-merge-ready`，缺少 PR/CI context 时拒绝。
Factory 主流程本阶段不产生或接受真实 PR/CI context，真实 READY 始终阻断。
模拟 final gate PASS 只产生离线状态，merge approval 仍要求 live READY 与人工
exact-head 授权，fixture 永不满足。阶段 2 再接入可信验证和实际远端证据；阶段 3
才验证业务任务、实际 Provider receipt、MERGE_READY 与合并后的 main Gate。

## 离线验收边界

`tests/test_factory_project.py` 使用独立临时 Git 仓库、标明 fixture 的 runner、
receipt validator 与项目 API doubles。它验证 Harness 的委托、绑定、阻断和
状态投影，不证明真实 FootballPrediction runner、账户或 CI 可用。
已有普通 Factory、adapter 与预算/UNKNOWN 测试继续验证原路径。
没有新增 reviewer 分块、综合、调度、Provider qualification 或历史任务恢复。

另在临时目录读取 FootballPrediction 基线
`05dc75eb9c2e9e5ec042840d91fee4a3d480ce60` 的 policy 源码进行了离线委托检查：
三种 workflow class 的 required backends 与当前 `gpt-5.6-terra / medium`
pin 均正确返回，未授权路径被项目原函数拒绝。此检查没有运行 reviewer，
没有读取认证内容，也不证明真实 receipt、Provider 或最终 PR gate 可用。
项目 receipt 的时效/工具漂移判定仍由原 validator 负责；不新增猜测的 TTL。
