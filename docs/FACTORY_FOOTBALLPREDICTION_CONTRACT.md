# Factory FootballPrediction 合同适配：阶段 1

本模块只接入项目合同；阶段 2 的显式 Docker 验证和 PR CI 适配见
[FACTORY_FOOTBALLPREDICTION_PHASE2.md](FACTORY_FOOTBALLPREDICTION_PHASE2.md)。
Fixture 通过为 `OFFLINE_CONTRACT_PASS`，不是真实 `READY_FOR_USER_ACCEPTANCE`、
`MERGE_READY` 或 `DONE`。缺少实际受信任验证和 exact PR/CI context 时真实模式阻断。

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
Factory 主流程仅在显式阶段 2 模式接受经验证的 PR/CI context；首次付费执行仍因
canonical runner 物理费用上界未证明而阻断。
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

## 目录初始化与真实接口离线集成

canonical operation 在现有缓存、取消和 RUNNING/UNKNOWN 防重发检查之后，
付费 reservation 之前执行可信本地准备。Controller 只接受账本中的候选路径，
收紧自有 candidate/mission 目录权限；Runtime 经 `review_arguments` 从
mission/reviewer/exact HEAD 推导 `.cmh-review-evidence` 路径，复用已有
`_private_dir` 检查和创建 owner-only 目录。拒绝路径穿越、symlink、非目录
冲突和不可信祖先，不接受 Builder 指定的 evidence 路径。argv、environment
及 watchdog 准备失败不会产生 paid operation；失败后不需要退款或改写 UNKNOWN。
已 dispatch 的失败仍按原 UNKNOWN 规则保留 reservation，历史任务不补派。
外层 stdout/stderr 在启动 runner 前设置为 0600。

DeepSeek receipt 消费者绑定 scope 时从 Git 读取原始 bytes。CRLF 与 LF 各自
保留精确 hash，不做换行归一化。Controller 的 Git 字节解码路径同样不做
universal-newline 转换；修改任何 scope 字节都不能借用原 scope 审批。

`tests/test_factory_project_integration.py` 从只读项目仓库的上述固定 SHA
提取正式源码，使用临时 synthetic base/candidate，执行真实 Controller →
LocalRuntime → review_arguments → adapter → canonical runner/validator。
只替换 trusted checkout 的 fixture 定位、认证/环境探测和 Provider backend；
原项目 CLI 参数、receipt writer、classifier/consumer 仍运行。fake backend
位于 `tests/fixtures/footballprediction_fake_backend.py`，其回执和模拟身份仅
用于临时测试，绝非正式执行证据。未找到只读源码会明确 SKIP，不能报告真实
接口验收 PASS；可用 `FOOTBALLPREDICTION_CONTRACT_REPO` 指定源码位置。
测试不读取认证内容、不运行真实模型、Docker、CI 或业务 E2E。

本次真实接口集成发现额外 P1：当前项目 `classify --json` 返回
`review_receipt` 路径与 `classification`，没有 adapter 所要求的内嵌 `receipt`。
Owner 已单独授权最小接口兼容修复。adapter 现在要求原 classifier 返回
VALID_CURRENT、current_approval_eligible=true 并指向当前原始 receipt；比较
分类前后的完整字节/hash，再消费原文件。缺失引用、分类拒绝、非私有文件、
无 verdict 或分类过程中发生变化均阻断。不采用模拟内嵌 receipt 作为替代，
不修改 canonical argv、模型 pin、双审数量或 P3 策略。

## 首次付费审核之前的费用条件（仅调查，未实现新计费能力）

在上述项目 SHA，`deepseek_review_chunks.py` 的 diff/prompt 分块上限分别是
32,000/40,000 bytes，最多 64 chunks。`_run_chunked_review` 对每个 chunk
执行一次 `backend.run`；小 diff 执行一次。每次 backend 创建一个 Claude CLI
进程，默认/最大 backend timeout 为 900 秒。Factory 的一个 outer operation
因此不是一个 Provider HTTP 请求：它可能包含 1～64 次 backend 执行；CLI
内部请求、重试、输出 token 和物理费用上限尚未证明。两个 reviewer 的 outer
reservation 也不能当作“两次 HTTP 请求”的证据。Codex CLI 内部请求数同样
未证明。Factory watchdog 和逻辑 token reservation 都不是物理费用硬上界。

首次真实付费审核必须先明确并批准 exact diff/scope 对应的 chunk 数、两条
canonical lane 的费用暴露及可接受上限；证明或取得明确有限的请求、输出和
重试授权，并验证 usage/费用观测及 timeout/cancellation 的实际行为。两个
必需 backend 的认证、模型 pin、正式 validator 和本地准备需在付费前确认
可用。计费或结果不确定时继续保留 UNKNOWN，不自动重试、补发或返还预算。
在这些条件未满足前，本轮离线 PASS 不能支持首次真实付费审核的成本安全结论。
