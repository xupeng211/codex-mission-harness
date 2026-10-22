# 进展驱动执行策略（离线实现）

本策略在已有 Factory Controller、operation journal、候选工作区、执行事件和 QA 上增加明确的可选模式，不迁移历史任务、Receipt、Ledger 或 UNKNOWN。默认不选择新模式；原配置仍使用原来的严格预算合同。

## 基线与未合并分支

本次基于本地已有 `origin/main` 提交 `360e185223f173d65430a194ab3be1517537dd5c`，不是最初目录所在的旧离线合同分支 `a70ac8f0e2de904e10210d70427c67a5ccfca18c`。本地 `main`、原目录和 FootballPrediction 均不修改。

已检查 `fix/pre-request-budget-admission-20261022` / `1bf403e56455a35e5ef3c984114b7f6986d7e915`，未合并、未删除。该提交的 `ProxyPolicy.request_token_bounds()` 固定返回 `(None, None)`，`admit_request()` 因此以 `REQUEST_TOKEN_BOUNDS_UNPROVEN` 拒绝请求；缺少可信输入 Token 上界和强制输出界，不能宣称严格物理硬帽已得到保证。

保留现有单次物理尝试、UNKNOWN 锁定、逐请求证据、实际返回模型检查、专属单凭据代理绑定、重定向/重试/回退禁止。借鉴该分支补充了代理在未派发时的 `REQUEST_NOT_DISPATCHED` 哈希证据。没有引入它的全局 Token 准入机制，也没有改变当前严格模式的原有准入行为。该分支的严格请求上界证明仍待独立处理。

## 明确选择和授权

离线配置见 `config/factory.progress.example.json`（fixture-only，不能作为客户任务直接运行）。现有 `factory-run` JSON 入口可携带完整授权；便捷 `submit` 不会自动生成或批准 Owner 授权。核心字段：

```json
{
  "execution_policy": {"mode": "progress_driven", "idle_timeout_seconds": 900},
  "budget": {}
}
```

新模式拒绝同时携带旧预算字段或 `max_rounds`，避免含糊地忽略历史授权。缺省或显式 `{"mode":"strict_budget"}` 使用旧模式。历史任务的不可变 policy 不允许原地升级；Owner 必须为新任务另行授权。

任务必须有 `progress_authorization`，包含以下精确绑定；Operator 输入不等于 Owner 自动批准，授权记录须来自 Owner：

- `approval_id`、`mission_id`、`repository`、`base`、`objective`、`acceptance`、`allowed_paths`、Controller 候选 `worktree`。
- `policy_sha256`：`digest(policy_identity(validate_config(config)))`。
- `lane_identities`：Factory 计算的执行身份字典；developer 使用 `developer_binding(spec)[1]`，包括已选择路由。不能凭模型标签代替实际路由绑定。
- `expires_at`：带时区的授权到期时间；这是授权有效期，不是默认执行时长预算。
- `financial`：逐 lane 的 `prepaid_only` 或 `not_authorized`。本实现要求 `second_reviewer` 为 `not_authorized`，真实额外付费调用不能通过此策略取得准入。

通用 full-delivery 模式仍执行计划、开发、业务测试、CI、独立 GPT/DeepSeek 双审及审核驱动返工。模拟双审只能证明离线编排合同，不是实际 Provider 资格证明。local_candidate 仍要求原有完整 `local_candidate_authorization`；新模式用绑定的 `execution_policy` 替代其中的 `max_rounds`，不要求旧 Token 字段。其业务测试不变，多轮同线程返修可继续；交付仍仅为本地候选，不能取得正式双审或 Merge 资格。

## 如何继续、诊断和停止

- Controller 不按累计/单次 Token、agent-run 数、任务总年龄或固定返修轮数停止新模式；保留观测值和调用记录。
- 规划不继承 32,000 Token / 120 秒限制。原生 Codex CLI 和 thread 配置均显式关闭继承的 `rollout_budget`；运行器不安装 Token interrupt。
- ProxyRelay 在进展模式不按 Token、128 个请求或运行总年龄截止；每请求的协议大小、socket 无响应超时、路由和物理尝试检查继续生效。
- 复用 App Server `item/completed`：比较命令、退出码、输出哈希、工作区内容证据。无新上下文的相同错误和动作第二次记录低成本诊断，第三次安全停止。新的成功诊断观测允许重新验证；交替重复旧观测不能刷新循环。相同读操作第六次记录诊断，第十二次停止；新解释、读到不同输出或源码变化允许必要重读。
- 每次已完成的命令/文件变更后检查实际工作区路径。越界即停止，不进入下一次执行；Controller checkpoint 的原范围检查仍保留。操作本身内部的所有文件写入无法逐次拦截，隔离沙箱继续提供外部边界。
- Controller 对相同输入/身份的重新派发、相同候选内容及失败 QA/审核证据保留诊断记录；重复不变的证据安全停止。已完成 operation 原样复用；RUNNING/UNKNOWN 永不自动重放。
- 独立进程看门狗按有效事件静默或 Controller 死亡停止整个进程组。有效事件延长存活，任务总年龄不参与判断。已证明完成的线程在 Controller 做 QA 时停放，静默计时仅在返修活动恢复后继续；Controller 失联保护不暂停。跨轮次中止原因另存到当前 operation 的原始证据。通用业务 gate 的持续输出也会刷新静默看门狗；静默中止保留 `*.watchdog.json` 并记为 UNKNOWN，不能靠自动返修抹掉。
- 无响应判断只说明在授权静默窗口内无法继续证明进展，不断言安静运行必然无效。可以为任务明确配置适当窗口。Token 数、耗时和改动行数都不能单独证明劳动有效。

这些规则能识别可复现的机械循环和路径越界，不能可靠理解“同样在授权路径内，但实现已经偏离业务目标”或“修改少量无关内容来制造新证据”。任务目标、测试和独立审核仍是语义质量边界；本实现没有声称新增 AI 语义监督能力。诊断优先记录具体证据；不能安全确定或恢复时停止，不自动再开一轮模型诊断。

## 财务与明确限制

`prepaid_only` 是 Owner 对指定套餐通道和任务范围的授权，绝非美元/CNY 费用保证。官方 lane 还必须是显式 ChatGPT 身份，API-key 身份不能走此通道；代理仍必须经过已有单 Codex OAuth 凭据和专属代理政策验证。上游套餐、Credits 余额或真实账单无法由本地遥测证明，金额仍为 UNKNOWN，不自动购买/充值，不授权额外 API 或 Credits 消费。若不能由 Owner/Provider 明确保证指定通道的消费边界，应保持 `not_authorized`。

额外付费 DeepSeek、API、Credits 和审核必须另走既有可证明的财务准入。本次没有添加或降低该准入：进展模式真实 `second_reviewer` 调用明确阻断。因此真实 full-delivery 尚不就绪，不能把离线模拟双审 PASS 当成收费放行。

现有 `factory_runtime.prepare_project_review()` 和 `factory_validation.run()/capture()` 使用固定总时限接口。为了避免暗中保留冲突，进展模式明确拒绝 `trusted_validation` 配置和项目 canonical review 派发。兼容这些接口需要另行针对性工程与证据；本次不修改项目审核器、Reviewer V3 或 Model Routing。

新模式不接受 `hosted_ci` / `project_pr_ci` 的自动远程写入组合，直接 Push/Merge/部署 stage 也阻断。Owner 的发布和每次 Merge 权限未转交。原有严格模式的项目验证、真实双审、财务门禁及单独发布授权保持独立。

UNKNOWN 的已观测 Token 按原值保留。进展模式没有虚构有限 Token 预留：未结算预留标为 `UNBOUNDED_UNKNOWN`，总承诺标为 `UNKNOWN`；仍然禁止后续收费派发。旧严格合同的有限预留算法和字段不变。

## 离线验证与上线判断

`tests/test_factory_progress.py` 使用模拟生成、临时 Git 仓库、loopback HTTP、原生 Codex 元数据/沙箱协议（不发起 turn inference）以及独立进程看门狗。覆盖超历史阈值开发、必要重读、重复错误/重启、范围越界、多轮返修、静默/Controller 失联、UNKNOWN 重启锁定、旧策略隔离、收费和远程动作阻断。

旧 Factory 测试和 Reviewer V2 测试仍需通过；最终任务报告记录实际命令、数量和结果。没有真实模型、真实项目开发、真实付费审核、购买/充值、远程 Push/PR/Merge/部署的证据。本轮验收完成即停止；重新开展真实业务开发仍需补足上述接口/财务证据及 Owner 新授权。

最终离线结果：769 项全量测试通过（86.693 秒），其中新增进展策略验收 30 项通过；`git diff --check` 通过。最终全量测试使用 socket 外连拦截器，`EXTERNAL_CONNECTION_ATTEMPTS=0`。原生协议测试仅使用元数据和本地沙箱，不启动真实推理。日志中的 CLI 负向用例报错和弃用提示是预期用例输出，不改变 unittest 的 OK。

证据目录：`/home/xupeng/codex-mission-harness-evidence/progress-driven-execution-20261022-2qlyvv5f`。在本工作树运行 `PYTHONPATH=.:src:tests python3 /home/xupeng/codex-mission-harness-evidence/progress-driven-execution-20261022-2qlyvv5f/run_offline.py` 可复现带外连拦截的全量测试；新增直接测试为 `PYTHONPATH=.:src:tests python3 -m unittest test_factory_progress`。
