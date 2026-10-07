# Software Delivery Factory 最终交付验收

本文件说明验收方法和证据入口；最终状态、实际 Git HEAD、hosted CI run URLs 和结果清单由外部不可改写的运行账本及最终 `acceptance-summary.json` 给出。不能仅凭本文宣称某个后来改动的 HEAD 已通过验收。

2026-10-07 的受控验收根目录：`/home/xupeng/codex-mission-harness-evidence/production-acceptance-20261007/`。其中没有复制 API key；认证文件仅按私有路径读取。最终 merge/release 不属于验收操作。

## 真实开发与审核

小型隔离 Git 项目已有加法函数与真实 Python unittest。需求是增加保留小数、负数和空输入行为的平均值功能，修改代码和测试。

`scripts/factory_acceptance.py` 使用生产 `LocalRuntime`；规划、实施、审核与返工都是真实官方 Codex / DeepSeek 调用，没有 fixture agent。第一个真实 implement 完成后，验收控制器在 `score.py` 注入“37 个元素时错误返回 0”的故障，保存变更前后 SHA256，不更改模型回答和它写出的测试。reviewer 必须自己产生 finding。交付成功还要求有 reviewer finding 触发的真实 rework，只有测试返工不满足该验收。

`real-review-rework/acceptance-report.json` 记录了两条真实审核 lane 各自发现问题、自动返工、复测、两家复审 PASS、原仓库未修改的完整闭环。`real-e2e/` 另行保留了真实测试发现该故障并自动返工的结果，未冒充 reviewer-triggered 验收。

`real-hosted-factory-accepted/` 在相同闭环中加入了 GitHub 专用 acceptance repository 的 Actions：每轮 exact candidate HEAD 自动 push 到 `factory/...` 分支，再保存 workflow、matrix jobs 和 run URL；缺失/未完成/跳过的必需 job 不能获得 PASS。

OpenAI profile 使用官方独立认证目录、`gpt-6.1-sol`；DeepSeek 使用 `https://api.deepseek.com/chat/completions`、`deepseek-flash`。没有将全局 `cli_proxy_api` 当作 OpenAI。所有完成/失败 dispatch 和真实 usage 都进入新 SQLite 账本、只读证据 envelope 和 raw transcript。

## 发现并修复的问题

- DeepSeek 旧别名 `deepseek-chat` 实际返回 `deepseek-flash`，原实现正确拒绝身份不符，却丢掉已返回 usage。新 worker 保留完整响应、usage 和 requested/returned model；新授权选择 canonical model。旧失败 UNKNOWN 保持原值。
- reviewer 的 source reference 容易误用原 repository 目录。输入现在明确给出 structured schema，并要求引用独立 review checkout；校验失败只有证明完成后才允许一次计费的格式恢复。
- 一次 Codex turn 可以包含多个原生模型请求，12 次固定执行额度不足以表达任务资源。新授权增加按规模选择的 calls/token reservations/wall-clock/rework 边界，native rollout budget 和遥测 cutoff；历史 authority 不扩大。
- DeepSeek 的 socket timeout 不是完整请求时长限制。请求和 hosted CI 现在由独立 watchdog 控制的单请求 worker 执行，可取消，控制器崩溃后也有截止时间。
- Harness 原先仅跑本地 CI。新增薄 GitHub adapter 发布专用候选分支、验证 exact SHA、指定 workflows 和实际 jobs；LOCAL_CI 与 HOSTED_CI 明确分开，未配置 hosted 不声称通过。
- Codex 运行 Python 测试可能生成 bytecode，导致干净小项目产生无关 scope 变更。官方 shell policy 设置禁止意外 bytecode，验收项目保留标准 `.gitignore`；历史 scope failure 保持原记录。
- Codex 会自动写入项目 trust bookkeeping，原来的整文件 config hash 会让新任务无理由地触发旧任务复审。现在 profile identity 使用排除该 bookkeeping 的语义配置 hash，仍对真实模型配置变化产生新身份；这不是改写旧 receipt。
- 真实 token cutoff 证明失败 turn 的已观察 usage 可能只覆盖此前完成的响应。现在区分完整 HTTP/turn 结算和部分遥测；部分 telemetry 原样保留，未完成 dispatch 的全额 UNKNOWN reservation 永久保留，不能据此释放预算。
- 用户入口需要填写内部参数。新增 setup 自动识别项目门禁、私有第二 Provider credential 输入、最近任务选择、简洁中文状态及 delivery/resume/cancel 入口；原 JSON CLI 保持兼容。

## 故障、恢复和历史

`crash-probe/acceptance-report.json` 记录真实 `turn/started` 后控制器 SIGKILL、受控子进程退出、两次 resume 均为 UNKNOWN、paid operation 数保持 1，UNKNOWN reservation 保持永久占用。没有再次发送未知请求。

单元和 native 协议回归同时验证：完成的实现可在控制器 checkpoint 前崩溃后恢复且不重调模型；agent timeout；真实取消；stale HEAD/脏树；源码被测试修改；测试/CI失败自动返工；malformed review；缺失/篡改 evidence；Provider failure；未知 usage；返工失败/上限；budget exhaustion；并发/重复 resume；hosted run 和 job identity；人类 exact-head approval。

旧任务 `history-baseline.json` 与最终 `history-preservation.json` 比较，旧账本和本轮初始失败账本只读保留。initial `deepseek-chat` 的真实失败不能通过修复代码或回填 usage 伪装成功。真实 profile 切换结果在 `profile-switch-report.json`，必须证明新的 OpenAI review identity、DeepSeek receipt 原样保留、历史 operations 不变。

## 安装与 CI

仓库 Actions 在 Python 3.11/3.12/3.13/3.14 上运行 editable install、完整测试/compile checks、wheel build、独立 venv wheel install 和 installed CLI E2E。最终 run URL 和 exact code HEAD 记录在最终报告。Acceptance 项目的每轮 Actions 是另外的托管记录，不能代替 Harness 自身 CI。

尚未通过的步骤不能在最终报告写成 PASS。真实的剩余限制包括：Linux、本地已有依赖、完整文本上下文容量、官方账户访问权、UNKNOWN 不可盲目重发、token admission 非精确美元扣费保证、最终合并/发布必须人工单独批准。
