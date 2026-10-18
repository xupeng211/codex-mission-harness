# PR B 本地交付状态（2026-10-18）

最新工程结果及 E2E_08 待批执行边界见 [PRB_FINAL_DELIVERY.md](PRB_FINAL_DELIVERY.md)。
以下保留之前工程迭代的记录；其中的待执行编号与测试数量不代表最新状态。

本地实现已完成，仍缺一次获授权的真实模型验收。**尚未交付真实
`LOCAL_CANDIDATE_READY`**。本次没有启动 Harness 模型推理，也没有 Push、PR、Merge 或部署。

本阶段从干净的 `956045b2d07c87ba88365b4225eb0af4d023b8e2` 开始，
开发分支为 `fix/prb-terminal-delivery`。最终提交、Tree、完整补丁和测试日志位于：

`/home/xupeng/.local/state/harness-delivery-evidence/PRB_ENGINEERING_20261018T020633Z/`

## 直接影响交付的修复

| 文件 | 行为与目的 |
| --- | --- |
| `src/harness/codex.py` | 保留默认成功校验；允许 Factory 读取失败/中断的终态以保存证据。 |
| `src/harness/factory_runtime.py` | 超限只发一次 `turn/interrupt`，在原截止时间内最多再读 5 秒。收集匹配 thread/turn 的终态与单调累计 usage，接受相同快照的幂等通知，过滤其他 turn 的 usage。 |
| 同上 | 只有 `completed` 加合法 usage 才确认用量完整；`failed`、`interrupted`、EOF、超时和缺失 usage 不会变成成功。已排队的成功完成事件可以被收集，但超限仍由 Controller 阻断，不能进入 QA 或继续返修。 |
| 同上 | 单 Agent 可返修会话使用可存储的 thread；一次性独立 lane 保持 ephemeral。恢复同一 thread 时复核模型、provider 和 effort。 |
| `src/harness/factory.py` | 从已校验的 QA operation 提取最多 16 KiB/日志的结尾，放入返修输入，解决 Agent 无权读取 Controller 日志路径的问题。保持一次普通返修限制。 |
| 同上 | 不确定返修也按累计 thread usage 的增量记账，避免重复计算第一 turn；UNKNOWN 和其未知预留继续保留。将项目 mission scope 传入现有只读保护。 |
| `src/harness/factory_candidate.py` | 拒绝包含非法辅助计数的 usage 快照，避免不可信用量进入结算。 |

## 历史调查与模型选择

E2E_01 无模型 operation；E2E_02–05 的 implementation operation 均保持原记录的
`UNKNOWN`。E2E_05 原始 usage 为 128,185，首次阈值为 120,000，终态未读到。
本次仅只读检查这些历史文件，未恢复、重放、重分类或验收历史候选。

`gpt-6-luna / low` 来自历史 `operator-config.json` 和对应授权，Harness 本身没有将
developer 固定为该模型。E2E_02/03 在探索期间被预算观察截断；04/05 在完成编辑后被截断。
05 中累计输入 126,653（包含 cached input 103,168），输出 1,532，说明阈值主要被反复输入上下文消耗。
这不足以单独证明模型能力是根因。缺少工具依赖的尝试、协议截断以及不可恢复的 ephemeral
thread 均有直接工程证据；提高阈值无法解决后两项。

现有 profile 已支持 `model`、`effort`，无需新增模型调度。拟验收使用
`gpt-6.1-sol / high`。本机 `codex-cli 0.163.0` 的零推理测试确认 thread start/resume
接受并报告该选择，恢复后 thread ID 一致；**这不证明账户有推理权限，也不证明实际执行模型**。
真实验收还必须有成功的 turn、匹配的模型报告及无异模型 reroute。

官方依据：[模型说明](https://developers.openai.com/api/docs/models)、
[App Server 协议](https://learn.chatgpt.com/docs/app-server)、
[模型目录不等于账户推理权限](https://developers.openai.com/siwc/token-sharing-open-source/codex-app-server)。

## 已执行验证

- 基线 `make verify`：678 项测试通过，54.646 秒。
- 最终 `make verify`：696 项测试通过，55.615 秒；`git diff --check` 通过。
- 新回归覆盖真实 JSON 消息解析、超限后的排队完成事件、acceptance 前的异步通知、
  中断 acknowledgement 不等于完成、失败终态、缺失 usage、EOF、drain 超时、重复/回退快照、
  异 thread/turn、模型 reroute 和恢复后的模型/effort 不匹配。
- 本机 Codex 零推理测试覆盖：强模型/high 配置、可存储 thread 同 ID 恢复、ephemeral
  无法恢复的反例、原有 filesystem/network/凭据隔离，以及 Controller scope 只读。
  `thread/inject_items` 仅为测试注入合成历史，没有 `turn/start`。
- Controller Docker 工程验证：从指定业务基线独立 clone，不修改 `market.py`。
  新增一个故意错误的测试断言得到 `FAIL/exit 1`（1 failed、8 passed），
  纠正测试断言后得到 `PASS/exit 0`（9 passed），两次 cleanup 均为 `COMPLETE`。
  使用真实 `factory_validation.run()` 和 `validate_result()`、原有锁定镜像、静态检查和格式检查。
  这是测试夹具的工程验证，**不是 Agent 自主修复业务需求或真实交付**。
- 来源工作树原有 HEAD 实测为 `7fe8cfeb11dcf22ab9077ee95fb94bec31356145`，工作树干净；
  目标旧基线对象 `14633c3ca99309a1a4d6d9b5b107f2c0b8c98342` 可读取。
  工程副本从目标基线建立，前后确认正式来源 HEAD/Tree/状态均未改变。

最终完整测试结果、日志 SHA、Git 身份与保留历史文件的哈希复核见证据目录
`engineering-delivery.json`。测试代码位于 `tests/test_factory_turn_completion.py`、
`test_factory_candidate.py`、`test_factory_local_protocol.py`、`test_factory_preflight.py`
和原有 `test_factory.py`。

## 唯一待批准的真实验收

已生成新的 E2E_06 mission/config 草稿，未 submit、未执行；草稿带显式 pending approval
约束和过期授权，确认无法进入派发。批准后只替换该待批约束、授权标识及期限，并重新绑定
当前 runtime 身份，再运行现有 `harness factory-run`。若身份变化则先核对变化，不沿用旧身份。

| 项目 | 拟执行边界 |
| --- | --- |
| 模型 | 官方 App Server `gpt-6.1-sol / high`，无 fallback、无资格探测 turn |
| 需求 | 全新候选修复 `valid_triple()` 缺 home/draw/away 且含额外字段时的 KeyError，新增三个回归 |
| 基线 | `14633c3ca99309a1a4d6d9b5b107f2c0b8c98342` |
| 范围 | 仅 `src/ml/value_mvp/market.py` 和 `tests/unit/ml/value_mvp/test_market.py`；另有 Controller 管理的 mission scope |
| 次数 | 首次实现 1 turn，普通 QA 失败最多同 thread 返修 1 turn；未知状态立即停止 |
| 预算 | 首 turn 120,000、返修增量 36,000、总量 156,000 tokens；墙钟 900 秒；不提高历史 E2E_05 阈值 |
| QA | 独立 Controller、原有 digest 固定镜像、`make verify-targeted`，不可跳过静态/格式/实际业务测试 |
| 状态目录 | `/home/xupeng/.local/state/codex-factory-prb-real-e2e-06`（尚不存在） |

token 限额是派发预留/使用量观察阈值，无法保证物理 token 或货币硬封顶；费用为 UNKNOWN。
完成时必须保存匹配的 `turn/completed`、完整 usage、新候选 HEAD/Tree/base/diff、真实 QA
日志和 `LOCAL_CANDIDATE_READY`；任何缺项不得宣称核心目标完成。当前未生成上述真实交付标记。

已知剩余风险：账户推理权限、服务端实际模型路由、真实模型效率以及真实 QA 失败后模型返修
效果仍未获验证。外层 Codex 的精确执行模型、总 usage 和金额无法从本阶段可信证据确定，均为 UNKNOWN；
本次 Harness 新增模型推理派发为 0，未发现已确认的额外模型浪费。环境测试先前暴露的 native
恢复失败已通过代码修复和零推理反例/正例验证。
