# PR B 最终交付准备（2026-10-18）

**尚未达成真实 `LOCAL_CANDIDATE_READY`。唯一待授权步骤是新的真实 E2E_08。**
本轮未派发收费模型任务，未恢复历史 Mission，未进行远端写操作。
工程起点为 `89752f1502f569d0d7da4192ce3d31c160694e82`，
分支为 `fix/prb-final-delivery-readiness`。

证据目录：

`/home/xupeng/.local/state/harness-delivery-evidence/PRB_FINAL_ENGINEERING_20261018/`

## 技术决策与实际修复

继续使用官方 Codex App Server。已有实现包含隔离 clone、scope/Git/授权绑定、
正常终态确认、累计 usage 增量结算、UNKNOWN 永久预留、独立可信 Docker QA
和最多一次普通返修。没有证据支持为这次交付另建执行后端或移除项目工作流。

E2E_07 已写出业务修复及三个回归，但在累计观察
`19,802 → 42,887 → 71,858 → 104,320 → 138,717` tokens 后触发
120,000 首次上限，终态为 `interrupted`，没有进入正式 QA。
其中输入 135,806（包含 cached input 101,504）、输出 2,911；
这些是不完整观察值，不能当作完整账单。减少重复读取后仍有五个响应周期，
所以继续用同一不足阈值重复试跑没有工程依据。

本轮发现并修复了另一个原生协议缺口：**对仍被订阅的已加载 thread 调用
`thread/resume`，配置覆盖会被忽略。**此前只断言返修预算出现在请求参数中，
不足以证明原生运行时应用了它。

`src/harness/factory_runtime.py` 现在在同 thread 返修恢复前确认
`thread/unsubscribe`，让无其他订阅的空闲会话按新配置从原历史恢复；
继续复用同一个 App Server 进程和 thread ID。
取消订阅无法确认、恢复失败或返回不同 thread ID 时，在 `turn/start` 前停止，
由既有 UNKNOWN/预留机制保存失败，绝不换 thread 重试。
Controller 对包含 cached input 的完整观察量及返修增量继续独立限额，
不依赖原生 budget 与 provider 的加权计数方式相同。

本机 `codex-cli 0.163.0` 零推理反例/正例确认：

- 绕过修复、保持订阅时，请求的测试配置 `low` 被忽略，仍报告 `high`。
- 取消订阅后，同一 thread ID 报告 `low`，恢复后仍可使用隔离命令访问候选代码。
- 仅在隔离测试中改变 effort，作为可观察的配置见证；生产配置仍固定为授权的 `high`。
- 测试仅注入合成消息历史，没有 `turn/start`，不证明模型推理权限。

App Server 生命周期和取消订阅接口见
[官方文档](https://learn.chatgpt.com/docs/app-server)。覆盖配置的反例和正例以本机测试为准；
不把历史源码或文档中的行为直接当作已安装版本的实测结果。

## 离线验证

基线 `make verify`：700 项通过，57.084 秒。
新增回归验证历史用量前缀在原授权下停止、更大显式授权仍必须等待正常终态、
长 thread 历史下返修只按增量限额，以及取消订阅和 thread 身份失败时不得派发。
人工构造的未来用量和完成事件均有注释，不声称预测了真实完成成本。

最终 `make verify`：706 项通过，57.618 秒；`git diff --check` 通过。
重点回归先后为 75 项通过（8.682 秒）和 34 项通过（5.551 秒），
最后新增的 thread 身份保护由上述 706 项全量运行覆盖。
命令与结果见 `targeted-final.log`、`resume-fix-final.log`、`final-verify.log`；
最终 Git 身份、日志摘要、完整补丁和 SHA256 在 `engineering-delivery.json`。

在新的业务隔离副本上，执行真实 `factory_validation.run()`、`validate_result()`
及成功结果的 local acceptance 校验，使用原有固定 digest 镜像与
`make verify-targeted`：

| 工程步骤 | 实测结果 |
| --- | --- |
| 只新增缺 home/draw/away 且带 extra 的三个测试 | FAIL，exit 1；3 failed、8 passed，三项均为对应 KeyError |
| 最小修复 `valid_triple()` 的必需键判定 | PASS，exit 0；11 passed，静态/格式检查通过 |
| 两次 Docker 生命周期 | cleanup COMPLETE，4.457 / 4.384 秒 |

业务基线：`14633c3ca99309a1a4d6d9b5b107f2c0b8c98342`。
工程副本最终 HEAD：`434996fe12d26f93ea55baadcc48d3d939f9fb60`，
Tree：`f24e32e778ad23236e3935f66ca86783af8d2add`。
完整业务夹具 diff 和原始结果在 `business-run-02/`。
初次辅助脚本因未剥离 ANSI 颜色而断言日志失败，已修正解析并使用新的副本重跑；
第一次原始 QA 的三项预期失败及日志仍保留，没有修改门禁。

**业务修复由外层工程脚本手写，仅证明真实门禁能够检出并验证该缺陷。**
没有创建交付事件，没有将此副本称为真实 Agent 候选，也没有验收 E2E_07 的产物。
同 thread 自主返修仍需真实模型验证，合成协议测试不能替代它。

历史 E2E_01–07 全部 30,180 个文件的初始 SHA256 已记录，最后重新核对；
正式来源的 HEAD/Tree/dirty 状态也单独核对。
本轮 Harness 模型推理派发为 0；外层助理的精确 tokens 和金额 UNKNOWN。

## 一次性真实执行申请（待用户批准）

草稿为证据目录内 `e2e08.mission.draft.json` 和
`e2e08.operator-config.draft.json`，不是生效的默认配置。
任务文字保留 PENDING APPROVAL，授权期限为过去时间；两项独立拒绝已验证。
没有 submit、没有创建 E2E_08 状态目录。

| 授权项 | 完整执行边界 |
| --- | --- |
| Mission | 全新 `HARNESS_MVP_PRB_REAL_DELIVERY_E2E_08`；不恢复或消费历史授权 |
| 模型与渠道 | `gpt-6.1-sol / high`，官方 OpenAI App Server，现有 ChatGPT OAuth；无 fallback、无第三方收费渠道 |
| 任务与基线 | 在上述业务基线修复 `valid_triple()`，新增三个缺字段带 extra 回归 |
| Agent 写范围 | 仅 `src/ml/value_mvp/market.py`、`tests/unit/ml/value_mvp/test_market.py`；scope 由 Controller 管理 |
| 执行次数 | 首次实现 1 turn；仅普通 QA 失败时最多同 thread 返修 1 turn；无额外 planner/reviewer/资格探测模型任务 |
| 首次 tokens | 300,000，包含 cached input 的累计观察上限 |
| 返修 tokens | 最多增量 180,000；不返修则不发生该次用量 |
| 总 tokens / 时间 | 480,000；Mission 墙钟 900 秒 |
| 可信 QA | 相同 digest 固定镜像、Controller 独立 `make verify-targeted`，必须执行业务测试、静态和格式检查 |
| 停止条件 | UNKNOWN、身份/授权/scope 漂移、预算超限或返修后仍失败即停止，不自动创建下一 Mission |
| 远端动作 | Push、PR、Merge、Release、Deploy 全部禁止 |

300,000 为此前五个周期已观察量的约 2.16 倍，给正常收尾留下空间；180,000
考虑返修会带着已有历史继续输入。这是工程余量选择，**不是实测完成量或费用预测**。
上限会增加潜在消费额度，必须取得新授权，不能把它描述为预算不变。
tokens 仅为预留/观察阈值；通知到达前可能已有在途请求，不能保证物理 tokens 或货币硬封顶。
该 OAuth 渠道没有本地可核验的逐 token 价格或最终账单，金额仍为 UNKNOWN；
不会切换 API key 或收费渠道来绕过这一限制。

预期收益是让新 Agent 有机会正常完成，进入已验证可用的可信 QA，并取得真实完整
HEAD/Tree/diff、正常完成事件、usage 与最终 `LOCAL_CANDIDATE_READY`。
仍有模型访问、路由、执行效率、在途计费和真实自主返修效果未被实测的风险。

批准后仅将待批文字替换为实际授权事实，绑定本轮封存的 Harness HEAD/Tree、
来源身份及重新核对的 executor identity，设置短期有效授权，然后执行一次现有
`harness factory-run`。运行前若有实质身份变化或新的硬阻断，先停止核对；
不沿用失效身份。完成或失败后封存该新 Mission 的完整原始证据。
