# Antigravity CLI 第二审（候选，尚待真实接入验收）

只替换现有 `second_reviewer` 的执行 backend。配置参考
`config/factory.antigravity.example.json`：provider=`antigravity`、
backend=`antigravity-cli`、显式 Gemini model、effort=`medium`、绝对 `cli_path`。
原有配置默认保持 DeepSeek；没有自动 fallback。

## 调用和输入

Factory 的 `review` → `LocalRuntime.second_review` 选择新适配器，仍使用
`Factory.operation` 的预留、缓存、UNKNOWN 阻断和现有 AppServerProcess 子进程树监督。
一次逻辑启动：`--new-project --model … --effort medium --output-format json
--print-timeout <最多600>s --sandbox --log-file <私有路径>
--disable-slash-commands --settings <本次settings> --print <本次prompt>`。
没有 continue 或格式修复第二次调用；CLI 内部重试策略不改，总请求数 UNKNOWN。
停止沿用既有5秒子进程回收窗口和 ECHILD 验证，低于60秒收尾预算。

每次 operation 在私有运行目录新建独立输入树，放入中性需求、不变量、完整 diff、
准确 BASE/HEAD 与目标对象 hash，以及完整 HEAD 的常规 UTF-8 文本源码、测试和依赖文件。
不提供 Builder 会话、第一审结论或其他审核输出。沿用现有 full-source 容量上限，
超限直接阻断，不截断；非文本/非普通文件在输入清单显式列为 excluded，二进制变更阻断。
报告要求实际阅读范围、上下文缺口和未验证事实。

原生权限 settings 沿用已试验的 deny write/command/url/MCP，禁止访问工作区外文件；
没有跳过权限开关。这些选项和前后 hash 相等不构成操作系统强隔离证明。
输入前后 hash、prompt/settings hash 都被原始生命周期及 operation 证据绑定。
发现输入变动、版本不符、证据缺失或本地停止不明均阻断。

仅继承缓存登录所需桌面环境和原代理/证书变量，不读凭据、不继承 API key 或端点覆盖。
记录的是实际传给受管子进程的脱敏环境（scheme、脱敏host/port、NO_PROXY 范围），
不自动切节点，不写私人节点到源码。配置走代理不等于实际路由证明；节点、GUI同路由、
实际出口均可保持 UNKNOWN。真实验收时按既有一次试验证据方法单独确认节点与连接。

## 接收与消费

CLI 外层是实测的单 JSON `status/response/error/finished_reason/usage/...`。
`response` 请求为结构化报告：`completion/verdict/target/read_scope/context_gaps/review`，
其中 `review` 复用现有 REVIEW_SCHEMA 和位置/严重程度验证；只允许整体 JSON 或单个
JSON fence，不扫描“PASS”字样，不从截断/重复正文提取可用后缀，不依赖一次成功报告的措辞。
这是适配器向审核员请求的格式，不冒充 CLI 原生结构化输出保证或新的正式 receipt。
模型实际能否按此格式返回，仍待真实接入验收。

只有进程exit=0、原始status=SUCCESS、无error/异常finished_reason、报告COMPLETE、
版本正确、原件未变且ECHILD证据一致，才可接收。COMPLETE/FAIL 是有效结果；
全部P0–P3通过原 `findings → feedback → rework` 交回开发员，P3也不滤掉。
ERROR/超时/取消/格式无效不成为代码缺陷，而是保留UNKNOWN operation并阻断后续派发。

私有原始 stdout、stderr、原生日志、argv、CLI版本/hash、UTC/单调时间、exit/信号、
超时/取消分支、输入前后hash、公开JSON终态/usage、可识别重试code与ResponseID均保留。
自动提取仅固定运行字段，不输出日志正文或私有推理。内部code500不当成HTTP状态；
无定位证据时 failure_layer=UNKNOWN，不凭通用文字猜代理、额度或模型能力。
现金费用与实际权益消耗 UNKNOWN。UNKNOWN操作的预留和历史失败不会重写/退款。

## FootballPrediction 合同兼容范围

项目主审仍走原 canonical Codex runner/validator，项目 `required_backends` 不变。
Factory额外第二审要求显式绑定 `codex-cli + antigravity-cli`。Antigravity使用自己
的报告artifact和生命周期，不创建或借用DeepSeek/Claude receipt。

原生政策只要求Codex的STRICT任务：最终消费者重验Antigravity报告和停止，再把真正
Codex receipt交给原生 `merge_ready(use_project_policy=True)`，其scope/治理/PR/CI
规则继续全部执行。原生政策要求DeepSeek的NORMAL/CRITICAL任务：本候选明确阻断
替代，不触发fallback，不绕过业务项目政策。若要替代这些项目原生岗位，需要另有
明确的业务政策变更授权；本候选没有修改FootballPrediction源码或治理。

## 离线与真实验收

测试使用模拟CLI，但经过实际Factory/LocalRuntime适配器和现有受管启动、停止与
反馈链；覆盖成功缓存、COMPLETE/FAIL全部严重程度返工、exit0/ERROR、截断/重复/
无效/版本不符/输入变动、超时与取消（包含独立session后代）、项目STRICT最终消费
及CRITICAL替代阻断。模拟返工不表示完成真实自动返工。

下一次真实验收应冻结本候选准确HEAD，以本候选自身的完整BASE..HEAD差异作为中性静态
样本，只调用 `Factory.review(..., "second_reviewer")` 一次，最多600秒执行、60秒收尾。
这样能验收实际的输入生产、operation预留、适配器、报告消费与停止链，且不重开已DONE
的FootballPrediction业务。不要运行整个Factory任务，从而额外调用Builder或主审。
原工具试验材料HEAD仍是 `170ac6aaad593f25bbe0244b6e0d063c0ef2c8a0`，历史结论不改，
本次选用Harness候选作为新接入验收材料的差异必须记录。完整绑定与操作步骤写在本轮
源码树外HANDOFF。
