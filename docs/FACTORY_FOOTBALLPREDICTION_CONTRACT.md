# Factory FootballPrediction：Controller 执行与交付桥

本模块复用项目 trusted-base policy、canonical profiles、双审核原 runner/validator、
PR readiness 和 merge-ready。它不提供 Merge、部署、数据采集或业务检查器。
实现/离线测试不等于真实远端验收。fixture 永远只有 `OFFLINE_CONTRACT_PASS`。
main 已有的显式可信 QA / PR CI 接口保留，见
[FACTORY_FOOTBALLPREDICTION_PHASE2.md](FACTORY_FOOTBALLPREDICTION_PHASE2.md)。
两套验证/交付策略分别绑定原证据格式，不混配或互相冒充。

兼容边界：main 的 `trusted_validation` / `project_pr_ci` 保留原可信 QA 绑定、
人工 exact-head 发布授权、PR CI 刷新和 canonical final gate；Controller 的
`project_container` / `project_delivery` 保留原容器生命周期、严格执行绑定和远端观察恢复。
同时配置两套执行策略会被拒绝，不自动迁移旧证据。STRICT 的发布和 READY 消费要求
所选执行器实际成功的当前 strict 记录；配置本身和 fixture 不满足真实验证。
main 的本地单线程返工及路由不触发 Controller 的发布路径；返工的累计 usage 只按
同一授权线程的当前 turn 增量消费，其他线程/turn 和 delegation 仍阻断。

## 启动与冻结

真实入口仍为 `harness factory-run <mission-v2.json> --config <operator.json>
--state-dir <repository-external-private-directory>`。该命令会启动付费任务，**只能在
Owner 另行批准后执行**。`harness factory-doctor` 不调用模型，但不证明账户可用。

mission/spec、scope 原始字节、policy、预算与 repository-external 状态存入既有
immutable SQLite；不复用历史 mission ID、不改写历史 reservation 或 UNKNOWN。
`approved_mission_scope` 字段仍为 `approval_id / mission_id / base / path / content /
sha256 / expires_at`，path 必须为 `docs/agentic/missions/<mission-id>.json`。
Controller 在隔离 clone 提交 scope，Builder 不能修改；scope 自身也须明确授权。
base、head 均使用完整 40 字符 SHA。用户源工作区和安装入口不会自动改变。

项目 mode 配置必须设置 `project_contract=footballprediction` 和
`independent_review_required=true`，仍保留三个 profiles。只有 developer profile
用于 App Server；两个 canonical reviewer 的模型、认证、重试和语义由 trusted base
决定，reviewer profiles 不能覆盖它们。push-only `hosted_ci` 与项目模式互斥。

新增的 Controller 配置片段（示意值不是执行或费用授权）：

```json
{
  "project_container": {
    "image_id": "sha256:<64 lowercase hex of an already-installed trusted dev image>",
    "profiles": ["targeted", "pr", "strict"],
    "postgres_image_id": "sha256:<64 lowercase hex of the trusted local PostgreSQL 15 image>"
  },
  "checks": [["make", "verify-targeted"]],
  "ci": [["make", "verify-pr"]],
  "project_delivery": {"repository": "xupeng211/FootballPrediction", "base_branch": "main"},
  "project_review_limits": {
    "approval_id": "<explicit bounded review authorization reference>",
    "max_deepseek_chunks": 2,
    "max_canonical_diff_bytes": 64000,
    "allow_unknown_provider_usage": true
  }
}
```

上例不会证明 STRICT 已验证。原 `AGENTS.md` 和 `docs/AGENT_WORKFLOW.md` 要求
STRICT 在 PR 前实际通过 `make verify-strict`；Controller 必须在既有 `checks`
或 `ci` 中配置该命令，并授权 strict profile 及固定 dev/PostgreSQL 镜像。
缺少配置或成功执行证据时，Factory 在审核派发/发布之前阻断，不自动增加命令、
费用或降低 profile。NORMAL 与其他 workflow 的既有合同处理不变。

strict 结果以既有 operation 保存，绑定 immutable 任务、完整 BASE/HEAD/tree/diff/
scope/policy、容器策略/镜像、timeout 策略和 Controller 执行器源码版本。
仅允许当前完整执行记录的 PASS/exit 0；targeted、PR、未运行的配置、旧格式证据、
失败/超时/取消/UNKNOWN 与 fixture 不能替代它。发布、只读恢复、最终 gate 和
READY 报告重新核对记录及原始证据；源码/合同/执行条件变化使旧结果失效。
同一任务和版本的有效 strict 可以跨 checks/ci、round 和重启复用，无需逐阶段重跑；
恢复不把原 UNKNOWN 改写为成功。本规则不修改项目分类器、profile 实现或检查矩阵。

mission v2 另需 `pr_body_template`：Controller 审定的项目现有 PR 模板正文，包含
Summary、Scope、Documentation Impact、Tests、Risk、Rollback 和适用的 Strict
Review Evidence。只支持 `{{candidate_head}}`、`{{review_timestamp}}` 两个占位符，
后者来自已验证 Codex receipt 的 `review_completed_at`。CRITICAL 的 Provider
字段按项目规则用逗号列出 `codex-cli, claude-code-deepseek`。正文仍须通过原项目
trusted-base preflight，不能凭模板或 Factory 自填 PASS 跳过审核。
preflight 及委托规则代码均从准确 trusted BASE 导入；其 Git、archive/lifecycle、
disposable-proof marker 和 scope/config 读取的数据根显式指向候选，archive
changed-line 输入绑定完整批准 BASE。依赖隐式 cwd 的 Git 也在候选目录读取，
不执行候选提供的治理代码；任何预检拒绝发生在 push/create/update 之前。

## A：受控容器验证

`factory_container.py` 只由 Controller 调用；只接受上述 canonical make profile，
实际在容器执行 `python3 scripts/devops/validation_profiles.py <profile>`。候选不能
修改 Makefile、scripts/devops、scripts/ops/helpers、workflow、schemas/agentic 或
原 review authority；package 执行字段/lockfile、QA 配置、config、测试调度器和容器定义也须保持 base
规则不变，涉及它们须另行明确授权任务。验证前重建准确 base/head/tree、完整 diff、文件集合、scope
和 policy；还直接校验实际 tracked 源码字节/mode，不能仅依赖 Git stat cache。

Ruff 权威保护按批准的完整 BASE→HEAD Git 对象比较，覆盖任意层级的
`ruff.toml`、`.ruff.toml`，以及 `pyproject.toml` 中的 `[tool.ruff]`。
新增、修改、删除、重命名和类型变化不能借普通业务 scope 授权改变 QA 标准；
同路径同类型且 Ruff 表不变的嵌套 pyproject 业务元数据编辑仍可继续，根配置的原保护不变。
从两个端点的配置逐条追踪直接 `extend` 关系，依赖文件即使不是 TOML 后缀也受保护。
只解析仓库内普通 Git blob，不执行候选代码、不跟随符号链接或读取仓库外文件；
缺失、损坏、循环、越界或需环境/用户目录展开的依赖无法核实，明确拒绝并要求
单独的 policy mission。当前项目桥未实现这种独立 QA 变更授权入口，不能凭候选标记或
布尔字段放行，也不修改原项目 Ruff 配置发现或检查命令。

ESLint 权威按同样的完整 Git 端点比较，固定原版本为 8.57.1。
各层 `.eslintrc.js/.cjs/.yaml/.yml/.json`、无后缀 `.eslintrc` 和
`package.json.eslintConfig` 的新增、修改、删除、重命名或类型/mode 变化均受保护。
原 lint 的 cwd 是仓库根；根 `.eslintignore`、根 package 的 `eslintIgnore` 及
会自动切换 flat 模式的根 `eslint.config.js/.mjs/.cjs` 也受保护。
嵌套 `.eslintignore`、嵌套 flat 文件不会由该固定命令选择。
JSON 配置的本地 `extends`（含 overrides）依赖同样冻结；只接受可在 Git 树内
精确确认的普通 blob，不猜测 Node 后缀/目录回退。固定合同的 recommended/jsdoc
依赖由原 lockfile 保护；动态配置、非 JSON YAML、自定义 parser/plugin 或无法
核实的依赖明确阻断，不执行候选配置。此桥没有建设通用 ESLint loader。
混合 package 文件保留无关元数据编辑：嵌套比较 ESLint 字段；根仅豁免已知展示
字段（如 description、author、license），scripts、依赖、type 和未知根字段仍冻结。
根 lockfile、`.npmrc` 和优先于 package-lock 的 `npm-shrinkwrap.json` 也按完整端点冻结；
固定基线没有后两者，不允许普通候选改变 npm 的执行环境或依赖选择。
发布正文预检入口重复核对 target/policy；容器 source_check 在镜像检查前运行。
这些是本地准入保证，不代表真实容器、独立审核或交付已通过。

`final_gate` 可委托现有项目 `agent-merge-ready`，缺少 PR/CI context 时拒绝。
Factory 主流程仅在显式阶段 2 模式接受经验证的 PR/CI context；首次付费执行仍因
canonical runner 物理费用上界未证明而阻断。该段描述 main 的原可信 QA / PR CI 路径；
Controller 路径仍须满足其既有显式审核费用授权、固定镜像和发布策略，不从兼容整合中获得新授权。
模拟 final gate PASS 只产生离线状态，merge approval 仍要求 live READY 与人工
exact-head 授权，fixture 永不满足。阶段 2 再接入可信验证和实际远端证据；阶段 3
才验证业务任务、实际 Provider receipt、MERGE_READY 与合并后的 main Gate。

pytest 权威以固定项目依赖 `pytest==9.0.2` 的配置发现为依据，按完整 BASE→HEAD
保护任意层级的 `pytest.toml`、`.pytest.toml`、`pytest.ini`、`.pytest.ini`（空文件也能
被选中），以及 `pyproject.toml` 的 `[tool.pytest]`/`[tool.pytest.ini_options]`、
`tox.ini` 的 `[pytest]` 和 `setup.cfg` 的 `[tool:pytest]`。配置或模式/类型变更、
删除和重命名导致的配置回退均须另行 policy mission；原根配置保护不变。
原计划的 pytest 参数位于 `tests/`，没有有效配置时还核对其目录/共同祖先上的
无 pytest 表 pyproject 回退 rootdir。未改变选择来源、同路径同类型且 pytest 节不变的
业务元数据可继续；INI 节采用保守的原节文本比较，TOML 保留值类型比较。
只读普通 Git blob；符号链接、异常类型、损坏或歧义语法明确拒绝，不执行候选配置、
不读取仓库外文件。保护不重写原 pytest 命令或发现机制；pytest 版本或原参数范围
若改变，须重新核实此绑定，不能据本地替身结果宣称真实容器/CI 已验证。

固定本地 image ID，`--pull=never`，不 build、不下载、不访问现有业务容器。
Controller 克隆一次性验证副本并设置批准 base 的 origin/main ref；只把副本挂入
容器，`.git` 只读。既有镜像 node_modules 经 Docker copy-out 进入临时副本，避免
root-owned anonymous volume 导致非 root 验证无法写缓存。不执行镜像 entrypoint。
容器使用当前 uid/gid、空白 env、network=none、read-only root、cap-drop=ALL、
no-new-privileges 和 CPU/memory/pids/tmpfs 限额；不挂 Docker socket、HOME、凭据、
已有数据库或外部 evidence。npm offline、pip no-index；依赖不足必须报告，不能联网补装。
空白环境仍保留固定的 `/opt/venv/bin:/usr/local/bin:/usr/bin:/bin`，以使用既有 dev
镜像中的项目 Python 依赖；不继承宿主或 agent 提供的 PATH。

`pr`/`strict` 另要求固定本地 PostgreSQL 15 image ID；预检检查两个镜像，缺失服务配置
或镜像仍阻断。Controller 创建任务独占 PostgreSQL：network=none、非 root、只读 root、
cap-drop、临时 tmpfs 数据、无宿主端口/持久卷/业务库；准确 mission/head/scope labels。
验证容器仅共享该网络命名空间的 loopback，认证 SELECT 1 就绪后才执行原 profile。
一次性随机密码只存在 0600 临时文件和进程环境，日志不输出；固定 wrapper 读取这个
单一文件后 env -i，不继承镜像/宿主凭据。PG 自身有截止时间，Controller 丢失也不会
无限运行；失败/超时/取消/异常都核对 ownership 后销毁资源，清理不明不能 PASS。
该全新隔离 cluster 的 fixture 数据库名固定为 `football_db`，因为原 init_db.sql
包含对该字面量的 GRANT；用户名/密码仍为任务独有，不代表连接任何已有同名数据库。
项目冷启动原检查负责临时建库、schema、合成写入回滚及删库。当前 pr 选定测试中
Redis 为替身，没有无条件真实 Redis 依赖，因此不启动 Redis；不运行原 compose
或连接已有 dev 服务。只有另行明确的测试数据库授权才能启用这条服务路径。

前后记录 candidate 与临时副本 tracked 源码摘要，意外变化不能 PASS；临时 cache
和测试产物随副本销毁。保留准确版本、scope、镜像、argv、exit code、原日志、时长、
超时/取消及清理证据。取消/超时会停止 Docker client 并强制移除对应命名容器，
成功 daemon 查询必须证明它已不存在；清理不确定不能 PASS。预检会核实这条专用
路径及本地 image，缺配置/镜像/daemon 仍明确阻断，不删除普通 Docker sandbox blocker。

所有验证 profile（包括无 PostgreSQL 的 targeted）都在容器内由独立 GNU timeout
限制进程寿命，TERM 后最多 5 秒再 KILL；`--rm` 只负责退出后删除，并非寿命限制。
Controller 被强制终止时验证仍会到期。首次 Docker 调用前写入私有、不可覆盖的
`<operation>.container.json`，绑定 mission、准确 target、policy、profile、随机资源名
与临时目录。恢复只对该记录列出的资源逐一核对 mission/head/scope/owner labels 后
清理，绝不按公共前缀批量删除。容器与临时目录的清理结果追加为事件，不能把原
RUNNING/UNKNOWN 验证改为通过，也不能自动重跑测试。退出码 137 的原因未被证明时
仅记录失败，不能冒称一定是 timeout。

新 lifecycle v2 保存完整 target 的规范 JSON SHA256，完整 target 仍在原 operation
证据中；资源、policy、profile 和临时目录继续显式保存。序列化记录最多 64 KiB，
写入前核对容量，超限时尚未创建任何容器。旧版内嵌 target 的中断记录保持原字节，
读取上限为可信 operation 中预期 target 的旧版序列化字节数加 64 KiB 元数据余量；
只接受完整 target 相等的旧格式。v2 自身仍受 64 KiB 限制。未知版本、损坏或身份
不匹配的记录不能清理，原证据路径、raw hash 和资源归属检查不变。

干净验证副本显式将 `refs/remotes/origin/main` 写为批准的完整 BASE，并通过同次执行
的可取消、受剩余 deadline 限制的 Git 客户端回读核实；不匹配时不创建容器。
`env -i` 同时传入 `BASE_REF`、`HEAD_REF` 和原 helper 所需的 `GITHUB_BASE_REF=main`，
使 profile 文件选择、静态诊断新增行和 gatekeeper 两条差异入口都使用完整批准范围，
不依赖来源工作区已有的 main/origin/main，也不修改原 canonical profile 或诊断门槛。

验证 stdout/stderr 经 Controller pipe 在写入持久日志之前遮蔽本任务已知的随机测试
密码；跨读取块保留最多密码长度减一的可能前缀，结束时保守遮蔽未完成前缀。
验证容器禁用 Docker 日志驱动，避免原始输出在另一处落盘；服务就绪/清理诊断仍保留。
这不识别任意未知秘密。Controller 被杀时可能丢失尚未写出的短尾部，但不依赖 finally
重写原日志来保护密码。任务凭据临时文件仍受私有目录/0600 和精确恢复清理保护。

PostgreSQL 清理区分命令结果与诊断写入结果。日志 write/flush 的 OSError 或关闭流
错误只追加无输出、无异常正文的错误类型/errno/命令结果摘要，不吞掉真实命令错误；
inspect 已成功时仍按本任务全部 ownership 标签核验，再执行一次有界移除及准确名称
的不存在确认。inspect 失败、输出损坏或身份不符时不删除；rm 非零或响应未知保持
清理未确认。重复 close 重新取得证据，不沿用旧成功。诊断丢失或服务 logs 命令失败
单独标为 diagnostics_complete=false，即使资源确已清理也不能得到容器检查 PASS。

取消后 resume 只允许在既有 RUNNING/UNKNOWN，以及清理尚未确认的 COMPLETE
非付费 checks/ci 记录上执行精确
ownership 核验与清理，不准备候选、不重新验证、不查询发布状态或调用模型。
COMPLETE 必须通过原操作证据与 lifecycle 摘要、任务和目标绑定核对；已确认清理的
记录跳过恢复。清理失败明确记为未确认；原 operation、COMPLETE/UNKNOWN、usage
和 reservation 保持原样，仅追加清理证据。
每次 Factory 执行有独立取消事件和不复用的身份；watcher 必须携带该身份，迟到的旧
取消或结束回调不能影响新任务。相同 LocalRuntime 的重叠执行被拒绝，直接 Controller
容器调用也建立任务身份；取消直接调用时须传入该次 `container_cancel` 事件。
独立 project_remote 状态观察同样建立新身份，并在正常或异常结束时释放；活动执行
只允许相同 mission 与所属线程借用其身份，并继续服从其取消。其他活动任务的查询
被拒绝，不覆盖身份或清除取消；旧任务已置位的事件和迟到回调对新观察没有权限。
源码 clone/remote-remove/checkout/update-ref 和依赖 create/cp 客户端同样登记到该执行身份，派发前检查取消和剩余 deadline，
准备期间可取消且不重新获得原 timeout；停止后仍执行有界、核对归属的 finally 清理。
准备和主验证客户端使用同一直接生命周期入口，以 Linux `waitid(WNOWAIT)` 观察退出，
禁止输出消费和取消回调提前 `poll/communicate` 回收 leader。它们与远端 worker
共用既有的归属核验和组收尾逻辑：
核对本次执行令牌、PID/starttime、直接父进程、UID、PGID/SID，在未回收子进程的
内核身份锚点仍有效时停止普通同组后代，然后回收 leader。无活进程时不发送组信号。
工作在原总时限及阶段上限内预留 0.1 秒与剩余时间四分之一的较小者供收尾，不增加
新的等待预算。`preparation_clients` 和 `validation_client_cleanup` 分别记录准备与主验证的
退出码、组停止、leader 回收、待父/init 回收的 zombie 与诊断状态；stdout/stderr 保持
各自原输出语义，主验证仍合并并即时脱敏。主验证退出成功也须确认普通同组后代已停止，
其确认结果参与 `cleanup_confirmed`。归属或组停止无法确认
时保留执行身份、阻止新派发，容器门禁不得宣称清理完成或 PASS。日志失败仍先尝试
安全收尾，保留原执行异常及可获得的退出码/输出；诊断缺失同样不能 PASS。产品不启用
subreaper，不保证主动 setsid 逃逸进程或任意 daemon 的回收。
源码准备中止时不再派发验证，未建立完整快照不声称源码完整性已确认。
gate 从首次镜像检查之前开始计时，镜像检查、原有源码/策略核验、源码准备、
依赖准备、PG 启动/隔离检查/健康检查、验证及结束源码核验共用一次绝对 deadline
和执行身份。原有源码/Git/策略核验在受跟踪的本地进程组内执行，取消可终止其
嵌套客户端；不改共享 Git 工具。停止后不派发普通检查，源码不能核实即不能 PASS。
只有既有有界 ownership 清理允许越过取消/deadline，elapsed 包含镜像及临时目录清理。
删除只派发一次；Docker 自动删除与取消重叠时，在两秒确认窗口内查询准确资源名，
只有肯定的不存在证据才能确认清理，原 rm 退出码仍保留。查询失败或未消失仍为未确认。

## B：专用分支、PR、必需 CI 与交付复核

发布前预检、首次最终预检与原 `agent_workflow` 内重复预检共用同一段明确的数据绑定：
规则模块只从已核实的可信 BASE 导入，preflight、gate、Git helper、governance 和
disposable proof helper 均读取准确候选，Git cwd 也为候选。显式传入批准的完整
BASE/HEAD，并将 legacy archive scanner 的隐式 base 绑定完整批准 BASE，不退回
HEAD~1。保留重复预检、原生命周期/归档/证明标记检查与各阶段原有权限和证据职责；
合法新脚本可用原规则认可的文件头声明，不需要自动补写备用 PR 正文段落。

只有双 receipt 当前有效且无任何 findings、本地 checks/ci PASS 后，Controller
才发布。`factory_remote.py` 固定可信 repository/main，以 mission+base 推导专用
`factory/<mission>-<base12>` 分支，以 scope/repo/base 的 marker 识别所有权。
Factory.prepare、本地报告和发布使用同一分支推导；发布/观察前核对本地分支。
恢复时同样要求原准确身份，不重命名旧候选或新建替代分支来通过 readiness。
它先核实远端 main 等于批准 base；从新建 Controller Git 元数据取准确提交，禁用
候选 hooks/config，不 force push。只有已证明的上一候选 publication 可更新同一
PR，其他 HEAD、closed PR、fork、不同 base 或模糊发现均拒绝。正文由 immutable
Controller template 与已验证 receipt 渲染，准确 HEAD/body/scope 均需绑定。
正文缓存重复检查按原始 UTF-8 字节与批准正文比较，保留 CRLF；即使只改变换行字节，
也按证据变化拒绝，不规范化或改写已保存正文及其 SHA256 路径。
PR 标题取任务目标中首个非空行并去除首尾空白，保持 200 字符上限；标题无效时在任何
远端写入前拒绝，原任务目标文本保持不变。

发布使用既有非付费 operation/evidence。创建/更新只尝试一次；响应丢失或崩溃后，
恢复只查询 branch 和 PR。仅当 repo/base/head/body/marker 全匹配时，追加只读
reconciliation operation 和 event，原 RUNNING/UNKNOWN 行保持不变。无法确认时
停在 UNKNOWN，不再次 push/create/update。观察到 push、未观察到 PR 也不会自动
补发；须人工判断外部状态。这是防重复优先的有限恢复，不承诺 exactly-once 网络写。

CI 复用 `adapter.ci` 和 trusted-base `pr_ready_check`，查询 active ruleset 对该
真实 PR 的 required checks，严格比较准确 base/head。missing/queued/in_progress
等待到既有 timeout；失败或 skipped 不能 PASS。push workflow 不能替代 PR checks。
remote worker 与父进程共用绝对单调截止时间；在原总时限内预留至多一秒（短时限为
其四分之一）供结果返回和回收。正常退出的完整 worker 结果才能确认等待 TIMEOUT；
取消、异常退出或父层强制中断分别保留其错误类型，operation 仍按既有规则记 UNKNOWN，
不把残缺输出补成正常结果，也不重新获得完整 timeout。
父层以 Linux `waitid(WNOWAIT)` 观察远端 worker 退出，在同组普通后代结束前
保留尚未回收的直接子 worker，作为防 PID/PGID 复用的内核锚点。每次组信号均
核对当前执行令牌、PID/starttime、父子关系、UID 及 PGID/SID；主 worker 已退出
也不能跳过组收尾。stdin 使用私有临时文件，stdout/stderr 原字节另存并绑定到
operation，避免 `communicate/poll` 提前回收锚点。收尾仍只使用原截止前的剩余时间。
`.cleanup.json` 区分组内进程已停止、leader 已回收、等待其父/init 回收的后代
zombie，以及诊断写入失败。无法确认归属或组停止时保留执行身份并阻止再次派发，
等待人工处理，不使用过期 PGID 猜测清理；原执行错误和 UNKNOWN 保留。
清理成功但诊断写入失败也如实记录并保留 UNKNOWN。产品不启用 subreaper，
不承诺收回主动 setsid 逃逸进程或任意 daemon；离线测试 subreaper 仅用于回收测试孤儿。
失败 CI 进入既有 rework → 新 checkpoint → 新 tests/reviews → PR update → 新 CI。

最终 `verify` 把实际 PR number/repo/base、两份 codex/deepseek receipt 与当前
CI status 传给 `adapter.merge_ready(use_project_policy=True)`；不 override backend。
原 canonical final gate 执行后再次核对 PR/CI。只有真实 mode 可达
`READY_FOR_USER_ACCEPTANCE`；delivery/status/approve 读取时会重新验证 receipt、
operation hashes、准确源码以及远端 PR/CI/final gate。新 HEAD、正文编辑、main
变化、过期 receipt 或失败 CI 使旧交付失效。READY 只表示合并前证据成立，
`DONE=false / MERGE_PERFORMED=false`，最终人工授权、Merge 后 exact main Gate 和
部署均不在本实现。status 现在可能做只读远端调用并追加观察证据。

只读 reconcile/ci/verify 的已结束 UNKNOWN 可以发起新的同目标观察；每次均有
独立 operation 和原始证据。只有新观察经现有远端检查为 PASS，且 repository、数值
PR、base/head/tree、scope、policy、正文、观察种类及适用 receipts 的完整输入一致，
才能追加 `remote_observation_recovered` 关联。读取时复核两个 operation、immutable
envelope 和 raw hashes；手写 PASS 事件不能解除阻断。旧 UNKNOWN、usage、reservation
始终不改。没有预先绑定数值 PR 的失败首次发现仍须人工确认，不能猜一个 PR 解除。
此恢复不适用于仍 RUNNING 的观察、付费审核或发布写入；发布原有只读 reconciliation
规则保持。历史恢复关系只证明原目标，不给新候选借用 CI 或交付结果。

远端认证只沿 Controller → remote worker → gh/git 的两层路径传递，复用 adapter
已有可信认证变量白名单；宿主其余变量、Git/loader/Python 注入被过滤。认证变量
不进入开发或审核 agent 环境、输入包、argv 或普通证据文件，日志只保留非秘密命令
和输出摘要，不记录认证值。

## C：收费前范围、分块与授权

每次新的 canonical review 在 reservation 之前重新核对实际 target/scope，并从
trusted base 调用纯 canonical chunk planner，覆盖完整 canonical diff、每块与
完整 prompt byte limits。Factory diff policy/hash 和项目 canonical diff policy/hash
分别保留；不截断或沿用旧候选的 plan。实际 chunk 数或 diff bytes 超过明确授权即
零派发阻断，两个 lane 都在首个收费审核前检查完整 DeepSeek plan。准备完成到实际
runner 启动之间再次重算并比较 admission，变化则不启动 provider。

可限制的是每个 DeepSeek outer review 的 backend/chunk 数、canonical diff bytes、
既有 outer agent-run 数、逻辑 token reservations、每次 timeout、mission wall clock
与返工轮数。`allow_unknown_provider_usage=true` 必须是 Owner 明确接受剩余未知的
授权输入，不是默认同意。每个 chunk 创建一个 CLI backend execution，**不等于
一次 HTTP 请求**。Codex/Claude CLI 内部请求、重试、完整 usage、输出 token 与
人民币物理硬上限仍 UNKNOWN。`project_review_limits` 拒绝 max_cost_cny、
max_http_requests、max_output_tokens 等无法执行的限制；不得把它们写成已生效。
既有 budget token 字段是 admission/reservation，canonical usage UNKNOWN 继续保留。

历史 ledger、UNKNOWN、reservation、canonical 模型/认证/重试不变；双审和
Factory all-findings（包括 P3）返工 barrier 不变。没有新增计费或审核框架。

## 验证证据边界

`test_factory_controller_gates.py` 的 Docker/GitHub API 与写入使用明确命名的 doubles，
即使测试 live 状态转换也不构成真实 PR 或 CI 证据。fixture/live marker 交叉被拒绝。
`test_factory_project_integration.py` 从准确项目 main
`a65464d1e5de498a072ed9a8fdf69ce46bcc04c5` 提取原 policy/planner/runner/validator，
仅替换 Provider 和认证环境探测，验证原接口；所有 fake identity 都只是离线材料。
设置 `FOOTBALLPREDICTION_CONTRACT_REPO` 指向拥有该 Git object 的只读仓库后运行
`make verify`。缺失来源是 UNVERIFIED/SKIP，不能冒称真实审核。

`test_factory_offline_readiness.py` 将真实 Factory.prepare/checkpoint、Remote
发布/观察/CI 和 adapter.ci 连接到上述固定对象的原 `pr_ready_check.evaluate`。
仅远端与 CI 响应使用替身，readiness 真实读取本地 Git；正常场景在隔离 fixture 状态
进入 READY，分支不匹配仍由原规则拒绝。开发者、审核、容器与其他 final-gate 条件
仍是已标明的离线 fixtures，不构成真实端到端交付、真实审核或正式 READY 授权。

真实容器检查、离线代码检查、真实远端、正式审核与业务验收必须分别报告。
本轮真实 PR writes/paid reviews/business mission 为 NOT_RUN，未改变安装入口。
