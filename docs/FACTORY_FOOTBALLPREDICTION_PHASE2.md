# FootballPrediction 阶段 2：安全验证与既有 PR CI

本轮是离线工程实现。默认 Factory 的 bubblewrap gate 与普通 push CI 保持原路径；
只有 `project_contract=footballprediction` 明确选择 `trusted_validation` / `project_pr_ci`
才接入以下路径。配置示例见 `config/factory.footballprediction.phase2.example.json`，
其中全零 image digest 是必须替换的占位符，不能运行成功。配置不构成远端发布授权。

## Controller 验证

仅接受原项目 `verify-targeted`、`verify-pr`、`verify-strict` 三种 profile。
STRICT/CRITICAL 的本地检查必须是 strict，CI 本地检查必须是 pr。
Controller 调用原 `scripts/devops/validation_profiles.py`，不运行候选 Compose / Dockerfile，
不 build、不 pull、不借用长期 dev 容器。镜像必须预先由可信操作者准备并以 repository
digest pin；镜像必须不包含凭据，并在 `/opt/cmh` 保存匹配候选的 `package-lock.json`、
`requirements.txt` 和已经完整安装的 `node_modules`，同时安装原项目所需 Python QA 依赖。
预检真实探测本地 daemon、digest、工具、关键依赖和锁文件哈希，字段存在不代表可用。
锁文件改变需要重新准备可信依赖镜像；Factory 不会联网补依赖。

Controller 使用固定本地 daemon socket，但该 socket、宿主 HOME、认证目录、原项目
Git 对象和 Factory evidence 从不挂载到候选容器。每轮 clone 一份独立 Git 对象快照，
清除远端 URL / hooks，保存只读 `origin/main` 基线用于原 profile 的完整范围计算，
整个快照只读挂载，并把原提交源码复制到限额 tmpfs 工作目录以允许正常 coverage/cache
产物。工作目录的 `.git` 是快照对象的独立只读挂载；验证前后 Git status 必须相同且
初始干净，任何源码变更都拒绝，忽略的测试产物只存在于临时 tmpfs。
容器采用非 root、只读根目录、cap-drop ALL、no-new-privileges、CPU/内存/PID 限额。

独立临时 PostgreSQL 使用固定可信 digest、临时密码、tmpfs、无端口和 `network=none`。
验证容器只共享这个数据库的回环网络命名空间，DB_HOST 固定为 127.0.0.1，
没有 bridge、宿主 gateway、生产网络或生产库。原冷启动蓝图门禁仍然执行，
不设置会跳过数据库失败的 `GATEKEEPER_LOCAL_CI` / local-hook 开关。
当前没有另建 Redis 服务；如果原 profile 实际需要它或其他服务，验证会失败关闭，
须在相同安全边界内确认项目依赖后做窄适配，不能改用宿主业务服务。

直接附着捕获完整 stdout/stderr（不依赖可轮转的 daemon 日志），记录 mission、head、
tree、profile、镜像 digest / image ID、配置哈希、起止时间、中断状态、真实退出码、
完整日志及其哈希。超过 64 MiB 日志上限、附着传输退出与容器退出不一致、OOM、
超时、启动失败、缺失环境准备标志、日志缺失或 cleanup 失败均为 UNKNOWN。
容器和匿名卷被清理，临时快照删除；cleanup 错误另行记录，绝不返回 PASS。
成功/失败证据与日志损坏时缓存不能恢复为通过；UNKNOWN/RUNNING 不自动重派发。

## PR CI 与授权

`project_pr_ci` 与普通 `hosted_ci` 分开；项目模式拒绝使用 push CI，原普通模式不变。
源仓库 origin 必须与受信任配置 repository 完全一致。候选冻结完整 head/tree，
分支名包含 mission 和完整 head，不允许 workflow 改动。

未来需要操作者单独批准当前候选及具体 PR 正文：

```sh
harness approve <mission> --action publish-pr --head <完整候选SHA> \
  --reason '<用户授权理由>' --pr-body /absolute/path/to/approved-pr-body.md \
  --config /absolute/path/to/operator-config.json
```

该命令只记录 owner approval，不联网。正文必须明确包含
`Mission scope contract: \`docs/agentic/missions/<mission>.json\``。
批准绑定 mission、repository、base/head/tree、分支、CI policy、正文哈希及到期时间。
之后经明确恢复才执行冻结候选的非 force push，并创建或复用唯一对应 PR。
实际远端写响应未知会落入原 UNKNOWN 操作，不自动重复创建。
默认批准非 Draft PR；已有 Draft 会明确阻断，不转换状态、不重开、不 rerun。
Factory 没有自动 merge/release/deploy 调用，候选从不获得 Controller GitHub 凭据。

只读 waiter 读取当前 Production Gate、适用于 main 的 ruleset checks 和 classic branch
protection checks。必须证明原项目两个必需检查都在实际规则中，未知必需检查/来源
会阻断。workflow 字节须与 trusted base 和候选相同；读取实际 synthetic merge revision
的 workflow blob。当前只支持该项目两个静态 job；新增 matrix、job-level 条件、
reusable workflow 或 checkout ref override 时明确拒绝，不猜测成功子集。

证据同时绑定 PR number、repo、head branch、main base/head SHA、synthetic merge 的
两个父提交、workflow ID/path/revision/blob、最新 run ID/attempt、pull_request 事件、
GitHub Actions app、对应 check suite/job/check-run 和完整 job 日志。两项 job 必须均
completed/success；缺失、重复、skipped、cancelled、failed、timed_out、neutral、UNKNOWN
均不能放行。checkout action 自己的 git log 输出必须证明实际测试 synthetic merge SHA，
后续候选程序输出不能伪装这个证据。它被标记为 `PR_SYNTHETIC_MERGE`，不称为候选
head 的独立测试。观察前后重读 PR、规则、run、最新 attempt，缓存和最终状态也重查。
当前远端取证失败只能阻断，不能从旧 green 或缓存恢复为通过。

## 阶段 1 合同及费用边界

原 scope 字节、base/head/tree/full diff、canonical 双 reviewer、原项目双 receipt
验证、Factory 默认任何 finding 阻断、预算与账本保护继续有效。CI 完成后仍调用
trusted-base 项目的 `agent-merge-ready`，不能使用 Factory 自填 PASS 代替。
状态恢复再次验证原 receipt 和项目 final gate。`OFFLINE_CONTRACT_PASS` 永远只说明
fixtures；live READY 表示可以提交用户验收/merge 判断，`DONE` 永远为 false。
人工 merge/release approval 原规则不变。

当前 canonical DeepSeek 外层 operation 可能触发最多 64 个 backend 执行，物理费用
上界未证明。所有非 simulation 项目任务在首次付费预检保持 HARD_BLOCKER；
本轮不提供解除字段，不修改 runner，也不执行 Qualification 或真实 review。
要真实交付，须先另行解决并批准物理费用边界，再取得业务执行和远端发布授权。

## 本轮验证分类

- VERIFIED：Factory/LocalRuntime 的离线调用路径、SQLite reservation/evidence/cache、
  原阶段 1 回执测试与异常拒绝；Docker 和 GitHub 行为由显式 fixture 替身提供。
- VERIFIED：本机 Alpine 临时容器隔离探针，真实 network=none、非 root、只读根目录、
  无宿主挂载/端口、cap-drop ALL/no-new-privileges、exit=0、cleanup=COMPLETE。
  这只证明探针的隔离条件，不是 FootballPrediction Docker E2E。
- VERIFIED：原生 Factory Agent command/exec 探针不能连接 `/var/run/docker.sock`
  或 `/run/docker.sock`，且未启动任何 model turn。`make verify` 共 616 项测试通过，
  新增阶段 2 专项 17 项通过（每项包含多种异常子场景）。
- REPORTED：项目正式 profile / Production Gate / operational contract 的受信任基线源码
  声明。已读取 FootballPrediction 精确基线对象，未修改其仓库。
- VERIFIED：只读读取一个既有 Production Gate run/job、当前 ruleset 和 classic protection
  信息，核对真实字段；checkout 日志解析出实际合成 SHA。该历史 run 的 PR association
  为空，不能作为本任务 CI 通过证据。
- UNVERIFIED：FootballPrediction 正式 profile、匹配锁文件的可信镜像、临时数据库
  对全部业务验证的充分性、当前新候选 PR CI 的完整远端取证、真实 provider receipts
  和生产交付。无真实 Provider 请求，无远端 PR、merge、release 或部署。

建议合并 Harness 变更前做独立 Exact-HEAD 审查；本轮未执行付费独立 review。
不需要通用容器平台、矩阵解释器、第二套 review policy 或新的调度层。
