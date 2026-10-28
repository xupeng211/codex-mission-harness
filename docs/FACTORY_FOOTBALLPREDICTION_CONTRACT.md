# Factory FootballPrediction：Controller 执行与交付桥

本模块复用项目 trusted-base policy、canonical profiles、双审核原 runner/validator、
PR readiness 和 merge-ready。它不提供 Merge、部署、数据采集或业务检查器。
实现/离线测试不等于真实远端验收。fixture 永远只有 `OFFLINE_CONTRACT_PASS`。

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

mission v2 另需 `pr_body_template`：Controller 审定的项目现有 PR 模板正文，包含
Summary、Scope、Documentation Impact、Tests、Risk、Rollback 和适用的 Strict
Review Evidence。只支持 `{{candidate_head}}`、`{{review_timestamp}}` 两个占位符，
后者来自已验证 Codex receipt 的 `review_completed_at`。CRITICAL 的 Provider
字段按项目规则用逗号列出 `codex-cli, claude-code-deepseek`。正文仍须通过原项目
trusted-base preflight，不能凭模板或 Factory 自填 PASS 跳过审核。

## A：受控容器验证

`factory_container.py` 只由 Controller 调用；只接受上述 canonical make profile，
实际在容器执行 `python3 scripts/devops/validation_profiles.py <profile>`。候选不能
修改 Makefile、scripts/devops、scripts/ops/helpers、workflow、schemas/agentic 或
原 review authority；package/lockfile、QA 配置、config、测试调度器和容器定义也须保持 base
规则不变，涉及它们须另行明确授权任务。验证前重建准确 base/head/tree、完整 diff、文件集合、scope
和 policy；还直接校验实际 tracked 源码字节/mode，不能仅依赖 Git stat cache。

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

## B：专用分支、PR、必需 CI 与交付复核

只有双 receipt 当前有效且无任何 findings、本地 checks/ci PASS 后，Controller
才发布。`factory_remote.py` 固定可信 repository/main，以 mission+base 推导专用
`factory/<mission>-<base12>` 分支，以 scope/repo/base 的 marker 识别所有权。
它先核实远端 main 等于批准 base；从新建 Controller Git 元数据取准确提交，禁用
候选 hooks/config，不 force push。只有已证明的上一候选 publication 可更新同一
PR，其他 HEAD、closed PR、fork、不同 base 或模糊发现均拒绝。正文由 immutable
Controller template 与已验证 receipt 渲染，准确 HEAD/body/scope 均需绑定。

发布使用既有非付费 operation/evidence。创建/更新只尝试一次；响应丢失或崩溃后，
恢复只查询 branch 和 PR。仅当 repo/base/head/body/marker 全匹配时，追加只读
reconciliation operation 和 event，原 RUNNING/UNKNOWN 行保持不变。无法确认时
停在 UNKNOWN，不再次 push/create/update。观察到 push、未观察到 PR 也不会自动
补发；须人工判断外部状态。这是防重复优先的有限恢复，不承诺 exactly-once 网络写。

CI 复用 `adapter.ci` 和 trusted-base `pr_ready_check`，查询 active ruleset 对该
真实 PR 的 required checks，严格比较准确 base/head。missing/queued/in_progress
等待到既有 timeout；失败或 skipped 不能 PASS。push workflow 不能替代 PR checks。
失败 CI 进入既有 rework → 新 checkpoint → 新 tests/reviews → PR update → 新 CI。

最终 `verify` 把实际 PR number/repo/base、两份 codex/deepseek receipt 与当前
CI status 传给 `adapter.merge_ready(use_project_policy=True)`；不 override backend。
原 canonical final gate 执行后再次核对 PR/CI。只有真实 mode 可达
`READY_FOR_USER_ACCEPTANCE`；delivery/status/approve 读取时会重新验证 receipt、
operation hashes、准确源码以及远端 PR/CI/final gate。新 HEAD、正文编辑、main
变化、过期 receipt 或失败 CI 使旧交付失效。READY 只表示合并前证据成立，
`DONE=false / MERGE_PERFORMED=false`，最终人工授权、Merge 后 exact main Gate 和
部署均不在本实现。status 现在可能做只读远端调用并追加观察证据。

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

真实容器检查、离线代码检查、真实远端、正式审核与业务验收必须分别报告。
本轮真实 PR writes/paid reviews/business mission 为 NOT_RUN，未改变安装入口。
